//! Disk-mode block apply benchmark (filter "db/disk-state"), run by `bench.run_commit`.
//!
//! The shape of executing real Base Sepolia blocks on an imported disk-mode database
//! (`import/run.zig`), without the EVM and without the real database: a synthetic state of
//! `Shape.accounts` accounts, every `contract_every`-th a contract whose slot count comes from
//! a skewed tier (most hold a few slots, a few hold hundreds of thousands), is streamed as
//! reth `HashedAccounts` / `HashedStorages` entries through `to_disk.ImporterType` (the same
//! bulk import the node's database comes from, sized by `to_disk.sizing` with `shape_node`),
//! onto `IoStorage` over the OS backend (a scratch file under `.zig-cache/tmp`, deleted
//! afterwards). The database is then reopened (an empty block cache) and the file's pages
//! dropped from the OS page cache (`fadvise`), so the first blocks read cold.
//!
//! Each block reads every key it touches first, as the evm would (`State.basic` /
//! `State.storage`: the "reads" phase), then writes them into an `Overlay` and commits it:
//! `Overlay.commit` -> `State.apply` -> `DiskState.apply` (the sparse root and the record
//! write-back: the "apply" phase), then `Database.commit_applied` journals it, as the runner
//! does. A block touches a few hot accounts and slots (system contracts, fee vaults: every
//! block), random existing accounts, random slots of random contracts (half of them large
//! ones), a few new accounts and new slots, and deletes some slots.
//!
//! Reported per block, cold (the first `blocks_cold`) and warm (the last half of the
//! `blocks_warm` that follow): ms of reads, apply (and DiskState's phases), journal, room;
//! grid reads (synchronous, block-cache misses), block-cache hits and misses, DiskState's
//! record and leaf resolutions and the tree reads they took.
//!
//! Benchmark scaffolding: fixtures come from the page allocator, and the scratch file is opened
//! and its page cache dropped here (Linux `fadvise`), not in library code.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

const bench = @import("bench.zig");
const changeset_module = @import("changeset.zig");
const overlay_module = @import("overlay.zig");
const branch_record = @import("branch_record.zig");
const to_disk = @import("../import/to_disk.zig");
const hashed_state = @import("../import/hashed_state.zig");
const SimStorage = @import("storage/sim_storage.zig").SimStorage;
const IoStorageType = @import("storage/io_storage.zig").IoStorageType;
const io_root = @import("../../utilities/io/root.zig");
const node = @import("../trie/node.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Hash = [32]u8;
const Address = [20]u8;
const AccountInfo = changeset_module.AccountInfo;
const Changeset = changeset_module.Changeset;
const Overlay = overlay_module.Overlay;
const Entry = hashed_state.Entry;

pub const name = "db/disk-state";

pub const Shape = struct {
    accounts: u32,
    contract_every: u32,
    /// Divides every slot tier (small shapes for tests).
    slot_divisor: u32,
    hot_accounts: u32,
    /// Slots of the hot contract (account 0) every block writes.
    hot_slots: u32,
    block_accounts: u32,
    block_contracts: u32,
    block_slots_per_contract: u32,
    block_new_accounts: u32,
    block_new_slots: u32,
    blocks_cold: u32,
    blocks_warm: u32,
    cache_blocks: u32,

    fn check(shape: Shape) void {
        assert(shape.accounts > shape.hot_accounts + 1);
        assert(shape.contract_every > shape.hot_accounts);
        assert(shape.slot_divisor > 0 and shape.blocks_cold > 0 and shape.blocks_warm > 1);
        assert(shape.hot_slots <= slots_tier(0, shape));
    }

    fn contracts(shape: Shape) u32 {
        return (shape.accounts + shape.contract_every - 1) / shape.contract_every;
    }

    fn block_slots(shape: Shape) u32 {
        return shape.hot_slots + shape.block_contracts * shape.block_slots_per_contract +
            shape.block_new_slots;
    }

    fn block_account_count(shape: Shape) u32 {
        return shape.hot_accounts + shape.block_accounts + shape.block_new_accounts;
    }
};

/// ~2M accounts, ~18M slots: ~4 GB of trees.
pub const shape_bench: Shape = .{
    .accounts = 2_000_000,
    .contract_every = 40,
    .slot_divisor = 1,
    .hot_accounts = 4,
    .hot_slots = 6,
    .block_accounts = 60,
    .block_contracts = 40,
    .block_slots_per_contract = 3,
    .block_new_accounts = 4,
    .block_new_slots = 8,
    .blocks_cold = 50,
    .blocks_warm = 400,
    // 64 MiB over ~4 GB of trees: about the node's cache over the real state, in ratio.
    .cache_blocks = 1024,
};

pub const shape_test: Shape = .{
    .accounts = 3000,
    .contract_every = 10,
    .slot_divisor = 100,
    .hot_accounts = 4,
    .hot_slots = 6,
    .block_accounts = 20,
    .block_contracts = 8,
    .block_slots_per_contract = 3,
    .block_new_accounts = 2,
    .block_new_slots = 4,
    .blocks_cold = 6,
    .blocks_warm = 12,
    .cache_blocks = 64,
};

// The synthetic state: everything is a function of the account index (and slot index).

fn mix(a: u64, b: u64) u64 {
    var bytes: [16]u8 = undefined;
    std.mem.writeInt(u64, bytes[0..8], a, .little);
    std.mem.writeInt(u64, bytes[8..16], b, .little);
    return std.hash.Wyhash.hash(0x5eed_d15c, &bytes);
}

fn address_of(index: u64) Address {
    var address: Address = @splat(0x5e);
    std.mem.writeInt(u64, address[12..20], index, .big);
    return address;
}

fn is_contract(index: u64, shape: Shape) bool {
    return index % shape.contract_every == 0;
}

/// Slots contract `index` holds at import: 0.1% hold 200k, 1.9% 5k, 18% 300, the rest 20;
/// account 0 (the hot contract) is in the largest tier.
fn slots_tier(index: u64, shape: Shape) u32 {
    const roll = if (index == 0) 0 else mix(index, 1) % 1000;
    const slots: u32 = if (roll < 1) 200_000 else if (roll < 20) 5000 else if (roll < 200)
        300
    else
        20;
    return @max(1, slots / shape.slot_divisor);
}

fn slots_of(index: u64, shape: Shape) u32 {
    if (!is_contract(index, shape)) return 0;
    return slots_tier(index, shape);
}

fn slot_of(index: u64, slot_index: u64) u256 {
    return @as(u256, mix(index, slot_index + 2)) << 128 | mix(slot_index, index + 7);
}

fn word_of(index: u64, slot_index: u64) u256 {
    return @max(1, mix(index ^ 0x77, slot_index) >> 8);
}

fn info_of(index: u64, shape: Shape, code_hash: *const Hash) AccountInfo {
    return .{
        .nonce = mix(index, 3) % 1000,
        .balance = mix(index, 4) >> 4,
        .code_hash = if (is_contract(index, shape)) code_hash.* else node.empty_code_hash,
    };
}

const code = [_]u8{ 0x60, 0x00, 0x60, 0x00, 0xf3 };

const Keyed = struct {
    hash: Hash,
    index: u32,

    fn less(_: void, a: Keyed, b: Keyed) bool {
        return std.mem.order(u8, &a.hash, &b.hash) == .lt;
    }
};

/// Trimmed big-endian bytes of `value` (reth's Compact integers).
fn trimmed(out: []u8, value: u256) []u8 {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    var start: usize = 0;
    while (start < 32 and bytes[start] == 0) start += 1;
    @memcpy(out[0 .. 32 - start], bytes[start..]);
    return out[0 .. 32 - start];
}

/// The reth `HashedAccounts` / `HashedStorages` streams of the state, in hashed-key order.
const Source = struct {
    shape: Shape,
    code_hash: Hash,
    order: []Keyed,
    /// Accounts stream position, and its value buffer.
    account_position: u32 = 0,
    account_value: [2 + 8 + 32 + 32]u8 = undefined,
    /// Storage stream: the contract's position, its slots sorted, the next slot.
    storage_position: u32 = 0,
    slots: []Keyed,
    slots_len: u32 = 0,
    slot_next: u32 = 0,
    storage_value: [64]u8 = undefined,
    /// Contracts in the 5k tier and above (where half the slot writes go).
    large: std.ArrayList(u32) = .empty,
    slots_total: u64 = 0,

    fn init(allocator: std.mem.Allocator, shape: Shape) !Source {
        shape.check();
        const order = try allocator.alloc(Keyed, shape.accounts);
        errdefer allocator.free(order);
        for (order, 0..) |*keyed, index| {
            keyed.* = .{ .hash = node.keccak256(&address_of(index)), .index = @intCast(index) };
        }
        std.mem.sort(Keyed, order, {}, Keyed.less);
        const slots = try allocator.alloc(Keyed, slots_tier(0, shape));
        var source: Source = .{
            .shape = shape,
            .code_hash = node.keccak256(&code),
            .order = order,
            .slots = slots,
        };
        for (0..shape.accounts) |index| {
            const count = slots_of(index, shape);
            source.slots_total += count;
            if (count >= 5000 / shape.slot_divisor and index > 0) {
                try source.large.append(allocator, @intCast(index));
            }
        }
        assert(source.slots_total > 0);
        return source;
    }

    fn deinit(source: *Source, allocator: std.mem.Allocator) void {
        source.large.deinit(allocator);
        allocator.free(source.slots);
        allocator.free(source.order);
        source.* = undefined;
    }

    fn accounts_source(source: *Source) hashed_state.EntrySource {
        return .{ .context = source, .next = next_account };
    }

    fn storages_source(source: *Source) hashed_state.EntrySource {
        return .{ .context = source, .next = next_slot };
    }

    fn next_account(context: *anyopaque) anyerror!?Entry {
        const source: *Source = @ptrCast(@alignCast(context));
        if (source.account_position == source.order.len) return null;
        const keyed = &source.order[source.account_position];
        source.account_position += 1;
        const info = info_of(keyed.index, source.shape, &source.code_hash);
        var nonce_bytes: [32]u8 = undefined;
        var balance_bytes: [32]u8 = undefined;
        const nonce = trimmed(&nonce_bytes, info.nonce);
        const balance = trimmed(&balance_bytes, info.balance);
        const has_code = !std.mem.eql(u8, &info.code_hash, &node.empty_code_hash);
        const flags: u16 = @intCast(nonce.len | balance.len << 4 |
            @as(usize, @intFromBool(has_code)) << 10);
        const value = &source.account_value;
        std.mem.writeInt(u16, value[0..2], flags, .little);
        var length: usize = 2;
        @memcpy(value[length..][0..nonce.len], nonce);
        length += nonce.len;
        @memcpy(value[length..][0..balance.len], balance);
        length += balance.len;
        if (has_code) {
            value[length..][0..32].* = info.code_hash;
            length += 32;
        }
        assert(length <= value.len);
        return .{ .key = &keyed.hash, .value = value[0..length] };
    }

    fn next_slot(context: *anyopaque) anyerror!?Entry {
        const source: *Source = @ptrCast(@alignCast(context));
        while (source.slot_next == source.slots_len) {
            if (source.storage_position == source.order.len) return null;
            source.fill_slots(source.order[source.storage_position].index);
            source.storage_position += 1;
        }
        const owner = &source.order[source.storage_position - 1];
        const slot = &source.slots[source.slot_next];
        source.slot_next += 1;
        const word = word_of(owner.index, slot.index);
        source.storage_value[0..32].* = slot.hash;
        const tail = trimmed(source.storage_value[32..], word);
        assert(tail.len > 0);
        return .{ .key = &owner.hash, .value = source.storage_value[0 .. 32 + tail.len] };
    }

    fn fill_slots(source: *Source, index: u32) void {
        const count = slots_of(index, source.shape);
        assert(count <= source.slots.len);
        for (source.slots[0..count], 0..) |*keyed, slot_index| {
            var bytes: [32]u8 = undefined;
            std.mem.writeInt(u256, &bytes, slot_of(index, slot_index), .big);
            keyed.* = .{ .hash = node.keccak256(&bytes), .index = @intCast(slot_index) };
        }
        std.mem.sort(Keyed, source.slots[0..count], {}, Keyed.less);
        source.slots_len = count;
        source.slot_next = 0;
    }
};

const Codes = struct {
    value: [4 + code.len + 1]u8 = undefined,
    key: Hash = undefined,
    done: bool = false,

    fn source(codes: *Codes) hashed_state.EntrySource {
        return .{ .context = codes, .next = next };
    }

    fn next(context: *anyopaque) anyerror!?Entry {
        const codes: *Codes = @ptrCast(@alignCast(context));
        if (codes.done) return null;
        codes.done = true;
        codes.key = node.keccak256(&code);
        std.mem.writeInt(u32, codes.value[0..4], code.len, .big);
        codes.value[4..][0..code.len].* = code;
        codes.value[4 + code.len] = 0; // Raw bytecode.
        return .{ .key = &codes.key, .value = &codes.value };
    }
};

// Per-block measurements.

/// Read counters of the database at one moment.
const Counters = struct {
    grid_reads: u64 = 0,
    cache_hits: u64 = 0,
    cache_misses: u64 = 0,
    records_resolved: u64 = 0,
    record_reads: u64 = 0,
    record_cache_hits: u64 = 0,
    leaves_resolved: u64 = 0,
    account_reads: u64 = 0,
    slot_reads: u64 = 0,
    read_memo_hits: u64 = 0,
    record_writes: u64 = 0,

    fn minus(after: Counters, before: Counters) Counters {
        var out: Counters = .{};
        inline for (@typeInfo(Counters).@"struct".field_names) |field| {
            assert(@field(after, field) >= @field(before, field));
            @field(out, field) = @field(after, field) - @field(before, field);
        }
        return out;
    }

    fn add(total: *Counters, delta: Counters) void {
        inline for (@typeInfo(Counters).@"struct".field_names) |field| {
            @field(total, field) += @field(delta, field);
        }
    }
};

const Totals = struct {
    blocks: u64 = 0,
    reads_ns: u64 = 0,
    apply_ns: u64 = 0,
    update_ns: u64 = 0,
    root_ns: u64 = 0,
    diff_ns: u64 = 0,
    write_ns: u64 = 0,
    journal_ns: u64 = 0,
    room_ns: u64 = 0,
    reads: Counters = .{},
    apply: Counters = .{},

    fn add(total: *Totals, sample: *const Totals) void {
        inline for (@typeInfo(Totals).@"struct".field_names) |field| {
            if (@TypeOf(@field(total, field)) == Counters) {
                @field(total, field).add(@field(sample, field));
            } else {
                @field(total, field) += @field(sample, field);
            }
        }
    }

    fn report(total: *const Totals, label: []const u8, shape: Shape, slots: u64) void {
        assert(total.blocks > 0);
        const blocks: f64 = @floatFromInt(total.blocks);
        const ms = struct {
            fn of(ns: u64, count: f64) f64 {
                return @as(f64, @floatFromInt(ns)) / 1e6 / count;
            }
        }.of;
        const per = struct {
            fn of(value: u64, count: f64) f64 {
                return @as(f64, @floatFromInt(value)) / count;
            }
        }.of;
        std.debug.print(
            "{s} {s} ({d} blocks, {d} accounts, {d} slots, cache {d} blocks): " ++
                "reads {d:.3} ms/block (grid reads {d:.1}, cache hits {d:.1} misses {d:.1}, " ++
                "account reads {d:.1}, slot reads {d:.1})\n",
            .{
                name,                                   label,
                total.blocks,                           shape.accounts,
                slots,                                  shape.cache_blocks,
                ms(total.reads_ns, blocks),             per(total.reads.grid_reads, blocks),
                per(total.reads.cache_hits, blocks),    per(total.reads.cache_misses, blocks),
                per(total.reads.account_reads, blocks), per(total.reads.slot_reads, blocks),
            },
        );
        const apply = &total.apply;
        std.debug.print(
            "  apply {d:.3} ms/block [update {d:.3} root {d:.3} diff {d:.3} write {d:.3}] " ++
                "journal {d:.3} room {d:.3}; grid reads {d:.1}, cache hits {d:.1} " ++
                "misses {d:.1}, records resolved {d:.1} read {d:.1} cached {d:.1}, " ++
                "leaves {d:.1}, account reads {d:.1}, slot reads {d:.1}, memo hits {d:.1}, " ++
                "record writes {d:.1}\n",
            .{
                ms(total.apply_ns, blocks),           ms(total.update_ns, blocks),
                ms(total.root_ns, blocks),            ms(total.diff_ns, blocks),
                ms(total.write_ns, blocks),           ms(total.journal_ns, blocks),
                ms(total.room_ns, blocks),            per(apply.grid_reads, blocks),
                per(apply.cache_hits, blocks),        per(apply.cache_misses, blocks),
                per(apply.records_resolved, blocks),  per(apply.record_reads, blocks),
                per(apply.record_cache_hits, blocks), per(apply.leaves_resolved, blocks),
                per(apply.account_reads, blocks),     per(apply.slot_reads, blocks),
                per(apply.read_memo_hits, blocks),    per(apply.record_writes, blocks),
            },
        );
    }
};

/// One key a block touches: an account (`slot` null) or a slot of it.
const Touch = struct { index: u64, slot: ?u256 = null, value: u256 = 0 };

fn RunType(comptime Storage: type) type {
    return struct {
        const Run = @This();
        const Importer = to_disk.ImporterType(Storage);
        const Database = Importer.Database;

        allocator: std.mem.Allocator,
        io: std.Io,
        storage: *Storage,
        shape: Shape,
        config: @import("database.zig").Config,
        db: Database,
        overlay: Overlay,
        changeset: Changeset,
        source: Source,
        prng: Prng,
        touches: []Touch,
        touches_len: u32 = 0,
        /// The applied changeset, encoded for the journal entry.
        encoded: []u8,
        accounts_created: u64 = 0,
        number: u64 = head_number,
        header: [32]u8 = @splat(0x48),

        const head_number: u64 = 1000;

        /// `self` must not move after this (the overlay and the disk clock point into it).
        fn init(
            self: *Run,
            allocator: std.mem.Allocator,
            io: std.Io,
            storage: *Storage,
            source: Source,
            config: @import("database.zig").Config,
        ) !void {
            const shape = source.shape;
            assert(config.engine.size_bytes() <= storage.size_bytes());
            self.* = .{
                .allocator = allocator,
                .io = io,
                .storage = storage,
                .shape = shape,
                .config = config,
                .db = try Database.init(allocator, storage, config),
                .overlay = undefined,
                .changeset = try Changeset.init(allocator, config.changeset),
                .source = source,
                .prng = Prng.init(0xd15c_be9c),
                .touches = try allocator.alloc(Touch, shape.block_slots() +
                    shape.block_account_count()),
                .encoded = try allocator.alloc(u8, config.engine.entry_body_size_max),
            };
            self.overlay = try Overlay.init(allocator, &self.db.state, .{
                .accounts_max = shape.block_account_count() + shape.block_slots(),
                .slots_max = shape.block_slots(),
                .codes_max = 1,
            });
        }

        fn deinit(self: *Run) void {
            const allocator = self.allocator;
            allocator.free(self.encoded);
            allocator.free(self.touches);
            self.overlay.deinit(allocator);
            self.changeset.deinit(allocator);
            self.db.deinit(allocator);
            self.* = undefined;
        }

        fn driver(self: *Run) to_disk.Driver {
            return .{ .context = self.storage, .tick = tick };
        }

        fn tick(context: *anyopaque) void {
            const storage: *Storage = @ptrCast(@alignCast(context));
            storage.tick();
        }

        fn now_ns(context: *anyopaque) u64 {
            const self: *Run = @ptrCast(@alignCast(context));
            return bench.now_ns(self.io);
        }

        /// Formats the database and bulk-imports the state as head `head_number`.
        fn import(self: *Run) !void {
            var importer: Importer = .{
                .allocator = self.allocator,
                .db = &self.db,
                .driver = self.driver(),
            };
            var codes: Codes = .{};
            try importer.format(0xd15c_be9c);
            try importer.load_codes(codes.source());
            const root = try importer.load_state(
                self.source.accounts_source(),
                self.source.storages_source(),
            );
            var headers: to_disk.SyntheticHeaders = .{
                .head_number = head_number,
                .state_root = root,
            };
            var chain: to_disk.HeaderChain = .{};
            try to_disk.fetch_chain(headers.source(), head_number, &chain);
            try importer.commit_head(&chain, root);
            assert(importer.stats.accounts == self.shape.accounts);
            assert(importer.stats.slots == self.source.slots_total);
        }

        fn counters(self: *Run) Counters {
            const trees = &self.db.flat.?;
            const stats = &self.db.disk.?.stats;
            return .{
                .grid_reads = trees.accounts.grid.stats.reads,
                .cache_hits = trees.cache.stats.hits,
                .cache_misses = trees.cache.stats.misses,
                .records_resolved = stats.records_resolved,
                .record_reads = stats.record_reads,
                .record_cache_hits = stats.record_cache_hits,
                .leaves_resolved = stats.leaves_resolved,
                .account_reads = stats.account_reads,
                .slot_reads = stats.slot_reads,
                .read_memo_hits = stats.read_memo_hits,
                .record_writes = stats.record_writes,
            };
        }

        /// The keys of the next block, with new values.
        fn plan_block(self: *Run) void {
            const shape = self.shape;
            const prng = &self.prng;
            self.touches_len = 0;
            for (1..shape.hot_accounts + 1) |index| self.touch(.{ .index = index });
            for (0..shape.block_accounts) |_| self.touch(.{ .index = prng.below(shape.accounts) });
            for (0..shape.block_new_accounts) |_| {
                self.touch(.{ .index = shape.accounts + self.accounts_created });
                self.accounts_created += 1;
            }
            for (0..shape.hot_slots) |slot_index| self.touch_slot(0, slot_index);
            for (0..shape.block_contracts) |contract| {
                const large = self.source.large.items;
                const index = if (contract % 2 == 0 and large.len > 0)
                    large[@intCast(prng.below(large.len))]
                else
                    prng.below(shape.contracts()) * shape.contract_every;
                for (0..shape.block_slots_per_contract) |_| {
                    self.touch_slot(index, prng.below(slots_of(index, shape)));
                }
            }
            for (0..shape.block_new_slots) |_| {
                const index = prng.below(shape.contracts()) * shape.contract_every;
                self.touch_slot(index, slots_of(index, shape) + prng.below(1 << 40));
            }
            assert(self.touches_len <= self.touches.len);
        }

        fn touch(self: *Run, item: Touch) void {
            assert(self.touches_len < self.touches.len);
            self.touches[self.touches_len] = item;
            self.touches_len += 1;
        }

        fn touch_slot(self: *Run, index: u64, slot_index: u64) void {
            assert(is_contract(index, self.shape));
            // One in eight writes deletes the slot.
            const value: u256 = if (self.prng.chance(1, 8)) 0 else self.prng.range(1, 1 << 60);
            self.touch(.{ .index = index, .slot = slot_of(index, slot_index), .value = value });
        }

        /// Reads every touched key, as the evm would before writing it.
        fn read_block(self: *Run) u64 {
            var checksum: u64 = 0;
            for (self.touches[0..self.touches_len]) |*item| {
                const address = address_of(item.index);
                if (item.slot) |slot| {
                    checksum +%= @truncate(self.db.state.storage(address, slot));
                } else if (self.db.state.basic(address)) |info| {
                    checksum +%= info.nonce;
                }
            }
            assert(self.touches_len > 0);
            return checksum;
        }

        fn write_block(self: *Run) !void {
            for (self.touches[0..self.touches_len]) |*item| {
                const address = address_of(item.index);
                if (item.slot) |slot| {
                    try self.overlay.set_storage(address, slot, item.value);
                    continue;
                }
                var info = self.overlay.basic(address) orelse AccountInfo{
                    .nonce = 0,
                    .balance = 0,
                    .code_hash = node.empty_code_hash,
                };
                info.nonce += 1;
                info.balance +%= self.prng.range(1, 1 << 40);
                try self.overlay.set_account(address, info);
            }
            assert(self.overlay.accounts.count() > 0);
        }

        /// One block: room, reads, writes, apply, journal (as `import/run.zig` does).
        fn block(self: *Run, sample: *Totals) !void {
            const room_start_ns = bench.now_ns(self.io);
            try self.make_room();
            sample.room_ns = bench.now_ns(self.io) - room_start_ns;
            self.plan_block();
            self.db.hold_checkpoints(true);
            defer self.db.hold_checkpoints(false);
            const before_reads = self.counters();
            const reads_start_ns = bench.now_ns(self.io);
            std.mem.doNotOptimizeAway(self.read_block());
            sample.reads_ns = bench.now_ns(self.io) - reads_start_ns;
            const before_apply = self.counters();
            sample.reads = before_apply.minus(before_reads);
            try self.write_block();
            const disk_before = self.db.disk.?.stats;
            const apply_start_ns = bench.now_ns(self.io);
            try self.apply_overlay();
            sample.apply_ns = bench.now_ns(self.io) - apply_start_ns;
            sample.apply = self.counters().minus(before_apply);
            const disk_after = &self.db.disk.?.stats;
            sample.update_ns = disk_after.update_ns - disk_before.update_ns;
            sample.root_ns = disk_after.root_ns - disk_before.root_ns;
            sample.diff_ns = disk_after.diff_ns - disk_before.diff_ns;
            sample.write_ns = disk_after.write_ns - disk_before.write_ns;
            const journal_start_ns = bench.now_ns(self.io);
            try self.journal();
            sample.journal_ns = bench.now_ns(self.io) - journal_start_ns;
            sample.blocks = 1;
            self.storage.tick();
        }

        /// `Overlay.commit` (State.apply -> DiskState.apply), retried while busy.
        fn apply_overlay(self: *Run) !void {
            var attempts: u32 = 0;
            while (true) : (attempts += 1) {
                if (attempts >= to_disk.busy_ticks_max) return error.Stalled;
                _ = self.overlay.commit(&self.changeset) catch |err| switch (err) {
                    error.Busy => {
                        self.storage.tick();
                        continue;
                    },
                    else => return err,
                };
                break;
            }
            assert(self.overlay.accounts.count() == 0);
        }

        /// `commit_applied` the applied block (made room for: never busy here).
        fn journal(self: *Run) !void {
            var bytes: [32]u8 = undefined;
            self.number += 1;
            std.mem.writeInt(u64, bytes[0..8], self.number, .big);
            const hash = node.keccak256(&bytes);
            if (self.changeset.encoded_length() > self.encoded.len) return error.BlockTooLarge;
            const encoded = self.changeset.encode(self.encoded);
            const committed = try self.db.commit_applied(&.{
                .hash = hash,
                .parent_hash = self.db.head_info.hash,
                .number = self.number,
                .timestamp = self.number * 2,
                .header = &self.header,
                .body = &.{},
                .receipts = &.{},
                .transaction_hashes = &.{},
                .changeset = encoded,
            });
            assert(committed.sequence > 0);
            assert(std.mem.eql(u8, &self.db.head_info.hash, &hash));
        }

        fn journal_used(db: *const Database) u64 {
            const journal_state = &db.engine.journal;
            assert(journal_state.head >= journal_state.tail);
            return journal_state.head - journal_state.tail + db.journal_bytes_pending;
        }

        /// Room for this block's entry and branch writes (`import/run.zig` `make_room`).
        fn roomy(db: *const Database) bool {
            const journal_config = db.engine.journal.config;
            const entry_max = Database.Engine.JournalType.entry_size_max(journal_config);
            const journal_roomy =
                journal_used(db) + 2 * entry_max <= journal_config.zone_size_bytes;
            const disk_config = db.config.disk_state.?;
            const span = db.disk_writes_closed + db.disk_writes_pending + db.disk_writes_current;
            const admission_roomy = span + 2 * disk_config.record_writes_max <=
                disk_config.replay_record_writes_max;
            const queue_roomy = db.queue_count + 1 <= db.config.queue_entries_max;
            return queue_roomy and journal_roomy and admission_roomy;
        }

        fn make_room(self: *Run) !void {
            const db = &self.db;
            var ticks: u32 = 0;
            while (true) : (ticks += 1) {
                if (db.phase != .ready) return error.NotReady;
                if (db.checkpoint_error) |err| return err;
                const journal_config = db.engine.journal.config;
                const half = journal_used(db) * 2 > journal_config.zone_size_bytes;
                const running = db.checkpoint_wanted or db.engine.checkpoint_phase != .idle;
                if ((half or !roomy(db)) and !running) db.request_checkpoint();
                if (roomy(db)) break;
                if (ticks >= to_disk.busy_ticks_max) return error.Stalled;
                self.storage.tick();
            }
            assert(roomy(db));
        }

        /// Cold blocks after the reopen, then warm blocks; reports both.
        fn measure(self: *Run, report: bool) !void {
            var cold: Totals = .{};
            var warm: Totals = .{};
            const total_blocks = self.shape.blocks_cold + self.shape.blocks_warm;
            for (0..total_blocks) |index| {
                var sample: Totals = .{};
                try self.block(&sample);
                if (index < self.shape.blocks_cold) {
                    cold.add(&sample);
                } else if (index >= self.shape.blocks_cold + self.shape.blocks_warm / 2) {
                    warm.add(&sample);
                }
            }
            assert(cold.blocks == self.shape.blocks_cold);
            assert(warm.blocks > 0);
            if (!report) return;
            cold.report("cold", self.shape, self.source.slots_total);
            warm.report("warm", self.shape, self.source.slots_total);
        }

        /// Closes and reopens the database: an empty block cache.
        fn reopen(self: *Run) !void {
            self.overlay.deinit(self.allocator);
            self.db.deinit(self.allocator);
            self.db = try Database.init(self.allocator, self.storage, self.config);
            try Importer.open(&self.db, self.driver());
            self.overlay = try Overlay.init(self.allocator, &self.db.state, .{
                .accounts_max = self.shape.block_account_count() + self.shape.block_slots(),
                .slots_max = self.shape.block_slots(),
                .codes_max = 1,
            });
            self.db.disk.?.clock = .{ .context = self, .now_ns = now_ns };
            assert(self.db.head_info.present);
        }
    };
}

/// Imports `shape`'s state into a database on `storage`, reopens it (`drop` then empties the
/// OS page cache of its file, if any), and measures the blocks.
fn run_on(
    comptime Storage: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    storage: *Storage,
    source: Source,
    config: @import("database.zig").Config,
    drop: ?Drop,
    report: bool,
) !void {
    const Run = RunType(Storage);
    const bench_run = try allocator.create(Run);
    defer allocator.destroy(bench_run);
    try bench_run.init(allocator, io, storage, source, config);
    defer bench_run.deinit();
    const import_start_ns = bench.now_ns(io);
    try bench_run.import();
    try bench_run.reopen();
    if (drop) |callback| callback.drop(callback.context);
    if (report) {
        const import_ns = bench.now_ns(io) - import_start_ns;
        std.debug.print("{s}: imported in {d:.1} s, grid {d} blocks of {d} KiB\n", .{
            name,
            @as(f64, @floatFromInt(import_ns)) / 1e9,
            config.engine.grid_block_count,
            config.engine.checkpoint_block_size / 1024,
        });
    }
    try bench_run.measure(report);
}

/// Drops the OS page cache of the scratch file (cold reads after the reopen).
const Drop = struct {
    context: *anyopaque,
    drop: *const fn (context: *anyopaque) void,
};

fn database_config(
    comptime Storage: type,
    source: *const Source,
    shape: to_disk.Shape,
) !@import("database.zig").Config {
    const counts: to_disk.Counts = .{
        .accounts = source.shape.accounts,
        .slots = source.slots_total,
        .codes = 1,
        .code_bytes = code.len,
    };
    const sizing = try to_disk.sizing(Storage, counts, shape);
    var config = sizing.config;
    config.flat_cache_blocks = source.shape.cache_blocks;
    assert(config.disk_state != null);
    return config;
}

const scratch_directory = ".zig-cache/tmp/needlefish-disk-state-bench";
const scratch_path = scratch_directory ++ "/data.db";

/// Runs the benchmark when `filter` matches its name.
pub fn run(io: std.Io, filter: ?[]const u8) void {
    if (filter) |pattern| {
        if (std.mem.indexOf(u8, name, pattern) == null) return;
    }
    run_os(io, std.heap.page_allocator, shape_bench) catch |err| {
        std.debug.print("{s}: failed: {s}\n", .{ name, @errorName(err) });
    };
}

fn run_os(io: std.Io, allocator: std.mem.Allocator, shape: Shape) !void {
    const IO = io_root.IO;
    if (builtin.os.tag != .linux) return;
    var backend = IO.init(.{}) catch |err| {
        std.debug.print("{s}: skipped, no IO backend: {s}\n", .{ name, @errorName(err) });
        return;
    };
    defer backend.deinit();
    const directory = std.Io.Dir.cwd();
    try directory.createDirPath(io, scratch_directory);
    defer directory.deleteDir(io, scratch_directory) catch |err| {
        std.debug.print("{s}: cannot remove {s}: {s}\n", .{
            name, scratch_directory, @errorName(err),
        });
    };
    delete_scratch(io);
    defer delete_scratch(io);
    const fd = try backend.open_file(scratch_path, .create);
    defer backend.close_now(fd);
    const Storage = IoStorageType(IO);
    var source = try Source.init(allocator, shape);
    defer source.deinit(allocator);
    const config = try database_config(Storage, &source, to_disk.shape_node);
    var storage = try Storage.init(allocator, &backend, fd, .{
        .size_bytes = config.engine.size_bytes(),
    });
    defer storage.deinit(allocator);
    var file: File = .{ .fd = fd };
    const drop: Drop = .{ .context = &file, .drop = File.drop };
    try run_on(Storage, allocator, io, &storage, source, config, drop, true);
}

const File = struct {
    fd: i32,

    fn drop(context: *anyopaque) void {
        const file: *File = @ptrCast(@alignCast(context));
        const linux = std.os.linux;
        assert(file.fd >= 0);
        _ = linux.fdatasync(file.fd);
        const result = linux.fadvise(file.fd, 0, 0, linux.POSIX_FADV.DONTNEED);
        if (result != 0) std.debug.print("{s}: fadvise failed: {d}\n", .{ name, result });
    }
};

fn delete_scratch(io: std.Io) void {
    std.Io.Dir.cwd().deleteFile(io, scratch_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => std.debug.print("{s}: cannot remove {s}: {s}\n", .{
            name, scratch_path, @errorName(err),
        }),
    };
}

test "disk state bench: a small state imports and blocks apply over SimStorage" {
    const allocator = std.testing.allocator;
    var source = try Source.init(allocator, shape_test);
    defer source.deinit(allocator);
    // The import tests' small shape, with room for this benchmark's blocks.
    var shape = @import("../import/to_disk_test.zig").shape_test;
    const record_writes_max: u32 = 512;
    shape.changeset.accounts_max = 64;
    shape.changeset.storage_max = 256;
    shape.disk_state.trie_nodes_max = 1 << 15;
    shape.disk_state.memo_entries_max = 1 << 15;
    shape.disk_state.memo_bytes_max = 8 << 20;
    shape.disk_state.record_writes_max = record_writes_max;
    shape.disk_state.record_write_bytes_max = record_writes_max * branch_record.value_bytes_max;
    shape.disk_state.replay_record_writes_max =
        record_writes_max * (2 * shape.chain.reorg_depth_max + 1);
    const config = try database_config(SimStorage, &source, shape);
    var storage = try SimStorage.init(allocator, .{
        .size_bytes = config.engine.size_bytes(),
        .seed = 5,
    });
    defer storage.deinit(allocator);
    try run_on(SimStorage, allocator, std.testing.io, &storage, source, config, null, false);
}
