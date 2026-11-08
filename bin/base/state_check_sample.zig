//! `base state-check` (`state_check.zig`): choosing what to check, deterministically from
//! `--seed` and the reference's answers at block N.
//!
//! A needlefish database stores hashed keys only, so addresses and slot keys come from
//! elsewhere:
//!
//! - Addresses (`Pool`): the emitters and the address-shaped indexed topics of the logs of
//!   recent blocks, the senders and recipients of recent transactions, and the system
//!   contracts (`system_contracts`).
//! - Accounts (`select_accounts`): the system contracts, then up to a quarter from the log
//!   emitters, then the rest of the pool, each group sorted and shuffled by the seed.
//! - Slots (`Planner`), in three phases, each within a key budget:
//!   1. `plan_accounts`: for every sampled log emitter and system contract, its own slots
//!      0..7, and probes of its holder maps: `keccak(pad(holder) ++ index)` for its first
//!      two holders (addresses in its logs' topics) at every `holder_indices` index.
//!   2. `plan_contracts` (after the probes are answered): for every sampled contract, the
//!      holder-map indices that came back nonzero for its remaining holders (`learn`), slots
//!      0..7 of contracts not probed, and `keccak(pad(address) ++ pad(i))` for i in 0..3 and
//!      sampled addresses (mostly zero: absence through a storage trie).
//!   3. `plan_ring`: slots of the EIP-2935 block-hash ring and the EIP-4788 beacon-root ring,
//!      which are nonzero, to fill the rest of the budget.

const std = @import("std");
const base = @import("base");

const node = base.execution.trie.node;
const assert = std.debug.assert;

pub const Hash = [32]u8;
pub const Address = [20]u8;

pub fn address_of(comptime hex: *const [40]u8) Address {
    var out: Address = undefined;
    _ = std.fmt.hexToBytes(&out, hex) catch unreachable; // Comptime: a bad literal fails the build.
    return out;
}

pub fn word(value: u256) Hash {
    var out: Hash = undefined;
    std.mem.writeInt(u256, &out, value, .big);
    return out;
}

/// EIP-2935 history contract: the hash of block n at slot n % 8191.
pub const history_contract = address_of("0000f90827f1c53a10cb7a02335b175320002935");
/// EIP-4788 beacon roots contract: timestamp t at slot t % 8191, its root at that + 8191.
pub const beacon_roots_contract = address_of("000f3df6d732807ef1319fb7b8bb8522d0beac02");
pub const ring_length = 8191;

/// OP Stack predeploys, Base preinstalls, and the system-call contracts.
pub const system_contracts = [_]Address{
    address_of("4200000000000000000000000000000000000015"), // L1Block
    address_of("4200000000000000000000000000000000000016"), // L2ToL1MessagePasser
    address_of("4200000000000000000000000000000000000019"), // BaseFeeVault
    address_of("420000000000000000000000000000000000001a"), // L1FeeVault
    address_of("4200000000000000000000000000000000000011"), // SequencerFeeVault
    address_of("420000000000000000000000000000000000001b"), // OperatorFeeVault
    address_of("420000000000000000000000000000000000000f"), // GasPriceOracle
    address_of("4200000000000000000000000000000000000007"), // L2CrossDomainMessenger
    address_of("4200000000000000000000000000000000000010"), // L2StandardBridge
    address_of("4200000000000000000000000000000000000006"), // WETH
    address_of("4200000000000000000000000000000000000012"), // OptimismMintableERC20Factory
    address_of("4200000000000000000000000000000000000018"), // ProxyAdmin
    address_of("4200000000000000000000000000000000000000"), // LegacyMessagePasser
    address_of("deaddeaddeaddeaddeaddeaddeaddeaddead0001"), // L1 attributes depositor
    address_of("ca11bde05977b3631167028862be2a173976ca11"), // Multicall3
    address_of("4e59b44847b379578588920ca78fbf26c0b4956c"), // CREATE2 deployer
    history_contract,
    beacon_roots_contract,
};

/// Indices whose mappings ERC-20 style contracts commonly key by holder: 0..9 (OpenZeppelin
/// v4 `_balances` at 0, WETH9's at 3, FiatToken's at 9) and OpenZeppelin v5's ERC-7201
/// `ERC20Storage` location (`_balances` is its first member).
pub const holder_indices = blk: {
    var indices: [11]Hash = undefined;
    for (0..10) |index| indices[index] = word(index);
    indices[10] = node.hex_to_hash(
        "52c63247e1f47db19d5ce0460030c497f067ca4cebf71ba98eeadabe20bace00",
    );
    break :blk indices;
};

pub const own_slots = 8;
pub const generic_indices = 4;
pub const generic_addresses = 4;
pub const probe_holders = 2;
pub const holders_max = 64;
pub const addresses_max = 1 << 16;
pub const emitters_max = 1 << 12;
/// Keys per `eth_getProof` call (endpoints cap them; 1024 is common).
pub const keys_per_call_max = 128;

comptime {
    assert(holder_indices.len <= 16); // `Contract.learned` is a u16 mask.
    assert(probe_holders * holder_indices.len + own_slots <= keys_per_call_max);
}

/// The storage key of `mapping(address => ...)` at slot `index`: keccak(pad(key) ++ index).
pub fn mapping_slot(key: *const Address, index: *const Hash) Hash {
    var preimage: [64]u8 = @splat(0);
    @memcpy(preimage[12..32], key);
    @memcpy(preimage[32..64], index);
    const slot = node.keccak256(&preimage);
    assert(!std.mem.eql(u8, &slot, index));
    return slot;
}

/// The address in an indexed topic, when it looks like one: 12 zero bytes, then an address
/// whose high 12 bytes are not all zero (small numbers such as token ids are not addresses).
pub fn topic_address(topic: *const Hash) ?Address {
    const zero: [12]u8 = @splat(0);
    if (!std.mem.eql(u8, topic[0..12], &zero)) return null;
    if (std.mem.eql(u8, topic[12..24], &zero)) return null;
    const address: Address = topic[12..32].*;
    assert(!std.mem.allEqual(u8, &address, 0));
    return address;
}

/// Addresses seen in recent blocks; log emitters with the addresses in their topics.
pub const Pool = struct {
    addresses: std.AutoArrayHashMapUnmanaged(Address, void) = .empty,
    holders: std.AutoArrayHashMapUnmanaged(Address, std.ArrayList(Address)) = .empty,

    pub fn add(pool: *Pool, arena: std.mem.Allocator, address: Address) !void {
        assert(pool.addresses.count() <= addresses_max);
        if (pool.addresses.count() == addresses_max) return;
        try pool.addresses.put(arena, address, {});
        assert(pool.addresses.contains(address));
    }

    pub fn add_log(
        pool: *Pool,
        arena: std.mem.Allocator,
        emitter: Address,
        topics: []const Hash,
    ) !void {
        try pool.add(arena, emitter);
        if (pool.holders.count() == emitters_max and !pool.holders.contains(emitter)) return;
        const entry = try pool.holders.getOrPut(arena, emitter);
        if (!entry.found_existing) entry.value_ptr.* = .empty;
        const holders = entry.value_ptr;
        // Topic 0 is the event signature.
        for (topics[@min(topics.len, 1)..]) |*topic| {
            const holder = topic_address(topic) orelse continue;
            try pool.add(arena, holder);
            if (holders.items.len == holders_max) continue;
            for (holders.items) |known| {
                if (std.mem.eql(u8, &known, &holder)) break;
            } else try holders.append(arena, holder);
        }
        assert(holders.items.len <= holders_max);
        assert(pool.holders.count() <= emitters_max);
    }

    pub fn holders_of(pool: *const Pool, address: *const Address) []const Address {
        const holders = pool.holders.get(address.*) orelse return &.{};
        assert(holders.items.len <= holders_max);
        return holders.items;
    }

    /// A log emitter or a system contract: it gets slots in the first phase.
    pub fn known_contract(pool: *const Pool, address: *const Address) bool {
        if (pool.holders.contains(address.*)) return true;
        for (&system_contracts) |*system| {
            if (std.mem.eql(u8, system, address)) return true;
        }
        return false;
    }
};

fn less_address(_: void, a: Address, b: Address) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

/// Fisher-Yates, so the order depends only on the seed and the input order.
pub fn shuffle(random: std.Random, items: []Address) void {
    if (items.len < 2) return;
    var index: usize = items.len - 1;
    while (index > 0) : (index -= 1) {
        const other: usize = @intCast(random.uintLessThan(u64, index + 1));
        assert(other <= index);
        std.mem.swap(Address, &items[index], &items[other]);
    }
}

fn sorted_shuffled(arena: std.mem.Allocator, random: std.Random, from: []const Address) ![]Address {
    const items = try arena.dupe(Address, from);
    std.mem.sort(Address, items, {}, less_address);
    shuffle(random, items);
    assert(items.len == from.len);
    return items;
}

/// `count` distinct accounts (fewer when the pool is smaller): the system contracts, up to a
/// quarter of `count` log emitters, then the rest of the pool.
pub fn select_accounts(
    arena: std.mem.Allocator,
    random: std.Random,
    pool: *const Pool,
    count: u32,
) ![]Address {
    assert(count > 0);
    var chosen: std.AutoArrayHashMapUnmanaged(Address, void) = .empty;
    for (system_contracts) |address| {
        if (chosen.count() == count) break;
        try chosen.put(arena, address, {});
    }
    const emitters_end = @min(count, chosen.count() + count / 4);
    for (try sorted_shuffled(arena, random, pool.holders.keys())) |address| {
        if (chosen.count() >= emitters_end) break;
        try chosen.put(arena, address, {});
    }
    for (try sorted_shuffled(arena, random, pool.addresses.keys())) |address| {
        if (chosen.count() == count) break;
        try chosen.put(arena, address, {});
    }
    assert(chosen.count() <= count);
    return chosen.keys();
}

/// Where a slot key came from (the report counts zero and nonzero words by kind).
pub const Kind = enum(u8) { own, holder, generic, ring };
pub const kinds = std.enums.values(Kind);

pub const Key = struct {
    slot: Hash,
    kind: Kind,
    /// `holder`: the `holder_indices` index; otherwise the slot index or the ring position.
    index: u16 = 0,
};

/// One `eth_getProof` call.
pub const Request = struct { address: Address, keys: []const Key };

/// A sampled contract after the first phase.
pub const Contract = struct {
    address: Address,
    /// Got slots in the first phase (`Pool.known_contract`).
    probed: bool,
    /// `holder_indices` indices whose probes came back nonzero.
    learned: u16 = 0,
};

/// Records that a holder probe came back nonzero.
pub fn learn(learned: *u16, key: *const Key, value: u256) void {
    if (key.kind != .holder or value == 0) return;
    assert(key.index < holder_indices.len);
    learned.* |= @as(u16, 1) << @intCast(key.index);
    assert(learned.* != 0);
}

/// Plans slot keys under budgets; a (contract, slot) pair is planned at most once.
pub const Planner = struct {
    arena: std.mem.Allocator,
    random: std.Random,
    requested: std.AutoHashMapUnmanaged([52]u8, void) = .empty,
    planned: u64 = 0,

    /// Adds `key` unless planned already; false once `budget` keys are planned.
    fn take(
        planner: *Planner,
        list: *std.ArrayList(Key),
        address: *const Address,
        key: Key,
        budget: u64,
    ) !bool {
        if (planner.planned >= budget) return false;
        var id: [52]u8 = undefined;
        @memcpy(id[0..20], address);
        @memcpy(id[20..52], &key.slot);
        const entry = try planner.requested.getOrPut(planner.arena, id);
        if (entry.found_existing) return true;
        try list.append(planner.arena, key);
        planner.planned += 1;
        assert(planner.planned == planner.requested.count());
        return true;
    }

    fn own(
        planner: *Planner,
        list: *std.ArrayList(Key),
        address: *const Address,
        budget: u64,
    ) !void {
        for (0..own_slots) |index| {
            const key: Key = .{ .slot = word(index), .kind = .own, .index = @intCast(index) };
            if (!try planner.take(list, address, key, budget)) return;
        }
    }

    /// Holder-map keys of `holders` at the indices in `mask`.
    fn holder_keys(
        planner: *Planner,
        list: *std.ArrayList(Key),
        address: *const Address,
        holders: []const Address,
        mask: u16,
        budget: u64,
    ) !void {
        assert(holders.len <= holders_max);
        for (holders) |*holder| {
            for (&holder_indices, 0..) |*index, position| {
                if (mask & (@as(u16, 1) << @intCast(position)) == 0) continue;
                const key: Key = .{
                    .slot = mapping_slot(holder, index),
                    .kind = .holder,
                    .index = @intCast(position),
                };
                if (!try planner.take(list, address, key, budget)) return;
            }
        }
    }
};

/// Splits `keys` into calls of at most `keys_per_call_max`; with `always`, an account
/// without keys still gets one call (its account proof).
fn append_requests(
    arena: std.mem.Allocator,
    requests: *std.ArrayList(Request),
    address: *const Address,
    keys: []const Key,
    always: bool,
) !void {
    if (keys.len == 0) {
        if (always) try requests.append(arena, .{ .address = address.*, .keys = &.{} });
        return;
    }
    var start: usize = 0;
    while (start < keys.len) : (start += keys_per_call_max) {
        const end = @min(start + keys_per_call_max, keys.len);
        try requests.append(arena, .{ .address = address.*, .keys = keys[start..end] });
    }
    assert(start >= keys.len);
}

/// Phase 1: one call per account, with own slots and holder probes for known contracts.
pub fn plan_accounts(
    planner: *Planner,
    accounts: []const Address,
    pool: *const Pool,
    budget: u64,
) ![]Request {
    var requests: std.ArrayList(Request) = .empty;
    const all: u16 = (1 << holder_indices.len) - 1;
    for (accounts) |*address| {
        var keys: std.ArrayList(Key) = .empty;
        if (pool.known_contract(address)) {
            try planner.own(&keys, address, budget);
            const holders = pool.holders_of(address);
            const probed = holders[0..@min(holders.len, probe_holders)];
            try planner.holder_keys(&keys, address, probed, all, budget);
        }
        assert(keys.items.len <= keys_per_call_max);
        try append_requests(planner.arena, &requests, address, keys.items, true);
    }
    assert(requests.items.len == accounts.len);
    assert(planner.planned <= @max(budget, 0));
    return requests.items;
}

/// Phase 2: learned holder maps first (likely nonzero), then own slots of contracts the
/// first phase did not probe, then generic mapping keys, each pass over every contract.
pub fn plan_contracts(
    planner: *Planner,
    contracts: []const Contract,
    accounts: []const Address,
    pool: *const Pool,
    budget: u64,
) ![]Request {
    assert(accounts.len > 0);
    const lists = try planner.arena.alloc(std.ArrayList(Key), contracts.len);
    for (lists) |*list| list.* = .empty;
    for (contracts, lists) |*contract, *list| {
        const holders = pool.holders_of(&contract.address);
        if (contract.learned == 0 or holders.len <= probe_holders) continue;
        const rest = holders[probe_holders..];
        try planner.holder_keys(list, &contract.address, rest, contract.learned, budget);
    }
    for (contracts, lists) |*contract, *list| {
        if (!contract.probed) try planner.own(list, &contract.address, budget);
    }
    for (contracts, lists) |*contract, *list| {
        for (0..generic_addresses) |_| {
            const other = &accounts[@intCast(planner.random.uintLessThan(u64, accounts.len))];
            for (0..generic_indices) |index| {
                const key: Key = .{
                    .slot = mapping_slot(other, &word(index)),
                    .kind = .generic,
                    .index = @intCast(index),
                };
                _ = try planner.take(list, &contract.address, key, budget);
            }
        }
    }
    var requests: std.ArrayList(Request) = .empty;
    for (contracts, lists) |*contract, list| {
        try append_requests(planner.arena, &requests, &contract.address, list.items, false);
    }
    assert(planner.planned <= budget or contracts.len == 0);
    return requests.items;
}

/// Phase 3: `count` more ring slots (fewer when the rings run out), alternating between the
/// ring contracts present at N.
pub fn plan_ring(planner: *Planner, rings: []const Address, count: u64) ![]Request {
    assert(rings.len <= 2);
    var requests: std.ArrayList(Request) = .empty;
    if (rings.len == 0 or count == 0) return requests.items;
    var lists: [2]std.ArrayList(Key) = .{ .empty, .empty };
    const budget = planner.planned + count;
    var draws: u64 = 0;
    const draws_max = count * 8 + 64;
    while (planner.planned < budget and draws < draws_max) : (draws += 1) {
        const which: usize = @intCast(draws % rings.len);
        const address = &rings[which];
        const history = std.mem.eql(u8, address, &history_contract);
        const positions: u64 = if (history) ring_length else 2 * ring_length;
        const position = planner.random.uintLessThan(u64, positions);
        const key: Key = .{ .slot = word(position), .kind = .ring, .index = @intCast(position) };
        _ = try planner.take(&lists[which], address, key, budget);
    }
    for (rings, lists[0..rings.len]) |*address, list| {
        try append_requests(planner.arena, &requests, address, list.items, false);
    }
    assert(planner.planned <= budget);
    return requests.items;
}

// Tests.

const testing = std.testing;

test "state-check: mapping slots and topic addresses" {
    // keccak256 of 64 zero bytes: the balance slot of the zero address in a map at slot 0.
    const zero_address: Address = @splat(0);
    const expected = node.hex_to_hash(
        "ad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5",
    );
    try testing.expectEqualSlices(u8, &expected, &mapping_slot(&zero_address, &word(0)));
    const holder: Address = @splat(0xab);
    try testing.expect(!std.mem.eql(u8, &mapping_slot(&holder, &word(0)), &expected));
    var topic: Hash = @splat(0);
    @memcpy(topic[12..32], &holder);
    try testing.expectEqualSlices(u8, &holder, &topic_address(&topic).?);
    // A small number (a token id, an amount) is not an address; nor is a full hash.
    try testing.expect(topic_address(&word(12345)) == null);
    try testing.expect(topic_address(&node.keccak256("event")) == null);
}

fn test_address(index: u64) Address {
    const hash = node.keccak256(std.mem.asBytes(&index));
    return hash[0..20].*;
}

/// A pool of `emitters` contracts with `holders` holders each and `others` plain addresses.
fn test_pool(arena: std.mem.Allocator, emitters: u64, holders: u64, others: u64) !Pool {
    var pool: Pool = .{};
    for (0..emitters) |emitter| {
        for (0..holders) |holder| {
            var topics: [3]Hash = .{ node.keccak256("Transfer"), @splat(0), @splat(0) };
            @memcpy(topics[1][12..32], &test_address(1_000_000 + emitter * 100 + holder));
            @memcpy(topics[2][12..32], &test_address(2_000_000 + holder));
            try pool.add_log(arena, test_address(emitter), &topics);
        }
    }
    for (0..others) |other| try pool.add(arena, test_address(3_000_000 + other));
    return pool;
}

test "state-check: accounts are the same for a seed, and differ across seeds" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const pool = try test_pool(arena, 40, 5, 300);
    var first_prng: std.Random.DefaultPrng = .init(7);
    var again_prng: std.Random.DefaultPrng = .init(7);
    var other_prng: std.Random.DefaultPrng = .init(8);
    const first = try select_accounts(arena, first_prng.random(), &pool, 100);
    const again = try select_accounts(arena, again_prng.random(), &pool, 100);
    const other = try select_accounts(arena, other_prng.random(), &pool, 100);
    try testing.expectEqual(@as(usize, 100), first.len);
    try testing.expectEqualSlices(Address, first, again);
    try testing.expect(!std.mem.eql(u8, std.mem.sliceAsBytes(first), std.mem.sliceAsBytes(other)));
    // The system contracts first, then a quarter emitters, all distinct.
    try testing.expectEqualSlices(Address, &system_contracts, first[0..system_contracts.len]);
    var emitters: u32 = 0;
    for (first[system_contracts.len..]) |*address| {
        emitters += @intFromBool(pool.holders.contains(address.*));
    }
    try testing.expect(emitters >= 25);
    for (first, 0..) |*a, index| {
        for (first[index + 1 ..]) |*b| try testing.expect(!std.mem.eql(u8, a, b));
    }
    // A pool smaller than asked: everything it has.
    const small = try test_pool(arena, 1, 1, 2);
    var small_prng: std.Random.DefaultPrng = .init(7);
    const all = try select_accounts(arena, small_prng.random(), &small, 1000);
    try testing.expectEqual(small.addresses.count() + system_contracts.len, all.len);
}

fn count_keys(requests: []const Request) u64 {
    var total: u64 = 0;
    for (requests) |request| total += request.keys.len;
    return total;
}

/// Every planned (address, slot) pair is distinct, and no call exceeds the key cap.
fn expect_distinct(arena: std.mem.Allocator, phases: []const []const Request) !void {
    var seen: std.AutoHashMapUnmanaged([52]u8, void) = .empty;
    for (phases) |requests| {
        for (requests) |request| {
            try testing.expect(request.keys.len <= keys_per_call_max);
            for (request.keys) |key| {
                var id: [52]u8 = undefined;
                @memcpy(id[0..20], &request.address);
                @memcpy(id[20..52], &key.slot);
                try testing.expect(!(try seen.getOrPut(arena, id)).found_existing);
            }
        }
    }
}

fn plan_all(arena: std.mem.Allocator, seed: u64, slots: u64) ![3][]const Request {
    var pool = try test_pool(arena, 30, 6, 200);
    var prng: std.Random.DefaultPrng = .init(seed);
    const accounts = try select_accounts(arena, prng.random(), &pool, 80);
    var planner: Planner = .{ .arena = arena, .random = prng.random() };
    const first = try plan_accounts(&planner, accounts, &pool, slots / 2);
    try testing.expectEqual(accounts.len, first.len);
    try testing.expect(planner.planned <= slots / 2);
    // Pretend every known contract has code and holder maps at indices 0 and 3.
    var contracts: std.ArrayList(Contract) = .empty;
    for (first) |request| {
        if (!pool.known_contract(&request.address)) continue;
        var contract: Contract = .{ .address = request.address, .probed = request.keys.len > 0 };
        for (request.keys) |*key| {
            const mapped = key.kind == .holder and (key.index == 0 or key.index == 3);
            learn(&contract.learned, key, @intFromBool(mapped));
        }
        try contracts.append(arena, contract);
    }
    const budget = slots - slots / 10;
    const second = try plan_contracts(&planner, contracts.items, accounts, &pool, budget);
    try testing.expect(planner.planned <= budget);
    const rings = [_]Address{ history_contract, beacon_roots_contract };
    const third = try plan_ring(&planner, &rings, slots - planner.planned);
    try testing.expectEqual(slots, planner.planned);
    for (third) |request| {
        for (request.keys) |key| {
            try testing.expectEqual(Kind.ring, key.kind);
            const limit: u64 = if (std.mem.eql(u8, &request.address, &history_contract))
                ring_length
            else
                2 * ring_length;
            try testing.expect(std.mem.readInt(u256, &key.slot, .big) < limit);
        }
    }
    try testing.expectEqual(slots, count_keys(first) + count_keys(second) + count_keys(third));
    try expect_distinct(arena, &.{ first, second, third });
    return .{ first, second, third };
}

test "state-check: slot plans keep their budgets, never repeat a key, and are seeded" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const plan = try plan_all(arena, 11, 2000);
    const again = try plan_all(arena, 11, 2000);
    for (plan, again) |requests, requests_again| {
        try testing.expectEqual(requests.len, requests_again.len);
        for (requests, requests_again) |a, b| {
            try testing.expectEqualSlices(u8, &a.address, &b.address);
            try testing.expectEqual(a.keys.len, b.keys.len);
            for (a.keys, b.keys) |x, y| try testing.expectEqualSlices(u8, &x.slot, &y.slot);
        }
    }
    // Learned holder maps are planned only at the learned indices, for holders not probed.
    var learned_keys: u32 = 0;
    for (plan[1]) |request| {
        for (request.keys) |key| {
            if (key.kind != .holder) continue;
            try testing.expect(key.index == 0 or key.index == 3);
            learned_keys += 1;
        }
    }
    try testing.expect(learned_keys > 0);
    // A seeded fuzz: many seeds and budgets, all invariants checked inside `plan_all`.
    var prng = base.testing.Prng.init(0x7363_6865_636b);
    for (0..16) |_| {
        _ = arena_state.reset(.retain_capacity);
        _ = try plan_all(arena_state.allocator(), prng.int(u64), prng.range(200, 4000));
    }
}

test "state-check: the pool bounds its holders and learns only nonzero holder probes" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const pool = try test_pool(arena, 1, holders_max + 20, 0);
    try testing.expectEqual(@as(usize, holders_max), pool.holders_of(&test_address(0)).len);
    try testing.expect(pool.known_contract(&system_contracts[0]));
    try testing.expect(!pool.known_contract(&test_address(99)));
    var learned: u16 = 0;
    learn(&learned, &.{ .slot = word(0), .kind = .own, .index = 0 }, 5);
    learn(&learned, &.{ .slot = word(0), .kind = .holder, .index = 2 }, 0);
    try testing.expectEqual(@as(u16, 0), learned);
    learn(&learned, &.{ .slot = word(0), .kind = .holder, .index = 10 }, 1);
    try testing.expectEqual(@as(u16, 1 << 10), learned);
}
