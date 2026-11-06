//! ethereum/tests GeneralStateTests runner (library part; the CLI is
//! `state_test_main.zig`, run with `zig build statetest -- <dir-or-file>`).
//!
//! For each test, fork, and (data, gas, value) index it builds the pre-state, runs the
//! transaction, and checks the post-state root (via the trie lane's `StateTrie`) and
//! the logs hash. This is test tooling: it allocates freely from a per-file arena.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const env = @import("env.zig");
const state_module = @import("state.zig");
const evm_module = @import("evm.zig");
const transaction = @import("transaction.zig");
const MemoryDatabase = @import("memory_db.zig").MemoryDatabase;
const Fork = @import("fork.zig").Fork;
const trie = @import("../trie/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const Value = std.json.Value;

pub const Options = struct {
    /// Only run this fork.
    fork: ?Fork = null,
    /// Only run test names containing this substring.
    name_filter: ?[]const u8 = null,
};

pub const Summary = struct {
    passed: u32 = 0,
    failed: u32 = 0,
    skipped: u32 = 0,

    pub fn add(summary: *Summary, other: Summary) void {
        summary.passed += other.passed;
        summary.failed += other.failed;
        summary.skipped += other.skipped;
    }
};

pub const Failure = struct {
    name: []const u8,
    fork: Fork,
    index: Index,
    reason: []const u8,
};

pub const Index = struct { data: usize, gas: usize, value: usize };

/// Shared execution resources reused across every case.
pub const Runner = struct {
    state: *state_module.State,
    evm: *evm_module.Evm,
    /// Called for each failing case.
    on_failure: ?*const fn (context: *anyopaque, failure: Failure) void = null,
    context: *anyopaque = undefined,
};

pub const Error = error{ InvalidFixture, OutOfMemory, TrieInitFailed } || evm_module.Error ||
    trie.state_trie.Error || std.json.ParseError(std.json.Scanner);

/// Run every case in one fixture file.
pub fn run_file(
    runner: *Runner,
    gpa: std.mem.Allocator,
    json: []const u8,
    options: Options,
) Error!Summary {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const root = try std.json.parseFromSliceLeaky(Value, arena, json, .{});
    if (root != .object) return error.InvalidFixture;
    var summary = Summary{};
    var tests = root.object.iterator();
    while (tests.next()) |entry| {
        if (options.name_filter) |filter| {
            if (std.mem.indexOf(u8, entry.key_ptr.*, filter) == null) continue;
        }
        const case = Case{ .name = entry.key_ptr.*, .fixture = entry.value_ptr.* };
        summary.add(try run_test(runner, arena, case, options));
    }
    return summary;
}

const Case = struct { name: []const u8, fixture: Value };

fn run_test(runner: *Runner, arena: std.mem.Allocator, case: Case, options: Options) Error!Summary {
    var summary = Summary{};
    const post = field(case.fixture, "post") orelse return error.InvalidFixture;
    if (post != .object) return error.InvalidFixture;
    var forks = post.object.iterator();
    while (forks.next()) |fork_entry| {
        const fork = Fork.from_test_name(fork_entry.key_ptr.*) orelse {
            summary.skipped += 1;
            continue;
        };
        if (options.fork) |only| {
            if (only != fork) continue;
        }
        if (fork_entry.value_ptr.* != .array) return error.InvalidFixture;
        for (fork_entry.value_ptr.array.items) |expected| {
            const reason = try run_case(runner, arena, case, fork, expected);
            if (reason) |message| {
                summary.failed += 1;
                if (runner.on_failure) |report| report(runner.context, .{
                    .name = case.name,
                    .fork = fork,
                    .index = try parse_index(expected),
                    .reason = message,
                });
            } else summary.passed += 1;
        }
    }
    return summary;
}

pub fn field(value: Value, name: []const u8) ?Value {
    if (value != .object) return null;
    return value.object.get(name);
}

fn parse_index(expected: Value) Error!Index {
    const indexes = field(expected, "indexes") orelse return error.InvalidFixture;
    return .{
        .data = try parse_usize(field(indexes, "data")),
        .gas = try parse_usize(field(indexes, "gas")),
        .value = try parse_usize(field(indexes, "value")),
    };
}

fn parse_usize(value: ?Value) Error!usize {
    const v = value orelse return error.InvalidFixture;
    return switch (v) {
        .integer => |i| if (i < 0) error.InvalidFixture else @intCast(i),
        .string => |s| @intCast(try parse_u256(s)),
        else => error.InvalidFixture,
    };
}

// ------------------------------------------------------------------ hex parsing

pub fn strip_hex(text: []const u8) []const u8 {
    if (std.mem.startsWith(u8, text, "0x") or std.mem.startsWith(u8, text, "0X")) return text[2..];
    return text;
}

pub fn parse_u256(text: []const u8) Error!u256 {
    const digits = strip_hex(text);
    if (digits.len == 0) return 0;
    if (digits.len > 64) return error.InvalidFixture;
    return std.fmt.parseInt(u256, digits, 16) catch error.InvalidFixture;
}

pub fn parse_u64(text: []const u8) Error!u64 {
    const value = try parse_u256(text);
    if (value > std.math.maxInt(u64)) return error.InvalidFixture;
    return @intCast(value);
}

pub fn parse_bytes(arena: std.mem.Allocator, text: []const u8) Error![]u8 {
    const digits = strip_hex(text);
    if (digits.len % 2 != 0) return error.InvalidFixture;
    const out = try arena.alloc(u8, digits.len / 2);
    _ = std.fmt.hexToBytes(out, digits) catch return error.InvalidFixture;
    return out;
}

pub fn parse_fixed(comptime size: usize, text: []const u8) Error![size]u8 {
    const digits = strip_hex(text);
    if (digits.len != size * 2) return error.InvalidFixture;
    var out: [size]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, digits) catch return error.InvalidFixture;
    return out;
}

pub fn string_of(value: ?Value) Error![]const u8 {
    const v = value orelse return error.InvalidFixture;
    if (v != .string) return error.InvalidFixture;
    return v.string;
}

fn u256_field(value: Value, name: []const u8) Error!u256 {
    return parse_u256(try string_of(field(value, name)));
}

fn u256_field_or(value: Value, name: []const u8, default: u256) Error!u256 {
    const text = field(value, name) orelse return default;
    return parse_u256(try string_of(text));
}

fn array_item(value: ?Value, index: usize) Error!Value {
    const v = value orelse return error.InvalidFixture;
    if (v != .array or index >= v.array.items.len) return error.InvalidFixture;
    return v.array.items[index];
}

// ------------------------------------------------------------------ case setup

fn load_pre(database: *MemoryDatabase, arena: std.mem.Allocator, pre: Value) Error!void {
    if (pre != .object) return error.InvalidFixture;
    var accounts = pre.object.iterator();
    while (accounts.next()) |entry| {
        const address = try parse_fixed(20, entry.key_ptr.*);
        const account = entry.value_ptr.*;
        const code = try parse_bytes(arena, try string_of(field(account, "code")));
        const balance = try u256_field(account, "balance");
        const nonce: u64 = @intCast(try u256_field(account, "nonce"));
        try database.put_account(address, balance, nonce, code);
        const storage = field(account, "storage") orelse continue;
        if (storage != .object) return error.InvalidFixture;
        var slots = storage.object.iterator();
        while (slots.next()) |slot| {
            const value = try parse_u256(try string_of(slot.value_ptr.*));
            try database.put_storage(address, try parse_u256(slot.key_ptr.*), value);
        }
    }
}

fn block_env(fork: Fork, fixture: Value) Error!env.BlockEnv {
    const block = field(fixture, "env") orelse return error.InvalidFixture;
    const random = field(block, "currentRandom");
    const excess_blob_gas: u64 = @intCast(try u256_field_or(block, "currentExcessBlobGas", 0));
    const fraction = if (fork.at_least(.prague))
        env.blob_update_fraction_prague
    else
        env.blob_update_fraction_cancun;
    return .{
        .number = @intCast(try u256_field(block, "currentNumber")),
        .coinbase = try parse_fixed(20, try string_of(field(block, "currentCoinbase"))),
        .timestamp = @intCast(try u256_field(block, "currentTimestamp")),
        .gas_limit = @intCast(@min(try u256_field(block, "currentGasLimit"), std.math.maxInt(u64))),
        .base_fee = try u256_field_or(block, "currentBaseFee", 0),
        .difficulty = try u256_field_or(block, "currentDifficulty", 0),
        .prevrandao = if (random) |r|
            try parse_fixed(32, try string_of(r))
        else
            primitives.b256_zero,
        .blob_base_fee = env.blob_base_fee(excess_blob_gas, fraction),
    };
}

pub fn access_list(arena: std.mem.Allocator, value: Value) Error![]transaction.AccessListItem {
    if (value != .array) return error.InvalidFixture;
    const items = try arena.alloc(transaction.AccessListItem, value.array.items.len);
    for (value.array.items, items) |item, *out| {
        const keys_value = field(item, "storageKeys") orelse return error.InvalidFixture;
        if (keys_value != .array) return error.InvalidFixture;
        const keys = try arena.alloc(B256, keys_value.array.items.len);
        for (keys_value.array.items, keys) |key, *key_out| {
            key_out.* = try parse_fixed(32, try string_of(key));
        }
        out.* = .{
            .address = try parse_fixed(20, try string_of(field(item, "address"))),
            .storage_keys = keys,
        };
    }
    return items;
}

pub fn hash_list(arena: std.mem.Allocator, value: Value) Error![]B256 {
    if (value != .array) return error.InvalidFixture;
    const hashes = try arena.alloc(B256, value.array.items.len);
    for (value.array.items, hashes) |item, *out| out.* = try parse_fixed(32, try string_of(item));
    return hashes;
}

/// EIP-7702 tuples. The authority is recovered here (low-s, y parity 0 or 1) rather than
/// taken from the fixture's `signer`, so invalid signatures exercise the skip path.
pub fn authorization_list(
    arena: std.mem.Allocator,
    value: Value,
) Error![]transaction.Authorization {
    if (value != .array) return error.InvalidFixture;
    const items = try arena.alloc(transaction.Authorization, value.array.items.len);
    for (value.array.items, items) |item, *out| {
        const nonce = try u256_field(item, "nonce");
        const y_parity = try u256_field(item, "yParity");
        const signed = consensus.Authorization{
            .chain_id = try u256_field(item, "chainId"),
            .address = .init(try parse_fixed(20, try string_of(field(item, "address")))),
            // An out-of-range nonce is never valid; `maxInt` makes the executor skip it.
            .nonce = std.math.cast(u64, nonce) orelse std.math.maxInt(u64),
            .y_parity = std.math.cast(u8, y_parity) orelse 2,
            .r = try u256_field(item, "r"),
            .s = try u256_field(item, "s"),
        };
        const authority = signed.recover_authority(consensus.recover_address);
        out.* = .{
            .chain_id = signed.chain_id,
            .address = signed.address.bytes,
            .nonce = signed.nonce,
            .authority = if (authority) |found| found.bytes else null,
        };
    }
    return items;
}

fn tx_env(arena: std.mem.Allocator, fixture: Value, index: Index) Error!transaction.TxEnv {
    const tx = field(fixture, "transaction") orelse return error.InvalidFixture;
    const to_text = try string_of(field(tx, "to"));
    var result = transaction.TxEnv{
        .caller = try parse_fixed(20, try string_of(field(tx, "sender"))),
        .gas_limit = try parse_u64(try string_of(try array_item(field(tx, "gasLimit"), index.gas))),
        .to = if (strip_hex(to_text).len == 0) null else try parse_fixed(20, to_text),
        .value = try parse_u256(try string_of(try array_item(field(tx, "value"), index.value))),
        .data = try parse_bytes(
            arena,
            try string_of(try array_item(field(tx, "data"), index.data)),
        ),
        .nonce = try parse_u64(try string_of(field(tx, "nonce"))),
    };
    if (field(tx, "gasPrice")) |price| {
        result.gas_price = try parse_u256(try string_of(price));
    } else {
        result.tx_type = .eip1559;
        result.gas_price = try u256_field(tx, "maxFeePerGas");
        result.gas_priority_fee = try u256_field(tx, "maxPriorityFeePerGas");
    }
    if (field(tx, "accessLists")) |lists| {
        const list = try array_item(lists, index.data);
        if (list != .null) {
            result.access_list = try access_list(arena, list);
            if (result.tx_type == .legacy) result.tx_type = .eip2930;
        }
    }
    if (field(tx, "blobVersionedHashes")) |hashes| {
        result.tx_type = .eip4844;
        result.blob_hashes = try hash_list(arena, hashes);
        result.max_fee_per_blob_gas = try u256_field(tx, "maxFeePerBlobGas");
    }
    if (field(tx, "authorizationList")) |list| {
        result.tx_type = .eip7702;
        result.authorization_list = try authorization_list(arena, list);
    }
    if (result.tx_type != .legacy) result.chain_id = 1;
    return result;
}

// ------------------------------------------------------------------ execution

fn run_case(
    runner: *Runner,
    arena: std.mem.Allocator,
    case: Case,
    fork: Fork,
    expected: Value,
) Error!?[]const u8 {
    var database = MemoryDatabase.init(arena);
    try load_pre(&database, arena, field(case.fixture, "pre") orelse return error.InvalidFixture);
    runner.state.reset(database.interface());
    const evm = runner.evm;
    evm.state = runner.state;
    evm.block = try block_env(fork, case.fixture);
    const tx = try tx_env(arena, case.fixture, try parse_index(expected));
    const result = try transaction.transact(evm, fork, &tx);
    const expects_exception = field(expected, "expectException") != null;
    var logs: []const state_module.Log = &.{};
    switch (result) {
        .invalid => |invalid| if (!expects_exception) {
            return try std.fmt.allocPrint(arena, "unexpected invalid tx: {t}", .{invalid});
        },
        .executed => |executed| {
            if (expects_exception) return "expected an invalid transaction";
            logs = executed.logs;
        },
    }
    const expected_logs = try parse_fixed(32, try string_of(field(expected, "logs")));
    const actual_logs = try logs_hash(arena, logs);
    if (!std.mem.eql(u8, &expected_logs, &actual_logs)) return "logs hash mismatch";
    const expected_root = try parse_fixed(32, try string_of(field(expected, "hash")));
    const actual_root = try state_root(arena, &database, runner.state);
    if (!std.mem.eql(u8, &expected_root, &actual_root)) {
        return try describe_state_mismatch(arena, &database, runner.state, expected);
    }
    return null;
}

/// keccak256(rlp([[address, [topics...], data], ...])).
pub fn logs_hash(arena: std.mem.Allocator, logs: []const state_module.Log) Error!B256 {
    var payload: usize = 0;
    for (logs) |log| payload += rlp.list_length(log_payload_length(&log));
    const buffer = try arena.alloc(u8, rlp.list_length(payload));
    var encoder = rlp.Encoder.init(buffer);
    encoder.list_header(payload);
    for (logs) |log| {
        encoder.list_header(log_payload_length(&log));
        encoder.bytes(&log.address);
        encoder.list_header(33 * @as(usize, log.topic_count));
        for (log.topic_slice()) |topic| encoder.bytes(&topic);
        encoder.bytes(log.data);
    }
    assert(encoder.written().len == buffer.len);
    return primitives.keccak256(buffer);
}

fn log_payload_length(log: *const state_module.Log) usize {
    return 21 + rlp.list_length(33 * @as(usize, log.topic_count)) + rlp.bytes_length(log.data);
}

const PostAccount = struct { info: state_module.AccountInfo, storage_from_database: bool };

/// The account as it stands after the transaction, or null if it does not exist.
fn post_account(
    database: *MemoryDatabase,
    state: *state_module.State,
    address: Address,
) ?PostAccount {
    if (state.accounts.getPtr(address)) |account| {
        if (!account.in_database) return null;
        return .{ .info = account.info, .storage_from_database = account.storage_epoch == 0 };
    }
    const info = database.accounts.get(address) orelse return null;
    return .{ .info = info, .storage_from_database = true };
}

fn state_root(
    arena: std.mem.Allocator,
    database: *MemoryDatabase,
    state: *state_module.State,
) Error!B256 {
    var addresses = try collect_addresses(arena, database, state);
    defer addresses.deinit(arena);
    const accounts: u32 = @intCast(addresses.count() + 16);
    const slots: u32 = @intCast(database.storage.count() + state.slots.count() + 16);
    // `init` may also fail to start its rehash threads; those errors are not fixture bugs.
    var state_trie = trie.StateTrie.init(arena, .{
        .accounts_max = accounts,
        .account_nodes_max = 4 * accounts,
        .storage_nodes_max = 4 * slots,
    }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.TrieInitFailed;
    defer state_trie.deinit(arena);
    for (addresses.keys()) |address| {
        const account = post_account(database, state, address) orelse continue;
        try state_trie.set_account(primitives.keccak256(&address), .{
            .nonce = account.info.nonce,
            .balance = account.info.balance,
            .code_hash = account.info.code_hash,
        });
    }
    var db_slots = database.storage.iterator();
    while (db_slots.next()) |entry| {
        const key = entry.key_ptr.*;
        const account = post_account(database, state, key.address) orelse continue;
        if (!account.storage_from_database or state.slots.contains(key)) continue;
        try set_slot(&state_trie, key, entry.value_ptr.*);
    }
    var cached = state.slots.iterator();
    while (cached.next()) |entry| {
        const owner = state.accounts.getPtr(entry.key_ptr.address).?;
        if (!owner.in_database or entry.value_ptr.epoch != owner.storage_epoch) continue;
        try set_slot(&state_trie, entry.key_ptr.*, entry.value_ptr.present);
    }
    return state_trie.root();
}

fn set_slot(state_trie: *trie.StateTrie, key: state_module.StorageKey, value: u256) Error!void {
    if (value == 0) return;
    const slot_hash = primitives.keccak256(&primitives.u256_to_b256(key.slot));
    try state_trie.set_storage(primitives.keccak256(&key.address), slot_hash, value);
}

fn collect_addresses(
    arena: std.mem.Allocator,
    database: *MemoryDatabase,
    state: *state_module.State,
) Error!std.AutoArrayHashMapUnmanaged(Address, void) {
    var addresses: std.AutoArrayHashMapUnmanaged(Address, void) = .empty;
    var db_accounts = database.accounts.keyIterator();
    while (db_accounts.next()) |address| try addresses.put(arena, address.*, {});
    var cached = state.accounts.keyIterator();
    while (cached.next()) |address| try addresses.put(arena, address.*, {});
    return addresses;
}

/// Name the first account whose balance, nonce, code, or storage differs.
fn describe_state_mismatch(
    arena: std.mem.Allocator,
    database: *MemoryDatabase,
    state: *state_module.State,
    expected: Value,
) Error![]const u8 {
    const post_state = field(expected, "state") orelse return "state root mismatch";
    if (post_state != .object) return "state root mismatch";
    var accounts = post_state.object.iterator();
    while (accounts.next()) |entry| {
        const address = try parse_fixed(20, entry.key_ptr.*);
        const actual = post_account(database, state, address) orelse {
            return try std.fmt.allocPrint(arena, "root: missing account {x}", .{address});
        };
        const want_balance = try u256_field(entry.value_ptr.*, "balance");
        const want_nonce = try u256_field(entry.value_ptr.*, "nonce");
        if (want_balance != actual.info.balance or want_nonce != actual.info.nonce) {
            const format = "root: {x} balance {d} want {d}, nonce {d} want {d}";
            return try std.fmt.allocPrint(arena, format, .{
                address, actual.info.balance, want_balance, actual.info.nonce, want_nonce,
            });
        }
    }
    return "state root mismatch (storage, code, or extra account)";
}

test "state_test: logs hash of no logs is keccak(rlp([]))" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const hash = try logs_hash(arena.allocator(), &.{});
    const expected = primitives.hex_to_b256(
        "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
    );
    try std.testing.expectEqualSlices(u8, &expected, &hash);
}

test "state_test: hex parsing" {
    try std.testing.expectEqual(@as(u256, 0x0a), try parse_u256("0x0a"));
    try std.testing.expectEqual(@as(u256, 0), try parse_u256("0x"));
    try std.testing.expectError(error.InvalidFixture, parse_u256("0xzz"));
}

test "state_test: an EEST EIP-7702 fixture (delegation to a precompile) passes end to end" {
    // One case from execution-spec-tests v5.4.0 `test_set_code_to_precompile` (identity,
    // CALL), `secretKey` removed. It covers authorization parsing and recovery, delegated
    // precompile semantics, and the state-root path, so the runner keeps compiling.
    const fixture = @embedFile("testdata/eip7702_set_code_to_precompile.json");
    const evm_test = @import("evm_test.zig");
    var database = MemoryDatabase.init(std.testing.allocator);
    defer database.deinit();
    var state = try state_module.State.init(
        std.testing.allocator,
        database.interface(),
        evm_test.test_limits,
    );
    defer state.deinit(std.testing.allocator);
    var machine = try evm_module.Evm.init(std.testing.allocator, evm_test.test_config, &state);
    defer machine.deinit(std.testing.allocator);
    var runner = Runner{ .state = &state, .evm = &machine };
    const summary = try run_file(&runner, std.testing.allocator, fixture, .{});
    try std.testing.expectEqual(@as(u32, 1), summary.passed);
    try std.testing.expectEqual(@as(u32, 0), summary.failed);
}
