//! Per-transaction differential check against real chain data.
//!
//! Input is one block directory as written by the replay lane's raw fetcher: `block.json`
//! (`eth_getBlockByNumber` with full transactions), `prestate.json` (`debug_traceBlock`
//! with `prestateTracer`: each transaction's own pre-state), and `receipts.json`. Every
//! transaction runs alone through `transaction.transact` on a database holding exactly its
//! pre-state, and its status, gas used, and logs are compared with the canonical receipt.
//! No trie, witness, or executor is involved, so a mismatch isolates the EVM.
//!
//! Envelopes are not re-encoded: the L1 data fee and operator fee price as zero. That only
//! changes fee-vault and sender balances, which receipts do not carry.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const env = @import("env.zig");
const op = @import("op.zig");
const state_module = @import("state.zig");
const evm_module = @import("evm.zig");
const transaction = @import("transaction.zig");
const state_test = @import("state_test.zig");
const MemoryDatabase = @import("memory_db.zig").MemoryDatabase;
const Fork = @import("fork.zig").Fork;
const Address = primitives.Address;
const Value = std.json.Value;

pub const Error = state_test.Error || error{BlockFileInvalid};

pub const Mismatch = struct {
    index: u32,
    hash: []const u8,
    reason: []const u8,
    expected: u64 = 0,
    actual: u64 = 0,
};

pub const Summary = struct {
    transactions: u32 = 0,
    passed: u32 = 0,
};

pub const Block = struct {
    block: Value,
    prestate: Value,
    receipts: Value,
};

pub const Chain = struct {
    fork: Fork,
    op: ?op.Context,
    chain_id: u64,
};

const field = state_test.field;
const string_of = state_test.string_of;
const parse_fixed = state_test.parse_fixed;
const parse_u256 = state_test.parse_u256;

fn u64_field(value: Value, name: []const u8) Error!u64 {
    const number = try parse_u256(try string_of(field(value, name)));
    return std.math.cast(u64, number) orelse error.BlockFileInvalid;
}

fn u256_field_or(value: Value, name: []const u8) Error!u256 {
    const text = field(value, name) orelse return 0;
    if (text == .null) return 0;
    return parse_u256(try string_of(text));
}

fn address_field(value: Value, name: []const u8) Error!?Address {
    const text = field(value, name) orelse return null;
    if (text == .null) return null;
    return try parse_fixed(20, try string_of(text));
}

pub fn block_timestamp(block: Value) Error!u64 {
    return u64_field(block, "timestamp");
}

pub fn block_env(block: Value, chain: Chain) Error!env.BlockEnv {
    return .{
        .number = try u64_field(block, "number"),
        .coinbase = (try address_field(block, "miner")) orelse return error.BlockFileInvalid,
        .timestamp = try u64_field(block, "timestamp"),
        .gas_limit = try u64_field(block, "gasLimit"),
        .base_fee = try u256_field_or(block, "baseFeePerGas"),
        .prevrandao = try parse_fixed(32, try string_of(field(block, "mixHash"))),
        .blob_base_fee = env.blob_base_fee(
            @intCast(try u256_field_or(block, "excessBlobGas")),
            env.blob_update_fraction_prague,
        ),
        .op = chain.op,
    };
}

/// `prestateTracer` accounts: hex balance, numeric or hex nonce, optional code and storage.
pub fn load_prestate(database: *MemoryDatabase, arena: std.mem.Allocator, pre: Value) Error!void {
    if (pre != .object) return error.BlockFileInvalid;
    var accounts = pre.object.iterator();
    while (accounts.next()) |entry| {
        const address = try parse_fixed(20, entry.key_ptr.*);
        const account = entry.value_ptr.*;
        const code_text = field(account, "code");
        const code = if (code_text) |text|
            try state_test.parse_bytes(arena, try string_of(text))
        else
            &.{};
        const nonce: u64 = switch (field(account, "nonce") orelse Value{ .integer = 0 }) {
            .integer => |number| std.math.cast(u64, number) orelse return error.BlockFileInvalid,
            .string => |text| std.math.cast(u64, try parse_u256(text)) orelse
                return error.BlockFileInvalid,
            else => return error.BlockFileInvalid,
        };
        try database.put_account(address, try u256_field_or(account, "balance"), nonce, code);
        const storage = field(account, "storage") orelse continue;
        if (storage != .object) return error.BlockFileInvalid;
        var slots = storage.object.iterator();
        while (slots.next()) |slot| {
            const value = try parse_u256(try string_of(slot.value_ptr.*));
            try database.put_storage(address, try parse_u256(slot.key_ptr.*), value);
        }
    }
}

pub fn tx_env(arena: std.mem.Allocator, tx: Value) Error!transaction.TxEnv {
    const type_number = try u64_field(tx, "type");
    const tx_type = std.enums.fromInt(transaction.TxType, type_number) orelse
        return error.BlockFileInvalid;
    var result = transaction.TxEnv{
        .tx_type = tx_type,
        .caller = (try address_field(tx, "from")) orelse return error.BlockFileInvalid,
        .gas_limit = try u64_field(tx, "gas"),
        .to = try address_field(tx, "to"),
        .value = try u256_field_or(tx, "value"),
        .data = try state_test.parse_bytes(arena, try string_of(field(tx, "input"))),
    };
    if (tx_type == .deposit) {
        result.mint = std.math.cast(u128, try u256_field_or(tx, "mint")) orelse
            return error.BlockFileInvalid;
        result.is_system_transaction = if (field(tx, "isSystemTx")) |flag|
            flag == .bool and flag.bool
        else
            false;
        return result;
    }
    result.nonce = try u64_field(tx, "nonce");
    result.chain_id = if (field(tx, "chainId") != null) try u64_field(tx, "chainId") else null;
    if (field(tx, "maxFeePerGas") != null) {
        result.gas_price = try u256_field_or(tx, "maxFeePerGas");
        result.gas_priority_fee = try u256_field_or(tx, "maxPriorityFeePerGas");
    } else {
        result.gas_price = try u256_field_or(tx, "gasPrice");
    }
    if (field(tx, "accessList")) |list| {
        result.access_list = try state_test.access_list(arena, list);
    }
    if (field(tx, "authorizationList")) |list| {
        result.authorization_list = try state_test.authorization_list(arena, list);
    }
    if (field(tx, "blobVersionedHashes")) |list| {
        result.blob_hashes = try state_test.hash_list(arena, list);
        result.max_fee_per_blob_gas = try u256_field_or(tx, "maxFeePerBlobGas");
    }
    return result;
}

/// Compare logs field by field; returns a reason on the first difference.
fn compare_logs(expected: Value, actual: []const state_module.Log) Error!?[]const u8 {
    if (expected != .array) return error.BlockFileInvalid;
    if (expected.array.items.len != actual.len) return "log count";
    for (expected.array.items, actual) |log_value, *log| {
        const address = (try address_field(log_value, "address")) orelse
            return error.BlockFileInvalid;
        if (!std.mem.eql(u8, &address, &log.address)) return "log address";
        const topics = field(log_value, "topics") orelse return error.BlockFileInvalid;
        if (topics != .array) return error.BlockFileInvalid;
        if (topics.array.items.len != log.topic_count) return "log topic count";
        for (topics.array.items, log.topic_slice()) |topic_value, topic| {
            const topic_bytes = try parse_fixed(32, try string_of(topic_value));
            if (!std.mem.eql(u8, &topic_bytes, &topic)) return "log topic";
        }
        const data_text = state_test.strip_hex(try string_of(field(log_value, "data")));
        if (data_text.len != log.data.len * 2) return "log data length";
        for (log.data, 0..) |byte, index| {
            const want = std.fmt.parseInt(u8, data_text[index * 2 ..][0..2], 16) catch
                return error.BlockFileInvalid;
            if (want != byte) return "log data";
        }
    }
    return null;
}

pub const Checker = struct {
    state: *state_module.State,
    evm: *evm_module.Evm,
    report: *const fn (context: *anyopaque, mismatch: Mismatch) void,
    report_context: *anyopaque,
};

/// Run every transaction of `block` alone on its own pre-state.
pub fn check_block(
    checker: *const Checker,
    arena: std.mem.Allocator,
    block: Block,
    chain: Chain,
) Error!Summary {
    const transactions = field(block.block, "transactions") orelse return error.BlockFileInvalid;
    if (transactions != .array) return error.BlockFileInvalid;
    if (block.prestate != .array or block.receipts != .array) return error.BlockFileInvalid;
    const count = transactions.array.items.len;
    if (block.prestate.array.items.len != count) return error.BlockFileInvalid;
    if (block.receipts.array.items.len != count) return error.BlockFileInvalid;
    checker.evm.block = try block_env(block.block, chain);
    var summary = Summary{};
    for (transactions.array.items, 0..) |tx, index| {
        const pre = field(block.prestate.array.items[index], "result") orelse
            return error.BlockFileInvalid;
        const receipt = block.receipts.array.items[index];
        summary.transactions += 1;
        if (try check_transaction(checker, arena, chain, tx, pre, receipt, @intCast(index))) {
            summary.passed += 1;
        }
    }
    assert(summary.passed <= summary.transactions);
    return summary;
}

fn check_transaction(
    checker: *const Checker,
    arena: std.mem.Allocator,
    chain: Chain,
    tx: Value,
    pre: Value,
    receipt: Value,
    index: u32,
) Error!bool {
    var database = MemoryDatabase.init(arena);
    try load_prestate(&database, arena, pre);
    checker.state.reset(database.interface());
    checker.evm.state = checker.state;
    const tx_value = try tx_env(arena, tx);
    var mismatch = Mismatch{
        .index = index,
        .hash = try string_of(field(tx, "hash")),
        .reason = "",
    };
    const result = try transaction.transact(checker.evm, chain.fork, &tx_value);
    const executed = switch (result) {
        .invalid => |reason| {
            mismatch.reason = @tagName(reason);
            checker.report(checker.report_context, mismatch);
            return false;
        },
        .executed => |executed| executed,
    };
    const status_ok = try u64_field(receipt, "status") == 1;
    const gas_used = try u64_field(receipt, "gasUsed");
    if (status_ok != (executed.status == .success)) {
        mismatch.reason = "status";
        mismatch.expected = @intFromBool(status_ok);
        mismatch.actual = @intFromBool(executed.status == .success);
    } else if (gas_used != executed.gas_used) {
        mismatch.reason = "gas used";
        mismatch.expected = gas_used;
        mismatch.actual = executed.gas_used;
    } else if (try compare_logs(field(receipt, "logs") orelse .null, executed.logs)) |reason| {
        mismatch.reason = reason;
    } else {
        return true;
    }
    checker.report(checker.report_context, mismatch);
    return false;
}

const testing = std.testing;
const Harness = @import("evm_test.zig").Harness;
const fuzz = @import("../../testing/fuzz.zig");
const Prng = @import("../../testing/prng.zig").Prng;

/// One EIP-1559 call to a contract that runs `MSTORE(0, 0x2a); LOG1(0, 32, 7)`:
/// 21000 intrinsic + 15 (five PUSH1) + 6 (MSTORE and one word) + 1006 (LOG1) = 22027 gas.
const fixture_block =
    \\{"number":"0x1","miner":"0x00000000000000000000000000000000000000c0",
    \\"timestamp":"0x10","gasLimit":"0x1c9c380","baseFeePerGas":"0x7",
    \\"mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000",
    \\"transactions":[{"type":"0x2","hash":"0x01",
    \\"from":"0x00000000000000000000000000000000000000ee",
    \\"to":"0x00000000000000000000000000000000000000aa","gas":"0x186a0","value":"0x0",
    \\"input":"0x","nonce":"0x0","chainId":"0x1","maxFeePerGas":"0x10",
    \\"maxPriorityFeePerGas":"0x1","accessList":[]}]}
;
const fixture_prestate =
    \\[{"txHash":"0x01","result":{
    \\"0x00000000000000000000000000000000000000ee":{"balance":"0xde0b6b3a7640000","nonce":0},
    \\"0x00000000000000000000000000000000000000aa":{"balance":"0x0","nonce":1,
    \\"code":"0x602a600052600760206000a100"}}}]
;
const fixture_receipts =
    \\[{"status":"0x1","gasUsed":"0x560b","logs":[{
    \\"address":"0x00000000000000000000000000000000000000aa",
    \\"topics":["0x0000000000000000000000000000000000000000000000000000000000000007"],
    \\"data":"0x000000000000000000000000000000000000000000000000000000000000002a"}]}]
;

const Recorder = struct {
    count: u32 = 0,
    reason: []const u8 = "",

    fn record(context: *anyopaque, mismatch: Mismatch) void {
        const recorder: *Recorder = @ptrCast(@alignCast(context));
        recorder.count += 1;
        recorder.reason = mismatch.reason;
    }
};

fn run_fixture(h: *Harness, recorder: *Recorder, receipts_text: []const u8) !Summary {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const block = Block{
        .block = try std.json.parseFromSliceLeaky(Value, arena, fixture_block, .{}),
        .prestate = try std.json.parseFromSliceLeaky(Value, arena, fixture_prestate, .{}),
        .receipts = try std.json.parseFromSliceLeaky(Value, arena, receipts_text, .{}),
    };
    const checker = Checker{
        .state = &h.state,
        .evm = &h.evm,
        .report = Recorder.record,
        .report_context = recorder,
    };
    return check_block(&checker, arena, block, .{ .fork = .prague, .op = null, .chain_id = 1 });
}

test "tx check: a matching receipt passes and each kind of difference is reported" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    var recorder = Recorder{};
    const summary = try run_fixture(&h, &recorder, fixture_receipts);
    try testing.expectEqual(@as(u32, 1), summary.passed);
    try testing.expectEqual(@as(u32, 0), recorder.count);

    var buffer: [fixture_receipts.len]u8 = fixture_receipts.*;
    const gas_at = std.mem.indexOf(u8, &buffer, "0x560b").?;
    buffer[gas_at + 5] = 'c';
    try testing.expectEqual(@as(u32, 0), (try run_fixture(&h, &recorder, &buffer)).passed);
    try testing.expectEqualStrings("gas used", recorder.reason);

    buffer = fixture_receipts.*;
    const data_at = std.mem.lastIndexOf(u8, &buffer, "2a\"").?;
    buffer[data_at] = '3';
    try testing.expectEqual(@as(u32, 0), (try run_fixture(&h, &recorder, &buffer)).passed);
    try testing.expectEqualStrings("log data", recorder.reason);
}

fn fuzz_receipts(h: *Harness, bytes: []const u8) !void {
    var seed: [8]u8 = @splat(0);
    @memcpy(seed[0..@min(bytes.len, 8)], bytes[0..@min(bytes.len, 8)]);
    var prng = Prng.init(std.mem.readInt(u64, &seed, .little));
    var buffer: [fixture_receipts.len]u8 = fixture_receipts.*;
    const flips: u32 = @intCast(prng.range(1, 4));
    for (0..flips) |_| {
        const alphabet = "0123456789abcdefx\":,[]{}";
        buffer[@intCast(prng.below(buffer.len))] = alphabet[@intCast(prng.below(alphabet.len))];
    }
    var recorder = Recorder{};
    // Any outcome but a crash is fine: a parse or field error, a pass, or a mismatch.
    const summary = run_fixture(h, &recorder, &buffer) catch return;
    try testing.expect(summary.passed + recorder.count == summary.transactions);
}

test "tx check: seeded fuzz of receipt JSON never crashes" {
    var h: Harness = undefined;
    try h.init(testing.allocator);
    defer h.deinit(testing.allocator);
    try fuzz.run_bytes(&h, fuzz_receipts, .{ .seed = 0x7c4e_0001, .iterations = 300 });
}
