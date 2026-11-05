//! ethereum/tests `TransactionTests` runner logic: decode `txbytes` with the strict
//! EIP-2718 decoder, apply the static signature and chain checks, and compare with the
//! fork's expectation (hash and sender, or an exception). Exceptions that need execution
//! context (intrinsic gas, init code size, gas * price overflow) are skipped.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const tx = @import("tx.zig");
const signature_module = @import("signature.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const Value = std.json.Value;

/// Chain id every TransactionTests vector signs for.
pub const test_chain_id = 1;
pub const txbytes_max = 16 << 20;

pub const Outcome = enum {
    valid_ok,
    valid_mismatch,
    invalid_rejected,
    invalid_accepted,
    /// A valid vector whose fee fields exceed u128: rejected like alloy (base/base), which
    /// types gas prices as u128; geth reads them as big integers.
    valid_wider_than_u128,
    skipped,
};

pub const Summary = struct {
    counts: [@typeInfo(Outcome).@"enum".field_names.len]u32 = @splat(0),

    pub fn add(summary: *Summary, outcome: Outcome) void {
        summary.counts[@backingInt(outcome)] += 1;
    }

    pub fn get(summary: Summary, outcome: Outcome) u32 {
        return summary.counts[@backingInt(outcome)];
    }

    pub fn failed(summary: Summary) u32 {
        return summary.get(.valid_mismatch) + summary.get(.invalid_accepted);
    }
};

const execution_exceptions = [_][]const u8{
    "INTRINSIC_GAS_TOO_LOW",
    "GASLIMIT_PRICE_PRODUCT_OVERFLOW",
    "INITCODE_SIZE_EXCEEDED",
    "INTRINSIC_NO_FLOOR_GAS",
};

pub const Accepted = struct { hash: B256, sender: Address };

pub const RejectError = tx.DecodeError || error{Rejected};

/// Decodes and statically validates a transaction as a mainnet (chain 1) node would at
/// the RLP/signature level.
pub fn check(bytes: []const u8) RejectError!Accepted {
    const envelope = try tx.Envelope.decode(bytes);
    if (envelope.is_deposit() or envelope == .eip8130) return error.Rejected; // Not Ethereum.
    const signature = envelope.signature().?;
    if (!signature.is_in_range() or !signature.is_low_s()) return error.Rejected; // EIP-2.
    if (envelope.chain_id()) |id| {
        if (id != test_chain_id) return error.Rejected;
    }
    // EIP-2681: the nonce stays below 2^64 - 1.
    if (envelope.nonce().? == std.math.maxInt(u64)) return error.Rejected;
    const sender = envelope.recover_sender(signature_module.recover_address) orelse
        return error.Rejected;
    return .{ .hash = envelope.hash(), .sender = sender };
}

pub fn accept(bytes: []const u8) ?Accepted {
    return check(bytes) catch null;
}

fn is_execution_exception(exception: []const u8) bool {
    for (execution_exceptions) |name| {
        if (std.mem.indexOf(u8, exception, name) != null) return true;
    }
    return false;
}

fn fixed(comptime T: type, value: ?Value) ?T {
    const item = value orelse return null;
    if (item != .string) return null;
    return T.from_hex(item.string) catch null;
}

/// One named test case for `fork` (falls back to no result: skipped).
pub fn run_case(case: Value, fork: []const u8, buffer: []u8) Outcome {
    if (case != .object) return .skipped;
    const txbytes = case.object.get("txbytes") orelse return .skipped;
    const results = case.object.get("result") orelse return .skipped;
    if (txbytes != .string or results != .object) return .skipped;
    const expected = results.object.get(fork) orelse return .skipped;
    if (expected != .object) return .skipped;
    const bytes = primitives.hex.decode_into(buffer, txbytes.string) catch null;
    var overflow = false;
    const accepted: ?Accepted = if (bytes) |raw| check(raw) catch |err| blk: {
        overflow = err == error.Overflow;
        break :blk null;
    } else null;
    if (expected.object.get("exception")) |exception| {
        if (exception != .string) return .skipped;
        if (is_execution_exception(exception.string)) return .skipped;
        return if (accepted == null) .invalid_rejected else .invalid_accepted;
    }
    const hash = fixed(B256, expected.object.get("hash")) orelse return .skipped;
    const sender = fixed(Address, expected.object.get("sender")) orelse return .skipped;
    const got = accepted orelse return if (overflow) .valid_wider_than_u128 else .valid_mismatch;
    assert(bytes != null);
    return if (got.hash.eql(hash) and got.sender.eql(sender)) .valid_ok else .valid_mismatch;
}

/// Every case of one TransactionTests file.
pub fn run_file(
    gpa: std.mem.Allocator,
    text: []const u8,
    fork: []const u8,
    on_failure: ?*const fn (name: []const u8, outcome: Outcome) void,
) !Summary {
    const parsed = try std.json.parseFromSlice(Value, gpa, text, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidVectorFile;
    const buffer = try gpa.alloc(u8, txbytes_max);
    defer gpa.free(buffer);
    var summary: Summary = .{};
    var iterator = parsed.value.object.iterator();
    while (iterator.next()) |entry| {
        const outcome = run_case(entry.value_ptr.*, fork, buffer);
        summary.add(outcome);
        if (outcome == .valid_mismatch or outcome == .invalid_accepted) {
            if (on_failure) |report| report(entry.key_ptr.*, outcome);
        }
    }
    return summary;
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "tx vectors: curated ethereum/tests TransactionTests" {
    const files = [_][]const u8{
        @embedFile("testdata/tx_vectors/dataTx_bcValidBlockTest.json"),
        @embedFile("testdata/tx_vectors/maxFeePerGas00prefix.json"),
        @embedFile("testdata/tx_vectors/RSsecp256k1.json"),
        @embedFile("testdata/tx_vectors/V_overflow64bitPlus27.json"),
        @embedFile("testdata/tx_vectors/RLPExtraRandomByteAtTheEnd.json"),
        @embedFile("testdata/tx_vectors/V_equals37.json"),
        @embedFile("testdata/tx_vectors/accessListStorage32Bytes.json"),
    };
    var total: Summary = .{};
    for (files) |text| {
        const summary = try run_file(testing.allocator, text, "Prague", null);
        for (&total.counts, summary.counts) |*sum, count| sum.* += count;
    }
    try testing.expectEqual(@as(u32, 0), total.failed());
    try testing.expect(total.get(.valid_ok) >= 2);
    try testing.expect(total.get(.invalid_rejected) >= 3);
}

test "tx vectors: seeded fuzz accept never crashes" {
    var prng = Prng.init(0x77);
    var bytes: [256]u8 = undefined;
    for (0..2_000) |_| {
        const length = prng.below(bytes.len);
        prng.fill(bytes[0..length]);
        if (length > 0) bytes[0] = @intCast(prng.below(5));
        if (accept(bytes[0..length])) |accepted| {
            try testing.expect(tx.Envelope.decode(bytes[0..length]) catch null != null);
            _ = accepted;
        }
    }
}

test "tx vectors: fuzz accept" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [512]u8 = undefined;
            _ = accept(bytes[0..smith.slice(&bytes)]);
        }
    }.run, .{});
}
