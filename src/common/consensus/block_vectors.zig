//! ethereum/tests `BlockchainTests` block-RLP checks: every block (and the genesis block)
//! must decode with the strict block decoder, re-encode byte-identical, hash to
//! `blockHeader.hash`, and match the header's transactions, ommers and withdrawals roots.
//! Blocks marked `expectException` are only counted: most exceptions need execution.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const rlp = @import("../rlp/root.zig");
const block_module = @import("block.zig");
const Block = block_module.Block;
const B256 = primitives.B256;
const Value = std.json.Value;

pub const block_bytes_max = 64 << 20;

pub const Outcome = enum {
    valid_ok,
    decode_failed,
    reencode_mismatch,
    hash_mismatch,
    root_mismatch,
    /// An `expectException` block the static decoder rejects.
    invalid_rejected,
    /// An `expectException` block that decodes: its exception needs execution context.
    invalid_decoded,
    skipped,
};

pub const Summary = struct {
    counts: [@typeInfo(Outcome).@"enum".field_names.len]u32 = @splat(0),

    pub fn add(summary: *Summary, outcome: Outcome) void {
        summary.counts[@backingInt(outcome)] += 1;
    }

    pub fn merge(summary: *Summary, other: Summary) void {
        for (&summary.counts, other.counts) |*sum, count| sum.* += count;
    }

    pub fn get(summary: Summary, outcome: Outcome) u32 {
        return summary.counts[@backingInt(outcome)];
    }

    pub fn failed(summary: Summary) u32 {
        return summary.get(.decode_failed) + summary.get(.reencode_mismatch) +
            summary.get(.hash_mismatch) + summary.get(.root_mismatch);
    }
};

/// Checks the header roots that depend only on the body.
fn roots_match(allocator: std.mem.Allocator, block: Block, raw_length: usize) !bool {
    const header = block.header;
    const body = block.body;
    const bytes = try allocator.alloc(u8, raw_length);
    defer allocator.free(bytes);
    const transaction_count = @max(body.transactions.count, 1);
    const items = try allocator.alloc([]const u8, transaction_count);
    defer allocator.free(items);
    const scratch: block_module.RootScratch = .{ .bytes = bytes, .items = items };
    const transactions_root = block_module.transactions_root(body.transactions, scratch);
    if (!transactions_root.eql(header.transactions_root)) return false;
    var encoder = rlp.Encoder.init(bytes);
    body.ommers.rlp_encode(&encoder);
    if (!primitives.keccak256(encoder.written()).eql(header.ommers_hash)) return false;
    if ((body.withdrawals == null) != (header.withdrawals_root == null)) return false;
    if (body.withdrawals) |withdrawals| {
        const withdrawal_items = try allocator.alloc([]const u8, @max(withdrawals.count, 1));
        defer allocator.free(withdrawal_items);
        const root = block_module.withdrawals_root(withdrawals, .{
            .bytes = bytes,
            .items = withdrawal_items,
        });
        if (!root.eql(header.withdrawals_root.?)) return false;
    }
    return true;
}

/// One valid block: decode, re-encode, hash, roots.
pub fn check_block(allocator: std.mem.Allocator, raw: []const u8, expected_hash: B256) !Outcome {
    const block = Block.decode(raw) catch return .decode_failed;
    assert(block.rlp_length() == raw.len);
    const encoded = try allocator.alloc(u8, raw.len);
    defer allocator.free(encoded);
    if (!std.mem.eql(u8, block.encode_to(encoded), raw)) return .reencode_mismatch;
    if (!block.hash().eql(expected_hash)) return .hash_mismatch;
    if (!try roots_match(allocator, block, raw.len)) return .root_mismatch;
    return .valid_ok;
}

fn string_of(object: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const item = object.get(key) orelse return null;
    return if (item == .string) item.string else null;
}

fn hash_of(object: std.json.ObjectMap, key: []const u8) ?B256 {
    const header = object.get(key) orelse return null;
    if (header != .object) return null;
    return B256.from_hex(string_of(header.object, "hash") orelse return null) catch null;
}

/// One block entry of a test's `blocks` array.
pub fn run_block(allocator: std.mem.Allocator, entry: Value, buffer: []u8) !Outcome {
    if (entry != .object) return .skipped;
    const rlp_hex = string_of(entry.object, "rlp") orelse return .skipped;
    const raw = primitives.hex.decode_into(buffer, rlp_hex) catch null;
    if (entry.object.get("expectException") != null) {
        const bytes = raw orelse return .invalid_rejected;
        _ = Block.decode(bytes) catch return .invalid_rejected;
        return .invalid_decoded;
    }
    const expected = hash_of(entry.object, "blockHeader") orelse return .skipped;
    return check_block(allocator, raw orelse return .decode_failed, expected);
}

pub const Report = *const fn (test_name: []const u8, index: usize, outcome: Outcome) void;

/// Every test of one BlockchainTests file; `index` 0 in a report is the genesis block.
pub fn run_file(gpa: std.mem.Allocator, text: []const u8, report: ?Report) !Summary {
    const parsed = try std.json.parseFromSlice(Value, gpa, text, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidVectorFile;
    var summary: Summary = .{};
    var tests = parsed.value.object.iterator();
    while (tests.next()) |test_entry| {
        if (test_entry.value_ptr.* != .object) continue;
        const object = test_entry.value_ptr.object;
        const blocks = object.get("blocks") orelse continue;
        if (blocks != .array) continue;
        var outcomes: [1]Outcome = .{.skipped};
        if (string_of(object, "genesisRLP")) |genesis_hex| {
            if (hash_of(object, "genesisBlockHeader")) |expected| {
                outcomes[0] = try run_hex(gpa, genesis_hex, expected);
                // A test-level `exceptions` marks a deliberately broken genesis.
                const broken = object.get("exceptions") != null;
                if (broken and outcomes[0] != .valid_ok) outcomes[0] = .invalid_rejected;
            }
        }
        record(&summary, report, test_entry.key_ptr.*, 0, outcomes[0]);
        for (blocks.array.items, 1..) |entry, index| {
            const length = if (entry == .object) hex_length(entry.object) else 0;
            const buffer = try gpa.alloc(u8, length);
            defer gpa.free(buffer);
            const outcome = try run_block(gpa, entry, buffer);
            record(&summary, report, test_entry.key_ptr.*, index, outcome);
        }
    }
    return summary;
}

fn hex_length(object: std.json.ObjectMap) usize {
    const text = string_of(object, "rlp") orelse return 0;
    return @min(text.len / 2, block_bytes_max);
}

fn run_hex(gpa: std.mem.Allocator, text: []const u8, expected: B256) !Outcome {
    const buffer = try gpa.alloc(u8, @min(text.len / 2, block_bytes_max));
    defer gpa.free(buffer);
    const raw = primitives.hex.decode_into(buffer, text) catch return .decode_failed;
    return check_block(gpa, raw, expected);
}

fn record(
    summary: *Summary,
    report: ?Report,
    name: []const u8,
    index: usize,
    outcome: Outcome,
) void {
    summary.add(outcome);
    const failure = switch (outcome) {
        .decode_failed, .reencode_mismatch, .hash_mismatch, .root_mismatch => true,
        else => false,
    };
    if (failure) if (report) |callback| callback(name, index, outcome);
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "block vectors: curated ethereum/tests BlockchainTests" {
    const text = @embedFile("testdata/block_vectors.json");
    const summary = try run_file(testing.allocator, text, null);
    try testing.expectEqual(@as(u32, 0), summary.failed());
    try testing.expect(summary.get(.valid_ok) >= 4);
}

test "block vectors: seeded fuzz check_block never crashes" {
    const text = @embedFile("testdata/block_vectors.json");
    const parsed = try std.json.parseFromSlice(Value, testing.allocator, text, .{});
    defer parsed.deinit();
    var tests = parsed.value.object.iterator();
    const object = tests.next().?.value_ptr.object;
    const genesis_hex = string_of(object, "genesisRLP").?;
    var original: [4096]u8 = undefined;
    const raw = try primitives.hex.decode_into(&original, genesis_hex);
    var prng = Prng.init(0xb10c);
    var mutated: [4096]u8 = undefined;
    for (0..500) |_| {
        @memcpy(mutated[0..raw.len], raw);
        const flips = 1 + prng.below(4);
        for (0..flips) |_| mutated[prng.below(raw.len)] ^= @intCast(1 + prng.below(255));
        const length = raw.len - prng.below(@min(raw.len, 8));
        const outcome = try check_block(testing.allocator, mutated[0..length], .zero);
        try testing.expect(outcome != .valid_ok); // The zero hash never matches.
    }
}

test "block vectors: fuzz block decode round trip" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var bytes: [1024]u8 = undefined;
            const input = bytes[0..smith.slice(&bytes)];
            const block = Block.decode(input) catch return;
            var encoded: [1024]u8 = undefined;
            try testing.expectEqualSlices(u8, input, block.encode_to(&encoded));
        }
    }.run, .{});
}
