//! Archive tests: a built archive round-trips through body and frame (and re-encodes byte for
//! byte), corruption and truncation are caught by the frame, every canonical-form rule of
//! the body is enforced, and the decoder survives arbitrary input (seeded and
//! coverage-guided fuzz: no crash, accepted bodies re-encode to themselves).

const std = @import("std");
const testing = std.testing;
const assert = std.debug.assert;

const archive_module = @import("archive.zig");
const db = @import("../../execution/db/root.zig");
const HeaderChain = @import("../../execution/db/witness_header_chain.zig").HeaderChain;
const fuzz = @import("../../testing/fuzz.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const Archive = archive_module.Archive;

const witness_config: db.witness.Witness.Config = .{
    .state_nodes_max = 32,
    .state_bytes_max = 4096,
    .codes_max = 8,
    .code_bytes_max = 1024,
    .keys_max = 4,
    .headers_max = 16,
    .header_bytes_max = 4096,
};

const config: Archive.Config = .{
    .witness = witness_config,
    .transactions_max = 32,
    .transaction_bytes_max = 4096,
    .accounts_max = 16,
    .slots_max = 16,
};

/// An archive over headers 1..`header_count` of a test chain: the last `blocks` are the
/// replayed blocks, each with `block + 1` transactions.
fn build(archive: *Archive, chain: *HeaderChain, header_count: u32, blocks: u32) !void {
    assert(blocks < header_count);
    archive.clear();
    archive.chain_id = 8453;
    chain.build(header_count, @splat(0x77));
    for (chain.headers()) |header| try archive.witness.headers.append(header);
    try archive.witness.state.append(&.{ 0xc2, 0x01, 0x02 });
    try archive.witness.state.append(&.{ 0xc1, 0x05 });
    try archive.witness.codes.append(&.{ 0x60, 0x00 });
    for (0..blocks) |block| {
        try archive.begin_block();
        for (0..block + 1) |position| {
            const raw = [_]u8{ 0x02, @intCast(block), @intCast(position) };
            const receipt: archive_module.Receipt = .{
                .status = position % 2 == 0,
                .cumulative_gas_used = 21_000 * (position + 1),
                .log_count = @intCast(position),
            };
            try archive.add_transaction(&raw, receipt);
        }
        try archive.add_account(.{ .address = @splat(1), .info = .{ .nonce = block } });
        try archive.add_account(.{ .address = @splat(2), .info = null });
        try archive.add_slot(.{ .address = @splat(1), .slot = 3, .value = block + 9 });
    }
}

fn encode_file(allocator: std.mem.Allocator, archive: *const Archive) ![]u8 {
    const body = try archive_module.encode_body(allocator, archive, witness_config);
    defer allocator.free(body);
    var out: std.Io.Writer.Allocating = .init(allocator);
    errdefer out.deinit();
    try archive_module.write_frame(body, &out.writer);
    return out.toOwnedSlice();
}

test "replay archive: round trip through body and frame" {
    const allocator = testing.allocator;
    var archive = try Archive.init(allocator, config);
    defer archive.deinit(allocator);
    var chain: HeaderChain = .{};
    try build(&archive, &chain, 6, 3);
    const file = try encode_file(allocator, &archive);
    defer allocator.free(file);
    var decoded = try Archive.init(allocator, config);
    defer decoded.deinit(allocator);
    try archive_module.decode(allocator, file, &decoded);

    try testing.expectEqual(@as(u64, 8453), decoded.chain_id);
    try testing.expectEqual(@as(u32, 3), decoded.block_count);
    try testing.expectEqual(@as(u32, 6), decoded.transactions_total());
    try testing.expectEqualSlices(u8, chain.headers()[2], decoded.parent_header());
    try testing.expectEqualSlices(u8, chain.headers()[5], decoded.block_header(2));
    try testing.expectEqual(@as(u32, 3), decoded.transaction_count(2));
    try testing.expectEqualSlices(u8, &.{ 0x02, 2, 1 }, decoded.transaction(2, 1));
    try testing.expectEqual(@as(u64, 42_000), decoded.block_receipts(1)[1].cumulative_gas_used);
    try testing.expectEqual(@as(?db.AccountInfo, null), decoded.block_accounts(2)[1].info);
    try testing.expectEqual(@as(u256, 11), decoded.block_slots(2)[0].value);

    // Canonical: the decoded archive encodes to the same body.
    const again = try encode_file(allocator, &decoded);
    defer allocator.free(again);
    try testing.expectEqualSlices(u8, file, again);
}

test "replay archive: the frame rejects corruption and truncation" {
    const allocator = testing.allocator;
    var archive = try Archive.init(allocator, config);
    defer archive.deinit(allocator);
    var chain: HeaderChain = .{};
    try build(&archive, &chain, 4, 2);
    const file = try encode_file(allocator, &archive);
    defer allocator.free(file);
    var out = try Archive.init(allocator, config);
    defer out.deinit(allocator);

    try testing.expectError(error.Truncated, archive_module.decode(allocator, file[0..20], &out));
    const short = file[0 .. file.len - 1];
    try testing.expectError(error.Corrupt, archive_module.decode(allocator, short, &out));
    const flipped = try allocator.dupe(u8, file);
    defer allocator.free(flipped);
    flipped[0] = 'X';
    try testing.expectError(error.BadMagic, archive_module.decode(allocator, flipped, &out));
    flipped[0] = 'N';
    flipped[20] ^= 1; // Digest.
    try testing.expectError(error.Corrupt, archive_module.decode(allocator, flipped, &out));
    flipped[20] ^= 1;
    flipped[4] = 2; // Version.
    const unsupported = archive_module.decode(allocator, flipped, &out);
    try testing.expectError(error.UnsupportedVersion, unsupported);
    try testing.expectEqual(@as(u32, 0), out.block_count);
}

test "replay archive: the body is strict" {
    const allocator = testing.allocator;
    var archive = try Archive.init(allocator, config);
    defer archive.deinit(allocator);
    var chain: HeaderChain = .{};
    try build(&archive, &chain, 4, 2);
    const body = try archive_module.encode_body(allocator, &archive, witness_config);
    defer allocator.free(body);
    var out = try Archive.init(allocator, config);
    defer out.deinit(allocator);
    try archive_module.decode_body(body, &out);

    // Trailing bytes.
    const longer = try std.mem.concat(allocator, u8, &.{ body, &.{0} });
    defer allocator.free(longer);
    try testing.expectError(error.NonCanonical, archive_module.decode_body(longer, &out));
    // Every truncation fails.
    for (0..body.len) |length| {
        try testing.expect(std.meta.isError(archive_module.decode_body(body[0..length], &out)));
    }
    // Zero blocks.
    const mutated = try allocator.dupe(u8, body);
    defer allocator.free(mutated);
    std.mem.writeInt(u32, mutated[8..12], 0, .little);
    try testing.expectError(error.NonCanonical, archive_module.decode_body(mutated, &out));
    // As many blocks as headers: no parent header left.
    std.mem.writeInt(u32, mutated[8..12], 4, .little);
    try testing.expect(std.meta.isError(archive_module.decode_body(mutated, &out)));
}

test "replay archive: unsorted post-state entries are rejected" {
    const allocator = testing.allocator;
    var archive = try Archive.init(allocator, config);
    defer archive.deinit(allocator);
    var chain: HeaderChain = .{};
    try build(&archive, &chain, 3, 1);
    // Swap the two accounts of block 0: no longer ascending.
    std.mem.swap(archive_module.AccountPost, &archive.accounts[0], &archive.accounts[1]);
    const body = try archive_module.encode_body(allocator, &archive, witness_config);
    defer allocator.free(body);
    var out = try Archive.init(allocator, config);
    defer out.deinit(allocator);
    try testing.expectError(error.NonCanonical, archive_module.decode_body(body, &out));
}

test "replay archive: headers must be hash-linked" {
    const allocator = testing.allocator;
    var archive = try Archive.init(allocator, config);
    defer archive.deinit(allocator);
    var chain: HeaderChain = .{};
    try build(&archive, &chain, 4, 1);
    // Rebuild the header list with a gap (headers 1, 2, 4): the codec accepts ascending
    // numbers, the archive requires a contiguous, linked run.
    archive.witness.headers.clear();
    for ([_]usize{ 0, 1, 3 }) |index| try archive.witness.headers.append(chain.headers()[index]);
    const body = try archive_module.encode_body(allocator, &archive, witness_config);
    defer allocator.free(body);
    var out = try Archive.init(allocator, config);
    defer out.deinit(allocator);
    try testing.expectError(error.NonCanonical, archive_module.decode_body(body, &out));
}

const FuzzContext = struct {
    out: *Archive,
    allocator: std.mem.Allocator,
    valid: []const u8,
};

/// Arbitrary bytes, or a valid body with a few bytes overwritten: decode never crashes, and
/// whatever it accepts re-encodes to exactly the input.
fn fuzz_decode(context: *const FuzzContext, input: []const u8) anyerror!void {
    var buffer: [fuzz.input_size_limit]u8 = undefined;
    var body: []const u8 = input;
    if (input.len > 0 and input[0] % 2 == 0) {
        @memcpy(buffer[0..context.valid.len], context.valid);
        var index: usize = 1;
        while (index + 1 < input.len) : (index += 2) {
            buffer[input[index] % context.valid.len] = input[index + 1];
        }
        body = buffer[0..context.valid.len];
    }
    archive_module.decode_body(body, context.out) catch return;
    const again = try archive_module.encode_body(context.allocator, context.out, witness_config);
    defer context.allocator.free(again);
    try testing.expectEqualSlices(u8, body, again);
}

test "replay archive: fuzz decode" {
    const allocator = testing.allocator;
    var archive = try Archive.init(allocator, config);
    defer archive.deinit(allocator);
    var chain: HeaderChain = .{};
    try build(&archive, &chain, 3, 2);
    const valid = try archive_module.encode_body(allocator, &archive, witness_config);
    defer allocator.free(valid);
    assert(valid.len < fuzz.input_size_limit);
    var out = try Archive.init(allocator, config);
    defer out.deinit(allocator);
    const context: FuzzContext = .{ .out = &out, .allocator = allocator, .valid = valid };
    try fuzz.run_bytes(&context, fuzz_decode, .{ .iterations = 512, .corpus = &.{valid} });
}
