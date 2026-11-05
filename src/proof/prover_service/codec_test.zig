//! Prover service codec tests: the base/base `types.rs` JSON vectors, strictness, and a
//! seeded fuzz of every decoder (arbitrary bytes never crash; random values round-trip).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const json = @import("../../utilities/json/root.zig");
const fuzz = @import("../../testing/fuzz.zig");
const protocol = @import("protocol.zig");
const codec = @import("codec.zig");

const hash_ab = "0xabababababababababababababababababababababababababababababababab";

fn decode_test(comptime T: type, buffer: []u8, raw: []const u8) codec.Error!T {
    var arena: std.heap.FixedBufferAllocator = .init(buffer);
    return codec.decode(T, arena.allocator(), raw);
}

test "prover service codec: proof request serializes like base/base" {
    const request: protocol.ProveBlockRangeRequest = .{
        .proof = .{
            .session_id = .from("proof-session"),
            .request = .{ .compressed = .{
                .start_block_number = 10,
                .number_of_blocks_to_prove = 20,
                .l1_head = @splat(0xab),
                .intermediate_block_interval = 10,
                .zk_vm = .sp1,
                .zk_backend = .cluster,
            } },
        },
    };
    var buffer: [1024]u8 = undefined;
    const encoded = try codec.encode_to(protocol.ProveBlockRangeRequest, &buffer, &request);
    const expected = "{\"proof\":{\"session_id\":\"proof-session\",\"request\":{" ++
        "\"proof_type\":\"compressed\",\"payload\":{\"start_block_number\":10," ++
        "\"number_of_blocks_to_prove\":20,\"l1_head\":\"" ++ hash_ab ++ "\"," ++
        "\"intermediate_block_interval\":10,\"zk_vm\":\"sp1\",\"zk_backend\":\"cluster\"}}}," ++
        "\"retry_failed\":true}";
    try testing.expectEqualStrings(expected, encoded);
    var scratch: [1024]u8 = undefined;
    const decoded = try decode_test(protocol.ProveBlockRangeRequest, &scratch, encoded);
    try testing.expect(std.meta.eql(request, decoded));
}

test "prover service codec: legacy request defaults and required fields" {
    var scratch: [1024]u8 = undefined;
    const legacy = "{\"proof\":{\"session_id\":\"s\",\"request\":{\"payload\":{" ++
        "\"start_block_number\":10,\"number_of_blocks_to_prove\":20," ++
        "\"intermediate_block_interval\":10,\"zk_vm\":\"sp1\"},\"proof_type\":\"compressed\"}}}";
    const request = try decode_test(protocol.ProveBlockRangeRequest, &scratch, legacy);
    try testing.expect(request.retry_failed);
    try testing.expectEqual(protocol.ZkBackend.cluster, request.proof.request.compressed.zk_backend);
    const missing_session = "{\"request\":{\"proof_type\":\"compressed\",\"payload\":{" ++
        "\"start_block_number\":10,\"number_of_blocks_to_prove\":20," ++
        "\"intermediate_block_interval\":10,\"zk_vm\":\"sp1\"}}}";
    try testing.expectError(
        error.MissingField,
        decode_test(protocol.ProofRequest, &scratch, missing_session),
    );
    const zero_interval = "{\"start_block_number\":1,\"number_of_blocks_to_prove\":2," ++
        "\"intermediate_block_interval\":0,\"zk_vm\":\"sp1\"}";
    try testing.expectError(
        error.InvalidField,
        decode_test(protocol.ZkProofRequest, &scratch, zero_interval),
    );
}

const tee_request_json = "{\"proof\":{\"l1_head\":\"0x" ++ hex_repeat("01") ++
    "\",\"agreed_l2_head_hash\":\"0x" ++ hex_repeat("02") ++
    "\",\"agreed_l2_output_root\":\"0x" ++ hex_repeat("03") ++
    "\",\"claimed_l2_output_root\":\"0x" ++ hex_repeat("04") ++
    "\",\"claimed_l2_block_number\":5," ++
    "\"proposer\":\"0x0000000000000000000000000000000000000006\"," ++
    "\"l1_head_number\":8,\"intermediate_block_interval\":5},\"tee_kind\":\"aws_nitro\"}";

fn hex_repeat(comptime pair: []const u8) []const u8 {
    comptime var text: []const u8 = "";
    inline for (0..32) |_| text = text ++ pair;
    return text;
}

test "prover service codec: tee request uses hex fixed values" {
    const request: protocol.TeeProofRequest = .{
        .proof = .{
            .l1_head = @splat(1),
            .agreed_l2_head_hash = @splat(2),
            .agreed_l2_output_root = @splat(3),
            .claimed_l2_output_root = @splat(4),
            .claimed_l2_block_number = 5,
            .proposer = address_six(),
            .l1_head_number = 8,
            .intermediate_block_interval = 5,
        },
        .tee_kind = .aws_nitro,
    };
    var buffer: [1024]u8 = undefined;
    const encoded = try codec.encode_to(protocol.TeeProofRequest, &buffer, &request);
    try testing.expectEqualStrings(tee_request_json, encoded);
    var scratch: [256]u8 = undefined;
    const no_kind = tee_request_json[0 .. tee_request_json.len - ",\"tee_kind\":\"aws_nitro\"}".len] ++
        "}";
    try testing.expectError(error.MissingField, decode_test(protocol.TeeProofRequest, &scratch, no_kind));
    // The flat shape (proof fields next to tee_kind) is rejected.
    const flat = "{\"l1_head\":\"0x" ++ comptime hex_repeat("01") ++ "\",\"tee_kind\":\"aws_nitro\"}";
    try testing.expectError(error.MissingField, decode_test(protocol.TeeProofRequest, &scratch, flat));
}

fn address_six() protocol.Address {
    var address: protocol.Address = @splat(0);
    address[19] = 6;
    return address;
}

test "prover service codec: tee result shape" {
    const roots = [_]protocol.Hash{ @splat(9), @splat(7) };
    const result: protocol.ProofResult = .{ .tee = .{
        .aggregate_proposal = .{
            .output_root = @splat(7),
            .signature = &.{ 1, 1, 1 },
            .l1_origin_hash = @splat(2),
            .l1_origin_number = 3,
            .l2_block_number = 20,
            .prev_output_root = @splat(4),
            .config_hash = @splat(5),
        },
        .intermediate_roots = &roots,
        .tee_kind = .aws_nitro,
        .tee_signer = @splat(0x11),
    } };
    var buffer: [2048]u8 = undefined;
    const encoded = try codec.encode_to(protocol.ProofResult, &buffer, &result);
    try testing.expect(std.mem.startsWith(u8, encoded, "{\"proof_type\":\"tee\",\"payload\":{"));
    try testing.expect(std.mem.indexOf(u8, encoded, "\"signature\":\"0x010101\"") != null);
    try testing.expect(std.mem.indexOf(u8, encoded, "\"schedule_id\":\"0x00") != null);
    var scratch: [2048]u8 = undefined;
    const decoded = try decode_test(protocol.ProofResult, &scratch, encoded);
    try testing.expectEqual(@as(usize, 2), decoded.tee.intermediate_roots.len);
    try testing.expectEqualSlices(u8, &.{ 1, 1, 1 }, decoded.tee.aggregate_proposal.signature);
    // base/base rejects a missing aggregate proposal and the nested `proof` shape.
    const missing = "{\"proof_type\":\"tee\",\"payload\":{\"intermediate_roots\":[]," ++
        "\"tee_kind\":\"aws_nitro\",\"tee_signer\":\"0x" ++ "1111111111111111111111111111111111111111\"}}";
    try testing.expectError(error.MissingField, decode_test(protocol.ProofResult, &scratch, missing));
    const nested = "{\"proof_type\":\"tee\",\"payload\":{\"proof\":{\"intermediate_roots\":[]}," ++
        "\"tee_kind\":\"aws_nitro\"}}";
    try testing.expectError(error.MissingField, decode_test(protocol.ProofResult, &scratch, nested));
}

test "prover service codec: strictness" {
    var scratch: [512]u8 = undefined;
    const Request = protocol.ListProofsRequest;
    const ok = try decode_test(Request, &scratch, "{\"offset\":0,\"limit\":5,\"extra\":[1,{}]}");
    try testing.expectEqual(@as(u32, 5), ok.limit);
    try testing.expect(ok.status_filter == null);
    const cases = [_]struct { []const u8, codec.Error }{
        .{ "{\"offset\":0,\"limit\":5,\"limit\":6}", error.DuplicateField },
        .{ "{\"offset\":01,\"limit\":5}", error.InvalidJson },
        .{ "{\"offset\":-1,\"limit\":5}", error.InvalidField },
        .{ "{\"offset\":1.5,\"limit\":5}", error.InvalidField },
        .{ "{\"offset\":0,\"limit\":4294967296}", error.InvalidField },
        .{ "{\"offset\":\"0\",\"limit\":5}", error.InvalidJson },
        .{ "{\"offset\":0,\"limit\":5,\"status_filter\":\"done\"}", error.InvalidField },
        .{ "{\"offset\":0,\"limit\":5} x", error.InvalidJson },
        .{ "{\"offset\":0}", error.MissingField },
    };
    for (cases) |case| try testing.expectError(case[1], decode_test(Request, &scratch, case[0]));
    const too_long = "{\"session_id\":\"" ++ comptime hex_repeat("aa") ++ "a\"}";
    try testing.expectError(error.TooLarge, decode_test(protocol.GetProofRequest, &scratch, too_long));
    const escaped = try decode_test(protocol.GetProofRequest, &scratch, "{\"session_id\":\"a\\\"b\"}");
    try testing.expectEqualStrings("a\"b", escaped.session_id.slice());
}

test "prover service codec: rfc 3339 timestamps" {
    var buffer: [20]u8 = undefined;
    try testing.expectEqualStrings("1970-01-01T00:00:00Z", codec.format_rfc3339(.{ .seconds = 0 }, &buffer));
    const instant: protocol.Timestamp = .{ .seconds = 1_793_880_000 };
    const text = codec.format_rfc3339(instant, &buffer);
    try testing.expectEqualStrings("2026-11-05T12:00:00Z", text);
    try testing.expectEqual(instant, codec.parse_rfc3339(text).?);
    try testing.expectEqual(instant, codec.parse_rfc3339("2026-11-05T12:00:00.123456789Z").?);
    try testing.expectEqual(instant, codec.parse_rfc3339("2026-11-05T12:00:00+00:00").?);
    try testing.expect(codec.parse_rfc3339("2026-02-30T00:00:00Z") == null);
    try testing.expect(codec.parse_rfc3339("1969-12-31T23:59:59Z") == null);
    try testing.expect(codec.parse_rfc3339("2026-11-05T12:00:00+01:00") == null);
    try testing.expect(codec.parse_rfc3339("2026-11-05T24:00:00Z") == null);
}

/// Every type a peer can send, for the decoder fuzz.
const fuzzed_types = .{
    protocol.ProveBlockRangeRequest,    protocol.ProveBlockRangeResponse,
    protocol.GetProofRequest,           protocol.GetProofResponse,
    protocol.CancelProofRequest,        protocol.DeleteProofRequest,
    protocol.ListProofsRequest,         protocol.ListProofsResponse,
    protocol.GetNextProofRequest,       protocol.GetNextProofResponse,
    protocol.HeartbeatRequest,          protocol.HeartbeatResponse,
    protocol.AbandonProofRequest,       protocol.AbandonProofResponse,
    protocol.WorkerSubmitProofRequest,  protocol.WorkerSubmitProofResponse,
    protocol.GetProofSessionRequest,    protocol.GetProofSessionResponse,
    protocol.RecordProofSessionRequest, protocol.RecordProofSessionResponse,
};

/// A random value of `T`: short lists, ASCII texts (with characters that need escapes),
/// four-digit-year timestamps, nonzero intervals.
fn random_value(comptime T: type, smith: *std.testing.Smith, arena: std.mem.Allocator) !T {
    switch (@typeInfo(T)) {
        .bool => return smith.value(bool),
        .int => return smith.value(T),
        .@"enum" => return smith.value(T),
        .optional => |info| {
            if (smith.value(bool)) return null;
            return try random_value(info.child, smith, arena);
        },
        .array => |info| {
            var bytes: [info.len]u8 = undefined;
            smith.bytes(&bytes);
            return bytes;
        },
        .pointer => |info| {
            const items = try arena.alloc(info.child, smith.valueRangeAtMost(u8, 0, 3));
            for (items) |*item| item.* = try random_value(info.child, smith, arena);
            return items;
        },
        .@"struct" => return random_struct(T, smith, arena),
        .@"union" => |info| {
            const Tag = std.meta.Tag(T);
            const tag = smith.value(Tag);
            inline for (info.field_names, info.field_types) |name, Field| {
                if (tag == @field(Tag, name)) {
                    return @unionInit(T, name, try random_value(Field, smith, arena));
                }
            }
            unreachable;
        },
        else => @compileError("unsupported"),
    }
}

fn random_struct(comptime T: type, smith: *std.testing.Smith, arena: std.mem.Allocator) !T {
    if (@hasDecl(T, "is_text")) {
        var text: T = .{};
        text.len = smith.valueRangeAtMost(u16, 0, @min(T.bytes_max, 12));
        for (text.buffer[0..text.len]) |*byte| byte.* = smith.valueRangeAtMost(u8, 1, 0x7f);
        return text;
    }
    if (@hasDecl(T, "is_timestamp")) {
        return .{ .seconds = smith.valueRangeAtMost(u64, 0, codec.timestamp_seconds_max) };
    }
    const info = @typeInfo(T).@"struct";
    var result: T = undefined;
    inline for (info.field_names, info.field_types) |name, Field| {
        @field(result, name) = try random_value(Field, smith, arena);
        if (comptime std.mem.eql(u8, name, "intermediate_block_interval")) {
            @field(result, name) |= 1;
        }
    }
    return result;
}

fn fuzz_round_trip(_: void, smith: *std.testing.Smith) anyerror!void {
    var memory: [16 * 1024]u8 = undefined;
    var arena: std.heap.FixedBufferAllocator = .init(&memory);
    var first: [8 * 1024]u8 = undefined;
    var second: [8 * 1024]u8 = undefined;
    const choice = smith.index(fuzzed_types.len);
    inline for (fuzzed_types, 0..) |T, index| {
        if (choice == index) {
            const value = try random_value(T, smith, arena.allocator());
            const encoded = try codec.encode_to(T, &first, &value);
            try json.validate(encoded);
            const decoded = try codec.decode(T, arena.allocator(), encoded);
            const again = try codec.encode_to(T, &second, &decoded);
            try testing.expectEqualStrings(encoded, again);
        }
    }
}

fn fuzz_decode(_: void, smith: *std.testing.Smith) anyerror!void {
    var input: [1024]u8 = undefined;
    const length = smith.slice(&input);
    var memory: [16 * 1024]u8 = undefined;
    var first: [16 * 1024]u8 = undefined;
    var second: [16 * 1024]u8 = undefined;
    inline for (fuzzed_types) |T| {
        var arena: std.heap.FixedBufferAllocator = .init(&memory);
        // Arbitrary input decodes or fails cleanly; a success re-encodes canonically.
        if (codec.decode(T, arena.allocator(), input[0..length])) |value| {
            const encoded = try codec.encode_to(T, &first, &value);
            const decoded = try codec.decode(T, arena.allocator(), encoded);
            try testing.expectEqualStrings(encoded, try codec.encode_to(T, &second, &decoded));
        } else |_| {}
    }
}

test "prover service codec: fuzz round trip" {
    try fuzz.run({}, fuzz_round_trip, .{ .iterations = 1024 });
}

test "prover service codec: fuzz decode" {
    const corpus = [_][]const u8{
        tee_request_json,
        "{\"offset\":0,\"limit\":5}",
        "{\"job\":null}",
        "{\"session_id\":\"x\",\"session_type\":\"stark\"}",
    };
    try fuzz.run({}, fuzz_decode, .{ .iterations = 512, .corpus = &corpus });
}
