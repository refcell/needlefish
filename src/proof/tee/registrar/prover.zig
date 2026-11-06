//! JSON-RPC client for prover instance readiness and signer endpoints (base/base
//! `registrar/src/prover.rs`): `readyz`, `enclave_signerPublicKey` and
//! `enclave_signerAttestation`. Byte lists travel as serde's `Vec<Vec<u8>>`, JSON arrays of
//! integer arrays, in stable signer order. Generic over the endpoint so tests can fake it;
//! production uses `proof/rpc` `Endpoint`, one per instance.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../../utilities/json/root.zig");
const keccak = @import("../../../common/crypto/keccak.zig");
const reconciler = @import("reconciler.zig");
const rpc_endpoint = @import("../../rpc/endpoint.zig");

const Secp256k1 = std.crypto.ecc.Secp256k1;

/// Signers one instance reports.
pub const signers_max = reconciler.instance_signer_count_max;
/// Bytes of one signer's public key or attestation document.
pub const item_bytes_max: u32 = 32 * 1024;

pub const Error = error{
    /// The instance did not answer, or answered with a JSON-RPC error.
    ProverClient,
    /// The answer is not a list of byte lists within the limits.
    InvalidResponse,
    /// A nonce list longer than `signers_max` or a nonce too long to send.
    InvalidNonces,
    InvalidPublicKey,
    OutOfMemory,
};

/// Byte lists decoded into the endpoint's arena, valid until its next `reset`.
pub const ByteLists = struct {
    items: [signers_max][]const u8 = undefined,
    count: u32 = 0,

    pub fn slice(lists: *const ByteLists) []const []const u8 {
        assert(lists.count <= signers_max);
        return lists.items[0..lists.count];
    }
};

pub fn Client(comptime EndpointType: type) type {
    return struct {
        /// Probes `readyz`; a `null` result is ready, a JSON-RPC error is not.
        pub fn readyz(endpoint: *EndpointType) Error!void {
            endpoint.reset();
            _ = endpoint.call("readyz", &.{}) catch |err| switch (err) {
                error.NotFound => if (endpoint.last_error == null) return else {
                    return error.ProverClient;
                },
                error.CallFailed => return error.ProverClient,
            };
            assert(endpoint.last_error == null);
        }

        /// The SEC1 public key of each enclave signer.
        pub fn signer_public_keys(endpoint: *EndpointType) Error!ByteLists {
            endpoint.reset();
            const raw = endpoint.call("enclave_signerPublicKey", &.{}) catch
                return error.ProverClient;
            return parse_byte_lists(endpoint.arena.allocator(), raw);
        }

        /// The raw Nitro attestation of each enclave signer; `nonces`, when given, holds one
        /// entry per signer in signer order.
        pub fn signer_attestations(
            endpoint: *EndpointType,
            nonces: ?[]const []const u8,
        ) Error!ByteLists {
            endpoint.reset();
            const arena = endpoint.arena.allocator();
            const nonces_json = if (nonces) |list| try write_byte_lists(arena, list) else "null";
            const raw = endpoint.call("enclave_signerAttestation", &.{
                .{ .raw_json = "null" },
                .{ .raw_json = nonces_json },
            }) catch return error.ProverClient;
            return parse_byte_lists(arena, raw);
        }
    };
}

/// The production client over `proof/rpc` endpoints.
pub fn RpcClient(comptime IO: type) type {
    return Client(rpc_endpoint.Endpoint(IO));
}

/// The Ethereum address of a compressed (33-byte) or uncompressed (65-byte) SEC1 key.
pub fn derive_address(public_key: []const u8) Error![20]u8 {
    const valid_length = (public_key.len == 33 and (public_key[0] == 2 or public_key[0] == 3)) or
        (public_key.len == 65 and public_key[0] == 4);
    if (!valid_length) return error.InvalidPublicKey;
    const point = Secp256k1.fromSec1(public_key) catch return error.InvalidPublicKey;
    const uncompressed = point.toUncompressedSec1();
    assert(uncompressed[0] == 4);
    const digest = keccak.keccak256(uncompressed[1..]);
    return digest[12..32].*;
}

/// Writes `lists` as a JSON array of integer arrays into `arena`.
fn write_byte_lists(arena: std.mem.Allocator, lists: []const []const u8) Error![]const u8 {
    if (lists.len > signers_max) return error.InvalidNonces;
    var out: std.Io.Writer.Allocating = .init(arena);
    const writer = &out.writer;
    writer.writeByte('[') catch return error.OutOfMemory;
    for (lists, 0..) |list, index| {
        if (list.len > item_bytes_max) return error.InvalidNonces;
        if (index > 0) writer.writeByte(',') catch return error.OutOfMemory;
        writer.writeByte('[') catch return error.OutOfMemory;
        for (list, 0..) |byte, position| {
            if (position > 0) writer.writeByte(',') catch return error.OutOfMemory;
            writer.print("{d}", .{byte}) catch return error.OutOfMemory;
        }
        writer.writeByte(']') catch return error.OutOfMemory;
    }
    writer.writeByte(']') catch return error.OutOfMemory;
    const text = out.written();
    assert(text.len >= 2 and text[0] == '[');
    return text;
}

/// Parses a JSON array of up to `signers_max` arrays of integers 0..255 into `arena`.
pub fn parse_byte_lists(arena: std.mem.Allocator, raw: []const u8) Error!ByteLists {
    var scanner = json.Scanner.init(raw);
    var lists: ByteLists = .{};
    const open = scanner.next() catch return error.InvalidResponse;
    if (open.tag != .array_begin) return error.InvalidResponse;
    var buffer: [item_bytes_max]u8 = undefined;
    while (true) {
        const token = scanner.next() catch return error.InvalidResponse;
        if (token.tag == .array_end) break;
        if (token.tag != .array_begin) return error.InvalidResponse;
        if (lists.count == signers_max) return error.InvalidResponse;
        const length = try parse_bytes(&scanner, &buffer);
        lists.items[lists.count] = try arena.dupe(u8, buffer[0..length]);
        lists.count += 1;
    }
    const end = scanner.next() catch return error.InvalidResponse;
    if (end.tag != .end) return error.InvalidResponse;
    assert(lists.count <= signers_max);
    return lists;
}

/// Reads integers until the inner array closes.
fn parse_bytes(scanner: *json.Scanner, buffer: *[item_bytes_max]u8) Error!u32 {
    var length: u32 = 0;
    while (true) {
        const token = scanner.next() catch return error.InvalidResponse;
        if (token.tag == .array_end) break;
        if (token.tag != .number) return error.InvalidResponse;
        if (length == item_bytes_max) return error.InvalidResponse;
        buffer[length] = std.fmt.parseInt(u8, token.bytes, 10) catch
            return error.InvalidResponse;
        length += 1;
    }
    assert(length <= item_bytes_max);
    return length;
}

const testing = std.testing;
const Param = rpc_endpoint.Param;

const FakeEndpoint = struct {
    arena: std.heap.ArenaAllocator,
    last_error: ?u8 = null,
    answer: ?[]const u8 = null,
    rpc_error: bool = false,
    method: []const u8 = "",
    nonces_json: []const u8 = "",

    fn reset(endpoint: *FakeEndpoint) void {
        endpoint.last_error = null;
        _ = endpoint.arena.reset(.retain_capacity);
    }

    fn call(
        endpoint: *FakeEndpoint,
        method: []const u8,
        params: []const Param,
    ) error{ NotFound, CallFailed }![]const u8 {
        endpoint.method = method;
        if (params.len == 2) endpoint.nonces_json = params[1].raw_json;
        if (endpoint.rpc_error) {
            endpoint.last_error = 1;
            return error.NotFound;
        }
        return endpoint.answer orelse error.NotFound;
    }
};

const Fake = Client(FakeEndpoint);

test "registrar prover: readyz, keys and attestations through the endpoint" {
    var endpoint: FakeEndpoint = .{ .arena = .init(testing.allocator) };
    defer endpoint.arena.deinit();
    try Fake.readyz(&endpoint);
    try testing.expectEqualStrings("readyz", endpoint.method);
    endpoint.rpc_error = true;
    try testing.expectError(error.ProverClient, Fake.readyz(&endpoint));
    try testing.expectError(error.ProverClient, Fake.signer_public_keys(&endpoint));
    endpoint.rpc_error = false;
    endpoint.answer = "[[4,1,2],[3]]";
    const keys = try Fake.signer_public_keys(&endpoint);
    try testing.expectEqualStrings("enclave_signerPublicKey", endpoint.method);
    try testing.expectEqual(@as(u32, 2), keys.count);
    try testing.expectEqualSlices(u8, &.{ 4, 1, 2 }, keys.slice()[0]);
    const nonce_a = [_]u8{ 0, 255 };
    const attestations = try Fake.signer_attestations(&endpoint, &.{ &nonce_a, "" });
    try testing.expectEqualStrings("enclave_signerAttestation", endpoint.method);
    try testing.expectEqualStrings("[[0,255],[]]", endpoint.nonces_json);
    try testing.expectEqual(@as(u32, 2), attestations.count);
    _ = try Fake.signer_attestations(&endpoint, null);
    try testing.expectEqualStrings("null", endpoint.nonces_json);
    endpoint.answer = "[[256]]";
    try testing.expectError(error.InvalidResponse, Fake.signer_public_keys(&endpoint));
}

test "registrar prover: derive_address matches hardhat account zero" {
    const compressed = [_]u8{
        0x03, 0x83, 0x18, 0x53, 0x5b, 0x54, 0x10, 0x5d, 0x4a, 0x7a, 0xae, 0x60, 0xc0, 0x8f, 0xc4,
        0x5f, 0x96, 0x87, 0x18, 0x1b, 0x4f, 0xdf, 0xc6, 0x25, 0xbd, 0x1a, 0x75, 0x3f, 0xa7, 0x39,
        0x7f, 0xed, 0x75,
    };
    const expected = [_]u8{
        0xf3, 0x9f, 0xd6, 0xe5, 0x1a, 0xad, 0x88, 0xf6, 0xf4, 0xce,
        0x6a, 0xb8, 0x82, 0x72, 0x79, 0xcf, 0xff, 0xb9, 0x22, 0x66,
    };
    try testing.expectEqual(expected, try derive_address(&compressed));
    const point = try Secp256k1.fromSec1(&compressed);
    const uncompressed = point.toUncompressedSec1();
    try testing.expectEqual(expected, try derive_address(&uncompressed));
    var mismatch = uncompressed;
    mismatch[0] = 2;
    const empty: []const u8 = &.{};
    const bad_lengths = [_][]const u8{ empty, &(@as([33]u8, @splat(4))), &mismatch };
    for (bad_lengths) |key| try testing.expectError(error.InvalidPublicKey, derive_address(key));
    const long: [66]u8 = @splat(4);
    try testing.expectError(error.InvalidPublicKey, derive_address(&long));
}

test "registrar prover: fuzz byte-list parsing and round trips" {
    const fuzz = @import("../../../testing/fuzz.zig");
    try fuzz.run({}, struct {
        fn one(_: void, smith: *std.testing.Smith) anyerror!void {
            var arena: std.heap.ArenaAllocator = .init(testing.allocator);
            defer arena.deinit();
            var raw: [96]u8 = undefined;
            const raw_len = smith.index(raw.len);
            smith.bytes(raw[0..raw_len]);
            if (parse_byte_lists(arena.allocator(), raw[0..raw_len])) |lists| {
                try testing.expect(lists.count <= signers_max);
            } else |_| {}
            var data: [4][8]u8 = undefined;
            var lists: [4][]const u8 = undefined;
            const count = smith.index(5);
            for (0..count) |index| {
                smith.bytes(&data[index]);
                lists[index] = data[index][0..smith.index(9)];
            }
            const text = try write_byte_lists(arena.allocator(), lists[0..count]);
            const parsed = try parse_byte_lists(arena.allocator(), text);
            try testing.expectEqual(@as(u32, @intCast(count)), parsed.count);
            for (lists[0..count], parsed.slice()) |want, got| {
                try testing.expectEqualSlices(u8, want, got);
            }
        }
    }.one, .{ .iterations = 2000 });
}
