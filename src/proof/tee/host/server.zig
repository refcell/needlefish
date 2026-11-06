//! The TEE host's signer and health JSON-RPC (base/base
//! `crates/proof/tee/nitro-host/src/server.rs`, `NitroSignerRpc` and the health modules):
//!
//!   enclave_signerPublicKey()                    -> one 65-byte SEC1 key per enclave
//!   enclave_signerAttestation(user_data, nonces) -> one NSM attestation per enclave
//!   healthz()                                    -> {"version": ..} or -32000
//!   readyz()                                     -> null (never registration gated)
//!
//! Byte strings are JSON arrays of numbers, as serde writes `Vec<u8>`. Both signer methods
//! are all or nothing: the registrar needs every enclave's key or attestation to register
//! them all, so one unreachable enclave fails the call. `nonces`, when given, has one entry
//! per enclave in link order. The proving method (`prover_prove`) is not served: proofs
//! reach the enclaves through the prover service and its workers (`proof_generator.zig`).
//!
//! SECURITY: unauthenticated control-plane endpoint; deploy on a private network only.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../../utilities/json/root.zig");
const rpc = @import("../../../utilities/rpc/root.zig");
const http = @import("../../../utilities/http/root.zig");
const enclave = @import("../enclave/root.zig");
const link_module = @import("link.zig");
const health_module = @import("health.zig");
const registration = @import("registration.zig");

const Link = link_module.Link;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const protocol = enclave.protocol;
const enclaves_max = registration.enclaves_max;

pub const method = struct {
    pub const signer_public_key = "enclave_signerPublicKey";
    pub const signer_attestation = "enclave_signerAttestation";
    pub const healthz = "healthz";
    pub const readyz = "readyz";
};

/// base/base `link_err` codes: an enclave-rejected request is invalid params.
pub const link_failed_code: i32 = -32001;

pub const DecodeError = error{
    InvalidParams,
    UserDataTooLong,
    NonceTooLong,
    NonceCountMismatch,
};

/// Decoded `enclave_signerAttestation` params; slices point into `Buffers`.
pub const Attestation = struct {
    user_data: ?[]const u8 = null,
    nonces: ?[]const []const u8 = null,
};

pub const Buffers = struct {
    user_data: [protocol.user_data_bytes_max]u8 = undefined,
    nonces: [enclaves_max][protocol.nonce_bytes_max]u8 = undefined,
    nonce_slices: [enclaves_max][]const u8 = undefined,
};

/// Reads a JSON array of byte values after its `[` token into `out`.
fn read_byte_array(scanner: *json.Scanner, out: []u8) error{ InvalidParams, TooLong }![]u8 {
    var count: usize = 0;
    while (count <= out.len) : (count += 1) {
        const token = scanner.next() catch return error.InvalidParams;
        if (token.tag == .array_end) return out[0..count];
        if (count == out.len) return error.TooLong;
        if (token.tag != .number) return error.InvalidParams;
        out[count] = std.fmt.parseUnsigned(u8, token.bytes, 10) catch return error.InvalidParams;
    }
    assert(count == out.len + 1);
    return error.TooLong;
}

/// A byte array value, or null for JSON `null` or a missing value.
fn parse_bytes(raw: ?[]const u8, out: []u8) error{ InvalidParams, TooLong }!?[]u8 {
    const text = raw orelse return null;
    var scanner = json.Scanner.init(text);
    const first = scanner.next() catch return error.InvalidParams;
    if (first.tag == .null) return null;
    if (first.tag != .array_begin) return error.InvalidParams;
    const bytes = try read_byte_array(&scanner, out);
    assert(bytes.len <= out.len);
    return bytes;
}

fn parse_nonces(
    raw: ?[]const u8,
    buffers: *Buffers,
    signer_count: u32,
) DecodeError!?[]const []const u8 {
    assert(signer_count > 0 and signer_count <= enclaves_max);
    const text = raw orelse return null;
    var scanner = json.Scanner.init(text);
    const first = scanner.next() catch return error.InvalidParams;
    if (first.tag == .null) return null;
    if (first.tag != .array_begin) return error.InvalidParams;
    var count: u32 = 0;
    while (count <= enclaves_max) : (count += 1) {
        const token = scanner.next() catch return error.InvalidParams;
        if (token.tag == .array_end) break;
        if (count == enclaves_max) return error.NonceCountMismatch;
        if (token.tag != .array_begin) return error.InvalidParams;
        buffers.nonce_slices[count] = read_byte_array(&scanner, &buffers.nonces[count]) catch |err|
            return if (err == error.TooLong) error.NonceTooLong else error.InvalidParams;
    }
    if (count != signer_count) return error.NonceCountMismatch;
    return buffers.nonce_slices[0..count];
}

/// Decodes `[user_data, nonces]` or `{"user_data": .., "nonces": ..}`; both optional.
pub fn decode_attestation(
    buffers: *Buffers,
    signer_count: u32,
    params: []const u8,
) DecodeError!Attestation {
    assert(signer_count > 0 and signer_count <= enclaves_max);
    if (params.len == 0) return .{};
    json.validate(params) catch return error.InvalidParams;
    var user_raw: ?[]const u8 = null;
    var nonces_raw: ?[]const u8 = null;
    if (params[0] == '{') {
        user_raw = json.find_path(params, &.{"user_data"}) catch return error.InvalidParams;
        nonces_raw = json.find_path(params, &.{"nonces"}) catch return error.InvalidParams;
    } else if (params[0] == '[') {
        var cursor = rpc.Params.init(params) catch return error.InvalidParams;
        user_raw = cursor.optional_raw() catch return error.InvalidParams;
        nonces_raw = cursor.optional_raw() catch return error.InvalidParams;
        cursor.finish() catch return error.InvalidParams;
    } else return error.InvalidParams;
    const user_data = parse_bytes(user_raw, &buffers.user_data) catch |err| return switch (err) {
        error.TooLong => error.UserDataTooLong,
        error.InvalidParams => error.InvalidParams,
    };
    return .{
        .user_data = user_data,
        .nonces = try parse_nonces(nonces_raw, buffers, signer_count),
    };
}

fn write_bytes(writer: *json.Writer, bytes: []const u8) json.Writer.WriteError!void {
    try writer.begin_array();
    for (bytes) |byte| try writer.integer(byte);
    try writer.end_array();
}

pub const Server = struct {
    links: []const *Link,
    health: health_module.Health,
    buffers: Buffers = .{},
    message: [256]u8 = undefined,
    requests: u64 = 0,

    pub fn init(links: []const *Link, health: health_module.Health) Server {
        assert(links.len > 0 and links.len <= enclaves_max);
        assert(health.version.len > 0);
        return .{ .links = links, .health = health };
    }

    pub const methods = [_]rpc.Method(*Server){
        .{ .name = method.signer_public_key, .handler = signer_public_key },
        .{ .name = method.signer_attestation, .handler = signer_attestation },
        .{ .name = method.healthz, .handler = healthz },
        .{ .name = method.readyz, .handler = readyz },
    };
    pub const Router = rpc.Router(*Server, &methods);

    /// The HTTP handler (`http.Server(IO, *Server, Server.handle_http)`).
    pub fn handle_http(
        server: *Server,
        request: *const http.Request,
        response: *http.ResponseBuilder,
    ) void {
        server.requests += 1;
        _ = Router.handle(server, request.body, response.writer());
    }

    fn fail(
        server: *Server,
        call: *Call,
        code: i32,
        comptime format: []const u8,
        arguments: anytype,
    ) HandlerError {
        const text = std.fmt.bufPrint(&server.message, format, arguments) catch
            server.message[0..];
        assert(text.len <= server.message.len);
        return call.fail(code, text);
    }

    fn link_failed(server: *Server, call: *Call, link: *const Link, err: anyerror) HandlerError {
        const code: i32 = switch (err) {
            error.InvalidRequest, error.EnclaveInvalidRequest => rpc.code.invalid_params,
            else => link_failed_code,
        };
        const detail = link.last_failure_message();
        return server.fail(call, code, "enclave link failed: {t}: {s}", .{ err, detail });
    }
};

fn signer_public_key(server: *Server, call: *Call) HandlerError!void {
    try call.params.finish();
    var keys: [enclaves_max]enclave.crypto.PublicKey = undefined;
    for (server.links, 0..) |link, index| {
        keys[index] = link.signer_public_key() catch |err|
            return server.link_failed(call, link, err);
    }
    const writer = call.writer;
    writer.begin_array() catch return error.WriteFailed;
    for (keys[0..server.links.len]) |*key| write_bytes(writer, key) catch return error.WriteFailed;
    writer.end_array() catch return error.WriteFailed;
}

fn signer_attestation(server: *Server, call: *Call) HandlerError!void {
    const count: u32 = @intCast(server.links.len);
    const params = call.params.scanner.input;
    const invalid = rpc.code.invalid_params;
    const buffers = &server.buffers;
    const decoded = decode_attestation(buffers, count, params) catch |err| return switch (err) {
        error.InvalidParams => error.InvalidParams,
        error.UserDataTooLong => call.fail(invalid, "user_data exceeds 512-byte limit"),
        error.NonceTooLong => call.fail(invalid, "nonce exceeds 512-byte limit"),
        error.NonceCountMismatch => server.fail(
            call,
            invalid,
            "nonces length must equal signer count {d}",
            .{count},
        ),
    };
    var documents: [enclaves_max][]const u8 = undefined;
    for (server.links, 0..) |link, index| {
        const nonce = if (decoded.nonces) |nonces| nonces[index] else null;
        documents[index] = link.signer_attestation(.{
            .user_data = decoded.user_data,
            .nonce = nonce,
        }) catch |err| return server.link_failed(call, link, err);
    }
    // Each document lives in its own link's arena until that link's next call.
    const writer = call.writer;
    writer.begin_array() catch return error.WriteFailed;
    for (documents[0..count]) |document| {
        write_bytes(writer, document) catch return error.WriteFailed;
    }
    writer.end_array() catch return error.WriteFailed;
}

fn healthz(server: *Server, call: *Call) HandlerError!void {
    try call.params.finish();
    switch (server.health.check()) {
        .healthy => {},
        .unhealthy => |reason| return call.fail(health_module.unhealthy_code, reason),
    }
    const writer = call.writer;
    writer.begin_object() catch return error.WriteFailed;
    writer.key("version") catch return error.WriteFailed;
    writer.string(server.health.version) catch return error.WriteFailed;
    writer.end_object() catch return error.WriteFailed;
}

fn readyz(server: *Server, call: *Call) HandlerError!void {
    _ = server;
    try call.params.finish();
    call.writer.null_value() catch return error.WriteFailed;
}

const testing = std.testing;
const fuzz = @import("../../../testing/fuzz.zig");

const Fixture = struct {
    locals: [2]*link_module.LocalEnclave,
    links: [2]*Link,
    fakes: [2]enclave.nsm.Fake,
    server: Server,
    out: [256 * 1024]u8,

    fn create() !*Fixture {
        const fixture = try testing.allocator.create(Fixture);
        errdefer testing.allocator.destroy(fixture);
        var created: u32 = 0;
        errdefer for (fixture.locals[0..created]) |local| local.destroy();
        while (created < 2) : (created += 1) {
            fixture.fakes[created] = .init(80 + created);
            const nsm_server: enclave.Server = try .init_enclave(fixture.fakes[created].nsm());
            fixture.locals[created] = try .create(testing.allocator, nsm_server, .{
                .request_bytes_max = 64 * 1024,
                .client_options = link_module.unused_client_options,
            });
            fixture.links[created] = &fixture.locals[created].link;
        }
        fixture.server = .init(&fixture.links, .{ .version = "0.0.0" });
        return fixture;
    }

    fn destroy(fixture: *Fixture) void {
        for (fixture.locals) |local| local.destroy();
        testing.allocator.destroy(fixture);
    }

    fn call(fixture: *Fixture, body: []const u8) []const u8 {
        var writer: std.Io.Writer = .fixed(&fixture.out);
        _ = Server.Router.handle(&fixture.server, body, &writer);
        return writer.buffered();
    }
};

fn expect_contains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("missing {s} in {s}\n", .{ needle, haystack });
        return error.TestExpectedContains;
    }
}

test "tee host server: signer public keys of every enclave, as byte arrays" {
    const fixture = try Fixture.create();
    defer fixture.destroy();
    const reply = fixture.call(
        \\{"jsonrpc":"2.0","id":1,"method":"enclave_signerPublicKey","params":[]}
    );
    var expected_buffer: [2048]u8 = undefined;
    var expected: std.Io.Writer = .fixed(&expected_buffer);
    var writer = json.Writer.init(&expected);
    try writer.begin_array();
    for (fixture.locals) |local| try write_bytes(&writer, local.server.signer_public_key());
    try writer.end_array();
    try expect_contains(reply, expected.buffered());
    try testing.expect(std.mem.startsWith(u8, expected.buffered(), "[[4,"));
}

test "tee host server: attestations bind each enclave's nonce" {
    const fixture = try Fixture.create();
    defer fixture.destroy();
    const reply = fixture.call(
        \\{"jsonrpc":"2.0","id":2,"method":"enclave_signerAttestation",
        \\ "params":[[1,2,3],[[110,49],[110,50]]]}
    );
    try expect_contains(reply, "\"result\":[[");
    try testing.expectEqual(@as(u32, 1), fixture.fakes[0].attestations);
    try testing.expectEqual(@as(u32, 1), fixture.fakes[1].attestations);
    const named = fixture.call(
        \\{"jsonrpc":"2.0","id":3,"method":"enclave_signerAttestation",
        \\ "params":{"user_data":null}}
    );
    try expect_contains(named, "\"result\":[[");
    const mismatch = fixture.call(
        \\{"jsonrpc":"2.0","id":4,"method":"enclave_signerAttestation","params":[null,[[1]]]}
    );
    try expect_contains(mismatch, "nonces length must equal signer count 2");
    try expect_contains(mismatch, "-32602");
}

test "tee host server: a local-mode enclave fails attestation with the link code" {
    const local = try link_module.test_local_enclave(0x91);
    defer local.destroy();
    const links = [_]*Link{&local.link};
    var server: Server = .init(&links, .{ .version = "1.2.3" });
    var out: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out);
    _ = Server.Router.handle(&server,
        \\{"jsonrpc":"2.0","id":1,"method":"enclave_signerAttestation","params":[]}
    , &writer);
    try expect_contains(writer.buffered(), "-32001");
    try expect_contains(writer.buffered(), "Unavailable");
    writer = .fixed(&out);
    _ = Server.Router.handle(&server,
        \\{"jsonrpc":"2.0","id":2,"method":"healthz","params":[]}
    , &writer);
    try expect_contains(writer.buffered(), "\"result\":{\"version\":\"1.2.3\"}");
    writer = .fixed(&out);
    _ = Server.Router.handle(&server,
        \\{"jsonrpc":"2.0","id":3,"method":"readyz"}
    , &writer);
    try expect_contains(writer.buffered(), "\"result\":null");
}

test "tee host server: healthz is gated by the registration checker" {
    const local = try link_module.test_local_enclave(0x92);
    defer local.destroy();
    const links = [_]*Link{&local.link};
    var fake: registration.FakeRegistry = .{};
    var checker: registration.Checker = try .init(&links, fake.registry());
    var server: Server = .init(&links, .{ .version = "1", .checker = &checker });
    var out: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out);
    const body =
        \\{"jsonrpc":"2.0","id":1,"method":"healthz"}
    ;
    _ = Server.Router.handle(&server, body, &writer);
    try expect_contains(writer.buffered(), health_module.not_valid_message);
    fake.allow(local.server.signer_address());
    writer = .fixed(&out);
    _ = Server.Router.handle(&server, body, &writer);
    try expect_contains(writer.buffered(), "\"version\":\"1\"");
}

test "tee host server: attestation params decode and refuse oversized fields" {
    var buffers: Buffers = .{};
    const plain = try decode_attestation(&buffers, 1, "[[7,8],[[255]]]");
    try testing.expectEqualSlices(u8, &.{ 7, 8 }, plain.user_data.?);
    try testing.expectEqualSlices(u8, &.{255}, plain.nonces.?[0]);
    const empty = try decode_attestation(&buffers, 1, "[]");
    try testing.expect(empty.user_data == null and empty.nonces == null);
    try testing.expectError(error.InvalidParams, decode_attestation(&buffers, 1, "[[256]]"));
    try testing.expectError(error.InvalidParams, decode_attestation(&buffers, 1, "[\"0x01\"]"));
    try testing.expectError(error.InvalidParams, decode_attestation(&buffers, 1, "[1,2,3]"));
    const mismatch = decode_attestation(&buffers, 2, "[null,[[1]]]");
    try testing.expectError(error.NonceCountMismatch, mismatch);
    var long_buffer: [4096]u8 = undefined;
    var long: std.Io.Writer = .fixed(&long_buffer);
    try long.writeAll("[[");
    for (0..protocol.user_data_bytes_max + 1) |index| {
        if (index > 0) try long.writeByte(',');
        try long.writeByte('0');
    }
    try long.writeAll("]]");
    const too_long = decode_attestation(&buffers, 1, long.buffered());
    try testing.expectError(error.UserDataTooLong, too_long);
}

fn fuzz_decode(_: void, smith: *std.testing.Smith) anyerror!void {
    var input: [256]u8 = undefined;
    const len = smith.slice(&input);
    var buffers: Buffers = .{};
    const decoded = decode_attestation(&buffers, 2, input[0..len]) catch return;
    if (decoded.user_data) |data| try testing.expect(data.len <= protocol.user_data_bytes_max);
    if (decoded.nonces) |nonces| {
        try testing.expectEqual(@as(usize, 2), nonces.len);
        for (nonces) |nonce| try testing.expect(nonce.len <= protocol.nonce_bytes_max);
    }
}

test "tee host server: seeded fuzz attestation params" {
    try fuzz.run({}, fuzz_decode, .{
        .iterations = 512,
        .input_size_max = 256,
        .corpus = &.{ "[[1,2],[[3],[4]]]", "{\"nonces\":[[1],[2]]}", "[null,null]" },
    });
}

fn fuzz_round_trip(_: void, smith: *std.testing.Smith) anyerror!void {
    var bytes: [64]u8 = undefined;
    const len = smith.slice(&bytes);
    var text_buffer: [64 * 4 + 16]u8 = undefined;
    var text: std.Io.Writer = .fixed(&text_buffer);
    try text.writeByte('[');
    var writer = json.Writer.init(&text);
    try write_bytes(&writer, bytes[0..len]);
    try text.writeByte(']');
    var buffers: Buffers = .{};
    const decoded = try decode_attestation(&buffers, 1, text.buffered());
    try testing.expectEqualSlices(u8, bytes[0..len], decoded.user_data.?);
}

test "tee host server: seeded fuzz byte array round trip" {
    try fuzz.run({}, fuzz_round_trip, .{ .iterations = 256, .input_size_max = 64 });
}
