//! The Enclave link end to end in process: client, frames, handler, and server
//! (base/base `client.rs` and `handler.rs` tests).

const std = @import("std");
const testing = std.testing;

const proof_client = @import("../../client/root.zig");
const crypto = @import("crypto.zig");
const protocol = @import("protocol.zig");
const transport = @import("transport.zig");
const nsm_module = @import("nsm.zig");
const server_module = @import("server.zig");
const handler_module = @import("handler.zig");
const client_module = @import("client.zig");
const attestation = @import("../nitro/attestation.zig");

/// Options for requests that fail before the client runs (no KZG settings needed).
const unused_options: proof_client.client.Options = .{
    .builder = proof_client.client.default_builder_config,
    .kzg_settings = undefined,
    .kzg_workspace = undefined,
};

const Link = struct {
    server: server_module.Server,
    handler: handler_module.Handler,
    client: client_module.Client,
    wire: [64 * 1024]u8,

    fn create(server: server_module.Server) !*Link {
        const link = try testing.allocator.create(Link);
        errdefer testing.allocator.destroy(link);
        link.server = server;
        link.handler = try .init(testing.allocator, &link.server, .{
            .request_bytes_max = 64 * 1024,
            .client_options = unused_options,
        });
        errdefer link.handler.deinit();
        link.client = try .init(testing.allocator, .{ .request_bytes_max = 64 * 1024 });
        return link;
    }

    fn destroy(link: *Link) void {
        link.client.deinit();
        link.handler.deinit();
        testing.allocator.destroy(link);
    }

    fn call(link: *Link, request: protocol.Request) client_module.LinkError!protocol.Response {
        const in_process: client_module.InProcess = .{
            .handler = &link.handler,
            .wire = &link.wire,
        };
        return in_process.call(&link.client, &request);
    }
};

fn local_server() !server_module.Server {
    return .init_local(try crypto.Signer.from_bytes(&@as([32]u8, @splat(0x21))));
}

test "enclave link: the in-process signer address matches the server" {
    const link = try Link.create(try local_server());
    defer link.destroy();
    const key = try client_module.expect_signer_public_key(try link.call(.signer_public_key));
    const address = try client_module.signer_address_of(&key);
    try testing.expectEqual(link.server.signer_address(), address);
}

test "enclave link: an empty witness is a proof rejection" {
    const link = try Link.create(try local_server());
    defer link.destroy();
    try testing.expectError(error.EnclaveProofFailed, link.call(.{ .prove = &.{} }));
    try testing.expectEqual(protocol.FailureKind.proof, link.client.last_failure.?.kind);
}

test "enclave link: an oversized nonce is refused before sending" {
    const link = try Link.create(try local_server());
    defer link.destroy();
    const nonce: [protocol.nonce_bytes_max + 1]u8 = @splat(0);
    var wire: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&wire);
    var reader: std.Io.Reader = .fixed(&.{});
    const request: protocol.Request = .{ .signer_attestation = .{ .nonce = &nonce } };
    try testing.expectError(
        error.InvalidRequest,
        link.client.exchange(&reader, &writer, &request),
    );
    try testing.expectEqual(@as(usize, 0), writer.buffered().len);
}

test "enclave link: the handler answers an oversized nonce with an invalid request failure" {
    const link = try Link.create(try local_server());
    defer link.destroy();
    const nonce: [protocol.nonce_bytes_max + 1]u8 = @splat(0);
    const request: protocol.Request = .{ .signer_attestation = .{ .nonce = &nonce } };
    const response = link.handler.respond(&request);
    try testing.expectEqual(protocol.FailureKind.invalid_request, response.failure.kind);
}

test "enclave link: a nonce at the limit reaches the NSM (none in local mode)" {
    const link = try Link.create(try local_server());
    defer link.destroy();
    const at_limit: [protocol.nonce_bytes_max]u8 = @splat(0);
    const request: protocol.Request = .{ .signer_attestation = .{
        .user_data = &at_limit,
        .nonce = &at_limit,
    } };
    try testing.expectError(error.EnclaveAttestationFailed, link.call(request));
}

test "enclave link: an enclave-mode attestation binds the signer key and nonce" {
    var fake: nsm_module.Fake = .init(11);
    const link = try Link.create(try .init_enclave(fake.nsm()));
    defer link.destroy();
    const response = try link.call(.{ .signer_attestation = .{ .nonce = "fresh" } });
    const document = try client_module.expect_attestation(response);
    const report = try attestation.AttestationReport.parse(document);
    const public_key = link.server.signer_public_key();
    try testing.expectEqualSlices(u8, public_key, report.document.public_key.?);
    try testing.expectEqualStrings("fresh", report.document.nonce.?);
}

test "enclave link: a legacy error reply is a proof rejection for a prove request" {
    var client: client_module.Client = try .init(testing.allocator, .{ .request_bytes_max = 64 });
    defer client.deinit();
    var payload_buffer: [32]u8 = undefined;
    var payload: std.Io.Writer = .fixed(&payload_buffer);
    try protocol.encode_response(&payload, &.{ .error_text = "boom" });
    var wire: [64]u8 = undefined;
    var wire_writer: std.Io.Writer = .fixed(&wire);
    try transport.write(&wire_writer, payload.buffered());
    var reader: std.Io.Reader = .fixed(wire_writer.buffered());
    const request: protocol.Request = .{ .prove = &.{} };
    try testing.expectError(error.EnclaveProofFailed, client.receive(&reader, &request));
    try testing.expectEqualStrings("boom", client.last_failure.?.message);
}

test "enclave link: a peer closing mid exchange is a frame error" {
    var client: client_module.Client = try .init(testing.allocator, .{ .request_bytes_max = 64 });
    defer client.deinit();
    var wire: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&wire);
    var reader: std.Io.Reader = .fixed(&.{});
    const request: protocol.Request = .signer_public_key;
    try testing.expectError(error.EndOfStream, client.exchange(&reader, &writer, &request));
}
