//! One host-side connection to an enclave (base/base `EnclaveClient` as the nitro host
//! holds it): an Enclave link `Client` and the transport that carries its frames.
//!
//! The transport is an interface. On a Nitro instance it is a vsock connection per request
//! (outside the standard library, so supplied by the binary); in local mode and in tests it
//! is an enclave `Handler` in this process (`InProcess`), which runs the same framing,
//! checks, and error mapping as a socket. Replies point into the client's arena and stay
//! valid until the next call on the same link.

const std = @import("std");
const assert = std.debug.assert;

const enclave = @import("../enclave/root.zig");

const protocol = enclave.protocol;
const crypto = enclave.crypto;

pub const LinkError = enclave.client.LinkError;

/// Carries one request to the enclave and returns its decoded response.
pub const Transport = struct {
    context: *anyopaque,
    call: *const fn (
        context: *anyopaque,
        client: *enclave.Client,
        request: *const protocol.Request,
    ) LinkError!protocol.Response,
};

pub const Link = struct {
    client: enclave.Client,
    transport: Transport,
    /// Requests sent and requests that failed, for diagnostics.
    calls: u64 = 0,
    failures: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        config: enclave.client.Config,
        transport: Transport,
    ) std.mem.Allocator.Error!Link {
        assert(config.request_bytes_max > 0);
        assert(config.response_bytes_max > 0);
        return .{ .client = try .init(allocator, config), .transport = transport };
    }

    pub fn deinit(link: *Link) void {
        link.client.deinit();
        link.* = undefined;
    }

    fn call(link: *Link, request: *const protocol.Request) LinkError!protocol.Response {
        link.calls += 1;
        const transport = link.transport;
        const response = transport.call(transport.context, &link.client, request) catch |err| {
            link.failures += 1;
            return err;
        };
        assert(link.failures <= link.calls);
        return response;
    }

    /// The enclave's 65-byte uncompressed SEC1 signer key.
    pub fn signer_public_key(link: *Link) LinkError!crypto.PublicKey {
        const key = try enclave.client.expect_signer_public_key(
            try link.call(&.signer_public_key),
        );
        assert(key[0] == 0x04);
        return key;
    }

    /// The enclave signer's Ethereum address.
    pub fn signer_address(link: *Link) LinkError!crypto.Address {
        const key = try link.signer_public_key();
        return enclave.client.signer_address_of(&key);
    }

    /// An NSM attestation document over the signer key (fails in local mode).
    pub fn signer_attestation(
        link: *Link,
        request: protocol.AttestationRequest,
    ) LinkError![]const u8 {
        const document = try enclave.client.expect_attestation(
            try link.call(&.{ .signer_attestation = request }),
        );
        assert(document.len <= link.client.response_buffer.len);
        return document;
    }

    /// Proves the claim of `preimages` in the enclave and returns its signed proposal.
    pub fn prove(
        link: *Link,
        preimages: []const protocol.Preimage,
    ) LinkError!protocol.TeeProofResult {
        const result = try enclave.client.expect_proof(try link.call(&.{ .prove = preimages }));
        assert(result.tee_kind == .aws_nitro);
        assert(result.intermediate_roots.len <= protocol.TeeProofResult.intermediate_roots_max);
        return result;
    }

    /// The enclave's message for the last failure, or an empty string.
    pub fn last_failure_message(link: *const Link) []const u8 {
        const failure = link.client.last_failure orelse return "";
        return failure.message;
    }
};

/// An enclave `Handler` in this process (base/base `EnclaveClient::in_process`).
pub const InProcess = struct {
    handler: *enclave.Handler,
    /// Holds one framed response; at least the handler's response limit plus the header.
    wire: []u8,

    pub fn transport(in_process: *InProcess) Transport {
        assert(in_process.wire.len >= enclave.transport.header_bytes);
        assert(in_process.wire.len >= in_process.handler.config.response_bytes_max);
        return .{ .context = in_process, .call = call };
    }

    fn call(
        context: *anyopaque,
        client: *enclave.Client,
        request: *const protocol.Request,
    ) LinkError!protocol.Response {
        const in_process: *InProcess = @ptrCast(@alignCast(context));
        const inner: enclave.client.InProcess = .{
            .handler = in_process.handler,
            .wire = in_process.wire,
        };
        return inner.call(client, request);
    }
};

/// A local-mode enclave (server, handler, link) in this process, for development and
/// tests: base/base `Server::new_local` behind `EnclaveClient::in_process`.
pub const LocalEnclave = struct {
    server: enclave.Server,
    handler: enclave.Handler,
    in_process: InProcess,
    link: Link,
    allocator: std.mem.Allocator,

    pub const Options = struct {
        request_bytes_max: u32,
        response_bytes_max: u32 = 256 * 1024,
        client_options: @import("../../client/root.zig").client.Options,
    };

    /// Creates the enclave at a stable address (the handler points into it).
    pub fn create(
        allocator: std.mem.Allocator,
        server: enclave.Server,
        options: Options,
    ) std.mem.Allocator.Error!*LocalEnclave {
        assert(options.request_bytes_max > 0);
        const local = try allocator.create(LocalEnclave);
        errdefer allocator.destroy(local);
        local.allocator = allocator;
        local.server = server;
        local.handler = try .init(allocator, &local.server, .{
            .request_bytes_max = options.request_bytes_max,
            .response_bytes_max = options.response_bytes_max,
            .client_options = options.client_options,
        });
        errdefer local.handler.deinit();
        const wire_bytes = options.response_bytes_max + enclave.transport.header_bytes;
        const wire = try allocator.alloc(u8, wire_bytes);
        local.in_process = .{ .handler = &local.handler, .wire = wire };
        errdefer allocator.free(local.in_process.wire);
        local.link = try .init(allocator, .{
            .request_bytes_max = options.request_bytes_max,
            .response_bytes_max = options.response_bytes_max,
        }, local.in_process.transport());
        return local;
    }

    pub fn destroy(local: *LocalEnclave) void {
        const allocator = local.allocator;
        local.link.deinit();
        allocator.free(local.in_process.wire);
        local.handler.deinit();
        allocator.destroy(local);
    }
};

const testing = std.testing;

/// Options for requests that never reach the client (no KZG settings needed).
pub const unused_client_options: @import("../../client/root.zig").client.Options = .{
    .builder = @import("../../client/root.zig").client.default_builder_config,
    .kzg_settings = undefined,
    .kzg_workspace = undefined,
};

/// A local enclave with a fixed key, for tests.
pub fn test_local_enclave(key_byte: u8) !*LocalEnclave {
    const signer = try crypto.Signer.from_bytes(&@as([32]u8, @splat(key_byte)));
    return LocalEnclave.create(testing.allocator, .init_local(signer), .{
        .request_bytes_max = 64 * 1024,
        .client_options = unused_client_options,
    });
}

test "tee host link: the in-process signer key and address match the enclave" {
    const local = try test_local_enclave(0x31);
    defer local.destroy();
    const key = try local.link.signer_public_key();
    try testing.expectEqualSlices(u8, local.server.signer_public_key(), &key);
    try testing.expectEqual(local.server.signer_address(), try local.link.signer_address());
    try testing.expectEqual(@as(u64, 2), local.link.calls);
    try testing.expectEqual(@as(u64, 0), local.link.failures);
}

test "tee host link: failures keep the enclave's message" {
    const local = try test_local_enclave(0x32);
    defer local.destroy();
    try testing.expectError(error.EnclaveProofFailed, local.link.prove(&.{}));
    try testing.expectError(error.EnclaveAttestationFailed, local.link.signer_attestation(.{}));
    try testing.expectEqual(@as(u64, 2), local.link.failures);
    try testing.expectEqualStrings("Unavailable", local.link.last_failure_message());
}

test "tee host link: an enclave-mode link returns an attestation document" {
    var fake: enclave.nsm.Fake = .init(17);
    const server: enclave.Server = try .init_enclave(fake.nsm());
    const local = try LocalEnclave.create(testing.allocator, server, .{
        .request_bytes_max = 64 * 1024,
        .client_options = unused_client_options,
    });
    defer local.destroy();
    const document = try local.link.signer_attestation(.{ .nonce = "n1" });
    try testing.expect(document.len > 0);
    try testing.expectEqual(@as(u32, 1), fake.attestations);
}
