//! The host side of the Enclave link (base/base
//! `crates/proof/tee/nitro-enclave/src/client.rs`): one request and one response per
//! connection, over any `std.Io.Reader`/`Writer` pair.
//!
//! Requests that break an enclave limit are refused before anything is written. Typed
//! enclave failures and the legacy untyped `Error` reply (a proof failure for a prove
//! request, an attestation failure otherwise) become errors; `last_failure` keeps the
//! enclave's message. `InProcess` runs an enclave `Handler` in this process over memory,
//! through the same framing, checks, and error mapping as a vsock connection. Connect
//! and response timeouts belong to the caller's `utilities/io` stream.

const std = @import("std");
const assert = std.debug.assert;

const crypto = @import("crypto.zig");
const handler_module = @import("handler.zig");
const protocol = @import("protocol.zig");
const transport = @import("transport.zig");

const Allocator = std.mem.Allocator;

pub const LinkError = transport.ReadError || std.Io.Writer.Error || protocol.DecodeError ||
    handler_module.ServeError || error{
    RequestTooLarge,
    /// The request breaks a limit the enclave enforces (refused before sending).
    InvalidRequest,
    /// The enclave answered for another operation.
    UnexpectedResponse,
    /// The signer public key is not a 65-byte uncompressed SEC1 point.
    InvalidSignerKey,
    /// The enclave refused the request as invalid.
    EnclaveInvalidRequest,
    /// The enclave's proof pipeline failed.
    EnclaveProofFailed,
    /// The enclave's NSM could not attest.
    EnclaveAttestationFailed,
};

pub const Config = struct {
    request_bytes_max: u32,
    response_bytes_max: u32 = 256 * 1024,
    limits: protocol.Limits = .{},
};

pub const Client = struct {
    allocator: Allocator,
    config: Config,
    request_buffer: []u8,
    response_buffer: []u8,
    /// Owns the slices of the last decoded response.
    arena: std.heap.ArenaAllocator,
    last_failure: ?protocol.Failure = null,

    pub fn init(allocator: Allocator, config: Config) Allocator.Error!Client {
        assert(config.request_bytes_max > 0 and config.response_bytes_max > 0);
        const request_buffer = try allocator.alloc(u8, config.request_bytes_max);
        errdefer allocator.free(request_buffer);
        return .{
            .allocator = allocator,
            .config = config,
            .request_buffer = request_buffer,
            .response_buffer = try allocator.alloc(u8, config.response_bytes_max),
            .arena = .init(allocator),
        };
    }

    pub fn deinit(client: *Client) void {
        client.arena.deinit();
        client.allocator.free(client.response_buffer);
        client.allocator.free(client.request_buffer);
        client.* = undefined;
    }

    /// Validates and encodes `request`; returns the payload to frame.
    pub fn encode(client: *Client, request: *const protocol.Request) LinkError![]const u8 {
        if (request.validate()) |failure| {
            client.last_failure = failure;
            return error.InvalidRequest;
        }
        var writer: std.Io.Writer = .fixed(client.request_buffer);
        protocol.encode_request(&writer, request) catch return error.RequestTooLarge;
        assert(writer.buffered().len > 0);
        return writer.buffered();
    }

    /// Reads and decodes one response, mapping enclave failures to errors.
    pub fn receive(
        client: *Client,
        reader: *std.Io.Reader,
        request: *const protocol.Request,
    ) LinkError!protocol.Response {
        const payload = try transport.read(reader, client.response_buffer);
        _ = client.arena.reset(.retain_capacity);
        const response = try protocol.decode_response(
            client.arena.allocator(),
            payload,
            client.config.limits,
        );
        assert(payload.len > 0);
        switch (response) {
            .failure => |failure| {
                client.last_failure = failure;
                return switch (failure.kind) {
                    .invalid_request => error.EnclaveInvalidRequest,
                    .proof => error.EnclaveProofFailed,
                    .attestation => error.EnclaveAttestationFailed,
                };
            },
            .error_text => |message| {
                const is_prove = request.* == .prove;
                client.last_failure = .{
                    .kind = if (is_prove) .proof else .attestation,
                    .message = message,
                };
                return if (is_prove) error.EnclaveProofFailed else error.EnclaveAttestationFailed;
            },
            else => return response,
        }
    }

    /// Sends `request` over the stream and returns the enclave's answer.
    pub fn exchange(
        client: *Client,
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
        request: *const protocol.Request,
    ) LinkError!protocol.Response {
        const payload = try client.encode(request);
        try transport.write(writer, payload);
        return client.receive(reader, request);
    }
};

/// The proof of a prove response.
pub fn expect_proof(response: protocol.Response) LinkError!protocol.TeeProofResult {
    return switch (response) {
        .prove => |result| switch (result) {
            .tee => |tee| tee,
            .zk => error.UnexpectedResponse,
        },
        else => error.UnexpectedResponse,
    };
}

/// The signer public key of a response, checked to be 65-byte uncompressed SEC1.
pub fn expect_signer_public_key(response: protocol.Response) LinkError!crypto.PublicKey {
    const key = switch (response) {
        .signer_public_key => |key| key,
        else => return error.UnexpectedResponse,
    };
    if (key.len != crypto.public_key_length or key[0] != 0x04) return error.InvalidSignerKey;
    return key[0..crypto.public_key_length].*;
}

/// The signer's Ethereum address from its public key.
pub fn signer_address_of(public_key: *const crypto.PublicKey) LinkError!crypto.Address {
    const secp256k1 = @import("../../../common/crypto/secp256k1/root.zig");
    const point = public_key[1..65].*;
    if (secp256k1.decode_public_key(&point) == null) return error.InvalidSignerKey;
    assert(public_key[0] == 0x04);
    return secp256k1.public_key_to_address(&point);
}

pub fn expect_attestation(response: protocol.Response) LinkError![]const u8 {
    return switch (response) {
        .signer_attestation => |document| document,
        else => error.UnexpectedResponse,
    };
}

/// An enclave `Handler` in this process, reached over memory.
pub const InProcess = struct {
    handler: *handler_module.Handler,
    /// Holds the framed response.
    wire: []u8,

    pub fn call(
        in_process: InProcess,
        client: *Client,
        request: *const protocol.Request,
    ) LinkError!protocol.Response {
        const payload = try client.encode(request);
        assert(payload.len > 0);
        const framed = try client.allocator.alloc(u8, payload.len + transport.header_bytes);
        defer client.allocator.free(framed);
        var request_writer: std.Io.Writer = .fixed(framed);
        try transport.write(&request_writer, payload);
        var request_reader: std.Io.Reader = .fixed(request_writer.buffered());
        var response_writer: std.Io.Writer = .fixed(in_process.wire);
        try in_process.handler.serve(&request_reader, &response_writer);
        var response_reader: std.Io.Reader = .fixed(response_writer.buffered());
        return client.receive(&response_reader, request);
    }
};
