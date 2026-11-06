//! The enclave side of the Enclave link (base/base
//! `crates/proof/tee/nitro-enclave/src/handler.rs`): reads one request frame, runs it on
//! the server, and writes one response frame.
//!
//! A request that breaks a limit is answered with an `invalid_request` failure; a failed
//! proof or attestation with a `proof` or `attestation` failure carrying the error name.
//! A frame that does not decode gets no answer (base/base returns the codec error). The
//! request read deadline (five minutes in base/base) belongs to the stream: the caller's
//! `utilities/io` socket bounds it.

const std = @import("std");
const assert = std.debug.assert;
const log = std.log.scoped(.enclave);

const proof_client = @import("../../client/root.zig");
const protocol = @import("protocol.zig");
const server_module = @import("server.zig");
const transport = @import("transport.zig");

const Allocator = std.mem.Allocator;

pub const Config = struct {
    /// Largest request frame (the witness bundle of a prove request).
    request_bytes_max: u32,
    /// Largest response frame (a proof or an attestation document).
    response_bytes_max: u32 = 256 * 1024,
    limits: protocol.Limits = .{},
    client_options: proof_client.client.Options,
};

pub const ServeError = transport.ReadError || std.Io.Writer.Error || protocol.DecodeError ||
    error{ResponseTooLarge};

pub const Handler = struct {
    allocator: Allocator,
    server: *const server_module.Server,
    config: Config,
    request_buffer: []u8,
    response_buffer: []u8,
    proof: *server_module.Proof,

    pub fn init(
        allocator: Allocator,
        server: *const server_module.Server,
        config: Config,
    ) Allocator.Error!Handler {
        assert(config.request_bytes_max > 0);
        assert(config.response_bytes_max >= 1024);
        const request_buffer = try allocator.alloc(u8, config.request_bytes_max);
        errdefer allocator.free(request_buffer);
        const response_buffer = try allocator.alloc(u8, config.response_bytes_max);
        errdefer allocator.free(response_buffer);
        return .{
            .allocator = allocator,
            .server = server,
            .config = config,
            .request_buffer = request_buffer,
            .response_buffer = response_buffer,
            .proof = try allocator.create(server_module.Proof),
        };
    }

    pub fn deinit(handler: *Handler) void {
        handler.allocator.destroy(handler.proof);
        handler.allocator.free(handler.response_buffer);
        handler.allocator.free(handler.request_buffer);
        handler.* = undefined;
    }

    /// Reads one request from `reader`, runs it, and writes the response to `writer`.
    pub fn serve(
        handler: *Handler,
        reader: *std.Io.Reader,
        writer: *std.Io.Writer,
    ) ServeError!void {
        const payload = try transport.read(reader, handler.request_buffer);
        var arena: std.heap.ArenaAllocator = .init(handler.allocator);
        defer arena.deinit();
        const request = try protocol.decode_request(
            arena.allocator(),
            payload,
            handler.config.limits,
        );
        const response = handler.respond(&request);
        var response_writer: std.Io.Writer = .fixed(handler.response_buffer);
        protocol.encode_response(&response_writer, &response) catch
            return error.ResponseTooLarge;
        assert(response_writer.buffered().len > 0);
        try transport.write(writer, response_writer.buffered());
    }

    /// The response to one decoded request. Byte strings point into the handler.
    pub fn respond(handler: *Handler, request: *const protocol.Request) protocol.Response {
        if (request.validate()) |failure| return .{ .failure = failure };
        const server = handler.server;
        switch (request.*) {
            .prove => |preimages| {
                server.prove(
                    handler.allocator,
                    preimages,
                    handler.config.client_options,
                    handler.proof,
                ) catch |err| {
                    log.info("prove failed: {t}", .{err});
                    return .{ .failure = .{ .kind = .proof, .message = @errorName(err) } };
                };
                return .{ .prove = .{ .tee = handler.proof.result() } };
            },
            .signer_public_key => return .{ .signer_public_key = server.signer_public_key() },
            .signer_attestation => |attestation| {
                // Half the response buffer leaves room for the frame's own encoding.
                const out = handler.response_buffer[handler.response_buffer.len / 2 ..];
                const document = server.signer_attestation(attestation, out) catch |err| {
                    return .{ .failure = .{ .kind = .attestation, .message = @errorName(err) } };
                };
                assert(document.len <= out.len);
                return .{ .signer_attestation = document };
            },
        }
    }
};
