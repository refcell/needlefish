//! `base nitro-enclave`: the TEE enclave server in local mode (base/base
//! `bin/prover/nitro-enclave` + `nitro-enclave/src/runtime.rs`). Real enclaves listen on vsock
//! port 8000 and sign with an NSM-derived key; std has no vsock and the project links no NSM
//! driver, so this binds TCP (default 127.0.0.1:8000) and takes the signer key from a flag.
//! Each connection carries length-prefixed link frames, served one request at a time.

const std = @import("std");
const assert = std.debug.assert;
const base = @import("base");

const enclave = base.proof.tee.enclave;
const kzg = base.common.crypto.kzg;
const Io = std.Io;

const usage =
    \\usage: base nitro-enclave --signer-key <hex> [--listen <ip:port>] [--request-bytes-max <n>]
    \\  --signer-key         secp256k1 signer key (local mode; real enclaves derive it)
    \\  --listen             TCP address in place of vsock port 8000 (default 127.0.0.1:8000)
    \\  --request-bytes-max  largest request frame (default 268435456)
    \\
;

pub const Flags = struct {
    signer_key: []const u8 = "",
    host: [4]u8 = .{ 127, 0, 0, 1 },
    port: u16 = 8000,
    request_bytes_max: u32 = 256 << 20,
};

pub fn parse(args: []const []const u8) error{InvalidArguments}!Flags {
    var flags: Flags = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 2) {
        if (index + 1 >= args.len) return error.InvalidArguments;
        const name = args[index];
        const value = args[index + 1];
        if (std.mem.eql(u8, name, "--signer-key")) {
            flags.signer_key = value;
        } else if (std.mem.eql(u8, name, "--listen")) {
            try parse_listen(value, &flags);
        } else if (std.mem.eql(u8, name, "--request-bytes-max")) {
            flags.request_bytes_max = std.fmt.parseInt(u32, value, 10) catch
                return error.InvalidArguments;
            if (flags.request_bytes_max == 0) return error.InvalidArguments;
        } else return error.InvalidArguments;
    }
    if (flags.signer_key.len == 0) return error.InvalidArguments;
    assert(flags.request_bytes_max > 0);
    return flags;
}

fn parse_listen(value: []const u8, flags: *Flags) error{InvalidArguments}!void {
    const colon = std.mem.lastIndexOfScalar(u8, value, ':') orelse return error.InvalidArguments;
    var parts = std.mem.splitScalar(u8, value[0..colon], '.');
    for (&flags.host) |*octet| {
        const part = parts.next() orelse return error.InvalidArguments;
        octet.* = std.fmt.parseInt(u8, part, 10) catch return error.InvalidArguments;
    }
    if (parts.next() != null) return error.InvalidArguments;
    flags.port = std.fmt.parseInt(u16, value[colon + 1 ..], 10) catch
        return error.InvalidArguments;
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const flags = parse(args) catch {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    const signer = enclave.Signer.from_hex(flags.signer_key) catch {
        std.debug.print("nitro-enclave: invalid --signer-key\n", .{});
        return 2;
    };
    const allocator = init.gpa;
    const server: enclave.Server = .init_local(signer);
    const storage = try allocator.create(kzg.blob.Settings.Storage);
    defer allocator.destroy(storage);
    const workspace = try allocator.create(kzg.blob.Workspace);
    defer allocator.destroy(workspace);
    const settings = try kzg.blob.Settings.init(storage);
    var handler = try enclave.Handler.init(allocator, &server, .{
        .request_bytes_max = flags.request_bytes_max,
        .client_options = .{
            .builder = base.proof.client.client.default_builder_config,
            .kzg_settings = &settings,
            .kzg_workspace = workspace,
        },
    });
    defer handler.deinit();
    const address: Io.net.IpAddress = .{ .ip4 = .{ .bytes = flags.host, .port = flags.port } };
    var listener = try address.listen(init.io, .{ .reuse_address = true });
    defer listener.deinit(init.io);
    const host = flags.host;
    const port = listener.socket.address.getPort();
    std.debug.print("nitro-enclave: signer 0x{x} on {d}.{d}.{d}.{d}:{d} (local mode)\n", .{
        &server.signer_address(), host[0], host[1], host[2], host[3], port,
    });
    while (true) {
        const stream = listener.accept(init.io) catch |err| {
            std.debug.print("nitro-enclave: accept failed: {t}\n", .{err});
            continue;
        };
        serve_connection(init.io, &handler, stream);
    }
}

/// Serves requests on one connection until the peer closes it or a frame fails.
fn serve_connection(io: Io, handler: *enclave.Handler, stream: Io.net.Stream) void {
    defer stream.close(io);
    var read_buffer: [64 * 1024]u8 = undefined;
    var write_buffer: [28 * 1024]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var writer = stream.writer(io, &write_buffer);
    // A connection carries at most this many requests before the host must reconnect.
    const requests_max: u32 = 1 << 20;
    var served: u32 = 0;
    while (served < requests_max) : (served += 1) {
        handler.serve(&reader.interface, &writer.interface) catch |err| {
            if (err != error.EndOfStream) {
                std.debug.print("nitro-enclave: connection closed: {t}\n", .{err});
            }
            return;
        };
        writer.interface.flush() catch return;
    }
    assert(served == requests_max);
}

test "nitro-enclave: argument parsing" {
    const key = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const flags = try parse(&.{ "--signer-key", key, "--listen", "0.0.0.0:9000" });
    try std.testing.expectEqual(@as(u16, 9000), flags.port);
    try std.testing.expectEqual(@as(u8, 0), flags.host[0]);
    try std.testing.expectError(error.InvalidArguments, parse(&.{}));
    const bad_listen = parse(&.{ "--signer-key", key, "--listen", "1.2.3:4" });
    try std.testing.expectError(error.InvalidArguments, bad_listen);
    const zero = parse(&.{ "--signer-key", key, "--request-bytes-max", "0" });
    try std.testing.expectError(error.InvalidArguments, zero);
}
