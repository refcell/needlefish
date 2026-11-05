//! WebSocket (RFC 6455): handshake helpers and frame codec. A client and server on the IO
//! interface build on this (see the lane backlog).

pub const frame = @import("frame.zig");
pub const Opcode = frame.Opcode;
pub const Header = frame.Header;
pub const Limits = frame.Limits;
pub const Role = frame.Role;
pub const CloseCode = frame.CloseCode;
pub const decode_frame = frame.decode_frame;
pub const encode_header = frame.encode_header;
pub const apply_mask = frame.apply_mask;
pub const accept_key = frame.accept_key;
pub const client_key = frame.client_key;
pub const parse_close = frame.parse_close;
pub const client = @import("client.zig");
pub const Client = client.Client;
pub const stream = @import("stream.zig");
pub const server = @import("server.zig");
pub const Server = server.Server;

test {
    _ = @import("frame_test.zig");
    _ = @import("client_test.zig");
    _ = @import("server_test.zig");
}
