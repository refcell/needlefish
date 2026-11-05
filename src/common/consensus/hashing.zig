//! Streaming keccak256 over RLP encodings: no buffer sized for the encoded value.

const std = @import("std");
const primitives = @import("../primitives/root.zig");
const rlp = @import("../rlp/root.zig");
const keccak = @import("../crypto/keccak.zig");
const B256 = primitives.B256;

/// Feeds encoded bytes into a keccak hasher.
pub const KeccakSink = struct {
    hasher: keccak.Hasher = .{},

    fn write(context: *anyopaque, data: []const u8) void {
        const sink: *KeccakSink = @ptrCast(@alignCast(context));
        sink.hasher.update(data);
    }

    pub fn encoder(sink: *KeccakSink) rlp.Encoder {
        return rlp.Encoder.init_sink(.{ .context = sink, .write = write });
    }

    pub fn final(sink: *KeccakSink) B256 {
        return .{ .bytes = sink.hasher.final() };
    }
};

/// keccak256(rlp(value)) for any type `rlp.codec` can encode.
pub fn keccak_rlp(value: anytype) B256 {
    var sink: KeccakSink = .{};
    var encoder = sink.encoder();
    rlp.encode(&encoder, value);
    std.debug.assert(encoder.position == rlp.length(value));
    return sink.final();
}

test "hashing: keccak_rlp matches buffered hash" {
    const list = struct { a: u64, b: []const u8 }{ .a = 1024, .b = "hello" };
    var buffer: [32]u8 = undefined;
    const encoded = rlp.encode_to(&buffer, list);
    try std.testing.expect(keccak_rlp(list).eql(primitives.keccak256(encoded)));
}
