//! `ItemList(Item)`: a zero-copy RLP list. It holds the list's validated payload and
//! decodes items lazily through a bounded iterator, so decoding never allocates.

const std = @import("std");
const assert = std.debug.assert;
const rlp = @import("../rlp/root.zig");

/// `decode_item(*Decoder) !Item` must consume exactly one item.
pub fn ItemList(comptime Item: type, comptime decode_item: anytype) type {
    return struct {
        payload: []const u8 = &.{},
        count: u32 = 0,

        const Self = @This();
        pub const empty: Self = .{};

        pub const Iterator = struct {
            decoder: rlp.Decoder,

            pub fn next(self: *Iterator) ?Item {
                if (self.decoder.is_empty()) return null;
                return decode_item(&self.decoder) catch unreachable; // Validated.
            }
        };

        pub fn iterator(list: Self) Iterator {
            return .{ .decoder = rlp.Decoder.init(list.payload) };
        }

        pub fn from_payload(payload: []const u8) !Self {
            var decoder = rlp.Decoder.init(payload);
            var count: u32 = 0;
            // Every item consumes at least one byte: bounded by payload.len.
            while (!decoder.is_empty()) : (count += 1) _ = try decode_item(&decoder);
            assert(count <= payload.len);
            return .{ .payload = payload, .count = count };
        }

        /// Encodes `items` (with `rlp.encode`) into `buffer` as a list payload.
        pub fn build(buffer: []u8, items: []const Item) Self {
            var encoder = rlp.Encoder.init(buffer);
            for (items) |item| rlp.encode(&encoder, item);
            return .{ .payload = encoder.written(), .count = @intCast(items.len) };
        }

        pub fn rlp_length(list: Self) usize {
            return rlp.list_length(list.payload.len);
        }

        pub fn rlp_encode(list: Self, encoder: *rlp.Encoder) void {
            encoder.list_header(list.payload.len);
            encoder.raw(list.payload);
        }

        pub fn decode_list(decoder: *rlp.Decoder) !Self {
            const items = try decoder.list();
            return from_payload(items.input);
        }

        pub fn rlp_decode(decoder: *rlp.Decoder) !Self {
            return decode_list(decoder);
        }
    };
}

/// `decode_item` for plain codec types.
pub fn codec_decoder(comptime Item: type) fn (*rlp.Decoder) rlp.Error!Item {
    return struct {
        fn decode(decoder: *rlp.Decoder) rlp.Error!Item {
            return rlp.decode(Item, decoder);
        }
    }.decode;
}
