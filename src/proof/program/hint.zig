//! Typed hints of the fault-proof program. Port of base/base
//! `crates/proof/proof/src/hint.rs`: a hint is `<type> 0x<hex data>`, where the data is
//! the concatenation of the parts.

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../preimage/root.zig");

pub const HintType = enum {
    l1_block_header,
    l1_transactions,
    l1_receipts,
    l1_blob,
    l1_precompile,
    l2_block_header,
    l2_transactions,
    l2_code,
    starting_l2_output,
    l2_state_node,
    l2_account_proof,
    l2_account_storage_proof,
    l2_payload_witness,

    /// The wire name: the tag with `-` for `_`.
    pub fn name(hint_type: HintType) []const u8 {
        return switch (hint_type) {
            inline else => |tag| comptime dashed(@tagName(tag)),
        };
    }

    pub fn from_name(text: []const u8) ?HintType {
        inline for (@typeInfo(HintType).@"enum".field_names) |field_name| {
            const tag = @field(HintType, field_name);
            if (std.mem.eql(u8, text, tag.name())) return tag;
        }
        return null;
    }
};

fn dashed(comptime tag: []const u8) *const [tag.len]u8 {
    comptime {
        var out: [tag.len]u8 = tag[0..tag.len].*;
        for (&out) |*char| if (char.* == '_') {
            char.* = '-';
        };
        const final = out;
        return &final;
    }
}

/// Largest data of a hint built by `send` (the payload witness hint has its own path).
pub const data_bytes_max: u32 = 256;

pub const SendError = preimage.channel.Error || error{HintTooLarge};

/// Writes `<type> 0x<hex(parts...)>` to `writer`.
pub fn send(
    writer: preimage.HintWriter,
    hint_type: HintType,
    parts: []const []const u8,
) SendError!void {
    assert(parts.len > 0);
    var text: [32 + 2 + data_bytes_max * 2]u8 = undefined;
    const type_name = hint_type.name();
    var length: usize = type_name.len + 3;
    @memcpy(text[0..type_name.len], type_name);
    @memcpy(text[type_name.len..length], " 0x");
    var data_bytes: u32 = 0;
    for (parts) |part| {
        data_bytes += @intCast(part.len);
        if (data_bytes > data_bytes_max) return error.HintTooLarge;
        for (part) |byte| {
            const pair = std.fmt.hex(byte);
            text[length..][0..2].* = pair;
            length += 2;
        }
    }
    assert(length == type_name.len + 3 + data_bytes * 2);
    try writer.write(text[0..length]);
}

test "hint: names round trip" {
    inline for (@typeInfo(HintType).@"enum".field_names) |field_name| {
        const tag = @field(HintType, field_name);
        try std.testing.expectEqual(tag, HintType.from_name(tag.name()).?);
    }
    try std.testing.expectEqualStrings("l2-payload-witness", HintType.l2_payload_witness.name());
    try std.testing.expectEqual(@as(?HintType, null), HintType.from_name("l2_code"));
}
