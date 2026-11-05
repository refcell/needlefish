//! Transaction field types with custom RLP: `TxKind`, `AccessList`,
//! `AuthorizationList` (EIP-7702) and `HashList` (EIP-4844 blob hashes).
//!
//! List-valued fields are zero copy: they hold the validated RLP payload of the list
//! (borrowed from the decoded input, or from a caller buffer when built) and expose
//! bounded iterators. Decoding validates the full structure once, so iteration can
//! assert instead of re-checking.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../primitives/root.zig");
const rlp = @import("../rlp/root.zig");
const signature_module = @import("signature.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const Encoder = rlp.Encoder;
const Decoder = rlp.Decoder;
const Signature = signature_module.Signature;

/// Destination of a transaction: contract creation or a call to an address.
pub const TxKind = union(enum) {
    create,
    call: Address,

    pub fn rlp_length(kind: TxKind) usize {
        return switch (kind) {
            .create => 1,
            .call => 21,
        };
    }

    pub fn rlp_encode(kind: TxKind, encoder: *Encoder) void {
        switch (kind) {
            .create => encoder.bytes(&.{}),
            .call => |address| encoder.bytes(&address.bytes),
        }
    }

    pub fn rlp_decode(decoder: *Decoder) rlp.Error!TxKind {
        const payload = try decoder.bytes();
        if (payload.len == 0) return .create;
        if (payload.len != 20) return error.Overflow;
        return .{ .call = Address.from_slice(payload) };
    }

    pub fn to(kind: TxKind) ?Address {
        return switch (kind) {
            .create => null,
            .call => |address| address,
        };
    }
};

/// A list of 32-byte hashes (blob versioned hashes, storage keys).
pub const HashList = struct {
    /// RLP payload: concatenated 33-byte items (`0xa0 || hash`).
    payload: []const u8 = &.{},

    pub const empty: HashList = .{};

    pub fn count(list: HashList) usize {
        assert(list.payload.len % 33 == 0);
        return list.payload.len / 33;
    }

    pub fn get(list: HashList, index: usize) B256 {
        assert(index < list.count());
        const item = list.payload[index * 33 ..][0..33];
        assert(item[0] == 0xa0);
        return B256.from_slice(item[1..33]);
    }

    /// Validates a list payload of 32-byte strings.
    pub fn from_payload(payload: []const u8) rlp.Error!HashList {
        if (payload.len % 33 != 0) return error.Overflow;
        var index: usize = 0;
        while (index < payload.len) : (index += 33) {
            if (payload[index] != 0xa0) return error.Overflow;
        }
        return .{ .payload = payload };
    }

    /// Writes `hashes` as a payload into `buffer` (33 bytes each).
    pub fn build(buffer: []u8, hashes: []const B256) HashList {
        assert(buffer.len >= hashes.len * 33);
        for (hashes, 0..) |hash, i| {
            buffer[i * 33] = 0xa0;
            buffer[i * 33 + 1 ..][0..32].* = hash.bytes;
        }
        return .{ .payload = buffer[0 .. hashes.len * 33] };
    }

    pub fn rlp_length(list: HashList) usize {
        return rlp.list_length(list.payload.len);
    }

    pub fn rlp_encode(list: HashList, encoder: *Encoder) void {
        encoder.list_header(list.payload.len);
        encoder.raw(list.payload);
    }

    pub fn rlp_decode(decoder: *Decoder) rlp.Error!HashList {
        const items = try decoder.list();
        return from_payload(items.input);
    }
};

/// EIP-2930 access list: `[[address, [storage_key, ...]], ...]`.
pub const AccessList = struct {
    payload: []const u8 = &.{},
    address_count: u32 = 0,
    storage_key_count: u32 = 0,

    pub const empty: AccessList = .{};

    pub const Item = struct { address: Address, storage_keys: HashList };

    pub const Iterator = struct {
        decoder: Decoder,

        pub fn next(self: *Iterator) ?Item {
            if (self.decoder.is_empty()) return null;
            // Structure was validated when the list was decoded or built.
            var entry = self.decoder.list() catch unreachable;
            const address = entry.fixed(20) catch unreachable;
            const keys = entry.list() catch unreachable;
            assert(entry.is_empty());
            return .{
                .address = .{ .bytes = address },
                .storage_keys = .{ .payload = keys.input },
            };
        }
    };

    pub fn iterator(list: AccessList) Iterator {
        return .{ .decoder = Decoder.init(list.payload) };
    }

    pub fn from_payload(payload: []const u8) rlp.Error!AccessList {
        var decoder = Decoder.init(payload);
        var addresses: u32 = 0;
        var keys: u32 = 0;
        // Every entry consumes at least 23 bytes, so the loop is bounded by payload.len.
        while (!decoder.is_empty()) {
            var entry = try decoder.list();
            _ = try entry.fixed(20);
            const storage_keys = try HashList.rlp_decode(&entry);
            try entry.finish();
            addresses += 1;
            keys += @intCast(storage_keys.count());
        }
        return .{ .payload = payload, .address_count = addresses, .storage_key_count = keys };
    }

    /// Encodes `items` into `buffer` and returns a list borrowing it.
    pub fn build(buffer: []u8, items: []const BuildItem) AccessList {
        var encoder = Encoder.init(buffer);
        var keys: u32 = 0;
        for (items) |item| {
            const keys_length: usize = item.storage_keys.len * 33;
            encoder.list_header(21 + rlp.list_length(keys_length));
            encoder.bytes(&item.address.bytes);
            encoder.list_header(keys_length);
            for (item.storage_keys) |key| encoder.bytes(&key.bytes);
            keys += @intCast(item.storage_keys.len);
        }
        return .{
            .payload = encoder.written(),
            .address_count = @intCast(items.len),
            .storage_key_count = keys,
        };
    }

    pub const BuildItem = struct { address: Address, storage_keys: []const B256 = &.{} };

    pub fn rlp_length(list: AccessList) usize {
        return rlp.list_length(list.payload.len);
    }

    pub fn rlp_encode(list: AccessList, encoder: *Encoder) void {
        encoder.list_header(list.payload.len);
        encoder.raw(list.payload);
    }

    pub fn rlp_decode(decoder: *Decoder) rlp.Error!AccessList {
        const items = try decoder.list();
        return from_payload(items.input);
    }
};

/// EIP-7702 magic prefix for authorization signing hashes.
pub const authorization_magic: u8 = 0x05;

/// A signed EIP-7702 authorization tuple.
pub const Authorization = struct {
    chain_id: u256,
    address: Address,
    nonce: u64,
    y_parity: u8,
    r: u256,
    s: u256,

    /// keccak256(0x05 || rlp([chain_id, address, nonce])).
    pub fn signing_hash(authorization: Authorization) B256 {
        const unsigned = .{
            .chain_id = authorization.chain_id,
            .address = authorization.address,
            .nonce = authorization.nonce,
        };
        var buffer: [1 + 3 + 33 + 21 + 9]u8 = undefined;
        buffer[0] = authorization_magic;
        const encoded = rlp.encode_to(buffer[1..], unsigned);
        return primitives.keccak256(buffer[0 .. 1 + encoded.len]);
    }

    /// The authority (signer); null when the signature is invalid. EIP-7702 requires
    /// low-s and y_parity in {0, 1}.
    pub fn recover_authority(
        authorization: Authorization,
        recoverer: signature_module.Recoverer,
    ) ?Address {
        if (authorization.y_parity > 1) return null;
        const signature: Signature = .{
            .y_parity = authorization.y_parity == 1,
            .r = authorization.r,
            .s = authorization.s,
        };
        if (!signature.is_low_s()) return null;
        return recoverer(authorization.signing_hash(), signature);
    }
};

pub const AuthorizationList = struct {
    payload: []const u8 = &.{},
    count: u32 = 0,

    pub const empty: AuthorizationList = .{};

    pub const Iterator = struct {
        decoder: Decoder,

        pub fn next(self: *Iterator) ?Authorization {
            if (self.decoder.is_empty()) return null;
            return rlp.decode(Authorization, &self.decoder) catch unreachable;
        }
    };

    pub fn iterator(list: AuthorizationList) Iterator {
        return .{ .decoder = Decoder.init(list.payload) };
    }

    pub fn from_payload(payload: []const u8) rlp.Error!AuthorizationList {
        var decoder = Decoder.init(payload);
        var count: u32 = 0;
        while (!decoder.is_empty()) : (count += 1) {
            _ = try rlp.decode(Authorization, &decoder);
        }
        return .{ .payload = payload, .count = count };
    }

    pub fn build(buffer: []u8, items: []const Authorization) AuthorizationList {
        var encoder = Encoder.init(buffer);
        for (items) |item| rlp.encode(&encoder, item);
        return .{ .payload = encoder.written(), .count = @intCast(items.len) };
    }

    pub fn rlp_length(list: AuthorizationList) usize {
        return rlp.list_length(list.payload.len);
    }

    pub fn rlp_encode(list: AuthorizationList, encoder: *Encoder) void {
        encoder.list_header(list.payload.len);
        encoder.raw(list.payload);
    }

    pub fn rlp_decode(decoder: *Decoder) rlp.Error!AuthorizationList {
        const items = try decoder.list();
        return from_payload(items.input);
    }
};

const testing = std.testing;

test "tx fields: tx kind" {
    var buffer: [32]u8 = undefined;
    try testing.expectEqualSlices(u8, &.{0x80}, rlp.encode_to(&buffer, @as(TxKind, .create)));
    const address = Address.comptime_hex("0x3535353535353535353535353535353535353535");
    const encoded = rlp.encode_to(&buffer, TxKind{ .call = address });
    try testing.expectEqual(@as(usize, 21), encoded.len);
    try testing.expect((try rlp.decode_exact(TxKind, encoded)).to().?.eql(address));
    try testing.expectError(error.Overflow, rlp.decode_exact(TxKind, &.{ 0x82, 1, 2 }));
}

test "tx fields: access list build, decode, iterate" {
    const key_a = B256{ .bytes = @splat(1) };
    const key_b = B256{ .bytes = @splat(2) };
    const items = [_]AccessList.BuildItem{
        .{ .address = Address{ .bytes = @splat(0xaa) }, .storage_keys = &.{ key_a, key_b } },
        .{ .address = Address{ .bytes = @splat(0xbb) } },
    };
    var buffer: [256]u8 = undefined;
    const list = AccessList.build(&buffer, &items);
    try testing.expectEqual(@as(u32, 2), list.address_count);
    try testing.expectEqual(@as(u32, 2), list.storage_key_count);
    var encoded_buffer: [300]u8 = undefined;
    const encoded = rlp.encode_to(&encoded_buffer, list);
    const decoded = try rlp.decode_exact(AccessList, encoded);
    try testing.expectEqual(list.address_count, decoded.address_count);
    var iterator = decoded.iterator();
    const first = iterator.next().?;
    try testing.expect(first.address.eql(items[0].address));
    try testing.expect(first.storage_keys.get(1).eql(key_b));
    try testing.expectEqual(@as(usize, 0), iterator.next().?.storage_keys.count());
    try testing.expect(iterator.next() == null);
    // An entry with a 19-byte address is rejected.
    var bad: [22]u8 = @splat(0);
    bad[0] = 0xd5;
    bad[1] = 0x93;
    bad[21] = 0xc0;
    try testing.expectError(error.Overflow, AccessList.from_payload(&bad));
}

test "tx fields: authorization list" {
    const authorization: Authorization = .{
        .chain_id = 1,
        .address = Address{ .bytes = @splat(0xcc) },
        .nonce = 7,
        .y_parity = 1,
        .r = 5,
        .s = 6,
    };
    var buffer: [128]u8 = undefined;
    const list = AuthorizationList.build(&buffer, &.{ authorization, authorization });
    const again = try AuthorizationList.from_payload(list.payload);
    try testing.expectEqual(@as(u32, 2), again.count);
    var iterator = again.iterator();
    try testing.expectEqual(@as(u64, 7), iterator.next().?.nonce);
    try testing.expect(iterator.next() != null);
    try testing.expect(iterator.next() == null);
}

test "tx fields: authority recovery" {
    const key = try primitives.hex.decode_array(
        32,
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    );
    var authorization: Authorization = .{
        .chain_id = 0,
        .address = Address{ .bytes = @splat(0xcc) },
        .nonce = 0,
        .y_parity = 0,
        .r = 0,
        .s = 0,
    };
    const signature = try signature_module.sign(key, authorization.signing_hash());
    authorization.y_parity = @intFromBool(signature.y_parity);
    authorization.r = signature.r;
    authorization.s = signature.s;
    const authority = authorization.recover_authority(signature_module.recover_address).?;
    try testing.expect(authority.eql(signature_module.address_from_private(key).?));
    authorization.y_parity = 2;
    try testing.expect(authorization.recover_authority(signature_module.recover_address) == null);
}
