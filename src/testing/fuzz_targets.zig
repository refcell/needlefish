//! Cross-lane fuzz targets owned by the dst-fuzz lane.
//!
//! Lanes keep fuzz tests next to their code; this file adds targets for public APIs
//! that the audit found uncovered, checking properties that span modules:
//!   - transactions: any accepted encoding is canonical (re-encodes byte-identical),
//!     including the block-body (network) wrapping, and hashing never fails.
//!   - channels: frame reassembly matches a reference model; rejected frames leave the
//!     channel unchanged.
//!   - trie proofs: a proof tampered anywhere never verifies to a different value, and
//!     arbitrary proof bytes never crash the verifier.
//!   - bls12-381 points: decoding is canonical (accepted bytes == compress(point)).
//!   - rlp comptime codec: accepted input re-encodes byte-identically.

const std = @import("std");
const assert = std.debug.assert;
const Smith = std.testing.Smith;
const fuzz = @import("fuzz.zig");
const tx_module = @import("../common/consensus/tx.zig");
const rlp = @import("../common/rlp/root.zig");
const channel_module = @import("../consensus/protocol/channel.zig");
const frame_module = @import("../consensus/protocol/frame.zig");
const trie_module = @import("../execution/trie/trie.zig");
const proof_module = @import("../execution/trie/proof.zig");
const Signature = @import("../common/consensus/signature.zig").Signature;
const BlockInfo = @import("../consensus/protocol/block.zig").BlockInfo;

const Envelope = tx_module.Envelope;
const tx_bytes_max = 2048;

fn random_kind(smith: *Smith) tx_module.TxKind {
    if (smith.value(bool)) return .create;
    var to: tx_module.TxKind = .{ .call = undefined };
    smith.bytes(&to.call.bytes);
    return to;
}

/// A structurally valid envelope from fuzz input, so mutations start near valid inputs.
fn random_envelope(smith: *Smith, input: []const u8) Envelope {
    const signature: Signature = .{
        .y_parity = smith.value(bool),
        .r = smith.value(u256),
        .s = smith.value(u256),
    };
    return switch (smith.valueRangeAtMost(u8, 0, 2)) {
        0 => .{ .legacy = .{ .signature = signature, .tx = .{
            .chain_id = if (smith.value(bool)) smith.value(u64) >> 2 else null,
            .nonce = smith.value(u64),
            .gas_price = smith.value(u128),
            .gas_limit = smith.value(u64),
            .to = random_kind(smith),
            .value = smith.value(u256),
            .input = input,
        } } },
        1 => .{ .eip1559 = .{ .signature = signature, .tx = .{
            .chain_id = smith.value(u64),
            .nonce = smith.value(u64),
            .max_priority_fee_per_gas = smith.value(u128),
            .max_fee_per_gas = smith.value(u128),
            .gas_limit = smith.value(u64),
            .to = random_kind(smith),
            .value = smith.value(u256),
            .input = input,
            .access_list = .empty,
        } } },
        else => .{ .deposit = .{
            .source_hash = .{ .bytes = @splat(smith.value(u8)) },
            .from = .{ .bytes = @splat(smith.value(u8)) },
            .to = random_kind(smith),
            .mint = smith.value(u128),
            .value = smith.value(u256),
            .gas_limit = smith.value(u64),
            .is_system_transaction = smith.value(bool),
            .input = input,
        } },
    };
}

/// Accepted encodings must be canonical: decode then encode returns the same bytes.
fn check_tx_canonical(encoded: []const u8) !void {
    const envelope = Envelope.decode(encoded) catch return;
    try std.testing.expectEqual(encoded.len, envelope.encoded_length());
    var buffer: [tx_bytes_max * 2]u8 = undefined;
    try std.testing.expectEqualSlices(u8, encoded, envelope.encode_to(&buffer));
    _ = envelope.hash();
    try check_tx_lists(envelope);

    var network_buffer: [tx_bytes_max * 2]u8 = undefined;
    var encoder = rlp.Encoder.init(&network_buffer);
    envelope.encode_network(&encoder);
    const network = encoder.written();
    try std.testing.expectEqual(envelope.network_length(), network.len);
    var decoder = rlp.Decoder.init(network);
    const again = try Envelope.decode_network(&decoder);
    try std.testing.expect(decoder.is_empty());
    try std.testing.expectEqualSlices(u8, encoded, again.encode_to(&buffer));
}

/// Iterators trust validation done at decode time (`catch unreachable`): walk them all.
fn check_tx_lists(envelope: Envelope) !void {
    const access_list: tx_module.AccessList = switch (envelope) {
        // EIP-8130 nested lists are walked by `consensus/eip8130_test.zig` fuzzing.
        .legacy, .deposit, .eip8130 => return,
        inline else => |signed| signed.tx.access_list,
    };
    var addresses: u32 = 0;
    var keys: u64 = 0;
    var iterator = access_list.iterator();
    while (iterator.next()) |item| : (addresses += 1) keys += item.storage_keys.count();
    try std.testing.expectEqual(access_list.address_count, addresses);
    try std.testing.expectEqual(@as(u64, access_list.storage_key_count), keys);
    if (envelope != .eip7702) return;
    const authorizations = envelope.eip7702.tx.authorization_list;
    var count: u32 = 0;
    var authorization_iterator = authorizations.iterator();
    while (authorization_iterator.next()) |_| count += 1;
    try std.testing.expectEqual(authorizations.count, count);
}

/// Minimal big-endian RLP integer.
fn write_int(writer: *rlp.TreeWriter, value: u256) void {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, value, .big);
    const leading = @clz(value) / 8;
    writer.bytes(bytes[leading..]);
}

fn write_random_bytes(writer: *rlp.TreeWriter, smith: *Smith, comptime len: usize) void {
    var bytes: [len]u8 = undefined;
    smith.bytes(&bytes);
    writer.bytes(&bytes);
}

fn write_access_list(writer: *rlp.TreeWriter, smith: *Smith) void {
    writer.begin_list();
    var entries: u32 = 0;
    while (entries < 4 and !smith.eosWeightedSimple(1, 1)) : (entries += 1) {
        writer.begin_list();
        write_random_bytes(writer, smith, 20);
        writer.begin_list();
        var keys: u32 = 0;
        while (keys < 4 and !smith.eosWeightedSimple(1, 1)) : (keys += 1) {
            write_random_bytes(writer, smith, 32);
        }
        writer.end_list();
        writer.end_list();
    }
    writer.end_list();
}

fn write_authorizations(writer: *rlp.TreeWriter, smith: *Smith) void {
    writer.begin_list();
    var count: u32 = 0;
    while (count < 3 and !smith.eosWeightedSimple(1, 1)) : (count += 1) {
        writer.begin_list();
        write_int(writer, smith.value(u256));
        write_random_bytes(writer, smith, 20);
        write_int(writer, smith.value(u64));
        write_int(writer, smith.valueRangeAtMost(u8, 0, 1));
        write_int(writer, smith.value(u256));
        write_int(writer, smith.value(u256));
        writer.end_list();
    }
    writer.end_list();
}

/// EIP-2930 / 4844 / 7702 encodings with non-empty lists, built field by field.
fn random_typed_encoding(smith: *Smith, buffer: []u8) []u8 {
    const tx_type = smith.valueRangeAtMost(u8, 1, 4);
    const kind: TypedKind = switch (tx_type) {
        1 => .eip2930,
        3 => .eip4844,
        4 => .eip7702,
        else => .eip1559,
    };
    buffer[0] = tx_type;
    var writer: rlp.TreeWriter = .{ .buffer = buffer[1..] };
    writer.begin_list();
    write_int(&writer, smith.value(u64)); // chain_id
    write_int(&writer, smith.value(u64)); // nonce
    write_int(&writer, smith.value(u128)); // gas_price or max_priority_fee
    if (kind != .eip2930) write_int(&writer, smith.value(u128)); // max_fee
    write_int(&writer, smith.value(u64)); // gas_limit
    write_random_bytes(&writer, smith, 20); // to
    write_int(&writer, smith.value(u256)); // value
    var input: [48]u8 = undefined;
    writer.bytes(input[0..smith.slice(&input)]);
    write_access_list(&writer, smith);
    if (kind == .eip4844) {
        write_int(&writer, smith.value(u128));
        writer.begin_list();
        var hashes: u32 = 0;
        while (hashes < 6 and !smith.eosWeightedSimple(1, 1)) : (hashes += 1) {
            write_random_bytes(&writer, smith, 32);
        }
        writer.end_list();
    }
    if (kind == .eip7702) write_authorizations(&writer, smith);
    write_int(&writer, smith.valueRangeAtMost(u8, 0, 1));
    write_int(&writer, smith.value(u256));
    write_int(&writer, smith.value(u256));
    writer.end_list();
    return buffer[0 .. 1 + writer.written().len];
}

const TypedKind = enum { eip2930, eip1559, eip4844, eip7702 };

fn fuzz_tx_typed(_: void, smith: *Smith) anyerror!void {
    var buffer: [tx_bytes_max]u8 = undefined;
    const encoded = random_typed_encoding(smith, &buffer);
    _ = try Envelope.decode(encoded); // Well-formed by construction.
    try check_tx_canonical(encoded);
    if (encoded.len < 2) return;
    encoded[smith.valueRangeAtMost(u32, 1, @intCast(encoded.len - 1))] = smith.value(u8);
    try check_tx_canonical(encoded);
}

test "fuzz_targets: typed tx with lists is canonical" {
    try fuzz.run({}, fuzz_tx_typed, .{ .iterations = 2048 });
}

fn fuzz_tx(_: void, smith: *Smith) anyerror!void {
    var buffer: [tx_bytes_max]u8 = undefined;
    if (smith.value(bool)) {
        const len = smith.slice(&buffer);
        return check_tx_canonical(buffer[0..len]);
    }
    var input_buffer: [64]u8 = undefined;
    const input = input_buffer[0..smith.slice(&input_buffer)];
    const envelope = random_envelope(smith, input);
    const encoded = envelope.encode_to(&buffer);
    // The unmodified encoding must decode: the encoder only emits canonical forms.
    _ = try Envelope.decode(encoded);
    try check_tx_canonical(encoded);
    var flips: u32 = 0;
    while (flips < 4 and !smith.eosWeightedSimple(1, 1)) : (flips += 1) {
        encoded[smith.index(encoded.len)] = smith.value(u8);
    }
    const cut = smith.valueRangeAtMost(u32, 0, @intCast(encoded.len));
    try check_tx_canonical(encoded[0..cut]);
    try check_tx_canonical(encoded);
}

test "fuzz_targets: tx decode is canonical" {
    try fuzz.run({}, fuzz_tx, .{ .iterations = 2048, .input_size_max = 1024 });
}

const frame_numbers = 16;
const frame_data_max = 24;

const ChannelModel = struct {
    data: [frame_numbers][frame_data_max]u8 = undefined,
    lengths: [frame_numbers]u8 = @splat(0),
};

fn fuzz_channel(_: void, smith: *Smith) anyerror!void {
    const allocator = std.testing.allocator;
    const id: frame_module.ChannelId = @splat(0x11);
    var channel = channel_module.Channel.init(id, .{});
    defer channel.deinit(allocator);
    var model: ChannelModel = .{};
    var step: u32 = 0;
    while (step < 64 and !smith.eosWeightedSimple(15, 1)) : (step += 1) {
        var data: [frame_data_max]u8 = undefined;
        const len = smith.slice(&data);
        const frame: frame_module.Frame = .{
            .id = if (smith.boolWeighted(15, 1)) @splat(0x22) else id,
            .number = smith.valueRangeLessThan(u16, 0, frame_numbers),
            .data = data[0..len],
            .is_last = smith.boolWeighted(5, 1),
        };
        const count_before = channel.frame_count();
        const size_before = channel.estimated_size;
        const l1_block: BlockInfo = .{ .number = smith.value(u8) };
        if (channel.add_frame(allocator, frame, l1_block)) {
            try std.testing.expect(channel.inputs.contains(frame.number));
            @memcpy(model.data[frame.number][0..len], frame.data);
            model.lengths[frame.number] = @intCast(len);
        } else |err| {
            try std.testing.expect(err != error.OutOfMemory);
            try std.testing.expectEqual(count_before, channel.frame_count());
            try std.testing.expectEqual(size_before, channel.estimated_size);
        }
        try check_channel(&channel, &model);
    }
}

fn check_channel(channel: *const channel_module.Channel, model: *const ChannelModel) !void {
    var size: u64 = 0;
    var contiguous = true;
    var number: u16 = 0;
    while (number < frame_numbers) : (number += 1) {
        const present = channel.inputs.contains(number);
        if (present) size += model.lengths[number] + frame_module.Frame.size_overhead;
        if (channel.closed and number <= channel.last_frame_number and !present) {
            contiguous = false;
        }
        if (channel.closed and number > channel.last_frame_number) {
            try std.testing.expect(!present); // Frames past the end are pruned.
        }
    }
    try std.testing.expectEqual(size, channel.estimated_size);
    try std.testing.expectEqual(channel.closed and contiguous, channel.is_ready());
    if (!channel.is_ready()) return;
    var out: [frame_numbers * frame_data_max]u8 = undefined;
    const joined = channel.frame_data(&out);
    var offset: usize = 0;
    number = 0;
    while (number <= channel.last_frame_number) : (number += 1) {
        const expected = model.data[number][0..model.lengths[number]];
        try std.testing.expectEqualSlices(u8, expected, joined[offset..][0..expected.len]);
        offset += expected.len;
    }
    try std.testing.expectEqual(offset, joined.len);
}

test "fuzz_targets: channel reassembly matches model" {
    try fuzz.run({}, fuzz_channel, .{ .iterations = 1024 });
}

const Trie = trie_module.TrieType(.{ .key_bytes_max = 32, .value_size_max = 32 });

const TrieContext = struct { trie: *Trie, proof: *Trie.Proof };

fn fuzz_proof(context: TrieContext, smith: *Smith) anyerror!void {
    const trie = context.trie;
    trie.clear();
    var key: [3]u8 = undefined;
    var count: u32 = 0;
    while (count < 48 and !smith.eosWeightedSimple(7, 1)) : (count += 1) {
        // Small alphabet: shared prefixes create extensions and branches.
        key = .{ smith.value(u8) & 0x33, smith.value(u8) & 0x1f, smith.value(u8) };
        var value: [32]u8 = undefined;
        const len = @max(1, smith.slice(&value));
        try trie.put(&key, value[0..len]);
    }
    if (smith.value(bool)) key[2] ^= 0x80; // Probe an exclusion proof sometimes.
    const root = trie.root_hash();
    trie.prove(&key, context.proof);
    var nodes: [Trie.depth_max][]u8 = undefined;
    const proof = context.proof;
    for (0..proof.count) |index| {
        nodes[index] = @constCast(proof.node_at(@intCast(index)));
    }
    const view: []const []const u8 = nodes[0..proof.count];
    const expected = try proof_module.verify(root, &key, view);
    if (trie.get(&key)) |value| {
        try std.testing.expectEqualSlices(u8, value, expected.?);
    } else try std.testing.expect(expected == null);
    if (proof.count == 0) return;
    // Tamper with one byte: verification must fail or return the honest answer.
    const node_index = smith.index(proof.count);
    const node = nodes[node_index];
    const byte_index = smith.index(node.len);
    const original = node[byte_index];
    node[byte_index] = original ^ (smith.value(u8) | 1);
    defer node[byte_index] = original;
    const tampered = proof_module.verify(root, &key, view) catch return;
    try std.testing.expect(tampered == null and expected == null or
        (tampered != null and expected != null and std.mem.eql(u8, tampered.?, expected.?)));
}

fn fuzz_proof_garbage(_: void, smith: *Smith) anyerror!void {
    var storage: [4][128]u8 = undefined;
    var nodes: [4][]const u8 = undefined;
    const count = smith.valueRangeAtMost(u32, 0, nodes.len);
    for (nodes[0..count], storage[0..count]) |*node, *bytes| node.* = bytes[0..smith.slice(bytes)];
    var root: [32]u8 = undefined;
    // Root of the first node half the time, so the verifier gets past the hash check.
    if (count > 0 and smith.value(bool)) {
        std.crypto.hash.sha3.Keccak256.hash(nodes[0], &root, .{});
    } else smith.bytes(&root);
    var key: [33]u8 = undefined;
    const key_len = smith.slice(&key);
    _ = proof_module.verify(root, key[0..key_len], nodes[0..count]) catch {};
}

test "fuzz_targets: tampered trie proofs never lie" {
    const allocator = std.testing.allocator;
    var trie = try Trie.init(allocator, 1024);
    defer trie.deinit(allocator);
    const proof = try allocator.create(Trie.Proof);
    defer allocator.destroy(proof);
    try fuzz.run(TrieContext{ .trie = &trie, .proof = proof }, fuzz_proof, .{ .iterations = 512 });
}

test "fuzz_targets: trie proof verifier survives garbage" {
    try fuzz.run({}, fuzz_proof_garbage, .{ .iterations = 2048 });
}

const g1 = @import("../common/crypto/bls12_381/g1.zig");
const g2 = @import("../common/crypto/bls12_381/g2.zig");

/// Point decoding must be canonical: every accepted encoding is the one `compress`
/// emits, so two byte strings never name the same commitment (KZG, precompiles).
fn check_point_encoding(comptime group: type, bytes: *const [group.compressed_length]u8) !void {
    if (group.decompress_unchecked(bytes)) |point| {
        try std.testing.expect(point.is_on_curve());
        try std.testing.expectEqualSlices(u8, bytes, &group.compress(point));
    } else |_| {}
    if (group.decompress(bytes)) |point| {
        try std.testing.expect(group.is_in_subgroup(point));
    } else |_| {}
}

fn fuzz_bls_points(comptime group: type) fn (void, *Smith) anyerror!void {
    return struct {
        fn run(_: void, smith: *Smith) anyerror!void {
            var bytes: [group.compressed_length]u8 = undefined;
            if (smith.value(bool)) {
                smith.bytes(&bytes);
                // Set the compression flag most of the time to get past the first check.
                if (smith.boolWeighted(1, 3)) bytes[0] |= 0x80;
                return check_point_encoding(group, &bytes);
            }
            const scalar = smith.value(u64);
            const point = group.generator.to_jacobian().mul(scalar).to_affine();
            bytes = group.compress(point);
            const decoded = try group.decompress(&bytes);
            try std.testing.expect(decoded.eql(point));
            bytes[smith.index(bytes.len)] ^= smith.value(u8) | 1;
            try check_point_encoding(group, &bytes);
        }
    }.run;
}

test "fuzz_targets: bls12-381 g1 point encoding is canonical" {
    try fuzz.run({}, fuzz_bls_points(g1), .{ .iterations = 64 });
}

test "fuzz_targets: bls12-381 g2 point encoding is canonical" {
    try fuzz.run({}, fuzz_bls_points(g2), .{ .iterations = 32 });
}

const codec = @import("../common/rlp/codec.zig");

/// Every type kind the comptime codec maps: ints of several widths, bool, fixed arrays,
/// borrowed byte strings, byte wrappers, and nested lists.
const RlpShape = struct {
    small: u8,
    nonce: u64,
    value: u256,
    flag: bool,
    tag: [4]u8,
    data: []const u8,
    inner: struct { word: struct { bytes: [20]u8 }, count: u16, note: []const u8 },
};

/// The codec is canonical: whatever it accepts re-encodes to the identical bytes, so a
/// decoded value can be hashed or re-broadcast without changing its identity.
fn check_rlp_canonical(input: []const u8) !void {
    const value = codec.decode_exact(RlpShape, input) catch return;
    var buffer: [512]u8 = undefined;
    try std.testing.expect(codec.length(value) == input.len);
    try std.testing.expectEqualSlices(u8, input, codec.encode_to(&buffer, value));
}

fn fuzz_rlp_codec(_: void, smith: *Smith) anyerror!void {
    var bytes: [256]u8 = undefined;
    var data: [64]u8 = undefined;
    var note: [64]u8 = undefined;
    const value: RlpShape = .{
        .small = smith.value(u8),
        .nonce = smith.value(u64),
        .value = smith.value(u256),
        .flag = smith.value(bool),
        .tag = smith.value([4]u8),
        .data = data[0..smith.slice(&data)],
        .inner = .{
            .word = .{ .bytes = smith.value([20]u8) },
            .count = smith.value(u16),
            .note = note[0..smith.slice(&note)],
        },
    };
    const encoded = codec.encode_to(&bytes, value);
    const decoded = try codec.decode_exact(RlpShape, encoded);
    try std.testing.expectEqual(value.value, decoded.value);
    try std.testing.expectEqualSlices(u8, value.data, decoded.data);
    try std.testing.expectEqualSlices(u8, value.inner.note, decoded.inner.note);
    try check_rlp_canonical(encoded);
    // Mutate the valid encoding: anything still accepted must stay canonical.
    var mutated: [256]u8 = undefined;
    @memcpy(mutated[0..encoded.len], encoded);
    var length: u32 = @intCast(encoded.len);
    if (smith.value(bool)) length = smith.valueRangeAtMost(u32, 0, length);
    if (length > 0) mutated[smith.index(length)] = smith.value(u8);
    try check_rlp_canonical(mutated[0..length]);
    // Raw bytes too: most are rejected, all accepted ones are canonical.
    try check_rlp_canonical(bytes[0..smith.slice(&bytes)]);
}

test "fuzz_targets: rlp comptime codec is canonical and round trips" {
    try fuzz.run({}, fuzz_rlp_codec, .{ .iterations = 512 });
}

// ------------------------------------------------------------------ tx fields

const tx_fields = @import("../common/consensus/tx_fields.zig");
const signature_module = @import("../common/consensus/signature.zig");
const primitives = @import("../common/primitives/root.zig");
const field_bytes_max = 1024;

/// Anything a field decoder accepts re-encodes byte-identically, and the list iterators
/// (which `catch unreachable` on structure decoding validated) walk exactly the counted
/// items.
fn check_field_canonical(comptime T: type, input: []const u8) !void {
    const value = rlp.decode_exact(T, input) catch return;
    var buffer: [field_bytes_max + 16]u8 = undefined;
    try std.testing.expectEqualSlices(u8, input, rlp.encode_to(&buffer, value));
    if (T == tx_fields.AccessList) {
        var iterator = value.iterator();
        var addresses: u32 = 0;
        var keys: u32 = 0;
        while (iterator.next()) |item| : (addresses += 1) {
            for (0..item.storage_keys.count()) |index| _ = item.storage_keys.get(index);
            keys += @intCast(item.storage_keys.count());
        }
        try std.testing.expectEqual(value.address_count, addresses);
        try std.testing.expectEqual(value.storage_key_count, keys);
    } else if (T == tx_fields.AuthorizationList) {
        var iterator = value.iterator();
        var count: u32 = 0;
        while (iterator.next()) |_| count += 1;
        try std.testing.expectEqual(value.count, count);
    } else if (T == tx_fields.HashList) {
        for (0..value.count()) |index| _ = value.get(index);
    }
}

/// A small selector or count. Smith maps an out-of-range word to the range minimum, so
/// narrow ranges come out almost always 0; a reduced `u8` spreads evenly instead.
fn draw_below(smith: *Smith, comptime n: u8) u8 {
    comptime assert(n > 0);
    return smith.value(u8) % n;
}

fn draw_hash(smith: *Smith) primitives.B256 {
    var hash: primitives.B256 = undefined;
    smith.bytes(&hash.bytes);
    return hash;
}

fn draw_address(smith: *Smith) primitives.Address {
    var address: primitives.Address = undefined;
    smith.bytes(&address.bytes);
    return address;
}

/// Encodes a valid field of kind `which` into `out`.
fn build_field(smith: *Smith, which: u8, out: []u8) []u8 {
    assert(out.len >= field_bytes_max);
    var payload: [field_bytes_max - 16]u8 = undefined;
    var keys: [3][3]primitives.B256 = undefined;
    for (&keys) |*row| for (row) |*key| {
        key.* = draw_hash(smith);
    };
    switch (which) {
        0 => {
            const kind: tx_fields.TxKind = if (smith.value(bool)) .create else .{
                .call = draw_address(smith),
            };
            return rlp.encode_to(out, kind);
        },
        1 => {
            const count = draw_below(smith, 4);
            return rlp.encode_to(out, tx_fields.HashList.build(&payload, keys[0][0..count]));
        },
        2 => {
            var items: [3]tx_fields.AccessList.BuildItem = undefined;
            const count = draw_below(smith, 4);
            for (items[0..count], keys[0..count]) |*item, *row| item.* = .{
                .address = draw_address(smith),
                .storage_keys = row[0..draw_below(smith, 4)],
            };
            return rlp.encode_to(out, tx_fields.AccessList.build(&payload, items[0..count]));
        },
        else => {
            var items: [2]tx_fields.Authorization = undefined;
            const count = draw_below(smith, 3);
            for (items[0..count]) |*item| item.* = .{
                .chain_id = smith.value(u64),
                .address = draw_address(smith),
                .nonce = smith.value(u64),
                .y_parity = draw_below(smith, 2),
                .r = smith.value(u256),
                .s = smith.value(u256),
            };
            const list = tx_fields.AuthorizationList.build(&payload, items[0..count]);
            return rlp.encode_to(out, list);
        },
    }
}

fn fuzz_tx_fields(_: void, smith: *Smith) anyerror!void {
    var buffer: [field_bytes_max]u8 = undefined;
    const which = draw_below(smith, 4);
    const input: []u8 = if (smith.boolWeighted(3, 1))
        build_field(smith, which, &buffer)
    else
        buffer[0..smith.slice(&buffer)];
    if (input.len > 0 and smith.boolWeighted(1, 1)) {
        input[smith.index(input.len)] = smith.value(u8);
    }
    switch (which) {
        0 => try check_field_canonical(tx_fields.TxKind, input),
        1 => try check_field_canonical(tx_fields.HashList, input),
        2 => try check_field_canonical(tx_fields.AccessList, input),
        else => try check_field_canonical(tx_fields.AuthorizationList, input),
    }
}

test "fuzz_targets: tx field decoders are canonical and iterate what they count" {
    try fuzz.run({}, fuzz_tx_fields, .{ .iterations = 2048 });
}

/// `decode_legacy_v` inverts `legacy_v` and rejects everything that is not of its form.
fn fuzz_legacy_v(_: void, smith: *Smith) anyerror!void {
    const parity = smith.value(bool);
    const chain_id: ?u64 = if (smith.value(bool)) smith.value(u64) else null;
    const signature: Signature = .{ .y_parity = parity, .r = 1, .s = 1 };
    const v = signature.legacy_v(chain_id);
    const decoded = signature_module.decode_legacy_v(v).?;
    try std.testing.expectEqual(parity, decoded.y_parity);
    try std.testing.expectEqual(chain_id, decoded.chain_id);

    const near_v: u256 = smith.value(u8);
    const raw: u256 = if (smith.value(bool)) near_v else smith.value(u256);
    if (signature_module.decode_legacy_v(raw)) |any| {
        const again: Signature = .{ .y_parity = any.y_parity, .r = 1, .s = 1 };
        try std.testing.expectEqual(raw, again.legacy_v(any.chain_id));
    } else {
        const max_v = @as(u256, std.math.maxInt(u64)) * 2 + 36;
        try std.testing.expect(raw < 27 or (raw > 28 and raw < 35) or raw > max_v);
    }
}

test "fuzz_targets: legacy v decoding inverts encoding" {
    try fuzz.run({}, fuzz_legacy_v, .{ .iterations = 2048 });
}
