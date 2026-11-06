//! Gossip block archive: an append-only record of accepted unsafe blocks, stored as they
//! were gossiped (the snappy-compressed signed envelope). Blocks received live can then be
//! executed later, in order, once local state catches up to them (docs/UNSAFE_TIP.md).
//! This is a pure codec. The binary owns the file, and a reader trusts nothing it reads:
//! `verify` re-checks the signer and block hash of every record.
//!
//! Record layout (little endian), back to back:
//!
//!   data_length u32 | version u8 (1..4) | received_ms u64 | crc32(data) u32 | data
//!
//! A crash can leave a torn final record. `Reader.next` reports it as `error.Truncated`,
//! so the caller can cut the file back to `Reader.position` before appending again.

const std = @import("std");
const assert = std.debug.assert;
const block = @import("block.zig");
const validity = @import("validity.zig");
const snappy = @import("snappy.zig");
const primitives = @import("../../../common/primitives/root.zig");
const rollup_config = @import("../../protocol/rollup_config.zig");

pub const header_length = 17;
/// Largest record body: the compressed form of the largest gossip message.
pub const data_length_max: u32 = @intCast(snappy.max_compressed_length(snappy.gossip_size_max));

pub const Record = struct {
    version: block.Version,
    received_ms: u64,
    data: []const u8,
};

pub fn encode_header(output: *[header_length]u8, record: Record) void {
    assert(record.data.len > 0 and record.data.len <= data_length_max);
    std.mem.writeInt(u32, output[0..4], @intCast(record.data.len), .little);
    output[4] = @backingInt(record.version);
    std.mem.writeInt(u64, output[5..13], record.received_ms, .little);
    std.mem.writeInt(u32, output[13..17], std.hash.Crc32.hash(record.data), .little);
    assert(output[4] >= 1 and output[4] <= 4);
}

pub const Error = error{
    /// The bytes end inside a record (a torn final write).
    Truncated,
    /// A header field is out of range or the checksum does not match.
    Corrupt,
};

pub const Reader = struct {
    bytes: []const u8,
    /// End of the last complete, valid record.
    position: usize = 0,

    /// The next record, null at a clean end. `data` borrows `bytes`.
    pub fn next(reader: *Reader) Error!?Record {
        assert(reader.position <= reader.bytes.len);
        const rest = reader.bytes[reader.position..];
        if (rest.len == 0) return null;
        if (rest.len < header_length) return error.Truncated;
        const length = std.mem.readInt(u32, rest[0..4], .little);
        if (length == 0 or length > data_length_max) return error.Corrupt;
        const version: block.Version = switch (rest[4]) {
            1 => .v1,
            2 => .v2,
            3 => .v3,
            4 => .v4,
            else => return error.Corrupt,
        };
        if (rest.len - header_length < length) return error.Truncated;
        const data = rest[header_length..][0..length];
        const crc = std.mem.readInt(u32, rest[13..17], .little);
        if (crc != std.hash.Crc32.hash(data)) return error.Corrupt;
        reader.position += header_length + length;
        assert(reader.position <= reader.bytes.len);
        return .{
            .version = version,
            .received_ms = std.mem.readInt(u64, rest[5..13], .little),
            .data = data,
        };
    }
};

/// Gossip validation without the clock and the seen table: decode, signer, block hash,
/// version fields, and the Denim schedule. The envelope borrows `scratch`.
pub fn verify(
    config: *const rollup_config.RollupConfig,
    signer: primitives.Address,
    record: Record,
    scratch: []u8,
) (block.DecodeError || validity.Error)!block.Envelope {
    const envelope = try block.decode(record.version, record.data, scratch);
    const recovered = block.recover_signer(&envelope, config.l2_chain_id) orelse
        return error.Signature;
    if (!recovered.eql(signer)) return error.Signer;
    const payload = &envelope.payload;
    const computed = try validity.block_hash(config, payload, envelope.parent_beacon_block_root);
    if (!computed.eql(payload.block_hash)) return error.BlockHash;
    try validity.check_version_fields(config, &envelope);
    try validity.check_base_time(config, payload);
    assert(envelope.version == record.version);
    return envelope;
}

const testing = std.testing;
const Prng = @import("../../../testing/prng.zig").Prng;
const fuzz = @import("../../../testing/fuzz.zig");
const ssz = @import("ssz_payload.zig");

fn append(output: []u8, position: *usize, record: Record) void {
    encode_header(output[position.*..][0..header_length], record);
    @memcpy(output[position.* + header_length ..][0..record.data.len], record.data);
    position.* += header_length + record.data.len;
}

test "archive: records round trip and a torn tail is reported" {
    var prng = Prng.init(5);
    var file: [4096]u8 = undefined;
    var datas: [6][64]u8 = undefined;
    var lengths: [6]usize = undefined;
    var position: usize = 0;
    for (&datas, &lengths, 0..) |*data, *length, index| {
        length.* = @intCast(prng.range(1, data.len));
        prng.fill(data[0..length.*]);
        const version: block.Version = @fromBackingInt(@intCast(1 + index % 4));
        const bytes = data[0..length.*];
        append(&file, &position, .{ .version = version, .received_ms = index, .data = bytes });
    }
    var reader: Reader = .{ .bytes = file[0..position] };
    for (datas, lengths, 0..) |data, length, index| {
        const record = (try reader.next()).?;
        try testing.expectEqual(@as(u64, index), record.received_ms);
        try testing.expectEqual(@as(u8, @intCast(1 + index % 4)), @backingInt(record.version));
        try testing.expectEqualSlices(u8, data[0..length], record.data);
    }
    try testing.expectEqual(@as(?Record, null), try reader.next());
    // Every cut inside the last record is torn, and the reader keeps the good prefix.
    const last_start = position - header_length - lengths[5];
    var cut = last_start + 1;
    while (cut < position) : (cut += 1) {
        var torn: Reader = .{ .bytes = file[0..cut] };
        var count: u32 = 0;
        while (torn.next() catch |err| {
            try testing.expectEqual(error.Truncated, err);
            break;
        }) |_| count += 1;
        try testing.expectEqual(@as(u32, 5), count);
        try testing.expectEqual(last_start, torn.position);
    }
    // A flipped data byte fails the checksum; a bad version is corrupt too.
    file[last_start + header_length] ^= 1;
    var flipped: Reader = .{ .bytes = file[0..position], .position = last_start };
    try testing.expectError(error.Corrupt, flipped.next());
    file[last_start + header_length] ^= 1;
    file[last_start + 4] = 5;
    var versioned: Reader = .{ .bytes = file[0..position], .position = last_start };
    try testing.expectError(error.Corrupt, versioned.next());
}

test "archive: verify checks the signer before anything else" {
    var prng = Prng.init(8);
    var storage: [8192]u8 = undefined;
    const payload = ssz.random_payload(&prng, .v2, &storage);
    var secret: [32]u8 = @splat(0);
    secret[31] = 7;
    var scratch: [16384]u8 = undefined;
    var compressed: [snappy.max_compressed_length(16384)]u8 = undefined;
    var compressor: snappy.Compressor = .{};
    const out = &compressed;
    const data = try block.encode_signed(8453, secret, null, payload, &scratch, &compressor, out);
    const config: rollup_config.RollupConfig = .{ .l2_chain_id = 8453 };
    const record: Record = .{ .version = .v2, .received_ms = 0, .data = data };
    var decoded: [16384]u8 = undefined;
    const signer: primitives.Address = .{
        .bytes = try @import("../../../common/crypto/secp256k1/root.zig").address(secret),
    };
    try testing.expectError(error.Signer, verify(&config, .zero, record, &decoded));
    // The right signer gets past the signature; the random payload's hash is wrong.
    if (verify(&config, signer, record, &decoded)) |_| {} else |err| {
        try testing.expect(err != error.Signer and err != error.Signature);
    }
    const wrong_chain: rollup_config.RollupConfig = .{ .l2_chain_id = 1 };
    try testing.expectError(error.Signer, verify(&wrong_chain, signer, record, &decoded));
}

fn fuzz_reader(_: void, input: []const u8) anyerror!void {
    var reader: Reader = .{ .bytes = input };
    var records: u32 = 0;
    while (reader.next() catch return) |record| : (records += 1) {
        assert(record.data.len > 0);
        assert(records < input.len);
    }
    try testing.expectEqual(input.len, reader.position);
}

test "archive: fuzz reader" {
    try fuzz.run_bytes({}, fuzz_reader, .{});
}
