//! Solidity-aligned types for the `INitroEnclaveVerifier` interface (base/base
//! `types.rs`), with ABI encoding identical to alloy's `SolValue::abi_encode`, which
//! is Solidity's `abi.encode(value)`: a dynamic struct is preceded by its offset.
//!
//! The journal borrows `user_data`, `nonce`, `public_key`, and `module_id` from the
//! attestation document bytes; it is valid only while those bytes live.

const std = @import("std");
const assert = std.debug.assert;

/// Maximum CA bundle size accepted by base/base content validation.
pub const cabundle_count_max: u32 = 32;
/// CA bundle plus the leaf certificate.
pub const chain_length_max: u32 = cabundle_count_max + 1;
/// Maximum PCR entries accepted by base/base content validation.
pub const pcr_count_max: u32 = 32;
pub const pcr_size_bytes: u32 = 48;

/// Ordering must match `INitroEnclaveVerifier.sol`; `unknown` is the fail-closed zero.
pub const VerificationResult = enum(u8) {
    unknown = 0,
    success = 1,
    root_cert_not_trusted = 2,
    intermediate_certs_not_trusted = 3,
    invalid_timestamp = 4,
};

/// Ordering must match `INitroEnclaveVerifier.sol`.
pub const ZkCoProcessorType = enum(u8) {
    unknown = 0,
    risc_zero = 1,
    succinct = 2,
};

/// Platform Configuration Register. Solidity splits the 48-byte value into a
/// `bytes32 first` and `bytes16 second` (`Bytes48`); the encoding does the split.
pub const Pcr = struct {
    index: u64,
    value: [pcr_size_bytes]u8,
};

pub const VerifierInput = struct {
    trusted_certs_prefix_len: u8,
    attestation_report: []const u8,

    pub fn encoded_size(input: *const VerifierInput) u64 {
        const size = 4 * word_bytes + padded_size(input.attestation_report.len);
        assert(size % word_bytes == 0);
        return size;
    }

    /// `abi.encode(VerifierInput)`.
    pub fn encode(input: *const VerifierInput, out: []u8) EncodeError![]u8 {
        const size = input.encoded_size();
        if (out.len < size) return error.NoSpaceLeft;
        var writer: AbiWriter = .{ .buffer = out[0..@intCast(size)] };
        writer.uint(word_bytes);
        writer.uint(input.trusted_certs_prefix_len);
        writer.uint(2 * word_bytes);
        writer.dynamic_bytes(input.attestation_report);
        assert(writer.position == size);
        return writer.buffer;
    }
};

pub const VerifierJournal = struct {
    result: VerificationResult,
    trusted_certs_prefix_len: u8,
    /// Attestation timestamp, Unix milliseconds.
    timestamp_ms: u64,
    /// Accumulated path digests, root to leaf (`certs`).
    certs: [chain_length_max][32]u8,
    /// Certificate `notAfter`, Unix seconds, parallel to `certs` (`certExpiries`).
    cert_expiries: [chain_length_max]u64,
    cert_count: u8,
    user_data: []const u8,
    nonce: []const u8,
    public_key: []const u8,
    /// Sorted by ascending index.
    pcrs: [pcr_count_max]Pcr,
    pcr_count: u8,
    module_id: []const u8,

    const head_words: u64 = 10;
    const pcr_words: u64 = 3;

    pub fn encoded_size(journal: *const VerifierJournal) u64 {
        assert(journal.cert_count <= chain_length_max);
        assert(journal.pcr_count <= pcr_count_max);
        var size: u64 = word_bytes + head_words * word_bytes;
        size += word_bytes + @as(u64, journal.cert_count) * word_bytes;
        size += word_bytes + @as(u64, journal.cert_count) * word_bytes;
        size += word_bytes + padded_size(journal.user_data.len);
        size += word_bytes + padded_size(journal.nonce.len);
        size += word_bytes + padded_size(journal.public_key.len);
        size += word_bytes + @as(u64, journal.pcr_count) * pcr_words * word_bytes;
        size += word_bytes + padded_size(journal.module_id.len);
        return size;
    }

    /// `abi.encode(VerifierJournal)`; returns the written prefix of `out`.
    pub fn encode(journal: *const VerifierJournal, out: []u8) EncodeError![]u8 {
        const size = journal.encoded_size();
        if (out.len < size) return error.NoSpaceLeft;
        var writer: AbiWriter = .{ .buffer = out[0..@intCast(size)] };
        writer.uint(word_bytes);
        journal.encode_head(&writer);
        journal.encode_tail(&writer);
        assert(writer.position == size);
        return writer.buffer;
    }

    /// Static fields inline, dynamic fields as offsets from the tuple start.
    fn encode_head(journal: *const VerifierJournal, writer: *AbiWriter) void {
        const certs_count: u64 = journal.cert_count;
        writer.uint(@backingInt(journal.result));
        writer.uint(journal.trusted_certs_prefix_len);
        writer.uint(journal.timestamp_ms);
        var offset: u64 = head_words * word_bytes;
        writer.uint(offset); // certs
        offset += word_bytes + certs_count * word_bytes;
        writer.uint(offset); // certExpiries
        offset += word_bytes + certs_count * word_bytes;
        writer.uint(offset); // userData
        offset += word_bytes + padded_size(journal.user_data.len);
        writer.uint(offset); // nonce
        offset += word_bytes + padded_size(journal.nonce.len);
        writer.uint(offset); // publicKey
        offset += word_bytes + padded_size(journal.public_key.len);
        writer.uint(offset); // pcrs
        offset += word_bytes + @as(u64, journal.pcr_count) * pcr_words * word_bytes;
        writer.uint(offset); // moduleId
        assert(writer.position == word_bytes + head_words * word_bytes);
    }

    fn encode_tail(journal: *const VerifierJournal, writer: *AbiWriter) void {
        const position_start = writer.position;
        writer.uint(journal.cert_count);
        for (journal.certs[0..journal.cert_count]) |*digest| writer.raw_word(digest);
        writer.uint(journal.cert_count);
        for (journal.cert_expiries[0..journal.cert_count]) |expiry| writer.uint(expiry);
        writer.dynamic_bytes(journal.user_data);
        writer.dynamic_bytes(journal.nonce);
        writer.dynamic_bytes(journal.public_key);
        writer.uint(journal.pcr_count);
        for (journal.pcrs[0..journal.pcr_count]) |*pcr| {
            writer.uint(pcr.index);
            writer.raw_word(pcr.value[0..32]);
            writer.padded(pcr.value[32..48]);
        }
        writer.dynamic_bytes(journal.module_id);
        assert(writer.position > position_start);
    }
};

pub const EncodeError = error{NoSpaceLeft};

const word_bytes: u64 = 32;

fn padded_size(length: usize) u64 {
    const size = std.mem.alignForward(u64, length, word_bytes);
    assert(size >= length and size - length < word_bytes);
    return size;
}

/// Writer over a buffer pre-sized by `encoded_size`; overruns are programmer errors.
const AbiWriter = struct {
    buffer: []u8,
    position: u64 = 0,

    fn uint(writer: *AbiWriter, value: u64) void {
        assert(writer.position + word_bytes <= writer.buffer.len);
        const word = writer.buffer[@intCast(writer.position)..][0..32];
        @memset(word[0..24], 0);
        std.mem.writeInt(u64, word[24..32], value, .big);
        writer.position += word_bytes;
    }

    fn raw_word(writer: *AbiWriter, word: *const [32]u8) void {
        assert(writer.position + word_bytes <= writer.buffer.len);
        @memcpy(writer.buffer[@intCast(writer.position)..][0..32], word);
        writer.position += word_bytes;
    }

    /// Left-aligned bytes, zero padded to a word boundary.
    fn padded(writer: *AbiWriter, bytes: []const u8) void {
        const size = padded_size(bytes.len);
        assert(writer.position + size <= writer.buffer.len);
        const target = writer.buffer[@intCast(writer.position)..][0..@intCast(size)];
        @memcpy(target[0..bytes.len], bytes);
        @memset(target[bytes.len..], 0);
        writer.position += size;
    }

    fn dynamic_bytes(writer: *AbiWriter, bytes: []const u8) void {
        writer.uint(bytes.len);
        writer.padded(bytes);
    }
};

const testing = std.testing;

// Golden vectors from `cast abi-encode` (Foundry) of the same values.
const journal_golden_hex =
    "0000000000000000000000000000000000000000000000000000000000000020" ++
    "0000000000000000000000000000000000000000000000000000000000000001" ++
    "0000000000000000000000000000000000000000000000000000000000000001" ++
    "000000000000000000000000000000000000000000000000000001937ac84543" ++
    "0000000000000000000000000000000000000000000000000000000000000140" ++
    "0000000000000000000000000000000000000000000000000000000000000180" ++
    "00000000000000000000000000000000000000000000000000000000000001c0" ++
    "00000000000000000000000000000000000000000000000000000000000001e0" ++
    "0000000000000000000000000000000000000000000000000000000000000220" ++
    "0000000000000000000000000000000000000000000000000000000000000260" ++
    "0000000000000000000000000000000000000000000000000000000000000340" ++
    "0000000000000000000000000000000000000000000000000000000000000001" ++
    "1111111111111111111111111111111111111111111111111111111111111111" ++
    "0000000000000000000000000000000000000000000000000000000000000001" ++
    "0000000000000000000000000000000000000000000000000000000096258ff5" ++
    "0000000000000000000000000000000000000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000000000000002" ++
    "abcd000000000000000000000000000000000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000000000000002" ++
    "0401000000000000000000000000000000000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000000000000002" ++
    "0000000000000000000000000000000000000000000000000000000000000000" ++
    "0101010101010101010101010101010101010101010101010101010101010101" ++
    "0202020202020202020202020202020200000000000000000000000000000000" ++
    "0000000000000000000000000000000000000000000000000000000000000003" ++
    "0101010101010101010101010101010101010101010101010101010101010101" ++
    "0202020202020202020202020202020200000000000000000000000000000000" ++
    "000000000000000000000000000000000000000000000000000000000000000b" ++
    "746573742d6d6f64756c65000000000000000000000000000000000000000000";

const input_golden_hex =
    "0000000000000000000000000000000000000000000000000000000000000020" ++
    "0000000000000000000000000000000000000000000000000000000000000001" ++
    "0000000000000000000000000000000000000000000000000000000000000040" ++
    "0000000000000000000000000000000000000000000000000000000000000004" ++
    "deadbeef00000000000000000000000000000000000000000000000000000000";

fn golden(comptime hex: []const u8) ![hex.len / 2]u8 {
    var out: [hex.len / 2]u8 = undefined;
    const decoded = try std.fmt.hexToBytes(&out, hex);
    assert(decoded.len == out.len);
    return out;
}

test "nitro types: journal ABI encoding matches Solidity abi.encode" {
    var journal: VerifierJournal = .{
        .result = .success,
        .trusted_certs_prefix_len = 1,
        .timestamp_ms = 1732931765571,
        .certs = undefined,
        .cert_expiries = undefined,
        .cert_count = 1,
        .user_data = &.{},
        .nonce = &.{ 0xab, 0xcd },
        .public_key = &.{ 0x04, 0x01 },
        .pcrs = undefined,
        .pcr_count = 2,
        .module_id = "test-module",
    };
    journal.certs[0] = @splat(0x11);
    journal.cert_expiries[0] = 2519044085;
    var value: [pcr_size_bytes]u8 = @splat(0x01);
    @memset(value[32..], 0x02);
    journal.pcrs[0] = .{ .index = 0, .value = value };
    journal.pcrs[1] = .{ .index = 3, .value = value };
    const expected = try golden(journal_golden_hex);
    var buffer: [2048]u8 = undefined;
    const encoded = try journal.encode(&buffer);
    try testing.expectEqual(expected.len, encoded.len);
    try testing.expectEqualSlices(u8, &expected, encoded);
    try testing.expectError(error.NoSpaceLeft, journal.encode(buffer[0 .. expected.len - 1]));
}

test "nitro types: verifier input ABI encoding matches Solidity abi.encode" {
    const input: VerifierInput = .{
        .trusted_certs_prefix_len = 1,
        .attestation_report = &.{ 0xde, 0xad, 0xbe, 0xef },
    };
    const expected = try golden(input_golden_hex);
    var buffer: [256]u8 = undefined;
    try testing.expectEqualSlices(u8, &expected, try input.encode(&buffer));
}

test "nitro types: enum ordering matches INitroEnclaveVerifier.sol" {
    try testing.expectEqual(@as(u8, 0), @backingInt(VerificationResult.unknown));
    try testing.expectEqual(@as(u8, 1), @backingInt(VerificationResult.success));
    try testing.expectEqual(@as(u8, 4), @backingInt(VerificationResult.invalid_timestamp));
    try testing.expectEqual(@as(u8, 2), @backingInt(ZkCoProcessorType.succinct));
}
