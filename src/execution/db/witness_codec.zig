//! Canonical binary codec for execution witnesses (`witness.Witness`), and the preimage view a
//! fault-proof oracle needs.
//!
//! Layout (every integer is a little-endian u32):
//!
//!     magic "NFWT" | version (1) | state | codes | keys | headers
//!     section = item_count | payload_bytes | item_count x (item_bytes | item)
//!
//! `payload_bytes` covers the items with their length prefixes, so a reader can skip a section.
//! Canonical form, the only form `decode` accepts:
//! - `state`, `codes`: strictly ascending by keccak256(item) (sorted, no duplicates),
//! - `keys`: 20-byte addresses or 32-byte slot keys, strictly ascending bytewise
//!   (`std.mem.order`: on a shared prefix the shorter key comes first),
//! - `headers`: valid RLP headers (`witness.header_number`), strictly ascending block number,
//! - no bytes after the headers section.
//! So the encoding is a bijection on accepted input: encode(decode(x)) == x.
//!
//! Preimages: every state node, code, and key is a keccak256 preimage. base/base
//! `crates/proof/preimage/src/key.rs` defines `PreimageKeyType::Keccak256 = 2`; a rendered
//! oracle key is the type byte followed by the low-order 31 bytes of the digest
//! (`PreimageKey::new_keccak256`, `From<PreimageKey> for [u8; 32]`). The host turns an
//! `ExecutionWitness` into preimages by hashing every item of `state`, `codes`, and `keys`
//! (`execution_witness_preimages` in `crates/proof/host/src/handler.rs`); `PreimageIterator`
//! yields the same set, and `preimage_key` renders the oracle key of a digest.

const std = @import("std");
const assert = std.debug.assert;

const trie = @import("../trie/root.zig");
const witness_module = @import("witness.zig");

const keccak256 = trie.node.keccak256;
const header_number = witness_module.header_number;

pub const Witness = witness_module.Witness;
pub const ByteList = witness_module.ByteList;
pub const Hash = [32]u8;

pub const magic = [4]u8{ 'N', 'F', 'W', 'T' };
pub const version: u32 = 1;
pub const sections_count = 4;
/// Magic and version.
pub const prefix_bytes = 8;
/// Item count and payload bytes.
pub const section_prefix_bytes = 8;
pub const item_prefix_bytes = 4;
/// base/base `PreimageKeyType::Keccak256`.
pub const keccak256_key_type: u8 = 2;

comptime {
    assert(magic.len + @sizeOf(u32) == prefix_bytes);
    assert(2 * @sizeOf(u32) == section_prefix_bytes);
    assert(@sizeOf(u32) == item_prefix_bytes);
}

pub const EncodeError = error{
    /// A key is neither 20 nor 32 bytes, a header does not decode, or two different headers
    /// share a block number.
    InvalidWitness,
    BufferTooSmall,
};

pub const DecodeError = error{
    BadMagic,
    UnsupportedVersion,
    /// A section header or payload runs past the end of the input.
    Truncated,
    /// The items do not exactly fill the section's `payload_bytes`.
    LengthMismatch,
    /// Out of canonical order, a duplicate, or a key of the wrong size.
    NonCanonical,
    InvalidHeader,
    TrailingBytes,
    /// More items or bytes than the output witness was configured for.
    WitnessFull,
};

const Kind = enum { hashed, key, header };

/// Encodes witnesses in canonical form. Owns the sort scratch, sized once from the witness
/// config, so encoding never allocates.
pub const Encoder = struct {
    state_order: []u32,
    state_hashes: []Hash,
    code_order: []u32,
    code_hashes: []Hash,
    key_order: []u32,
    header_order: []u32,
    header_numbers: []u64,
    /// Unique items per section after the last `prepare`.
    state_len: u32 = 0,
    codes_len: u32 = 0,
    keys_len: u32 = 0,
    headers_len: u32 = 0,

    pub fn init(allocator: std.mem.Allocator, config: Witness.Config) !Encoder {
        assert(config.state_nodes_max > 0 and config.codes_max > 0);
        assert(config.keys_max > 0 and config.headers_max > 0);
        // Every section and the whole encoding fit u32 lengths.
        const max_bytes: u64 = prefix_bytes + sections_count * section_prefix_bytes +
            item_prefix_bytes * (@as(u64, config.state_nodes_max) + config.codes_max +
                config.keys_max + config.headers_max) +
            config.state_bytes_max + config.code_bytes_max + @as(u64, config.keys_max) * 32 +
            config.header_bytes_max;
        assert(max_bytes <= std.math.maxInt(u32));
        var result: Encoder = undefined;
        result.state_order = try allocator.alloc(u32, config.state_nodes_max);
        errdefer allocator.free(result.state_order);
        result.state_hashes = try allocator.alloc(Hash, config.state_nodes_max);
        errdefer allocator.free(result.state_hashes);
        result.code_order = try allocator.alloc(u32, config.codes_max);
        errdefer allocator.free(result.code_order);
        result.code_hashes = try allocator.alloc(Hash, config.codes_max);
        errdefer allocator.free(result.code_hashes);
        result.key_order = try allocator.alloc(u32, config.keys_max);
        errdefer allocator.free(result.key_order);
        result.header_order = try allocator.alloc(u32, config.headers_max);
        errdefer allocator.free(result.header_order);
        result.header_numbers = try allocator.alloc(u64, config.headers_max);
        result.state_len = 0;
        result.codes_len = 0;
        result.keys_len = 0;
        result.headers_len = 0;
        return result;
    }

    pub fn deinit(self: *Encoder, allocator: std.mem.Allocator) void {
        allocator.free(self.header_numbers);
        allocator.free(self.header_order);
        allocator.free(self.key_order);
        allocator.free(self.code_hashes);
        allocator.free(self.code_order);
        allocator.free(self.state_hashes);
        allocator.free(self.state_order);
        self.* = undefined;
    }

    /// The canonical encoding's size: duplicates are dropped, so this sorts like `encode`.
    pub fn encoded_size(self: *Encoder, witness: *const Witness) EncodeError!u32 {
        try self.prepare(witness);
        return self.prepared_size(witness);
    }

    /// Writes the canonical encoding of `witness` into `out`; returns the bytes written.
    pub fn encode(self: *Encoder, witness: *const Witness, out: []u8) EncodeError!usize {
        try self.prepare(witness);
        const size = self.prepared_size(witness);
        if (out.len < size) return error.BufferTooSmall;
        var writer: Writer = .{ .out = out[0..size] };
        writer.bytes(&magic);
        writer.int(version);
        writer.section(&witness.state, self.state_order[0..self.state_len]);
        writer.section(&witness.codes, self.code_order[0..self.codes_len]);
        writer.section(&witness.keys, self.key_order[0..self.keys_len]);
        writer.section(&witness.headers, self.header_order[0..self.headers_len]);
        assert(writer.offset == size);
        return size;
    }

    fn prepare(self: *Encoder, witness: *const Witness) EncodeError!void {
        assert(witness.state.count <= self.state_order.len);
        assert(witness.codes.count <= self.code_order.len);
        assert(witness.keys.count <= self.key_order.len);
        assert(witness.headers.count <= self.header_order.len);
        self.state_len = prepare_hashed(&witness.state, self.state_order, self.state_hashes);
        self.codes_len = prepare_hashed(&witness.codes, self.code_order, self.code_hashes);
        self.keys_len = try prepare_keys(&witness.keys, self.key_order);
        self.headers_len = try prepare_headers(
            &witness.headers,
            self.header_order,
            self.header_numbers,
        );
    }

    fn prepared_size(self: *const Encoder, witness: *const Witness) u32 {
        var size: u32 = prefix_bytes;
        size += section_size(&witness.state, self.state_order[0..self.state_len]);
        size += section_size(&witness.codes, self.code_order[0..self.codes_len]);
        size += section_size(&witness.keys, self.key_order[0..self.keys_len]);
        size += section_size(&witness.headers, self.header_order[0..self.headers_len]);
        assert(size >= prefix_bytes + sections_count * section_prefix_bytes);
        return size;
    }
};

fn section_size(list: *const ByteList, order: []const u32) u32 {
    var size: u32 = section_prefix_bytes;
    for (order) |index| size += item_prefix_bytes + @as(u32, @intCast(list.get(index).len));
    assert(size >= section_prefix_bytes + item_prefix_bytes * order.len);
    return size;
}

const HashOrder = struct {
    hashes: []const Hash,

    fn less(self: HashOrder, a: u32, b: u32) bool {
        return std.mem.order(u8, &self.hashes[a], &self.hashes[b]) == .lt;
    }
};

/// Sorts `list` by keccak256 into `order` and drops duplicates; returns the unique count.
fn prepare_hashed(list: *const ByteList, order: []u32, hashes: []Hash) u32 {
    assert(order.len == hashes.len);
    assert(list.count <= order.len);
    const count = list.count;
    if (count == 0) return 0;
    for (0..count) |index| {
        hashes[index] = keccak256(list.get(@intCast(index)));
        order[index] = @intCast(index);
    }
    std.sort.pdq(u32, order[0..count], HashOrder{ .hashes = hashes }, HashOrder.less);
    var unique: u32 = 1;
    for (order[1..count]) |index| {
        const previous = order[unique - 1];
        if (std.mem.eql(u8, &hashes[index], &hashes[previous])) {
            // Equal digests are equal preimages (keccak256 collision resistance).
            assert(std.mem.eql(u8, list.get(index), list.get(previous)));
            continue;
        }
        order[unique] = index;
        unique += 1;
    }
    assert(unique <= count);
    return unique;
}

const BytesOrder = struct {
    list: *const ByteList,

    fn less(self: BytesOrder, a: u32, b: u32) bool {
        return std.mem.order(u8, self.list.get(a), self.list.get(b)) == .lt;
    }
};

fn prepare_keys(list: *const ByteList, order: []u32) EncodeError!u32 {
    assert(list.count <= order.len);
    const count = list.count;
    if (count == 0) return 0;
    for (0..count) |index| {
        if (!key_size_valid(list.get(@intCast(index)).len)) return error.InvalidWitness;
        order[index] = @intCast(index);
    }
    std.sort.pdq(u32, order[0..count], BytesOrder{ .list = list }, BytesOrder.less);
    var unique: u32 = 1;
    for (order[1..count]) |index| {
        if (std.mem.eql(u8, list.get(index), list.get(order[unique - 1]))) continue;
        order[unique] = index;
        unique += 1;
    }
    assert(unique <= count);
    return unique;
}

const NumberOrder = struct {
    numbers: []const u64,

    fn less(self: NumberOrder, a: u32, b: u32) bool {
        return self.numbers[a] < self.numbers[b];
    }
};

fn prepare_headers(list: *const ByteList, order: []u32, numbers: []u64) EncodeError!u32 {
    assert(order.len == numbers.len);
    assert(list.count <= order.len);
    const count = list.count;
    if (count == 0) return 0;
    for (0..count) |index| {
        const header = list.get(@intCast(index));
        numbers[index] = header_number(header) catch return error.InvalidWitness;
        order[index] = @intCast(index);
    }
    std.sort.pdq(u32, order[0..count], NumberOrder{ .numbers = numbers }, NumberOrder.less);
    var unique: u32 = 1;
    for (order[1..count]) |index| {
        const previous = order[unique - 1];
        if (numbers[index] == numbers[previous]) {
            if (!std.mem.eql(u8, list.get(index), list.get(previous))) {
                return error.InvalidWitness;
            }
            continue;
        }
        order[unique] = index;
        unique += 1;
    }
    assert(unique <= count);
    return unique;
}

fn key_size_valid(size: usize) bool {
    return size == 20 or size == 32;
}

const Writer = struct {
    out: []u8,
    offset: usize = 0,

    fn bytes(self: *Writer, data: []const u8) void {
        assert(data.len <= self.out.len - self.offset);
        @memcpy(self.out[self.offset..][0..data.len], data);
        self.offset += data.len;
    }

    fn int(self: *Writer, value: u32) void {
        assert(self.out.len - self.offset >= @sizeOf(u32));
        std.mem.writeInt(u32, self.out[self.offset..][0..4], value, .little);
        self.offset += @sizeOf(u32);
    }

    fn section(self: *Writer, list: *const ByteList, order: []const u32) void {
        const start = self.offset;
        const payload_bytes = section_size(list, order) - section_prefix_bytes;
        self.int(@intCast(order.len));
        self.int(payload_bytes);
        for (order) |index| {
            const item = list.get(index);
            self.int(@intCast(item.len));
            self.bytes(item);
        }
        assert(self.offset - start == section_prefix_bytes + payload_bytes);
    }
};

const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn remaining(self: *const Reader) usize {
        assert(self.offset <= self.bytes.len);
        return self.bytes.len - self.offset;
    }

    fn int(self: *Reader) DecodeError!u32 {
        if (self.remaining() < @sizeOf(u32)) return error.Truncated;
        const value = std.mem.readInt(u32, self.bytes[self.offset..][0..4], .little);
        self.offset += @sizeOf(u32);
        return value;
    }
};

/// Decodes a canonical encoding into `out` (cleared first, and cleared again on error).
/// `out`'s capacities bound the input: more items or bytes fail with `WitnessFull`.
pub fn decode(bytes: []const u8, out: *Witness) DecodeError!void {
    out.clear();
    errdefer out.clear();
    if (bytes.len < prefix_bytes) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..magic.len], &magic)) return error.BadMagic;
    var reader: Reader = .{ .bytes = bytes, .offset = magic.len };
    if (try reader.int() != version) return error.UnsupportedVersion;
    try decode_section(&reader, &out.state, .hashed);
    try decode_section(&reader, &out.codes, .hashed);
    try decode_section(&reader, &out.keys, .key);
    try decode_section(&reader, &out.headers, .header);
    if (reader.remaining() != 0) return error.TrailingBytes;
    assert(reader.offset == bytes.len);
}

/// The last accepted item of a section, for the strict order check.
const Previous = struct {
    hash: Hash = undefined,
    number: u64 = 0,
    set: bool = false,
};

fn decode_section(reader: *Reader, list: *ByteList, kind: Kind) DecodeError!void {
    assert(list.count == 0);
    const count = try reader.int();
    const payload_bytes = try reader.int();
    if (payload_bytes > reader.remaining()) return error.Truncated;
    if (count > list.ends.len) return error.WitnessFull;
    const section_end = reader.offset + payload_bytes;
    var previous: Previous = .{};
    var index: u32 = 0;
    while (index < count) : (index += 1) {
        if (section_end - reader.offset < item_prefix_bytes) return error.LengthMismatch;
        const item_bytes = try reader.int();
        if (item_bytes > section_end - reader.offset) return error.LengthMismatch;
        const item = reader.bytes[reader.offset..][0..item_bytes];
        reader.offset += item_bytes;
        try check_order(kind, list, item, &previous);
        list.append(item) catch return error.WitnessFull;
    }
    if (reader.offset != section_end) return error.LengthMismatch;
    assert(list.count == count);
}

fn check_order(
    kind: Kind,
    list: *const ByteList,
    item: []const u8,
    previous: *Previous,
) DecodeError!void {
    switch (kind) {
        .hashed => {
            const hash = keccak256(item);
            if (previous.set and std.mem.order(u8, &previous.hash, &hash) != .lt) {
                return error.NonCanonical;
            }
            previous.hash = hash;
        },
        .key => {
            if (!key_size_valid(item.len)) return error.NonCanonical;
            if (list.count > 0 and std.mem.order(u8, list.get(list.count - 1), item) != .lt) {
                return error.NonCanonical;
            }
        },
        .header => {
            const number = header_number(item) catch return error.InvalidHeader;
            if (previous.set and number <= previous.number) return error.NonCanonical;
            previous.number = number;
        },
    }
    previous.set = true;
}

/// The keccak256 preimage-oracle key of `digest`: type byte 2, then the digest's low-order
/// 31 bytes (base/base `PreimageKey::new_keccak256` rendered as `[u8; 32]`).
pub fn preimage_key(digest: Hash) Hash {
    var key = digest;
    key[0] = keccak256_key_type;
    assert(std.mem.eql(u8, key[1..], digest[1..]));
    return key;
}

pub const Preimage = struct {
    /// keccak256(bytes); `preimage_key(digest)` is the oracle key.
    digest: Hash,
    bytes: []const u8,
};

/// Yields every state node, code, and key of a witness with its keccak256 digest, in section
/// order: the preimages base/base's host derives from an `ExecutionWitness`. Works on any
/// witness; a canonical one yields no duplicates.
pub const PreimageIterator = struct {
    witness: *const Witness,
    section: u8 = 0,
    index: u32 = 0,

    pub fn init(witness: *const Witness) PreimageIterator {
        return .{ .witness = witness };
    }

    pub fn next(self: *PreimageIterator) ?Preimage {
        // Bounded: at most one step past each of the three preimage sections.
        var steps: u32 = 0;
        while (self.section < 3) : (steps += 1) {
            assert(steps < 3);
            const list = switch (self.section) {
                0 => &self.witness.state,
                1 => &self.witness.codes,
                2 => &self.witness.keys,
                else => unreachable,
            };
            if (self.index < list.count) {
                const bytes = list.get(self.index);
                self.index += 1;
                return .{ .digest = keccak256(bytes), .bytes = bytes };
            }
            self.section += 1;
            self.index = 0;
        }
        assert(self.section == 3);
        return null;
    }
};

/// The preimage of `digest` in a canonical witness (as `decode` produces): binary search on
/// the sorted state and code sections (one keccak256 per probe), then a bounded scan of the
/// keys (sorted by bytes, not by digest). Lookups by oracle key are not supported: the key
/// drops the digest's high byte, so hosts feed their key-value store from `PreimageIterator`.
pub fn lookup(witness: *const Witness, digest: *const Hash) ?[]const u8 {
    if (search_hashed(&witness.state, digest)) |bytes| return bytes;
    if (search_hashed(&witness.codes, digest)) |bytes| return bytes;
    for (0..witness.keys.count) |index| {
        const key = witness.keys.get(@intCast(index));
        if (std.mem.eql(u8, &keccak256(key), digest)) return key;
    }
    return null;
}

fn search_hashed(list: *const ByteList, digest: *const Hash) ?[]const u8 {
    var low: u32 = 0;
    var high: u32 = list.count;
    var probes: u32 = 0;
    while (low < high) : (probes += 1) {
        assert(probes <= 32);
        const middle = low + (high - low) / 2;
        const bytes = list.get(middle);
        switch (std.mem.order(u8, &keccak256(bytes), digest)) {
            .lt => low = middle + 1,
            .gt => high = middle,
            .eq => return bytes,
        }
    }
    assert(low == high);
    return null;
}
