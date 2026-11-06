//! Replay archive: everything `base replay run` needs to re-execute a range of Base blocks
//! offline, as one checksummed, compressed file.
//!
//! Frame (integers little-endian):
//!
//!     magic "NFRP" | version u32 = 1 | body_bytes u64 | keccak256(body) | deflate(body)
//!
//! The body is raw deflate (`std.compress.flate`, no container). The inflated body must have
//! exactly `body_bytes` bytes and match the digest, so a corrupt or truncated file is
//! rejected before it is parsed.
//!
//! Body:
//!
//!     chain_id u64 | block_count u32 | witness_bytes u32 | witness | block_count x block
//!     block = tx_count u32 | tx_count x (tx_bytes u32 | tx) |
//!             tx_count x receipt | account_count u32 | account_count x account |
//!             slot_count u32 | slot_count x slot
//!     receipt = status u8 | cumulative_gas_used u64 | log_count u32
//!     account = address [20] | present u8 | nonce u64 | balance [32] | code_hash [32]
//!     slot    = address [20] | slot [32] | value [32]
//!
//! `witness` is the canonical `NFWT` encoding (`db/witness_codec.zig`): `state` holds the
//! pre-state trie nodes every block needs (deduplicated across blocks), `codes` the bytecodes
//! read, `keys` is empty, and `headers` is a contiguous run of RLP headers, oldest first: the
//! ancestors BLOCKHASH may read, the parent of the first replayed block, then the replayed
//! blocks themselves (always the last `block_count` headers). Transactions are EIP-2718
//! encodings. Receipts, accounts and slots are the canonical chain's results, used only for
//! first-difference diagnostics (the header roots are the pass/fail check): the receipt of
//! each transaction, and the post-block value of every account and slot the block changed
//! (`present = 0`: the account was deleted). Accounts ascend strictly by address, slots by
//! (address, slot). The body is canonical (the witness codec's rules, no bytes after the last
//! transaction), so a body decodes to exactly one archive and re-encodes to itself.

const std = @import("std");
const assert = std.debug.assert;

const db = @import("../../execution/db/root.zig");
const trie = @import("../../execution/trie/root.zig");

const codec = db.witness_codec;
const witness_module = db.witness;
const Witness = witness_module.Witness;
const ByteList = witness_module.ByteList;
const Hash = [32]u8;
const keccak256 = trie.node.keccak256;
const flate = std.compress.flate;

pub const magic = [4]u8{ 'N', 'F', 'R', 'P' };
pub const version: u32 = 1;
/// Magic, version, body size, body digest.
pub const frame_bytes = 4 + 4 + 8 + 32;
/// Largest body a decoder accepts.
pub const body_bytes_max: u64 = 1 << 31;
/// Largest block range one archive holds.
pub const blocks_max: u32 = 1024;
/// Body bytes before the witness: chain id, block count, witness size.
const body_prefix_bytes = 8 + 4 + 4;

comptime {
    assert(frame_bytes == 48);
    assert(body_bytes_max < std.math.maxInt(u32));
}

pub const DecodeError = error{
    BadMagic,
    UnsupportedVersion,
    Truncated,
    TooLarge,
    /// The inflated body does not match its size or digest.
    Corrupt,
    /// The body breaks a canonical-form rule or does not fit the archive's capacity.
    NonCanonical,
    OutOfMemory,
} || codec.DecodeError;

pub const EncodeError = codec.EncodeError || error{ OutOfMemory, WriteFailed };

/// The canonical receipt of one transaction (diagnostics only).
pub const Receipt = struct {
    status: bool,
    cumulative_gas_used: u64,
    log_count: u32,
};

/// The post-block state of an account the block changed; null info: deleted.
pub const AccountPost = struct {
    address: [20]u8,
    info: ?db.AccountInfo,
};

/// The post-block value of a slot the block changed.
pub const SlotPost = struct {
    address: [20]u8,
    slot: u256,
    value: u256,
};

const receipt_bytes = 1 + 8 + 4;
const account_bytes = 20 + 1 + 8 + 32 + 32;
const slot_bytes = 20 + 32 + 32;

/// A decoded (or assembled) archive. Owns every byte it points at.
pub const Archive = struct {
    chain_id: u64 = 0,
    witness: Witness,
    /// Transactions of all blocks, in block order.
    transactions: ByteList,
    /// One per transaction, same order.
    receipts: []Receipt,
    accounts: []AccountPost,
    accounts_len: u32 = 0,
    slots: []SlotPost,
    slots_len: u32 = 0,
    /// Per block i, `[starts[i], starts[i+1])` indexes its transactions (and receipts),
    /// accounts and slots. Capacity `blocks_max + 1`; entry 0 is 0.
    block_starts: []u32,
    account_starts: []u32,
    slot_starts: []u32,
    block_count: u32 = 0,

    pub const Config = struct {
        witness: Witness.Config,
        transactions_max: u32,
        transaction_bytes_max: u32,
        accounts_max: u32,
        slots_max: u32,
    };

    pub fn init(allocator: std.mem.Allocator, config: Config) !Archive {
        assert(config.transactions_max > 0 and config.transaction_bytes_max > 0);
        assert(config.witness.headers_max >= 2);
        var witness = try Witness.init(allocator, config.witness);
        errdefer witness.deinit(allocator);
        var transactions = try ByteList.init(
            allocator,
            config.transactions_max,
            config.transaction_bytes_max,
        );
        errdefer transactions.deinit(allocator);
        const receipts = try allocator.alloc(Receipt, config.transactions_max);
        errdefer allocator.free(receipts);
        const accounts = try allocator.alloc(AccountPost, @max(config.accounts_max, 1));
        errdefer allocator.free(accounts);
        const slots = try allocator.alloc(SlotPost, @max(config.slots_max, 1));
        errdefer allocator.free(slots);
        const starts = try allocator.alloc(u32, 3 * (blocks_max + 1));
        @memset(starts, 0);
        return .{
            .witness = witness,
            .transactions = transactions,
            .receipts = receipts,
            .accounts = accounts,
            .slots = slots,
            .block_starts = starts[0 .. blocks_max + 1],
            .account_starts = starts[blocks_max + 1 ..][0 .. blocks_max + 1],
            .slot_starts = starts[2 * (blocks_max + 1) ..],
        };
    }

    pub fn deinit(self: *Archive, allocator: std.mem.Allocator) void {
        allocator.free(self.block_starts.ptr[0 .. 3 * (blocks_max + 1)]);
        allocator.free(self.slots);
        allocator.free(self.accounts);
        allocator.free(self.receipts);
        self.transactions.deinit(allocator);
        self.witness.deinit(allocator);
        self.* = undefined;
    }

    pub fn clear(self: *Archive) void {
        self.chain_id = 0;
        self.witness.clear();
        self.transactions.clear();
        self.accounts_len = 0;
        self.slots_len = 0;
        self.block_count = 0;
        assert(self.block_starts[0] == 0 and self.account_starts[0] == 0);
    }

    /// Starts the next block: the transactions, accounts and slots appended until the next
    /// call are its own.
    pub fn begin_block(self: *Archive) error{WitnessFull}!void {
        if (self.block_count == blocks_max) return error.WitnessFull;
        self.block_count += 1;
        self.block_starts[self.block_count] = self.transactions.count;
        self.account_starts[self.block_count] = self.accounts_len;
        self.slot_starts[self.block_count] = self.slots_len;
        assert(self.block_starts[self.block_count - 1] <= self.transactions.count);
    }

    /// Appends a transaction and its canonical receipt to the last block begun.
    pub fn add_transaction(
        self: *Archive,
        raw: []const u8,
        receipt: Receipt,
    ) error{WitnessFull}!void {
        assert(self.block_count > 0);
        try self.transactions.append(raw);
        self.receipts[self.transactions.count - 1] = receipt;
        self.block_starts[self.block_count] = self.transactions.count;
    }

    pub fn add_account(self: *Archive, account: AccountPost) error{WitnessFull}!void {
        assert(self.block_count > 0);
        if (self.accounts_len == self.accounts.len) return error.WitnessFull;
        self.accounts[self.accounts_len] = account;
        self.accounts_len += 1;
        self.account_starts[self.block_count] = self.accounts_len;
    }

    pub fn add_slot(self: *Archive, slot: SlotPost) error{WitnessFull}!void {
        assert(self.block_count > 0);
        if (self.slots_len == self.slots.len) return error.WitnessFull;
        self.slots[self.slots_len] = slot;
        self.slots_len += 1;
        self.slot_starts[self.block_count] = self.slots_len;
    }

    /// The RLP header of replayed block `index` (0 = first).
    pub fn block_header(self: *const Archive, index: u32) []const u8 {
        assert(index < self.block_count);
        const headers = &self.witness.headers;
        assert(headers.count > self.block_count);
        return headers.get(headers.count - self.block_count + index);
    }

    /// The RLP header of the parent of the first replayed block.
    pub fn parent_header(self: *const Archive) []const u8 {
        const headers = &self.witness.headers;
        assert(headers.count > self.block_count);
        return headers.get(headers.count - self.block_count - 1);
    }

    pub fn transaction_count(self: *const Archive, index: u32) u32 {
        assert(index < self.block_count);
        return self.block_starts[index + 1] - self.block_starts[index];
    }

    /// Transaction `position` of block `index`.
    pub fn transaction(self: *const Archive, index: u32, position: u32) []const u8 {
        assert(position < self.transaction_count(index));
        return self.transactions.get(self.block_starts[index] + position);
    }

    pub fn block_receipts(self: *const Archive, index: u32) []const Receipt {
        assert(index < self.block_count);
        return self.receipts[self.block_starts[index]..self.block_starts[index + 1]];
    }

    pub fn block_accounts(self: *const Archive, index: u32) []const AccountPost {
        assert(index < self.block_count);
        return self.accounts[self.account_starts[index]..self.account_starts[index + 1]];
    }

    pub fn block_slots(self: *const Archive, index: u32) []const SlotPost {
        assert(index < self.block_count);
        return self.slots[self.slot_starts[index]..self.slot_starts[index + 1]];
    }

    pub fn transactions_total(self: *const Archive) u32 {
        return self.block_starts[self.block_count];
    }

    /// Body bytes of everything after the witness.
    fn blocks_bytes(self: *const Archive) u64 {
        var size: u64 = 12 * @as(u64, self.block_count);
        const total = self.transactions_total();
        size += (4 + receipt_bytes) * @as(u64, total);
        for (0..total) |index| size += self.transactions.get(@intCast(index)).len;
        size += account_bytes * @as(u64, self.accounts_len);
        size += slot_bytes * @as(u64, self.slots_len);
        return size;
    }
};

/// Writes the canonical body of `archive` into memory from `allocator` (caller frees).
pub fn encode_body(
    allocator: std.mem.Allocator,
    archive: *const Archive,
    witness_config: Witness.Config,
) EncodeError![]u8 {
    assert(archive.block_count > 0);
    assert(archive.witness.headers.count > archive.block_count);
    var encoder = try codec.Encoder.init(allocator, witness_config);
    defer encoder.deinit(allocator);
    const witness_bytes = try encoder.encoded_size(&archive.witness);
    const size: u64 = body_prefix_bytes + witness_bytes + archive.blocks_bytes();
    if (size > body_bytes_max) return error.OutOfMemory;
    const body = try allocator.alloc(u8, @intCast(size));
    errdefer allocator.free(body);
    var writer: Writer = .{ .out = body };
    writer.int(u64, archive.chain_id);
    writer.int(u32, archive.block_count);
    writer.int(u32, witness_bytes);
    writer.offset += try encoder.encode(&archive.witness, body[writer.offset..][0..witness_bytes]);
    for (0..archive.block_count) |block| write_block(&writer, archive, @intCast(block));
    assert(writer.offset == body.len);
    return body;
}

fn write_block(writer: *Writer, archive: *const Archive, block: u32) void {
    const count = archive.transaction_count(block);
    writer.int(u32, count);
    for (0..count) |position| {
        const raw = archive.transaction(block, @intCast(position));
        writer.int(u32, @intCast(raw.len));
        writer.bytes(raw);
    }
    for (archive.block_receipts(block)) |receipt| {
        writer.int(u8, @intFromBool(receipt.status));
        writer.int(u64, receipt.cumulative_gas_used);
        writer.int(u32, receipt.log_count);
    }
    const accounts = archive.block_accounts(block);
    writer.int(u32, @intCast(accounts.len));
    for (accounts) |account| {
        writer.bytes(&account.address);
        const info = account.info orelse db.AccountInfo{};
        writer.int(u8, @intFromBool(account.info != null));
        writer.int(u64, info.nonce);
        writer.int(u256, info.balance);
        writer.bytes(&info.code_hash);
    }
    const slots = archive.block_slots(block);
    writer.int(u32, @intCast(slots.len));
    for (slots) |slot| {
        writer.bytes(&slot.address);
        writer.int(u256, slot.slot);
        writer.int(u256, slot.value);
    }
}

/// Parses a canonical body into `out` (cleared first, and again on error).
pub fn decode_body(body: []const u8, out: *Archive) DecodeError!void {
    out.clear();
    errdefer out.clear();
    var reader: Reader = .{ .bytes = body };
    const chain_id = try reader.int(u64);
    const block_count = try reader.int(u32);
    const witness_bytes = try reader.int(u32);
    if (block_count == 0 or block_count > blocks_max) return error.NonCanonical;
    try codec.decode(try reader.take(witness_bytes), &out.witness);
    if (out.witness.keys.count != 0) return error.NonCanonical;
    if (out.witness.headers.count <= block_count) return error.NonCanonical;
    try check_header_run(&out.witness.headers);
    out.chain_id = chain_id;
    for (0..block_count) |_| try read_block(&reader, out);
    if (reader.remaining() != 0) return error.NonCanonical;
    assert(out.block_count == block_count);
}

fn read_block(reader: *Reader, out: *Archive) DecodeError!void {
    out.begin_block() catch return error.NonCanonical;
    const count = try reader.int(u32);
    if (count > reader.remaining() / (4 + receipt_bytes)) return error.Truncated;
    const first = out.transactions.count;
    for (0..count) |_| {
        const length = try reader.int(u32);
        if (length == 0) return error.NonCanonical;
        const raw = try reader.take(length);
        out.add_transaction(raw, undefined) catch return error.NonCanonical;
    }
    var previous_gas: u64 = 0;
    for (out.receipts[first..][0..count]) |*receipt| {
        const status = try reader.int(u8);
        if (status > 1) return error.NonCanonical;
        receipt.* = .{
            .status = status == 1,
            .cumulative_gas_used = try reader.int(u64),
            .log_count = try reader.int(u32),
        };
        if (receipt.cumulative_gas_used < previous_gas) return error.NonCanonical;
        previous_gas = receipt.cumulative_gas_used;
    }
    try read_accounts(reader, out);
    try read_slots(reader, out);
}

fn read_accounts(reader: *Reader, out: *Archive) DecodeError!void {
    const count = try reader.int(u32);
    if (count > reader.remaining() / account_bytes) return error.Truncated;
    var previous: ?[20]u8 = null;
    for (0..count) |_| {
        const address = (try reader.take(20))[0..20].*;
        if (previous) |p| if (address_key(&p) >= address_key(&address)) {
            return error.NonCanonical;
        };
        previous = address;
        const present = try reader.int(u8);
        if (present > 1) return error.NonCanonical;
        const info: db.AccountInfo = .{
            .nonce = try reader.int(u64),
            .balance = try reader.int(u256),
            .code_hash = (try reader.take(32))[0..32].*,
        };
        // A deleted account is written as all-default fields.
        if (present == 0 and !info.eql(.{})) return error.NonCanonical;
        const post: AccountPost = .{ .address = address, .info = if (present == 1) info else null };
        out.add_account(post) catch return error.NonCanonical;
    }
}

fn read_slots(reader: *Reader, out: *Archive) DecodeError!void {
    const count = try reader.int(u32);
    if (count > reader.remaining() / slot_bytes) return error.Truncated;
    var previous: ?SlotPost = null;
    for (0..count) |_| {
        const slot: SlotPost = .{
            .address = (try reader.take(20))[0..20].*,
            .slot = try reader.int(u256),
            .value = try reader.int(u256),
        };
        if (previous) |p| if (!slot_less(&p, &slot)) return error.NonCanonical;
        previous = slot;
        out.add_slot(slot) catch return error.NonCanonical;
    }
}

pub fn address_key(address: *const [20]u8) u160 {
    return std.mem.readInt(u160, address, .big);
}

/// Strict (address, slot) order of `SlotPost`.
pub fn slot_less(a: *const SlotPost, b: *const SlotPost) bool {
    const a_key = address_key(&a.address);
    const b_key = address_key(&b.address);
    if (a_key != b_key) return a_key < b_key;
    return a.slot < b.slot;
}

/// The headers must be hash-linked: each one's parent hash is keccak256 of the previous
/// one. (The codec already checked they decode and strictly ascend by number.)
fn check_header_run(headers: *const ByteList) DecodeError!void {
    assert(headers.count >= 2);
    var previous = keccak256(headers.get(0));
    var previous_number = witness_module.header_number(headers.get(0)) catch
        return error.NonCanonical;
    for (1..headers.count) |index| {
        const header = headers.get(@intCast(index));
        const link = witness_module.header_link(header) catch return error.NonCanonical;
        if (link.number != previous_number + 1) return error.NonCanonical;
        if (!std.mem.eql(u8, &link.parent_hash, &previous)) return error.NonCanonical;
        previous = keccak256(header);
        previous_number = link.number;
    }
}

/// Big-endian for u256 words (like hashes), little-endian for lengths and counts.
const Writer = struct {
    out: []u8,
    offset: usize = 0,

    fn bytes(self: *Writer, data: []const u8) void {
        assert(data.len <= self.out.len - self.offset);
        @memcpy(self.out[self.offset..][0..data.len], data);
        self.offset += data.len;
    }

    fn int(self: *Writer, comptime T: type, value: T) void {
        const size = @sizeOf(T);
        const endian: std.builtin.Endian = if (T == u256) .big else .little;
        assert(size <= self.out.len - self.offset);
        std.mem.writeInt(T, self.out[self.offset..][0..size], value, endian);
        self.offset += size;
    }
};

const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn remaining(self: *const Reader) usize {
        assert(self.offset <= self.bytes.len);
        return self.bytes.len - self.offset;
    }

    fn int(self: *Reader, comptime T: type) DecodeError!T {
        const size = @sizeOf(T);
        const endian: std.builtin.Endian = if (T == u256) .big else .little;
        if (self.remaining() < size) return error.Truncated;
        const value = std.mem.readInt(T, self.bytes[self.offset..][0..size], endian);
        self.offset += size;
        return value;
    }

    fn take(self: *Reader, length: usize) DecodeError![]const u8 {
        if (self.remaining() < length) return error.Truncated;
        const slice = self.bytes[self.offset..][0..length];
        self.offset += length;
        return slice;
    }
};

/// Compresses `body` into a framed archive file written to `out`.
pub fn write_frame(body: []const u8, out: *std.Io.Writer) error{WriteFailed}!void {
    assert(body.len <= body_bytes_max);
    var prefix: [frame_bytes]u8 = undefined;
    @memcpy(prefix[0..4], &magic);
    std.mem.writeInt(u32, prefix[4..8], version, .little);
    std.mem.writeInt(u64, prefix[8..16], body.len, .little);
    prefix[16..48].* = keccak256(body);
    try out.writeAll(&prefix);
    var window: [flate.max_window_len]u8 = undefined;
    var compress = try flate.Compress.init(out, &window, .raw, .level_6);
    try compress.writer.writeAll(body);
    try compress.finish();
}

/// Inflates and checks a framed archive file; returns the body (from `allocator`).
pub fn read_frame(allocator: std.mem.Allocator, file: []const u8) DecodeError![]u8 {
    if (file.len < frame_bytes) return error.Truncated;
    if (!std.mem.eql(u8, file[0..4], &magic)) return error.BadMagic;
    if (std.mem.readInt(u32, file[4..8], .little) != version) return error.UnsupportedVersion;
    const body_bytes = std.mem.readInt(u64, file[8..16], .little);
    if (body_bytes > body_bytes_max) return error.TooLarge;
    const digest: Hash = file[16..48].*;
    const body = try allocator.alloc(u8, @intCast(body_bytes));
    errdefer allocator.free(body);
    var input: std.Io.Reader = .fixed(file[frame_bytes..]);
    var decompress: flate.Decompress = .init(&input, .raw, &.{});
    // One spare byte: a stream longer than `body_bytes` fills it and fails the size check.
    const spare = try allocator.alloc(u8, body.len + 1);
    defer allocator.free(spare);
    var output: std.Io.Writer = .fixed(spare);
    const inflated = decompress.reader.streamRemaining(&output) catch return error.Corrupt;
    if (inflated != body.len) return error.Corrupt;
    @memcpy(body, spare[0..body.len]);
    if (!std.mem.eql(u8, &keccak256(body), &digest)) return error.Corrupt;
    return body;
}

/// `read_frame` then `decode_body`.
pub fn decode(allocator: std.mem.Allocator, file: []const u8, out: *Archive) DecodeError!void {
    const body = try read_frame(allocator, file);
    defer allocator.free(body);
    try decode_body(body, out);
}
