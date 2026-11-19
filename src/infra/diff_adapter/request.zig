//! Differential execution protocol: the request line (newline-delimited JSON) and its
//! decoding into a `Case` of raw bytes and a header.
//!
//! Quantities are strict JSON-RPC quantities; fixed-size data must have its exact width;
//! variable data is `0x`-prefixed hex. Decoded bytes live in the caller's arena.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const keccak256 = @import("../../execution/trie/root.zig").node.keccak256;

const hex = primitives.hex;
const Header = consensus.Header;
const Hash = [32]u8;

/// The EVM serves BLOCKHASH for at most this many ancestors.
pub const ancestors_max = 256;

pub const Mode = enum { build, validate };

/// The `header` object of a request: inputs, and in validate mode the canonical results.
pub const RawHeader = struct {
    number: ?[]const u8 = null,
    timestamp: ?[]const u8 = null,
    coinbase: ?[]const u8 = null,
    prevRandao: ?[]const u8 = null,
    gasLimit: ?[]const u8 = null,
    baseFeePerGas: ?[]const u8 = null,
    extraData: ?[]const u8 = null,
    parentBeaconBlockRoot: ?[]const u8 = null,
    excessBlobGas: ?[]const u8 = null,
    stateRoot: ?[]const u8 = null,
    receiptsRoot: ?[]const u8 = null,
    transactionsRoot: ?[]const u8 = null,
    logsBloom: ?[]const u8 = null,
    gasUsed: ?[]const u8 = null,
    blobGasUsed: ?[]const u8 = null,
    withdrawalsRoot: ?[]const u8 = null,
    requestsHash: ?[]const u8 = null,
    hash: ?[]const u8 = null,
};

pub const RawWitness = struct {
    state: []const []const u8 = &.{},
    codes: []const []const u8 = &.{},
};

/// One request line as JSON. Unknown fields are ignored.
pub const RawRequest = struct {
    id: ?[]const u8 = null,
    chain: []const u8 = "",
    mode: []const u8 = "",
    ancestors: []const []const u8 = &.{},
    header: RawHeader = .{},
    transactions: []const []const u8 = &.{},
    witness: RawWitness = .{},
    trace: ?[]const u8 = null,
    /// `systemConfig` mode only.
    systemConfig: ?@import("system_config.zig").RawSystemConfig = null,
    /// `trie` mode only.
    trie: ?@import("trie_request.zig").RawTrie = null,
};

/// A decoded request.
pub const Case = struct {
    mode: Mode,
    /// RLP ancestor headers, newest first; `ancestors[0]` is the parent.
    ancestors: []const []const u8,
    parent: Header,
    parent_hash: Hash,
    /// The block's header: the inputs, the parent hash, and (validate mode) the canonical
    /// results. Build mode leaves the results at their defaults.
    header: Header,
    /// Validate mode: the canonical block hash.
    hash: ?Hash,
    transactions: []const []const u8,
    nodes: []const []const u8,
    codes: []const []const u8,
};

pub const Error = error{
    UnsupportedChain,
    InvalidMode,
    MissingField,
    InvalidField,
    InvalidAncestors,
    OutOfMemory,
    /// `trie` mode: an `address`, `slotKey` or `slotKeys` entry does not hash to its key.
    PreimageMismatch,
    /// `trie` mode: an account op's `code` does not hash to its `codeHash`.
    CodeMismatch,
};

/// Parses a request line. The result borrows `line` and `arena`.
pub fn parse(arena: std.mem.Allocator, line: []const u8) !RawRequest {
    return std.json.parseFromSliceLeaky(RawRequest, arena, line, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
        .max_value_len = line.len,
    });
}

/// The request id when the line is JSON with a string `id`, for error responses.
pub fn salvage_id(arena: std.mem.Allocator, line: []const u8) ?[]const u8 {
    const Id = struct { id: ?[]const u8 = null };
    const parsed = std.json.parseFromSliceLeaky(Id, arena, line, .{
        .ignore_unknown_fields = true,
        .max_value_len = line.len,
    }) catch return null;
    return parsed.id;
}

/// Decodes every field `raw` carries into a `Case`.
pub fn decode(arena: std.mem.Allocator, raw: *const RawRequest) Error!Case {
    if (!std.mem.eql(u8, raw.chain, "base-mainnet")) return error.UnsupportedChain;
    const mode = std.meta.stringToEnum(Mode, raw.mode) orelse return error.InvalidMode;
    if (raw.ancestors.len == 0 or raw.ancestors.len > ancestors_max) {
        return error.InvalidAncestors;
    }
    const ancestors = try bytes_list(arena, raw.ancestors);
    const parent = Header.decode(ancestors[0]) catch return error.InvalidAncestors;
    const parent_hash = keccak256(ancestors[0]);
    var header = try decode_inputs(arena, &raw.header);
    header.parent_hash = .{ .bytes = parent_hash };
    var hash: ?Hash = null;
    if (mode == .validate) {
        try decode_results(arena, &raw.header, &header);
        hash = try fixed(32, required(raw.header.hash));
    }
    const case: Case = .{
        .mode = mode,
        .ancestors = ancestors,
        .parent = parent,
        .parent_hash = parent_hash,
        .header = header,
        .hash = hash,
        .transactions = try bytes_list(arena, raw.transactions),
        .nodes = try bytes_list(arena, raw.witness.state),
        .codes = try bytes_list(arena, raw.witness.codes),
    };
    assert(case.ancestors.len == raw.ancestors.len);
    assert(case.transactions.len == raw.transactions.len);
    return case;
}

/// The block inputs (both modes): the fields a block builder takes from its attributes.
fn decode_inputs(arena: std.mem.Allocator, raw: *const RawHeader) Error!Header {
    var header: Header = .{
        .beneficiary = .{ .bytes = try fixed(20, required(raw.coinbase)) },
        .number = try quantity(u64, required(raw.number)),
        .gas_limit = try quantity(u64, required(raw.gasLimit)),
        .timestamp = try quantity(u64, required(raw.timestamp)),
        .extra_data = try bytes(arena, raw.extraData orelse "0x"),
        .mix_hash = .{ .bytes = try fixed(32, required(raw.prevRandao)) },
        .base_fee_per_gas = try quantity(u64, required(raw.baseFeePerGas)),
    };
    if (raw.parentBeaconBlockRoot) |root| {
        header.parent_beacon_block_root = .{ .bytes = try fixed(32, root) };
    }
    if (raw.excessBlobGas) |excess| header.excess_blob_gas = try quantity(u64, excess);
    assert(header.ommers_hash.eql(primitives.empty_ommers_hash));
    assert(header.difficulty == 0);
    return header;
}

/// The canonical header's result fields (validate mode).
fn decode_results(arena: std.mem.Allocator, raw: *const RawHeader, header: *Header) Error!void {
    _ = arena;
    header.state_root = .{ .bytes = try fixed(32, required(raw.stateRoot)) };
    header.receipts_root = .{ .bytes = try fixed(32, required(raw.receiptsRoot)) };
    header.transactions_root = .{ .bytes = try fixed(32, required(raw.transactionsRoot)) };
    header.logs_bloom = .{ .bytes = try fixed(256, required(raw.logsBloom)) };
    header.gas_used = try quantity(u64, required(raw.gasUsed));
    if (raw.blobGasUsed) |used| header.blob_gas_used = try quantity(u64, used);
    if (raw.withdrawalsRoot) |root| header.withdrawals_root = .{ .bytes = try fixed(32, root) };
    if (raw.requestsHash) |root| header.requests_hash = .{ .bytes = try fixed(32, root) };
    assert(header.state_root.bytes.len == 32);
}

fn required(field: ?[]const u8) Error![]const u8 {
    return field orelse error.MissingField;
}

pub fn quantity(comptime T: type, field: Error![]const u8) Error!T {
    const text = try field;
    return hex.decode_quantity(T, text) catch error.InvalidField;
}

pub fn fixed(comptime size: usize, field: anytype) Error![size]u8 {
    const text: []const u8 = if (@TypeOf(field) == Error![]const u8) try field else field;
    if (!has_prefix(text)) return error.InvalidField;
    return hex.decode_array(size, text) catch error.InvalidField;
}

fn has_prefix(text: []const u8) bool {
    return text.len >= 2 and text[0] == '0' and (text[1] == 'x' or text[1] == 'X');
}

/// Decodes `0x`-prefixed hex into the arena.
pub fn bytes(arena: std.mem.Allocator, text: []const u8) Error![]const u8 {
    if (!has_prefix(text)) return error.InvalidField;
    const size = hex.decoded_length(text) catch return error.InvalidField;
    const out = try arena.alloc(u8, size);
    hex.decode(out, text) catch return error.InvalidField;
    assert(out.len * 2 + 2 == text.len);
    return out;
}

fn bytes_list(arena: std.mem.Allocator, texts: []const []const u8) Error![]const []const u8 {
    const out = try arena.alloc([]const u8, texts.len);
    for (texts, out) |text, *item| item.* = try bytes(arena, text);
    assert(out.len == texts.len);
    return out;
}

const testing = std.testing;

const randao_hex = "1111111111111111111111111111111111111111" ++
    "111111111111111111111111";

test "diff request: decodes inputs strictly" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var parent: Header = .{ .number = 9, .timestamp = 100, .gas_limit = 30_000_000 };
    parent.base_fee_per_gas = 7;
    var buffer: [1024]u8 = undefined;
    const parent_rlp = @import("../../common/rlp/root.zig").encode_to(&buffer, parent);
    var parent_hex: [2048 + 2]u8 = undefined;
    hex.encode_prefixed(parent_hex[0 .. parent_rlp.len * 2 + 2], parent_rlp);
    const line = try std.fmt.allocPrint(arena,
        \\{{"id":"case-1","chain":"base-mainnet","mode":"build","ancestors":["{s}"],
        \\"header":{{"number":"0xa","timestamp":"0x65","gasLimit":"0x1c9c380",
        \\"coinbase":"0x4200000000000000000000000000000000000011","prevRandao":"0x{s}",
        \\"baseFeePerGas":"0x7","extraData":"0x00","unknown":1}},
        \\"transactions":["0x7e00"],"witness":{{"state":[],"codes":["0x60"]}}}}
    , .{ parent_hex[0 .. parent_rlp.len * 2 + 2], randao_hex });
    const raw = try parse(arena, line);
    try testing.expectEqualStrings("case-1", raw.id.?);
    const case = try decode(arena, &raw);
    try testing.expectEqual(Mode.build, case.mode);
    try testing.expectEqual(@as(u64, 10), case.header.number);
    try testing.expectEqual(@as(?u64, 7), case.header.base_fee_per_gas);
    try testing.expectEqualSlices(u8, &keccak256(parent_rlp), &case.header.parent_hash.bytes);
    try testing.expectEqual(@as(u64, 9), case.parent.number);
    try testing.expectEqualSlices(u8, &.{ 0x7e, 0x00 }, case.transactions[0]);
    try testing.expectEqual(@as(?Hash, null), case.hash);
    // A quantity with a leading zero, a short hash and a missing input are rejected.
    var bad = raw;
    bad.header.number = "0x0a";
    try testing.expectError(error.InvalidField, decode(arena, &bad));
    bad = raw;
    bad.header.prevRandao = "0x11";
    try testing.expectError(error.InvalidField, decode(arena, &bad));
    bad = raw;
    bad.header.gasLimit = null;
    try testing.expectError(error.MissingField, decode(arena, &bad));
    bad = raw;
    bad.mode = "replay";
    try testing.expectError(error.InvalidMode, decode(arena, &bad));
    try testing.expectEqualStrings("case-1", salvage_id(arena, line).?);
    try testing.expectEqual(@as(?[]const u8, null), salvage_id(arena, "{not json"));
}

test "diff request: seeded fuzz never crashes the decoder" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var prng = @import("../../testing/prng.zig").Prng.init(0xd1ff_0001);
    const alphabet = "{}[]\":,0x1a7e \"id\"\"mode\"\"build\"\"header\"\"ancestors\"";
    var line: [256]u8 = undefined;
    var round: u32 = 0;
    while (round < 2000) : (round += 1) {
        _ = arena_state.reset(.retain_capacity);
        const arena = arena_state.allocator();
        const len: usize = @intCast(prng.below(line.len + 1));
        for (line[0..len]) |*byte| byte.* = alphabet[@intCast(prng.below(alphabet.len))];
        const raw = parse(arena, line[0..len]) catch continue;
        _ = decode(arena, &raw) catch continue;
    }
}
