//! `basectl proofs`: recent dispute games from the L1 `DisputeGameFactory` (base/base
//! `commands/proofs.rs` `games` listing). Reads `gameCount()` and `gameAtIndex(i)` from
//! the factory, then each game's `status()`, `l2BlockNumber()`, and `rootClaim()`, all
//! through `eth_call`. The prover-service paths (`prover_*` requests, propose, submit,
//! finalize) are not ported.

const std = @import("std");
const assert = std.debug.assert;
const json = std.json;
const rpc = @import("../../batcher/rpc/root.zig");
const types = @import("types.zig");

const Writer = types.Writer;
const DecodeError = types.DecodeError;
const Probe = types.Probe;
const Address = types.Address;

pub const games_max = 32;

/// ABI selectors (first four bytes of keccak256 of the signature; checked in tests).
pub const selector_game_count = "4d1975b4"; // gameCount()
pub const selector_game_at_index = "bb8aa1fc"; // gameAtIndex(uint256)
pub const selector_status = "200d2ed2"; // status()
pub const selector_l2_block_number = "8b85902b"; // l2BlockNumber()
pub const selector_root_claim = "bcef3b55"; // rootClaim()

pub const GameStatus = enum(u8) {
    in_progress = 0,
    challenger_wins = 1,
    defender_wins = 2,

    pub fn text(status: GameStatus) []const u8 {
        return switch (status) {
            .in_progress => "IN_PROGRESS",
            .challenger_wins => "CHALLENGER_WINS",
            .defender_wins => "DEFENDER_WINS",
        };
    }
};

/// `gameAtIndex` return: `(GameType, Timestamp, IDisputeGame)`.
pub const GameEntry = struct {
    game_type: u32,
    created_at: u64,
    proxy: Address,
};

pub const Game = struct {
    index: u64,
    entry: GameEntry,
    status: Probe(GameStatus),
    l2_block_number: Probe(u64),
    root_claim: Probe(types.Hash),
};

pub const Report = struct {
    network: []const u8,
    l1_rpc: []const u8,
    factory: Address,
    total_games: u64,
    games: types.List(Game, games_max) = .{},
};

/// ABI word `index` of `eth_call` return data as an unsigned integer of at most 64 bits.
fn word_u64(value: json.Value, index: usize) DecodeError!u64 {
    var buffer: [32 * 3]u8 = undefined;
    const bytes = try rpc.data(value, &buffer);
    if (bytes.len < (index + 1) * 32) return error.MalformedResponse;
    const word = bytes[index * 32 ..][0..32];
    for (word[0..24]) |byte| if (byte != 0) return error.MalformedResponse;
    return std.mem.readInt(u64, word[24..32], .big);
}

pub fn decode_count(value: json.Value) DecodeError!u64 {
    return word_u64(value, 0);
}

pub fn decode_status(value: json.Value) DecodeError!GameStatus {
    const code = try word_u64(value, 0);
    if (code > 2) return error.MalformedResponse;
    return @fromBackingInt(@intCast(code));
}

pub fn decode_root_claim(value: json.Value) DecodeError!types.Hash {
    var buffer: [32]u8 = undefined;
    const bytes = rpc.data(value, &buffer) catch return error.MalformedResponse;
    if (bytes.len != 32) return error.MalformedResponse;
    return .{ .bytes = buffer };
}

pub fn decode_entry(value: json.Value) DecodeError!GameEntry {
    const game_type = try word_u64(value, 0);
    var buffer: [32 * 3]u8 = undefined;
    const bytes = try rpc.data(value, &buffer);
    assert(bytes.len >= 96);
    for (bytes[64..76]) |byte| if (byte != 0) return error.MalformedResponse;
    const entry: GameEntry = .{
        .game_type = std.math.cast(u32, game_type) orelse return error.MalformedResponse,
        .created_at = try word_u64(value, 1),
        .proxy = .{ .bytes = bytes[76..96].* },
    };
    return entry;
}

/// `[{"to":<target>,"data":"0x<selector><argument word>"},"latest"]`.
fn call_params(buffer: *[192]u8, target: Address, selector: []const u8, argument: ?u64) []u8 {
    assert(selector.len == 8);
    const params = if (argument) |word| std.fmt.bufPrint(
        buffer,
        "[{{\"to\":\"{f}\",\"data\":\"0x{s}{x:0>64}\"}},\"latest\"]",
        .{ target, selector, word },
    ) else std.fmt.bufPrint(
        buffer,
        "[{{\"to\":\"{f}\",\"data\":\"0x{s}\"}},\"latest\"]",
        .{ target, selector },
    );
    return params catch unreachable; // Proof: at most 42 + 74 + 32 bytes of fixed text.
}

pub fn fetch(context: *const types.Context, factory: Address, limit: u32) types.Fetched(Report) {
    assert(limit > 0 and limit <= games_max);
    const client = context.l1.client;
    var buffer: [192]u8 = undefined;
    const count_params = call_params(&buffer, factory, selector_game_count, null);
    const total = switch (types.probe(u64, client, "eth_call", count_params, decode_count)) {
        .ok => |count| count,
        .failed => |failure| return .{ .failed = .{ .what = "l1 rpc", .failure = failure } },
    };
    var report: Report = .{
        .network = context.network,
        .l1_rpc = context.l1.url,
        .factory = factory,
        .total_games = total,
    };
    var index = total;
    while (index > 0 and report.games.count < limit) {
        index -= 1;
        const params = call_params(&buffer, factory, selector_game_at_index, index);
        const entry = switch (types.probe(GameEntry, client, "eth_call", params, decode_entry)) {
            .ok => |entry| entry,
            .failed => |failure| return .{ .failed = .{ .what = "l1 rpc", .failure = failure } },
        };
        assert(report.games.push(fetch_game(client, index, entry)));
    }
    assert(report.games.count <= limit);
    return .{ .ok = report };
}

fn fetch_game(client: ?*rpc.Client, index: u64, entry: GameEntry) Game {
    var buffer: [192]u8 = undefined;
    const proxy = entry.proxy;
    const status = types.probe(
        GameStatus,
        client,
        "eth_call",
        call_params(&buffer, proxy, selector_status, null),
        decode_status,
    );
    const l2_block_number = types.probe(
        u64,
        client,
        "eth_call",
        call_params(&buffer, proxy, selector_l2_block_number, null),
        decode_count,
    );
    const root_claim = types.probe(
        types.Hash,
        client,
        "eth_call",
        call_params(&buffer, proxy, selector_root_claim, null),
        decode_root_claim,
    );
    assert(buffer.len == 192);
    return .{
        .index = index,
        .entry = entry,
        .status = status,
        .l2_block_number = l2_block_number,
        .root_claim = root_claim,
    };
}

pub fn render(report: *const Report, writer: *Writer) !void {
    assert(report.games.count <= games_max);
    try types.row(writer, "network", "{s}", .{report.network});
    try types.row(writer, "l1 rpc", "{s}", .{report.l1_rpc});
    try types.row(writer, "factory", "{f}", .{report.factory});
    try types.row(writer, "total games", "{d}", .{report.total_games});
    try types.row(writer, "showing", "{d}", .{report.games.count});
    for (report.games.slice()) |*game| {
        var key_buffer: [32]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buffer, "game[{d}]", .{game.index}) catch unreachable;
        const status = if (game.status.get()) |status| status.text() else "unknown";
        try types.row(writer, key, "type={d} status={s} l2_block={f} created={d} proxy={f}{f}", .{
            game.entry.game_type,
            status,
            types.optional_number(game.l2_block_number.get()),
            game.entry.created_at,
            game.entry.proxy,
            RootClaim{ .claim = game.root_claim.get() },
        });
    }
}

/// ` root_claim=0x..` when the claim was read, nothing otherwise.
const RootClaim = struct {
    claim: ?types.Hash,
    pub fn format(root: RootClaim, writer: *Writer) Writer.Error!void {
        if (root.claim) |claim| try writer.print(" root_claim={f}", .{claim});
    }
};

const testing = std.testing;
const FakeTransport = @import("fake.zig").FakeTransport;
const keccak = @import("../../common/crypto/keccak.zig");

test "basectl proofs: selectors match keccak256 signatures" {
    const pairs = .{
        .{ "gameCount()", selector_game_count },
        .{ "gameAtIndex(uint256)", selector_game_at_index },
        .{ "status()", selector_status },
        .{ "l2BlockNumber()", selector_l2_block_number },
        .{ "rootClaim()", selector_root_claim },
    };
    inline for (pairs) |pair| {
        const digest = keccak.keccak256(pair[0]);
        const hex = std.fmt.bytesToHex(digest[0..4].*, .lower);
        try testing.expectEqualStrings(pair[1], &hex);
    }
}

const word_zero = "0000000000000000000000000000000000000000000000000000000000000000";

test "basectl proofs: list newest games" {
    const count = "\"0x" ++ word_zero[0..63] ++ "2\"";
    const entry = "\"0x" ++ word_zero[0..63] ++ "1" ++ word_zero[0..56] ++ "6553f100" ++
        word_zero[0..24] ++ "abababababababababababababababababababab\"";
    const status = "\"0x" ++ word_zero[0..63] ++ "2\"";
    var fake: FakeTransport = .{ .answers = &.{
        .{ .method = "eth_call", .result = count, .once = true },
        .{ .method = "eth_call", .result = entry, .once = true },
        .{ .method = "eth_call", .result = status, .once = true },
        .{ .method = "eth_call", .result = status, .once = true },
        .{ .method = "eth_call", .result = "\"0x\"", .once = true },
    } };
    var client = try fake.client(testing.allocator);
    defer client.deinit(testing.allocator);
    const context: types.Context = .{ .l1 = .{ .client = &client, .url = "http://l1" } };
    const report = fetch(&context, .{ .bytes = @splat(0xfa) }, 1).ok;
    try testing.expectEqual(@as(u64, 2), report.total_games);
    const game = report.games.slice()[0];
    try testing.expectEqual(@as(u64, 1), game.index);
    try testing.expectEqual(GameStatus.defender_wins, game.status.ok);
    try testing.expectEqual(types.Failure.malformed, game.root_claim.failed);
    var buffer: [1024]u8 = undefined;
    var writer: Writer = .fixed(&buffer);
    try render(&report, &writer);
    try testing.expect(std.mem.indexOf(u8, writer.buffered(), "game[1]               type=1 " ++
        "status=DEFENDER_WINS l2_block=2 created=1700000000 proxy=0xabab") != null);
}
