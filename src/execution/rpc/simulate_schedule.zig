//! eth_simulateV1's block numbers and timestamps: base/base `sanitize_base_chain`
//! (crates/execution/rpc/src/eth/call.rs). Defaults follow the chain's own schedule (two
//! seconds per block, 200 ms per block from Denim, anchored on the genesis), number gaps
//! are filled with empty blocks, and at most `blocks_max` blocks may follow the base block.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");

const Call = rpc.Call;
const HandlerError = rpc.HandlerError;

/// reth `DEFAULT_MAX_SIMULATE_BLOCKS`.
pub const blocks_max: u64 = 256;
/// execution-apis error codes (reth `EthSimulateError::error_code`).
pub const code_block_number: i32 = -38020;
pub const code_block_timestamp: i32 = -38021;
pub const code_too_many_blocks: i32 = -38026;

const legacy_block_time: u64 = 2;
const denim_block_time_ms: u64 = 200;

pub const Schedule = struct {
    base_number: u64,
    prev_number: u64,
    prev_timestamp: u64,
    genesis_number: u64,
    genesis_timestamp: u64,
    /// Denim's activation time, when scheduled.
    denim: ?u64,

    /// One requested block: `number - 1 - prev_number` empty fillers come first.
    pub const Planned = struct { number: u64, timestamp: u64 };

    pub fn init(
        genesis_number: u64,
        genesis_timestamp: u64,
        denim: ?u64,
        base_number: u64,
        base_timestamp: u64,
    ) Schedule {
        return .{
            .base_number = base_number,
            .prev_number = base_number,
            .prev_timestamp = base_timestamp,
            .genesis_number = genesis_number,
            .genesis_timestamp = genesis_timestamp,
            .denim = denim,
        };
    }

    fn timestamp_for_block(schedule: *const Schedule, number: u64) u64 {
        const genesis_number = schedule.genesis_number;
        const genesis_timestamp = schedule.genesis_timestamp;
        if (schedule.denim) |denim| {
            const elapsed = denim -| genesis_timestamp;
            // div_ceil: the legacy block time is nonzero.
            const partial: u64 = @intFromBool(elapsed % legacy_block_time != 0);
            const blocks = elapsed / legacy_block_time + partial;
            const block = genesis_number +| blocks;
            const at = genesis_timestamp +| ((block -| genesis_number) *| legacy_block_time);
            if (number >= block) return at +| (((number -| block) *| denim_block_time_ms) / 1000);
        }
        return genesis_timestamp +| ((number -| genesis_number) *| legacy_block_time);
    }

    /// The default timestamp of block `number` after one at `prev`; null on overflow.
    pub fn next_timestamp(schedule: *const Schedule, number: u64, prev: u64) ?u64 {
        const scheduled = schedule.timestamp_for_block(number);
        if (scheduled > prev) return scheduled;
        if (schedule.denim) |denim| if (prev >= denim) return prev;
        return std.math.add(u64, prev, legacy_block_time) catch null;
    }

    /// Plans the block whose `blockOverrides` are `overrides` (null: none), advancing past
    /// its fillers. `buffer` holds an error's text.
    pub fn next(
        schedule: *Schedule,
        call: *Call,
        buffer: []u8,
        overrides: ?[]const u8,
    ) HandlerError!Planned {
        assert(buffer.len >= 128);
        const number_raw = try member(overrides, "number");
        const target = if (number_raw) |raw|
            saturate_u64(try quantity(u256, raw))
        else
            schedule.prev_number +| 1;
        if (target <= schedule.prev_number) {
            const text = "block numbers must be in order: {d} <= {d}";
            return fail(call, buffer, code_block_number, text, target, schedule.prev_number);
        }
        if (target -| schedule.base_number > blocks_max) {
            return call.fail(code_too_many_blocks, "too many blocks");
        }
        var filler = schedule.prev_number + 1;
        while (filler < target) : (filler += 1) {
            const prev = schedule.prev_timestamp;
            schedule.prev_timestamp = schedule.next_timestamp(filler, prev) orelse
                return fail_timestamp(call, buffer, prev, prev);
        }
        schedule.prev_number = target;
        const prev = schedule.prev_timestamp;
        const time_raw = try member(overrides, "time");
        const timestamp = if (time_raw) |raw| blk: {
            const timestamp = try quantity(u64, raw);
            // Nethermind (`SimulateTxExecutor.Execute`) refuses an overridden time that
            // does not pass the previous block's, even where Denim repeats a second.
            if (timestamp <= prev) {
                const text = "Block timestamp out of order {d} is <= than given base " ++
                    "timestamp of {d}!";
                return fail(call, buffer, code_block_timestamp, text, timestamp, prev);
            }
            break :blk timestamp;
        } else schedule.next_timestamp(target, prev) orelse
            return fail_timestamp(call, buffer, prev, prev);
        schedule.prev_timestamp = timestamp;
        return .{ .number = target, .timestamp = timestamp };
    }
};

fn fail_timestamp(call: *Call, buffer: []u8, got: u64, parent: u64) HandlerError {
    const text = "block timestamps must be in order: {d} <= {d}";
    return fail(call, buffer, code_block_timestamp, text, got, parent);
}

fn fail(
    call: *Call,
    buffer: []u8,
    code: i32,
    comptime text: []const u8,
    got: u64,
    parent: u64,
) HandlerError {
    // Proof: `next` asserts 128 bytes, more than the text and two u64s.
    const message = std.fmt.bufPrint(buffer, text, .{ got, parent }) catch unreachable;
    return call.fail(code, message);
}

/// The member `name` of the object `raw` (null `raw`: none), matched as Nethermind does
/// (ASCII case-insensitively, the last one); null when missing or null.
fn member(raw: ?[]const u8, name: []const u8) HandlerError!?[]const u8 {
    const object = raw orelse return null;
    const value = json.find_member_ignore_case(object, name) catch return error.InvalidParams;
    const text = value orelse return null;
    return if (std.mem.eql(u8, text, "null")) null else text;
}

fn quantity(comptime T: type, raw: []const u8) HandlerError!T {
    if (raw.len < 2 or raw[0] != '"' or raw[raw.len - 1] != '"') return error.InvalidParams;
    return json.parse_quantity(T, raw[1 .. raw.len - 1]) catch error.InvalidParams;
}

fn saturate_u64(value: u256) u64 {
    return @intCast(@min(value, std.math.maxInt(u64)));
}

test "simulate_schedule: legacy and Denim defaults" {
    const t = std.testing;
    // Legacy: two seconds per block from the genesis.
    var legacy = Schedule.init(0, 0, null, 5, 10);
    try t.expectEqual(@as(?u64, 12), legacy.next_timestamp(6, 10));
    // base/base `sanitize_base_chain_uses_denim_schedule`: Denim at 10 repeats the second.
    const denim = Schedule.init(0, 0, 10, 5, 10);
    try t.expectEqual(@as(?u64, 10), denim.next_timestamp(6, 10));
    try t.expectEqual(@as(?u64, null), legacy.next_timestamp(6, std.math.maxInt(u64)));
}
