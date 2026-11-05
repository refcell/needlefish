//! Shared L1 head calculation for proof services (base/base `l1-head`).
//!
//! The L1 head for proving L2 block `n` is `l1_origin(n) + sequence_window`, capped at the
//! finalized L1 block: by then every batch for `n` must be on L1, and a finalized head cannot
//! reorg. `cap_head` is the pure rule; `Calculator(IO)` fetches the inputs over JSON-RPC:
//!
//! 1. rollup node `optimism_outputAtBlock(n)` → `blockRef.l1origin.number`;
//! 2. L1 `eth_getBlockByNumber("finalized", false)` → number and hash;
//! 3. if capped below finalized, L1 `eth_getBlockByNumber(head, false)` → hash.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../json/root.zig");
const rpc = @import("../rpc/root.zig");
const http_client = @import("../http/client.zig");

pub const Address = rpc.client.Address;

pub const Head = struct {
    number: u64,
    hash: [32]u8,
};

pub const Error = error{
    Busy,
    L1OriginFetch,
    SequenceWindowOverflow,
    FinalizedBlockFetch,
    FinalizedBlockMissing,
    BlockFetch,
    BlockMissing,
};

/// `min(l1_origin + sequence_window, finalized)`.
pub fn cap_head(
    l1_origin: u64,
    sequence_window: u64,
    finalized: u64,
) error{SequenceWindowOverflow}!u64 {
    const desired = std.math.add(u64, l1_origin, sequence_window) catch
        return error.SequenceWindowOverflow;
    return @min(desired, finalized);
}

pub const Options = struct {
    http: http_client.Options = .{
        .send_buffer_size = 1024,
        .recv_buffer_size = 64 * 1024,
        .limits = .{ .head_size_max = 4 * 1024, .body_size_max = 60 * 1024 },
    },
};

pub fn Calculator(comptime IO: type, comptime Context: type) type {
    return struct {
        const Self = @This();
        const Rpc = rpc.Client(IO);
        pub const Callback = *const fn (context: Context, result: Error!Head) void;

        l1: Rpc,
        rollup: Rpc,
        context: Context = undefined,
        callback: ?Callback = null,
        sequence_window: u64 = 0,
        /// The block number for the request being built (`null` writes "finalized").
        param_block: ?u64 = null,
        desired: u64 = 0,
        finalized: Head = undefined,

        pub fn init(
            allocator: std.mem.Allocator,
            io: *IO,
            l1_endpoint: Address,
            rollup_endpoint: Address,
            options: Options,
        ) !Self {
            const body_max = options.http.limits.body_size_max;
            var l1 = try Rpc.init(allocator, io, l1_endpoint, options.http, body_max);
            errdefer l1.deinit();
            const rollup = try Rpc.init(allocator, io, rollup_endpoint, options.http, body_max);
            return .{ .l1 = l1, .rollup = rollup };
        }

        pub fn deinit(calculator: *Self) void {
            assert(!calculator.busy());
            calculator.rollup.deinit();
            calculator.l1.deinit();
            calculator.* = undefined;
        }

        pub fn busy(calculator: *const Self) bool {
            return calculator.callback != null;
        }

        /// Request timeouts: call periodically while busy.
        pub fn tick(calculator: *Self) void {
            calculator.l1.http.tick();
            calculator.rollup.http.tick();
        }

        /// Starts a calculation; `callback` runs exactly once from the IO loop.
        /// `calculator` must not move until then.
        pub fn calculate(
            calculator: *Self,
            l2_block_number: u64,
            sequence_window: u64,
            context: Context,
            callback: Callback,
        ) Error!void {
            if (calculator.busy()) return error.Busy;
            calculator.context = context;
            calculator.callback = callback;
            calculator.sequence_window = sequence_window;
            calculator.param_block = l2_block_number;
            calculator.rollup.call(
                *Self,
                calculator,
                on_output,
                "optimism_outputAtBlock",
                calculator,
                write_output_params,
            ) catch {
                calculator.callback = null;
                return error.L1OriginFetch;
            };
        }

        fn finish(calculator: *Self, result: Error!Head) void {
            const callback = calculator.callback.?;
            calculator.callback = null;
            callback(calculator.context, result);
        }

        fn write_output_params(
            calculator: *Self,
            writer: *json.Writer,
        ) json.Writer.WriteError!void {
            try writer.quantity(calculator.param_block.?);
        }

        fn write_block_params(
            calculator: *Self,
            writer: *json.Writer,
        ) json.Writer.WriteError!void {
            if (calculator.param_block) |number| {
                try writer.quantity(number);
            } else {
                try writer.string("finalized");
            }
            try writer.boolean(false);
        }

        fn fetch_block(calculator: *Self, number: ?u64) bool {
            calculator.param_block = number;
            const method = "eth_getBlockByNumber";
            const l1 = &calculator.l1;
            const params = write_block_params;
            if (number == null) {
                l1.call(*Self, calculator, on_finalized, method, calculator, params) catch
                    return false;
            } else {
                l1.call(*Self, calculator, on_block, method, calculator, params) catch
                    return false;
            }
            return true;
        }

        fn on_output(
            calculator: *Self,
            client: *Rpc,
            result: rpc.client.Error!rpc.client.Result,
        ) void {
            assert(client == &calculator.rollup);
            const raw = ok_result(result) orelse return calculator.finish(error.L1OriginFetch);
            const l1_origin = parse_l1_origin(raw) catch
                return calculator.finish(error.L1OriginFetch);
            calculator.desired = std.math.add(u64, l1_origin, calculator.sequence_window) catch
                return calculator.finish(error.SequenceWindowOverflow);
            if (!calculator.fetch_block(null)) calculator.finish(error.FinalizedBlockFetch);
        }

        fn on_finalized(
            calculator: *Self,
            client: *Rpc,
            result: rpc.client.Error!rpc.client.Result,
        ) void {
            assert(client == &calculator.l1);
            const raw = ok_result(result) orelse
                return calculator.finish(error.FinalizedBlockFetch);
            const finalized = parse_block(raw) catch |err| return calculator.finish(switch (err) {
                error.Missing => error.FinalizedBlockMissing,
                error.Invalid => error.FinalizedBlockFetch,
            });
            calculator.finalized = finalized;
            const head = @min(calculator.desired, finalized.number);
            if (head == finalized.number) return calculator.finish(finalized);
            if (!calculator.fetch_block(head)) calculator.finish(error.BlockFetch);
        }

        fn on_block(
            calculator: *Self,
            client: *Rpc,
            result: rpc.client.Error!rpc.client.Result,
        ) void {
            assert(client == &calculator.l1);
            const raw = ok_result(result) orelse return calculator.finish(error.BlockFetch);
            const block = parse_block(raw) catch |err| return calculator.finish(switch (err) {
                error.Missing => error.BlockMissing,
                error.Invalid => error.BlockFetch,
            });
            if (block.number != calculator.param_block.?) {
                return calculator.finish(error.BlockFetch);
            }
            calculator.finish(block);
        }
    };
}

fn ok_result(result: rpc.client.Error!rpc.client.Result) ?[]const u8 {
    const value = result catch return null;
    return switch (value) {
        .ok => |raw| raw,
        .rpc_error => null,
    };
}

/// A JSON number, or a QUANTITY string (both appear in rollup-node responses).
pub fn parse_number(raw: []const u8) error{Invalid}!u64 {
    if (raw.len >= 2 and raw[0] == '"' and raw[raw.len - 1] == '"') {
        return json.parse_quantity(u64, raw[1 .. raw.len - 1]) catch error.Invalid;
    }
    return std.fmt.parseInt(u64, raw, 10) catch error.Invalid;
}

/// `blockRef.l1origin.number` of an `optimism_outputAtBlock` result.
pub fn parse_l1_origin(raw: []const u8) error{Invalid}!u64 {
    const found = json.find_path(raw, &.{ "blockRef", "l1origin", "number" }) catch
        return error.Invalid;
    return parse_number(found orelse return error.Invalid);
}

/// Number and hash of an `eth_getBlockByNumber` result; `null` is `Missing`.
pub fn parse_block(raw: []const u8) error{ Missing, Invalid }!Head {
    if (std.mem.eql(u8, std.mem.trim(u8, raw, " \t\r\n"), "null")) return error.Missing;
    const number_raw = (json.find_path(raw, &.{"number"}) catch return error.Invalid) orelse
        return error.Invalid;
    const hash_raw = (json.find_path(raw, &.{"hash"}) catch return error.Invalid) orelse
        return error.Invalid;
    if (hash_raw.len < 2 or hash_raw[0] != '"' or hash_raw[hash_raw.len - 1] != '"') {
        return error.Invalid;
    }
    return .{
        .number = try parse_number(number_raw),
        .hash = json.parse_fixed(32, hash_raw[1 .. hash_raw.len - 1]) catch return error.Invalid,
    };
}

test {
    _ = @import("tests.zig");
}
