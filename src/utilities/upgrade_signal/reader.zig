//! Reads the upgrade schedule from L1 over JSON-RPC (base/base `AlloyUpgradeSignalReader`).
//!
//! One read pins an L1 block by tag (`eth_getBlockByNumber`), then makes both contract calls
//! at that block's hash (EIP-1898), so the schedule and the minimum version are consistent.
//! Provider failures surface as `Provider` (retryable, see `retry`), malformed return data as
//! `Decode`, and a schedule with no entries as `EmptySchedule`. Request timeouts are enforced
//! by `tick()`; a response body is bounded by the HTTP client's limits.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../json/root.zig");
const rpc = @import("../rpc/root.zig");
const http_client = @import("../http/client.zig");
const l1_head = @import("../l1_head/root.zig");
const contract = @import("contract.zig");
const Version = @import("version.zig").Version;

pub const Address = rpc.client.Address;

pub const BlockTag = enum {
    finalized,
    safe,
    latest,

    /// How often live reads poll for this tag (how often it typically advances).
    pub fn poll_interval_ns(tag: BlockTag) u64 {
        const ns_per_s = std.time.ns_per_s;
        return switch (tag) {
            .finalized => 15 * 60 * ns_per_s,
            .safe => (6 * 60 + 24) * ns_per_s,
            .latest => 12 * ns_per_s,
        };
    }
};

pub const Schedule = struct {
    l1_block_number: u64 = 0,
    l1_block_hash: [32]u8 = @splat(0),
    timestamps: [contract.schedule_length_max]u64 = undefined,
    count: u32 = 0,
    minimum_version: Version = .{ .packed_value = 0 },

    /// Entries with a known upgrade ID (newer entries this binary does not know are ignored).
    pub fn signals_count(schedule: *const Schedule) u32 {
        return @min(schedule.count, contract.upgrade_ids.len);
    }

    /// Activation timestamp of `upgrade_id`, if the schedule covers it.
    pub fn activation(schedule: *const Schedule, upgrade_id: []const u8) ?u64 {
        for (contract.upgrade_ids[0..schedule.signals_count()], 0..) |id, index| {
            if (std.mem.eql(u8, id, upgrade_id)) return schedule.timestamps[index];
        }
        return null;
    }
};

pub const Error = error{ Busy, Provider, Decode, EmptySchedule };

pub const Options = struct {
    block_tag: BlockTag = .finalized,
    http: http_client.Options = .{
        .send_buffer_size = 2048,
        .recv_buffer_size = 64 * 1024,
        .limits = .{ .head_size_max = 4 * 1024, .body_size_max = 60 * 1024 },
        .request_timeout_ns = 15 * std.time.ns_per_s,
    },
};

const return_data_max = 64 + 32 * contract.schedule_length_max;

pub fn Reader(comptime IO: type, comptime Context: type) type {
    return struct {
        const Self = @This();
        const Rpc = rpc.Client(IO);
        pub const Callback = *const fn (context: Context, result: Error!*const Schedule) void;
        const Step = enum { block, schedule, version };

        rpc: Rpc,
        contract_address: [20]u8,
        block_tag: BlockTag,
        context: Context = undefined,
        callback: ?Callback = null,
        step: Step = .block,
        schedule: Schedule = .{},
        return_data: [return_data_max]u8 = undefined,

        pub fn init(
            allocator: std.mem.Allocator,
            io: *IO,
            l1_endpoint: Address,
            contract_address: [20]u8,
            options: Options,
        ) !Self {
            const body_max = options.http.limits.body_size_max;
            return .{
                .rpc = try Rpc.init(allocator, io, l1_endpoint, options.http, body_max),
                .contract_address = contract_address,
                .block_tag = options.block_tag,
            };
        }

        pub fn deinit(reader: *Self) void {
            assert(!reader.busy());
            reader.rpc.deinit();
            reader.* = undefined;
        }

        pub fn busy(reader: *const Self) bool {
            return reader.callback != null;
        }

        pub fn tick(reader: *Self) void {
            reader.rpc.http.tick();
        }

        /// Starts one read; `callback` runs exactly once from the IO loop with a schedule
        /// that stays valid until the next `read`. `reader` must not move until then.
        pub fn read(reader: *Self, context: Context, callback: Callback) Error!void {
            if (reader.busy()) return error.Busy;
            reader.context = context;
            reader.callback = callback;
            reader.step = .block;
            reader.rpc.call(
                *Self,
                reader,
                on_result,
                "eth_getBlockByNumber",
                reader,
                write_block_params,
            ) catch {
                reader.callback = null;
                return error.Provider;
            };
        }

        fn finish(reader: *Self, result: Error!*const Schedule) void {
            const callback = reader.callback.?;
            reader.callback = null;
            callback(reader.context, result);
        }

        fn write_block_params(
            reader: *Self,
            writer: *json.Writer,
        ) json.Writer.WriteError!void {
            try writer.string(@tagName(reader.block_tag));
            try writer.boolean(false);
        }

        fn write_call_params(
            reader: *Self,
            writer: *json.Writer,
        ) json.Writer.WriteError!void {
            const selector = switch (reader.step) {
                .schedule => &contract.get_schedule_selector,
                .version => &contract.minimum_protocol_version_selector,
                .block => unreachable, // Calls are only built after the block is pinned.
            };
            try writer.begin_object();
            try writer.key("to");
            try writer.data(&reader.contract_address);
            try writer.key("data");
            try writer.data(selector);
            try writer.end_object();
            try writer.begin_object();
            try writer.key("blockHash");
            try writer.data(&reader.schedule.l1_block_hash);
            try writer.end_object();
        }

        fn call_contract(reader: *Self, step: Step) void {
            assert(step != .block);
            reader.step = step;
            reader.rpc.call(*Self, reader, on_result, "eth_call", reader, write_call_params) catch
                reader.finish(error.Provider);
        }

        fn on_result(
            reader: *Self,
            client: *Rpc,
            result: rpc.client.Error!rpc.client.Result,
        ) void {
            assert(client == &reader.rpc);
            assert(reader.busy());
            const value = result catch return reader.finish(error.Provider);
            const raw = switch (value) {
                .ok => |raw| raw,
                .rpc_error => return reader.finish(error.Provider),
            };
            switch (reader.step) {
                .block => {
                    const head = l1_head.parse_block(raw) catch
                        return reader.finish(error.Provider);
                    reader.schedule.l1_block_number = head.number;
                    reader.schedule.l1_block_hash = head.hash;
                    reader.call_contract(.schedule);
                },
                .schedule => {
                    const data = reader.decode_data(raw) catch return reader.finish(error.Decode);
                    const schedule = &reader.schedule;
                    schedule.count = contract.decode_schedule(data, &schedule.timestamps) catch
                        return reader.finish(error.Decode);
                    reader.call_contract(.version);
                },
                .version => {
                    const data = reader.decode_data(raw) catch return reader.finish(error.Decode);
                    reader.schedule.minimum_version = contract.decode_version(data) catch
                        return reader.finish(error.Decode);
                    if (reader.schedule.count == 0) return reader.finish(error.EmptySchedule);
                    reader.finish(&reader.schedule);
                },
            }
        }

        fn decode_data(reader: *Self, raw: []const u8) error{Decode}![]const u8 {
            if (raw.len < 2 or raw[0] != '"' or raw[raw.len - 1] != '"') return error.Decode;
            return json.parse_data(raw[1 .. raw.len - 1], &reader.return_data) catch
                error.Decode;
        }
    };
}
