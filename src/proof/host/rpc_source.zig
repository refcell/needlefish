//! A host `Source` over the L1 and L2 execution JSON-RPC endpoints (base/base
//! `backend/online.rs`), used by the recording `base proof run`.
//!
//! Every query is one blocking JSON-RPC call: it is sent through the non-blocking
//! `rpc.Client`, then the caller's `Pump` advances IO until the callback fires, for at most
//! `steps_max` steps. Raw consensus encodings come from the geth `debug_getRaw*` family, so
//! nothing is re-encoded from JSON fields; the handler hash-checks headers and rebuilds
//! list tries from the raw items, so a lying endpoint cannot plant a wrong preimage.
//!
//! The payload witness is the execution witness of the endpoint's canonical child of the
//! parent (`debug_executionWitness(parent + 1)`): when the derived block equals the
//! canonical one (an honest chain), it is exactly the witness of building it; otherwise
//! the client fails with a missing preimage instead of proving a wrong state. Blobs (beacon
//! API) and single preimages are not served yet: `NotFound`.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const handler_module = @import("handler.zig");

const Hash = [32]u8;
const CallResult = rpc.client.Error!rpc.client.Result;
const Chain = handler_module.Chain;
const Source = handler_module.Source;
const SourceError = handler_module.SourceError;

/// Advances the IO loop by one step (one `tick` or `run_for_ns` slice).
pub const Pump = struct {
    context: *anyopaque,
    step: *const fn (context: *anyopaque) anyerror!void,
};

pub const Options = struct {
    /// Pump steps one call may take before it fails.
    steps_max: u32 = 1 << 20,
    /// Items in one list result (transactions, receipts, witness entries).
    items_max: u32 = 1 << 16,
};

pub fn RpcSource(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Client = rpc.Client(IO);

        l1: *Client,
        l2: *Client,
        pump: Pump,
        options: Options,
        arena: std.heap.ArenaAllocator,
        /// The result of the call in flight; null while pending.
        result: ?CallResult = null,
        calls: u64 = 0,

        pub fn init(
            allocator: std.mem.Allocator,
            l1: *Client,
            l2: *Client,
            pump: Pump,
            options: Options,
        ) Self {
            assert(l1 != l2);
            assert(options.steps_max > 0);
            return .{
                .l1 = l1,
                .l2 = l2,
                .pump = pump,
                .options = options,
                .arena = .init(allocator),
            };
        }

        pub fn deinit(source: *Self) void {
            source.arena.deinit();
            source.* = undefined;
        }

        pub fn as_source(source: *Self) Source {
            return .{ .context = source, .vtable = &vtable };
        }

        const vtable: Source.VTable = .{
            .raw_header = raw_header,
            .transactions = transactions,
            .receipts = receipts,
            .blob = blob,
            .preimage = preimage,
            .payload_witness = payload_witness,
        };

        fn of(context: *anyopaque) *Self {
            const source: *Self = @ptrCast(@alignCast(context));
            _ = source.arena.reset(.retain_capacity);
            return source;
        }

        fn client_of(source: *Self, chain: Chain) *Client {
            return switch (chain) {
                .l1 => source.l1,
                .l2 => source.l2,
            };
        }

        fn on_result(source: *Self, client: *Client, result: CallResult) void {
            assert(client == source.l1 or client == source.l2);
            assert(source.result == null);
            // The body buffer is reused by the next call: keep a copy.
            const copied: CallResult = if (result) |value| switch (value) {
                .ok => |raw| if (source.arena.allocator().dupe(u8, raw)) |copy|
                    .{ .ok = copy }
                else |_|
                    error.InvalidResponse,
                .rpc_error => value,
            } else |err| err;
            source.result = copied;
        }

        /// One blocking call. Returns the raw JSON result, or `NotFound` for `null`.
        fn call(
            source: *Self,
            client: *Client,
            method: []const u8,
            param: Param,
        ) SourceError![]const u8 {
            assert(source.result == null);
            client.call(*Self, source, on_result, method, param, Param.write) catch
                return error.SourceFailed;
            source.calls += 1;
            var steps: u32 = 0;
            while (source.result == null) : (steps += 1) {
                if (steps == source.options.steps_max) return error.SourceFailed;
                source.pump.step(source.pump.context) catch return error.SourceFailed;
            }
            const result = source.result.?;
            source.result = null;
            const value = result catch return error.SourceFailed;
            const raw = switch (value) {
                .ok => |raw| raw,
                .rpc_error => return error.NotFound,
            };
            if (std.mem.eql(u8, raw, "null")) return error.NotFound;
            return raw;
        }

        fn raw_header(context: *anyopaque, chain: Chain, hash: Hash) SourceError![]const u8 {
            const source = of(context);
            const client = source.client_of(chain);
            const raw = try source.call(client, "debug_getRawHeader", .{ .hash = hash });
            return source.hex_value(raw);
        }

        fn transactions(
            context: *anyopaque,
            chain: Chain,
            hash: Hash,
        ) SourceError![]const []const u8 {
            const source = of(context);
            const client = source.client_of(chain);
            const raw = try source.call(client, "debug_getRawBlock", .{ .hash = hash });
            const block = try source.hex_value(raw);
            return source.block_transactions(block) catch error.SourceFailed;
        }

        fn receipts(context: *anyopaque, hash: Hash) SourceError![]const []const u8 {
            const source = of(context);
            const raw = try source.call(source.l1, "debug_getRawReceipts", .{ .hash = hash });
            return source.hex_list(raw);
        }

        fn blob(context: *anyopaque, hash: Hash, timestamp: u64) SourceError!handler_module.Blob {
            _ = of(context);
            _ = hash;
            _ = timestamp;
            return error.NotFound;
        }

        fn preimage(context: *anyopaque, hash: Hash) SourceError![]const u8 {
            _ = of(context);
            _ = hash;
            return error.NotFound;
        }

        fn payload_witness(
            context: *anyopaque,
            parent_hash: Hash,
            attributes_json: []const u8,
        ) SourceError![]const []const u8 {
            const source = of(context);
            assert(attributes_json.len > 0);
            const raw = try source.call(source.l2, "debug_getRawHeader", .{ .hash = parent_hash });
            const header_bytes = try source.hex_value(raw);
            const parent = rlp.decode_exact(consensus.Header, header_bytes) catch
                return error.SourceFailed;
            const number = std.math.add(u64, parent.number, 1) catch return error.SourceFailed;
            const witness = try source.call(source.l2, "debug_executionWitness", .{
                .number = number,
            });
            return source.witness_items(witness);
        }

        /// The raw header of block `number` (null: the latest) on `chain`; valid until the
        /// next call. For choosing boot values, so it is not hash-checked here.
        pub fn header_by_number(source: *Self, chain: Chain, number: ?u64) SourceError![]const u8 {
            _ = source.arena.reset(.retain_capacity);
            const param: Param = if (number) |value| .{ .number = value } else .latest;
            const raw = try source.call(source.client_of(chain), "debug_getRawHeader", param);
            return source.hex_value(raw);
        }

        /// Decodes a JSON hex string into arena bytes.
        fn hex_value(source: *Self, raw: []const u8) SourceError![]const u8 {
            var scanner = json.Scanner.init(raw);
            const token = scanner.next() catch return error.SourceFailed;
            if (token.tag != .string) return error.SourceFailed;
            return source.decode_hex(token.bytes);
        }

        fn decode_hex(source: *Self, text: []const u8) SourceError![]const u8 {
            const size = if (text.len >= 2) (text.len - 2) / 2 else 0;
            const out = source.arena.allocator().alloc(u8, size) catch return error.SourceFailed;
            return json.parse_data(text, out) catch error.SourceFailed;
        }

        /// Decodes a JSON array of hex strings.
        fn hex_list(source: *Self, raw: []const u8) SourceError![]const []const u8 {
            var scanner = json.Scanner.init(raw);
            const first = scanner.next() catch return error.SourceFailed;
            if (first.tag != .array_begin) return error.SourceFailed;
            return source.scan_strings(&scanner);
        }

        fn scan_strings(source: *Self, scanner: *json.Scanner) SourceError![]const []const u8 {
            var items: std.ArrayList([]const u8) = .empty;
            const allocator = source.arena.allocator();
            while (true) {
                const token = scanner.next() catch return error.SourceFailed;
                if (token.tag == .array_end) break;
                if (token.tag != .string) return error.SourceFailed;
                if (items.items.len == source.options.items_max) return error.SourceFailed;
                const bytes = try source.decode_hex(token.bytes);
                items.append(allocator, bytes) catch return error.SourceFailed;
            }
            return items.items;
        }

        /// The `state`, `codes` and `keys` entries of an execution witness object.
        fn witness_items(source: *Self, raw: []const u8) SourceError![]const []const u8 {
            var all: std.ArrayList([]const u8) = .empty;
            const allocator = source.arena.allocator();
            for ([_][]const u8{ "state", "codes", "keys" }) |name| {
                const list = (json.find_path(raw, &.{name}) catch return error.SourceFailed) orelse
                    return error.SourceFailed;
                const items = try source.hex_list(list);
                if (all.items.len + items.len > source.options.items_max) {
                    return error.SourceFailed;
                }
                all.appendSlice(allocator, items) catch return error.SourceFailed;
            }
            return all.items;
        }

        /// The EIP-2718 encodings of the transactions in an RLP block.
        fn block_transactions(source: *Self, block: []const u8) ![]const []const u8 {
            var outer = rlp.Decoder.init(block);
            var fields = try outer.list();
            try outer.finish();
            _ = try fields.raw(); // Header.
            var body = try fields.list();
            var items: std.ArrayList([]const u8) = .empty;
            const allocator = source.arena.allocator();
            while (!body.is_empty()) {
                if (items.items.len == source.options.items_max) return error.TooManyItems;
                const header = try body.peek_header();
                // Legacy transactions are embedded as lists, typed ones as byte strings.
                const item = if (header.list) try body.raw() else try body.bytes();
                try items.append(allocator, item);
            }
            return items.items;
        }
    };
}

const Param = union(enum) {
    hash: Hash,
    number: u64,
    latest,

    fn write(param: Param, writer: *json.Writer) json.Writer.WriteError!void {
        switch (param) {
            .hash => |hash| try writer.data(&hash),
            .number => |number| try writer.quantity(number),
            .latest => try writer.string("latest"),
        }
    }
};
