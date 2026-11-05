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

const endpoint_module = @import("../rpc/endpoint.zig");
const json = @import("../../utilities/json/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const handler_module = @import("handler.zig");

const Hash = [32]u8;
const Param = endpoint_module.Param;
const Block = endpoint_module.Block;
const Chain = handler_module.Chain;
const Source = handler_module.Source;
const SourceError = handler_module.SourceError;

pub const Pump = endpoint_module.Pump;

pub const Options = struct {
    /// Pump steps one call may take before it fails.
    steps_max: u32 = 1 << 20,
    /// Items in one list result (transactions, receipts, witness entries).
    items_max: u32 = 1 << 16,
};

pub fn RpcSource(comptime IO: type) type {
    return struct {
        const Self = @This();
        const Endpoint = endpoint_module.Endpoint(IO);
        pub const Client = Endpoint.Client;

        l1: Endpoint,
        l2: Endpoint,
        options: Options,
        /// Beacon blobs (`beacon_blobs.zig`); without it blob hints fail as `NotFound`.
        blobs: ?handler_module.BlobFetcher = null,

        pub fn init(
            allocator: std.mem.Allocator,
            l1: *Client,
            l2: *Client,
            pump: Pump,
            options: Options,
        ) Self {
            assert(l1 != l2);
            assert(options.items_max > 0);
            return .{
                .l1 = .init(allocator, l1, pump, options.steps_max),
                .l2 = .init(allocator, l2, pump, options.steps_max),
                .options = options,
            };
        }

        pub fn deinit(source: *Self) void {
            source.l1.deinit();
            source.l2.deinit();
            source.* = undefined;
        }

        /// JSON-RPC calls made so far.
        pub fn calls(source: *const Self) u64 {
            return source.l1.calls + source.l2.calls;
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
            source.l1.reset();
            source.l2.reset();
            return source;
        }

        fn endpoint_of(source: *Self, chain: Chain) *Endpoint {
            return switch (chain) {
                .l1 => &source.l1,
                .l2 => &source.l2,
            };
        }

        /// One blocking call, with the host's error set.
        fn call(endpoint: *Endpoint, method: []const u8, param: Param) SourceError![]const u8 {
            return endpoint.call(method, &.{param}) catch |err| switch (err) {
                error.NotFound => error.NotFound,
                error.CallFailed => error.SourceFailed,
            };
        }

        fn hex_value(endpoint: *Endpoint, raw: []const u8) SourceError![]const u8 {
            return endpoint.hex(raw) catch error.SourceFailed;
        }

        fn hex_list(
            source: *Self,
            endpoint: *Endpoint,
            raw: []const u8,
        ) SourceError![]const []const u8 {
            return endpoint.hex_list(raw, source.options.items_max) catch error.SourceFailed;
        }

        fn raw_header(context: *anyopaque, chain: Chain, hash: Hash) SourceError![]const u8 {
            const endpoint = of(context).endpoint_of(chain);
            const raw = try call(endpoint, "debug_getRawHeader", .{ .hash = hash });
            return hex_value(endpoint, raw);
        }

        fn transactions(
            context: *anyopaque,
            chain: Chain,
            hash: Hash,
        ) SourceError![]const []const u8 {
            const source = of(context);
            const endpoint = source.endpoint_of(chain);
            const raw = try call(endpoint, "debug_getRawBlock", .{ .hash = hash });
            const block = try hex_value(endpoint, raw);
            return source.block_transactions(endpoint, block) catch error.SourceFailed;
        }

        fn receipts(context: *anyopaque, hash: Hash) SourceError![]const []const u8 {
            const source = of(context);
            const raw = try call(&source.l1, "debug_getRawReceipts", .{ .hash = hash });
            return source.hex_list(&source.l1, raw);
        }

        fn blob(context: *anyopaque, hash: Hash, timestamp: u64) SourceError!handler_module.Blob {
            const source = of(context);
            const fetcher = source.blobs orelse return error.NotFound;
            return fetcher.fetch(fetcher.context, hash, timestamp);
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
            const l2 = &source.l2;
            const raw = try call(l2, "debug_getRawHeader", .{ .hash = parent_hash });
            const parent = rlp.decode_exact(consensus.Header, try hex_value(l2, raw)) catch
                return error.SourceFailed;
            const number = std.math.add(u64, parent.number, 1) catch return error.SourceFailed;
            const witness = try call(l2, "debug_executionWitness", .{ .number = number });
            return source.witness_items(witness);
        }

        /// The raw header of block `number` (null: the latest) on `chain`; valid until the
        /// next call. For choosing boot values, so it is not hash-checked here.
        pub fn header_by_number(source: *Self, chain: Chain, number: ?u64) SourceError![]const u8 {
            const endpoint = source.endpoint_of(chain);
            endpoint.reset();
            const block: Block = if (number) |value| .{ .number = value } else .latest;
            const raw = try call(endpoint, "debug_getRawHeader", block.param());
            return hex_value(endpoint, raw);
        }

        /// The `state`, `codes` and `keys` entries of an execution witness object.
        fn witness_items(source: *Self, raw: []const u8) SourceError![]const []const u8 {
            var all: std.ArrayList([]const u8) = .empty;
            const allocator = source.l2.arena.allocator();
            for ([_][]const u8{ "state", "codes", "keys" }) |name| {
                const list = (json.find_path(raw, &.{name}) catch return error.SourceFailed) orelse
                    return error.SourceFailed;
                const items = try source.hex_list(&source.l2, list);
                if (all.items.len + items.len > source.options.items_max) {
                    return error.SourceFailed;
                }
                all.appendSlice(allocator, items) catch return error.SourceFailed;
            }
            return all.items;
        }

        /// The EIP-2718 encodings of the transactions in an RLP block.
        fn block_transactions(
            source: *Self,
            endpoint: *Endpoint,
            block: []const u8,
        ) ![]const []const u8 {
            var outer = rlp.Decoder.init(block);
            var fields = try outer.list();
            try outer.finish();
            _ = try fields.raw(); // Header.
            var body = try fields.list();
            var items: std.ArrayList([]const u8) = .empty;
            const allocator = endpoint.arena.allocator();
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
