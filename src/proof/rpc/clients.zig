//! Typed calls of the proof tools over a blocking `Endpoint` (base/base
//! `crates/proof/rpc/src/{l1_client,l2_client,rollup_client}.rs`): L1/L2 heads and raw
//! headers, `eth_call` and balances, and the rollup node's sync status and output roots.

const std = @import("std");
const assert = std.debug.assert;

const endpoint_module = @import("endpoint.zig");

const Error = endpoint_module.Error;
const Block = endpoint_module.Block;
const Address = endpoint_module.Address;
const Hash = endpoint_module.Hash;
const member = endpoint_module.member;

/// Calls on an execution endpoint (L1 or L2).
pub fn Execution(comptime EndpointType: type) type {
    return struct {
        endpoint: *EndpointType,

        const Self = @This();

        pub fn block_number(self: Self) Error!u64 {
            return endpoint_module.parse_quantity(try self.endpoint.call("eth_blockNumber", &.{}));
        }

        /// The raw RLP header (`debug_getRawHeader`), valid until the next call.
        pub fn raw_header(self: Self, block: Block) Error![]const u8 {
            const raw = try self.endpoint.call("debug_getRawHeader", &.{block.param()});
            const bytes = try self.endpoint.hex(raw);
            if (bytes.len == 0) return error.CallFailed;
            return bytes;
        }

        pub fn raw_header_by_hash(self: Self, hash: Hash) Error![]const u8 {
            const raw = try self.endpoint.call("debug_getRawHeader", &.{.{ .hash = hash }});
            return self.endpoint.hex(raw);
        }

        /// `eth_call` return data, valid until the next call.
        pub fn call_contract(
            self: Self,
            to: Address,
            data: []const u8,
            block: Block,
        ) Error![]const u8 {
            assert(data.len >= 4);
            const raw = try self.endpoint.call("eth_call", &.{
                .{ .call = .{ .to = to, .data = data } },
                block.param(),
            });
            return self.endpoint.hex(raw);
        }

        pub fn balance(self: Self, address: Address, block: Block) Error!u256 {
            const raw = try self.endpoint.call("eth_getBalance", &.{
                .{ .address = address },
                block.param(),
            });
            if (raw.len < 2 or raw[0] != '"') return error.CallFailed;
            const json = @import("../../utilities/json/root.zig");
            return json.parse_quantity(u256, raw[1 .. raw.len - 1]) catch error.CallFailed;
        }
    };
}

pub const BlockRef = struct { number: u64, hash: Hash };

pub const SyncStatus = struct {
    current_l1: BlockRef,
    head_l1: BlockRef,
    finalized_l1: BlockRef,
    safe_l2: BlockRef,
    finalized_l2: BlockRef,
    unsafe_l2: BlockRef,
    /// L1 origin number of the finalized L2 head (`finalized_l2.l1origin`).
    finalized_l2_origin: u64 = 0,
};

pub const OutputAtBlock = struct {
    output_root: Hash,
    block: BlockRef,
};

/// Calls on a rollup (consensus) node.
pub fn Rollup(comptime EndpointType: type) type {
    return struct {
        endpoint: *EndpointType,

        const Self = @This();

        pub fn sync_status(self: Self) Error!SyncStatus {
            const raw = try self.endpoint.call("optimism_syncStatus", &.{});
            return .{
                .current_l1 = try block_ref(raw, "current_l1"),
                .head_l1 = try block_ref(raw, "head_l1"),
                .finalized_l1 = try block_ref(raw, "finalized_l1"),
                .safe_l2 = try block_ref(raw, "safe_l2"),
                .finalized_l2 = try block_ref(raw, "finalized_l2"),
                .unsafe_l2 = try block_ref(raw, "unsafe_l2"),
                .finalized_l2_origin = try endpoint_module.parse_number(
                    try member(raw, &.{ "finalized_l2", "l1origin", "number" }),
                ),
            };
        }

        pub fn output_at_block(self: Self, number: u64) Error!OutputAtBlock {
            const raw = try self.endpoint.call("optimism_outputAtBlock", &.{.{ .number = number }});
            const output: OutputAtBlock = .{
                .output_root = try endpoint_module.parse_hash(try member(raw, &.{"outputRoot"})),
                .block = try block_ref(raw, "blockRef"),
            };
            if (output.block.number != number) return error.CallFailed;
            return output;
        }
    };
}

fn block_ref(raw: []const u8, name: []const u8) Error!BlockRef {
    return .{
        .number = try endpoint_module.parse_number(try member(raw, &.{ name, "number" })),
        .hash = try endpoint_module.parse_hash(try member(raw, &.{ name, "hash" })),
    };
}

const testing = std.testing;

test "clients: block refs from sync status JSON" {
    const zero = "\"0x0000000000000000000000000000000000000000000000000000000000000000\"";
    const raw = "{\"safe_l2\":{\"hash\":" ++ zero ++ ",\"number\":129}}";
    const ref = try block_ref(raw, "safe_l2");
    try testing.expectEqual(@as(u64, 129), ref.number);
    try testing.expectError(error.CallFailed, block_ref(raw, "unsafe_l2"));
}
