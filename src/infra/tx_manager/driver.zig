//! JSON-RPC driver for the sans-IO transaction manager.
//!
//! Performs the manager's actions over an execution JSON-RPC endpoint: the account nonce
//! (`eth_getTransactionCount`), fee suggestions (latest block base fee and
//! `eth_maxPriorityFeePerGas`), signing EIP-1559 transactions with a local key,
//! `eth_sendRawTransaction`, and receipts with a canonical-block check (a receipt whose
//! block hash differs from the canonical block at that height counts as not mined, as in
//! base/base `query_receipt`).
//!
//! The transport is injected (`batcher.rpc.Transport`), so tests and the simulator run
//! the driver against a fake L1. Candidate payloads are copied into memory allocated at
//! init; no allocation happens after that. Blob transactions need sidecars and are not
//! sent by this driver; the manager's blob fee logic is ready for a blob driver.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../batcher/rpc/root.zig");
const txdata = @import("../../batcher/txdata/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const manager_module = @import("manager.zig");
const errors = @import("errors.zig");

pub const Address = primitives.Address;
pub const Hash = manager_module.Hash;

pub const Candidate = struct {
    to: Address,
    value: u256 = 0,
    data: []const u8 = &.{},
    /// 0 asks the node (`eth_estimateGas`).
    gas_limit: u64 = 0,
};

pub const Config = struct {
    chain_id: u64,
    private_key: [32]u8,
    /// Sender address of `private_key`.
    from: Address,
    data_bytes_max: u32 = 128 * 1024,
    manager: manager_module.Config = .{},
};

pub const Error = rpc.Error || rpc.DecodeError || manager_module.SubmitError ||
    error{ DataTooLarge, GasEstimateTooLow };

pub fn Driver(comptime limits: manager_module.Limits) type {
    return struct {
        const Self = @This();
        const Manager = manager_module.Manager(limits);

        const Stored = struct {
            id: u64 = 0,
            to: Address = .{ .bytes = @splat(0) },
            value: u256 = 0,
            gas_limit: u64 = 0,
            data_length: u32 = 0,
        };

        manager: Manager,
        config: Config,
        stored: [limits.sends_max]Stored = @splat(.{}),
        data_memory: []u8,
        raw_buffer: []u8,
        params_buffer: []u8,
        suggestion: ?manager_module.Suggestion = null,
        tip_number: u64 = 0,
        rpc_failures: u64 = 0,

        pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
            assert(config.data_bytes_max > 0);
            const data_memory = try allocator.alloc(u8, limits.sends_max * config.data_bytes_max);
            errdefer allocator.free(data_memory);
            // A signed EIP-1559 transaction is its payload plus a few hundred bytes.
            const raw_buffer = try allocator.alloc(u8, config.data_bytes_max + 512);
            errdefer allocator.free(raw_buffer);
            const params_buffer = try allocator.alloc(u8, 2 * raw_buffer.len + 512);
            return .{
                .manager = try Manager.init(config.manager),
                .config = config,
                .data_memory = data_memory,
                .raw_buffer = raw_buffer,
                .params_buffer = params_buffer,
            };
        }

        pub fn deinit(driver: *Self, allocator: std.mem.Allocator) void {
            allocator.free(driver.params_buffer);
            allocator.free(driver.raw_buffer);
            allocator.free(driver.data_memory);
            driver.* = undefined;
        }

        /// Starts a send and returns its id. The payload is copied.
        pub fn send(
            driver: *Self,
            client: *rpc.Client,
            candidate: Candidate,
            now_ms: u64,
        ) Error!u64 {
            if (candidate.data.len > driver.config.data_bytes_max) return error.DataTooLarge;
            if (!driver.manager.has_capacity()) return error.PendingFull;
            if (driver.suggestion == null) try driver.refresh(client);
            if (!driver.manager.nonce.known()) driver.drain(client, now_ms);
            const gas_limit = if (candidate.gas_limit != 0)
                candidate.gas_limit
            else
                try driver.estimate_gas(client, candidate);
            if (gas_limit < 21_000) return error.GasEstimateTooLow;
            const id = try driver.manager.submit(now_ms, driver.suggestion.?, false);
            const index = driver.free_index().?; // Capacity was checked above.
            driver.stored[index] = .{
                .id = id,
                .to = candidate.to,
                .value = candidate.value,
                .gas_limit = gas_limit,
                .data_length = @intCast(candidate.data.len),
            };
            @memcpy(driver.data_of(index)[0..candidate.data.len], candidate.data);
            return id;
        }

        /// Refreshes fees and the chain tip, then performs every due action.
        pub fn step(driver: *Self, client: *rpc.Client, now_ms: u64) Error!void {
            try driver.refresh(client);
            driver.drain(client, now_ms);
        }

        pub fn take_completion(driver: *Self) ?manager_module.Completion {
            const completion = driver.manager.take_completion() orelse return null;
            const index = driver.index_of(completion.id).?;
            driver.stored[index] = .{};
            assert(driver.index_of(completion.id) == null);
            return completion;
        }

        fn drain(driver: *Self, client: *rpc.Client, now_ms: u64) void {
            const suggestion = driver.suggestion orelse return;
            // Each send yields at most one publish plus `hashes_max` receipt queries.
            const budget = 1 + limits.sends_max * (limits.hashes_max + 1);
            for (0..budget) |_| {
                const action = driver.manager.next_action(now_ms, suggestion) orelse return;
                switch (action) {
                    .fetch_nonce => |fetch| driver.fetch_nonce(client, fetch.generation),
                    .publish => |version| driver.publish(client, version, now_ms),
                    .query_receipt => |query| driver.query_receipt(client, query.id, query.hash),
                }
            }
        }

        fn refresh(driver: *Self, client: *rpc.Client) Error!void {
            const head = try client.call("eth_getBlockByNumber", "[\"latest\",false]");
            const base_fee = try rpc.quantity(u128, try rpc.field(head, "baseFeePerGas"));
            const number = try rpc.quantity(u64, try rpc.field(head, "number"));
            const tip = try rpc.quantity(u128, try client.call("eth_maxPriorityFeePerGas", "[]"));
            driver.tip_number = @max(driver.tip_number, number);
            driver.suggestion = .{ .tip_wei = tip, .base_fee_wei = base_fee };
            assert(driver.suggestion != null);
        }

        fn fetch_nonce(driver: *Self, client: *rpc.Client, generation: u64) void {
            var buffer: [96]u8 = undefined;
            const params = std.fmt.bufPrint(&buffer, "[\"0x{x}\",\"latest\"]", .{
                &driver.config.from.bytes,
            }) catch unreachable; // Fixed-size content.
            const value = client.call("eth_getTransactionCount", params) catch {
                driver.rpc_failures += 1;
                return driver.manager.on_chain_nonce(generation, null);
            };
            const chain_nonce = rpc.quantity(u64, value) catch null;
            driver.manager.on_chain_nonce(generation, chain_nonce);
        }

        fn publish(
            driver: *Self,
            client: *rpc.Client,
            version: manager_module.Action.Publish,
            now_ms: u64,
        ) void {
            assert(!version.is_blob);
            const index = driver.index_of(version.id).?;
            const stored = driver.stored[index];
            const envelope = txdata.sign_eip1559(.{
                .chain_id = driver.config.chain_id,
                .nonce = version.nonce,
                .fees = .{
                    .max_fee_per_gas = version.fees.fee_cap_wei,
                    .max_priority_fee_per_gas = version.fees.tip_wei,
                },
                .gas_limit = stored.gas_limit,
                .to = stored.to,
                .value = stored.value,
                .data = driver.data_of(index)[0..stored.data_length],
            }, driver.config.private_key) catch {
                // Signing a well-formed request with a valid key cannot fail; report the
                // attempt as an RPC failure so the manager retries it.
                return driver.manager.on_publish(version.id, @splat(0), .rpc, now_ms);
            };
            const raw = txdata.encode_raw(envelope, driver.raw_buffer);
            const hash = envelope.hash().bytes;
            const params = std.fmt.bufPrint(driver.params_buffer, "[\"0x{x}\"]", .{raw}) catch
                unreachable; // params_buffer holds twice the largest raw transaction.
            const sent = client.call("eth_sendRawTransaction", params);
            const result: ?errors.PublishError = if (sent) |_| null else |err| switch (err) {
                error.RpcError => errors.classify(client.last_error()),
                else => .rpc,
            };
            driver.manager.on_publish(version.id, hash, result, now_ms);
        }

        fn query_receipt(driver: *Self, client: *rpc.Client, id: u64, hash: Hash) void {
            const status = driver.receipt_status(client, hash) catch {
                // Unknown, not "not mined": leave the send's mined set untouched.
                driver.rpc_failures += 1;
                return;
            };
            driver.manager.on_receipt(id, hash, status);
        }

        fn receipt_status(
            driver: *Self,
            client: *rpc.Client,
            hash: Hash,
        ) Error!manager_module.ReceiptStatus {
            var buffer: [80]u8 = undefined;
            const params = std.fmt.bufPrint(&buffer, "[\"0x{x}\"]", .{&hash}) catch unreachable;
            const receipt = try client.call("eth_getTransactionReceipt", params);
            if (receipt == .null) return .not_found;
            const block_number_value = rpc.field(receipt, "blockNumber") catch return .not_found;
            if (block_number_value == .null) return .not_found;
            const block_number = try rpc.quantity(u64, block_number_value);
            const block_hash = try rpc.fixed(32, try rpc.field(receipt, "blockHash"));
            // `receipt` borrows the client's arena: read everything before the next call.
            const block_params =
                std.fmt.bufPrint(&buffer, "[\"0x{x}\",false]", .{block_number}) catch unreachable;
            const block = try client.call("eth_getBlockByNumber", block_params);
            if (block == .null) return .not_found;
            const canonical_hash = try rpc.fixed(32, try rpc.field(block, "hash"));
            if (!std.mem.eql(u8, &canonical_hash, &block_hash)) return .not_found;
            driver.tip_number = @max(driver.tip_number, block_number);
            return .{ .mined = .{ .block_number = block_number, .tip_number = driver.tip_number } };
        }

        fn estimate_gas(driver: *Self, client: *rpc.Client, candidate: Candidate) Error!u64 {
            const params = std.fmt.bufPrint(
                driver.params_buffer,
                "[{{\"from\":\"0x{x}\",\"to\":\"0x{x}\",\"value\":\"0x{x}\",\"data\":\"0x{x}\"}}]",
                .{
                    &driver.config.from.bytes,
                    &candidate.to.bytes,
                    candidate.value,
                    candidate.data,
                },
            ) catch unreachable; // params_buffer holds twice the largest payload.
            return rpc.quantity(u64, try client.call("eth_estimateGas", params));
        }

        fn data_of(driver: *Self, index: usize) []u8 {
            assert(index < limits.sends_max);
            const size = driver.config.data_bytes_max;
            return driver.data_memory[index * size ..][0..size];
        }

        fn free_index(driver: *const Self) ?usize {
            for (driver.stored, 0..) |stored, index| if (stored.id == 0) return index;
            return null;
        }

        fn index_of(driver: *const Self, id: u64) ?usize {
            assert(id > 0);
            for (driver.stored, 0..) |stored, index| if (stored.id == id) return index;
            return null;
        }
    };
}
