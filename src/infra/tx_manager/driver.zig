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
//! init; no allocation happens after that.
//!
//! Blob mode (`blobs_per_send_max > 0`): a candidate with blobs is sent as an EIP-4844
//! transaction in its network form with a sidecar. Commitments and proofs are computed
//! once at `send`; bumps re-sign only the fees (blob fee cap at least doubles, as the
//! manager's fee logic enforces). Blob fees come from `eth_blobBaseFee`.

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../batcher/rpc/root.zig");
const txdata = @import("../../batcher/txdata/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const manager_module = @import("manager.zig");
const errors = @import("errors.zig");
const blob_store = @import("blob_store.zig");
const blob_tx = @import("../../batcher/txdata/blob.zig");

pub const Blob = blob_store.Blob;

pub const Address = primitives.Address;
pub const Hash = manager_module.Hash;

pub const Candidate = struct {
    /// Null creates a contract with `data` as init code (the created address is
    /// `create_address(from, completion.nonce)`).
    to: ?Address,
    value: u256 = 0,
    data: []const u8 = &.{},
    /// 0 asks the node (`eth_estimateGas`).
    gas_limit: u64 = 0,
    /// Non-empty: an EIP-4844 send (needs blob mode; `data` empty, `value` zero, gas 21000).
    /// Blobs are copied.
    blobs: []const *const Blob = &.{},
};

pub const Config = struct {
    chain_id: u64,
    private_key: [32]u8,
    /// Sender address of `private_key`.
    from: Address,
    data_bytes_max: u32 = 128 * 1024,
    /// 0 disables blob sends (and the KZG setup they need).
    blobs_per_send_max: u8 = 0,
    /// 1 (EIP-7594 cell proofs) is what L1 mempools accept since Osaka.
    sidecar_version: u1 = 1,
    manager: manager_module.Config = .{},
    /// Called with every signed transaction right before it is broadcast, so a caller can
    /// journal the hash first and a crash mid-send never loses it (the withdrawer does).
    publish_hook: ?PublishHook = null,
};

pub const PublishHook = struct {
    context: *anyopaque,
    /// False holds the broadcast back (reported like an RPC failure, so it is retried).
    before_publish: *const fn (context: *anyopaque, id: u64, nonce: u64, hash: Hash) bool,
};

pub const Error = rpc.Error || rpc.DecodeError || manager_module.SubmitError ||
    error{ DataTooLarge, GasEstimateTooLow, BlobsDisabled, InvalidBlobCandidate } ||
    blob_store.StoreError;

pub fn Driver(comptime limits: manager_module.Limits) type {
    return struct {
        const Self = @This();
        const Manager = manager_module.Manager(limits);

        const Stored = struct {
            id: u64 = 0,
            to: ?Address = null,
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
        blobs: ?blob_store.BlobStore,
        suggestion: ?manager_module.Suggestion = null,
        tip_number: u64 = 0,
        rpc_failures: u64 = 0,

        pub fn init(allocator: std.mem.Allocator, config: Config) !Self {
            assert(config.data_bytes_max > 0);
            assert(config.blobs_per_send_max <= blob_store.blobs_per_send_limit);
            const data_memory = try allocator.alloc(u8, limits.sends_max * config.data_bytes_max);
            errdefer allocator.free(data_memory);
            // A signed transaction is its payload (or sidecar) plus a few hundred bytes.
            const blob_bytes = @as(usize, config.blobs_per_send_max) *
                blob_store.network_bytes_per_blob(config.sidecar_version);
            const raw_bytes = @max(config.data_bytes_max, blob_bytes) + 512;
            const raw_buffer = try allocator.alloc(u8, raw_bytes);
            errdefer allocator.free(raw_buffer);
            const params_buffer = try allocator.alloc(u8, 2 * raw_buffer.len + 512);
            errdefer allocator.free(params_buffer);
            var blobs: ?blob_store.BlobStore = null;
            if (config.blobs_per_send_max > 0) blobs = try blob_store.BlobStore.init(
                allocator,
                limits.sends_max,
                config.blobs_per_send_max,
                config.sidecar_version,
            );
            return .{
                .manager = try Manager.init(config.manager),
                .config = config,
                .data_memory = data_memory,
                .raw_buffer = raw_buffer,
                .params_buffer = params_buffer,
                .blobs = blobs,
            };
        }

        pub fn deinit(driver: *Self, allocator: std.mem.Allocator) void {
            if (driver.blobs) |*blobs| blobs.deinit(allocator);
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
            const is_blob = candidate.blobs.len > 0;
            if (is_blob) try driver.check_blob_candidate(candidate);
            if (!driver.manager.has_capacity()) return error.PendingFull;
            if (driver.suggestion == null) try driver.refresh(client);
            if (!driver.manager.nonce.known()) driver.drain(client, now_ms);
            const gas_limit = if (is_blob)
                21_000
            else if (candidate.gas_limit != 0)
                candidate.gas_limit
            else
                try driver.estimate_gas(client, candidate);
            if (gas_limit < 21_000) return error.GasEstimateTooLow;
            const index = driver.free_index().?; // Capacity was checked above.
            if (is_blob) try driver.blobs.?.store(@intCast(index), candidate.blobs);
            const id = try driver.manager.submit(now_ms, driver.suggestion.?, is_blob);
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

        fn check_blob_candidate(driver: *const Self, candidate: Candidate) Error!void {
            assert(candidate.blobs.len > 0);
            const blobs = driver.blobs orelse return error.BlobsDisabled;
            if (candidate.to == null) return error.InvalidBlobCandidate;
            if (candidate.blobs.len > blobs.blobs_per_send_max) return error.TooManyBlobs;
            // `blob_tx.sign` builds a plain blob carrier: no calldata, no value.
            if (candidate.data.len != 0 or candidate.value != 0) return error.InvalidBlobCandidate;
            if (candidate.gas_limit != 0 and candidate.gas_limit != 21_000) {
                return error.InvalidBlobCandidate;
            }
        }

        pub fn take_completion(driver: *Self) ?manager_module.Completion {
            const completion = driver.manager.take_completion() orelse return null;
            const index = driver.index_of(completion.id).?;
            if (driver.blobs) |*blobs| blobs.clear(@intCast(index));
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
            const blob_base_fee: u128 = if (driver.blobs == null)
                0
            else
                try rpc.quantity(u128, try client.call("eth_blobBaseFee", "[]"));
            driver.tip_number = @max(driver.tip_number, number);
            driver.suggestion = .{
                .tip_wei = tip,
                .base_fee_wei = base_fee,
                .blob_base_fee_wei = blob_base_fee,
            };
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
            const index = driver.index_of(version.id).?;
            const signed = driver.sign(version, index) catch {
                // Signing a well-formed request with a valid key cannot fail; report the
                // attempt as an RPC failure so the manager retries it.
                return driver.manager.on_publish(version.id, @splat(0), .rpc, now_ms);
            };
            if (driver.config.publish_hook) |hook| {
                if (!hook.before_publish(hook.context, version.id, version.nonce, signed.hash)) {
                    return driver.manager.on_publish(version.id, signed.hash, .rpc, now_ms);
                }
            }
            const buffer = driver.params_buffer;
            // params_buffer holds twice the largest raw transaction.
            const params = std.fmt.bufPrint(buffer, "[\"0x{x}\"]", .{signed.raw}) catch unreachable;
            const sent = client.call("eth_sendRawTransaction", params);
            const result: ?errors.PublishError = if (sent) |_| null else |err| switch (err) {
                error.RpcError => errors.classify(client.last_error()),
                else => .rpc,
            };
            driver.manager.on_publish(version.id, signed.hash, result, now_ms);
        }

        const Signed = struct { raw: []const u8, hash: Hash };

        fn sign(
            driver: *Self,
            version: manager_module.Action.Publish,
            index: usize,
        ) txdata.SignError!Signed {
            const stored = driver.stored[index];
            const fees: txdata.Fees = .{
                .max_fee_per_gas = version.fees.fee_cap_wei,
                .max_priority_fee_per_gas = version.fees.tip_wei,
            };
            if (version.is_blob) {
                assert(version.fees.blob_fee_cap_wei > 0);
                const blobs = &driver.blobs.?;
                const slot: u32 = @intCast(index);
                var hash_buffer: [33 * blob_store.blobs_per_send_limit]u8 = undefined;
                const envelope = try blob_tx.sign(.{
                    .chain_id = driver.config.chain_id,
                    .nonce = version.nonce,
                    .fees = fees,
                    .blob_fee_wei = version.fees.blob_fee_cap_wei,
                    .to = stored.to.?, // Blob candidates always have a recipient.
                    .versioned_hashes = blobs.versioned_hashes(slot),
                }, &hash_buffer, driver.config.private_key);
                const sidecar = blobs.sidecar(slot);
                const raw = blob_tx.encode_network(envelope, sidecar, driver.raw_buffer);
                return .{ .raw = raw, .hash = envelope.hash().bytes };
            }
            assert(version.fees.blob_fee_cap_wei == 0);
            const envelope = try txdata.sign_eip1559(.{
                .chain_id = driver.config.chain_id,
                .nonce = version.nonce,
                .fees = fees,
                .gas_limit = stored.gas_limit,
                .to = stored.to,
                .value = stored.value,
                .data = driver.data_of(index)[0..stored.data_length],
            }, driver.config.private_key);
            const raw = txdata.encode_raw(envelope, driver.raw_buffer);
            return .{ .raw = raw, .hash = envelope.hash().bytes };
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
            // Pre-Byzantium receipts carry a state root instead: treat them as successful.
            const success = if (rpc.field(receipt, "status")) |status_value|
                try rpc.quantity(u64, status_value) == 1
            else |_|
                true;
            // `receipt` borrows the client's arena: read everything before the next call.
            const block_params =
                std.fmt.bufPrint(&buffer, "[\"0x{x}\",false]", .{block_number}) catch unreachable;
            const block = try client.call("eth_getBlockByNumber", block_params);
            if (block == .null) return .not_found;
            const canonical_hash = try rpc.fixed(32, try rpc.field(block, "hash"));
            if (!std.mem.eql(u8, &canonical_hash, &block_hash)) return .not_found;
            driver.tip_number = @max(driver.tip_number, block_number);
            return .{ .mined = .{
                .block_number = block_number,
                .tip_number = driver.tip_number,
                .success = success,
            } };
        }

        fn estimate_gas(driver: *Self, client: *rpc.Client, candidate: Candidate) Error!u64 {
            assert(candidate.blobs.len == 0);
            var to_buffer: [56]u8 = undefined;
            // A creation omits `to`.
            const to_field = if (candidate.to) |to|
                std.fmt.bufPrint(&to_buffer, "\"to\":\"0x{x}\",", .{&to.bytes}) catch
                    unreachable // Fixed-size content.
            else
                "";
            const params = std.fmt.bufPrint(
                driver.params_buffer,
                "[{{\"from\":\"0x{x}\",{s}\"value\":\"0x{x}\",\"data\":\"0x{x}\"}}]",
                .{ &driver.config.from.bytes, to_field, candidate.value, candidate.data },
            ) catch unreachable; // params_buffer holds twice the largest payload.
            assert(params.len > 0);
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
