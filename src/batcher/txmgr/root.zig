//! Transaction manager: sends batcher payloads to L1 and keeps them alive until they
//! are included.
//!
//! Every payload gets the next nonce of the batcher account and occupies a slot until
//! the account's mined nonce passes it. A slot whose transaction is not mined within
//! `resubmit_after_ms` is re-signed with bumped fees under the same nonce (op txmgr
//! semantics), so a stuck or dropped transaction never blocks later nonces for long.
//! Slots and buffers are allocated once; the account key is used only for signing.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../rpc/root.zig");
const txdata = @import("../txdata/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const blobs = @import("../blobs/root.zig");
const kzg = blobs.kzg;
const blob_tx = txdata.blob;

const Address = primitives.Address;

pub const Config = struct {
    chain_id: u64,
    private_key: [32]u8,
    /// Sender address of `private_key`.
    from: Address,
    to: Address,
    slots_max: u8 = 8,
    tx_data_bytes_max: u32 = 128 * 1024,
    resubmit_after_ms: u64 = 12_000,
    /// "nonce too high" (a lower nonce has not reached this RPC backend yet) re-sends the
    /// same tx after `publish_retry_delay_ms`, at most this many times per tx, before it
    /// surfaces as an error (base/base `--publish-max-retries`, `--publish-retry-delay`).
    publish_max_retries: u8 = 10,
    publish_retry_delay_ms: u64 = 1_000,
    tip_wei_default: u128 = 1_000_000_000,
    /// Replacement fee bump in percent (geth requires 10 for non-blob transactions).
    bump_percent: u8 = 10,
    /// `blobs`: one frame per blob, one blob per transaction (EIP-4844).
    data_availability: DataAvailability = .calldata,
    /// Blob mode: frames (one per blob) packed into each transaction, 1..6.
    blobs_per_tx: u8 = 1,
    /// Calldata mode: also load the KZG prover and blob buffers so `force_blobs` can switch
    /// new transactions to blobs at runtime (base/base `force_blobs_when_throttling`).
    blob_override: bool = false,
    /// L1 blocks a tx must be buried under before its slot is freed (base/base
    /// `--num-confirmations`; 1 = included in the latest block).
    confirmations: u64 = 1,
    /// Floors for the suggested tip and the base fee the fee cap is computed from
    /// (base/base `--min-tip-cap`, `--min-basefee`).
    min_tip_wei: u128 = 0,
    min_base_fee_wei: u128 = 0,
};

/// Pull interface for transaction payloads (the channel manager's frames). A returned
/// slice is valid until the next call.
pub const FrameSource = struct {
    context: *anyopaque,
    next_fn: *const fn (context: *anyopaque) ?[]const u8,

    fn next(source: FrameSource) ?[]const u8 {
        return source.next_fn(source.context);
    }
};

const blobs_per_tx_max = blob_tx.blobs_per_tx_max;

pub const DataAvailability = enum { calldata, blobs };

pub const Slot = struct {
    state: enum { free, pending } = .free,
    nonce: u64 = 0,
    fees: txdata.Fees = .{ .max_fee_per_gas = 0, .max_priority_fee_per_gas = 0 },
    data: []u8,
    data_length: u32 = 0,
    sent_at_ms: u64 = 0,
    attempts: u32 = 0,
    /// The pool kept another tx at this nonce (ours from before a restart or reset, or
    /// a dropped one): bump and resend on the next poll instead of after a full period.
    replace_now: bool = false,
    /// A "nonce too high" retry of the same tx is due at this time.
    retry_at_ms: ?u64 = null,
    retries_left: u8 = 0,
    hash: primitives.B256 = .zero,
    /// Blob mode only: the encoded blob, its commitment and proof (computed once at
    /// submit; resubmissions only re-sign), and the current max blob fee.
    blobs: [blobs_per_tx_max]?*kzg.Blob = @splat(null),
    commitments: [blobs_per_tx_max]kzg.Commitment = @splat(@splat(0)),
    proofs: [blobs_per_tx_max]kzg.Proof = @splat(@splat(0)),
    blob_count: u8 = 0,
    blob_fee: u128 = 0,
};

pub const Error = rpc.Error || rpc.DecodeError || txdata.SignError || kzg.Error ||
    blobs.EncodeError || error{NoFreeSlot};

/// Upper bound of one blob's share of a blob transaction's network encoding.
const blob_network_bytes_per_blob = blobs.bytes_per_blob + 128;

pub const TxManager = struct {
    config: Config,
    slots: []Slot,
    next_nonce: ?u64,
    /// After a reset: the highest dropped nonce and the fees it carried. A new tx at a
    /// nonce up to this one bumps those fees, so it replaces a dropped copy still pooled.
    replaced: ?Replaced = null,
    /// When a nonce gap (no slot holds the account's `latest` nonce while later slots
    /// wait) was first seen; `needs_reset` reports it once it outlives a resubmit period.
    gap_since_ms: ?u64 = null,
    raw_buffer: []u8,
    params_buffer: []u8,
    prover: ?*kzg.Prover,
    /// Send new transactions as blobs even in calldata mode (needs `blob_override`).
    /// Pending ones keep their type: geth never replaces across blob and non-blob txs.
    force_blobs: bool = false,

    const Replaced = struct { nonce_max: u64, fees: txdata.Fees, blob_fee: u128 };

    pub fn init(allocator: std.mem.Allocator, config: Config) !TxManager {
        assert(config.slots_max > 0);
        assert(config.confirmations >= 1);
        assert(config.bump_percent >= 10);
        const slots = try allocator.alloc(Slot, config.slots_max);
        errdefer allocator.free(slots);
        var initialized: usize = 0;
        const use_blobs = config.data_availability == .blobs or config.blob_override;
        if (use_blobs) assert(config.tx_data_bytes_max <= blobs.blob_data_length_max);
        assert(config.blobs_per_tx >= 1 and config.blobs_per_tx <= blobs_per_tx_max);
        const blob_count: u8 = if (use_blobs) config.blobs_per_tx else 0;
        errdefer for (slots[0..initialized]) |slot| destroy_blobs(allocator, slot);
        for (slots) |*slot| {
            slot.* = .{ .data = try allocator.alloc(u8, config.tx_data_bytes_max) };
            initialized += 1;
            for (slot.blobs[0..blob_count]) |*blob| blob.* = try allocator.create(kzg.Blob);
        }
        const blob_bytes = @as(usize, blob_count) * blob_network_bytes_per_blob + 1024;
        const raw_length = @max(config.tx_data_bytes_max + 512, blob_bytes);
        const raw_buffer = try allocator.alloc(u8, raw_length);
        errdefer allocator.free(raw_buffer);
        const params_buffer = try allocator.alloc(u8, 2 * raw_buffer.len + 16);
        errdefer allocator.free(params_buffer);
        const prover = if (use_blobs) try create_prover(allocator) else null;
        return .{
            .config = config,
            .slots = slots,
            .next_nonce = null,
            .raw_buffer = raw_buffer,
            .params_buffer = params_buffer,
            .prover = prover,
        };
    }

    fn destroy_blobs(allocator: std.mem.Allocator, slot: Slot) void {
        allocator.free(slot.data);
        for (slot.blobs) |maybe_blob| {
            if (maybe_blob) |blob| allocator.destroy(blob);
        }
    }

    fn create_prover(allocator: std.mem.Allocator) !*kzg.Prover {
        const prover = try allocator.create(kzg.Prover);
        errdefer allocator.destroy(prover);
        prover.* = try kzg.Prover.init(allocator);
        return prover;
    }

    pub fn deinit(manager: *TxManager, allocator: std.mem.Allocator) void {
        for (manager.slots) |slot| destroy_blobs(allocator, slot);
        allocator.free(manager.slots);
        if (manager.prover) |prover| {
            prover.deinit(allocator);
            allocator.destroy(prover);
        }
        allocator.free(manager.raw_buffer);
        allocator.free(manager.params_buffer);
        manager.* = undefined;
    }

    pub fn pending_count(manager: *const TxManager) u32 {
        var count: u32 = 0;
        for (manager.slots) |slot| count += @intFromBool(slot.state == .pending);
        return count;
    }

    pub fn has_capacity(manager: *const TxManager) bool {
        return manager.pending_count() < manager.slots.len;
    }

    /// Queues one payload under the next nonce and sends it.
    pub fn submit(
        manager: *TxManager,
        client: *rpc.Client,
        tx_data: []const u8,
        now_ms: u64,
    ) Error!void {
        var single: SingleFrame = .{ .frame = tx_data };
        const sent = try manager.submit_from(client, single.source(), now_ms);
        assert(sent and single.frame == null);
    }

    /// Pulls payloads from `frames` into one transaction (one frame for calldata, up to
    /// `blobs_per_tx` blobs) and sends it under the next nonce. Nonce and fees are read
    /// before any frame is pulled, so an RPC failure never drops a frame. Returns false
    /// when `frames` was empty.
    pub fn submit_from(
        manager: *TxManager,
        client: *rpc.Client,
        frames: FrameSource,
        now_ms: u64,
    ) Error!bool {
        const slot = for (manager.slots) |*slot| {
            if (slot.state == .free) break slot;
        } else return error.NoFreeSlot;
        // `latest`, like base/base: pooled txs we do not track (a previous run's, or ones
        // dropped by a reset) are replaced at their nonces, never adopted. An adopted tx
        // that L1 evicts would leave a nonce gap nothing re-sends.
        const nonce = manager.next_nonce orelse try manager.account_nonce(client, "latest");
        var fees = try manager.suggested_fees(client);
        const as_blobs = manager.sends_blobs();
        var blob_fee = if (as_blobs) try manager.suggested_blob_fee(client) else 0;
        if (manager.replaced) |replaced| {
            if (nonce <= replaced.nonce_max) {
                fees = txdata.bump_fees(replaced.fees, fees, manager.replacement_bump_percent());
                blob_fee = @max(blob_fee, replaced.blob_fee *| 2);
            } else manager.replaced = null;
        }
        slot.blob_count = 0;
        if (as_blobs) {
            const prover = manager.prover.?;
            while (slot.blob_count < manager.config.blobs_per_tx) : (slot.blob_count += 1) {
                const tx_data = frames.next() orelse break;
                const index = slot.blob_count;
                const blob = slot.blobs[index].?;
                try blobs.encode(tx_data, blob);
                slot.commitments[index] = try prover.commitment(blob);
                slot.proofs[index] = try prover.blob_proof(blob, &slot.commitments[index]);
            }
            if (slot.blob_count == 0) return false;
        } else {
            const tx_data = frames.next() orelse return false;
            assert(tx_data.len > 0 and tx_data.len <= manager.config.tx_data_bytes_max);
            @memcpy(slot.data[0..tx_data.len], tx_data);
            slot.data_length = @intCast(tx_data.len);
        }
        slot.state = .pending;
        slot.nonce = nonce;
        slot.fees = fees;
        slot.blob_fee = blob_fee;
        slot.sent_at_ms = 0;
        slot.attempts = 0;
        slot.retries_left = manager.config.publish_max_retries;
        manager.next_nonce = nonce + 1;
        try manager.send(client, slot, now_ms);
        assert(slot.state == .pending);
        return true;
    }

    /// Frees slots whose nonce was mined and resubmits stale ones. Returns the number
    /// of transactions confirmed by this poll.
    pub fn poll(manager: *TxManager, client: *rpc.Client, now_ms: u64) Error!u32 {
        if (manager.pending_count() == 0) return 0;
        const mined_nonce = try manager.account_nonce(client, "latest");
        const confirmed_nonce = try manager.nonce_buried(client, mined_nonce);
        assert(confirmed_nonce <= mined_nonce or manager.config.confirmations > 1);
        manager.watch_gap(mined_nonce, now_ms);
        var confirmed: u32 = 0;
        for (manager.slots) |*slot| {
            if (slot.state != .pending) continue;
            if (slot.nonce < confirmed_nonce) {
                slot.state = .free;
                confirmed += 1;
                continue;
            }
            if (slot.nonce < mined_nonce) continue; // Mined; waiting for confirmations.
            if (slot.retry_at_ms) |retry_at_ms| {
                if (now_ms >= retry_at_ms) try manager.send(client, slot, now_ms);
                continue;
            }
            if (slot.replace_now or now_ms >= slot.sent_at_ms + manager.config.resubmit_after_ms) {
                try manager.bump(client, slot);
                try manager.send(client, slot, now_ms);
            }
        }
        return confirmed;
    }

    /// Tracks a nonce gap: pending slots wait while none holds the `latest` nonce. That
    /// happens when a confirmed tx is reorged out and L1 then drops it; nothing would
    /// ever fill the nonce, so every later tx would wait forever.
    fn watch_gap(manager: *TxManager, mined_nonce: u64, now_ms: u64) void {
        var lowest_pending: ?u64 = null;
        for (manager.slots) |slot| {
            if (slot.state != .pending) continue;
            lowest_pending = @min(lowest_pending orelse slot.nonce, slot.nonce);
        }
        const gap = if (lowest_pending) |lowest| lowest > mined_nonce else false;
        if (!gap) {
            manager.gap_since_ms = null;
        } else if (manager.gap_since_ms == null) {
            manager.gap_since_ms = now_ms;
        }
        assert(manager.gap_since_ms == null or lowest_pending != null);
    }

    /// True once a nonce gap has lasted a full resubmit period (a reorged-out tx had time
    /// to return). The caller must then `reset` and requeue the dropped frames' data.
    pub fn needs_reset(manager: *const TxManager, now_ms: u64) bool {
        const since = manager.gap_since_ms orelse return false;
        return now_ms -| since >= manager.config.resubmit_after_ms;
    }

    /// Forgets all pending work after a reset (the caller regenerates their data). The
    /// next submit reads the `latest` nonce, filling any gap, and replaces dropped txs
    /// that may still sit in the pool with bumped fees.
    pub fn reset(manager: *TxManager) void {
        for (manager.slots) |*slot| {
            if (slot.state != .pending) continue;
            slot.state = .free;
            var replaced: Replaced = manager.replaced orelse
                .{ .nonce_max = slot.nonce, .fees = slot.fees, .blob_fee = slot.blob_fee };
            replaced.nonce_max = @max(replaced.nonce_max, slot.nonce);
            replaced.fees = .{
                .max_fee_per_gas = @max(replaced.fees.max_fee_per_gas, slot.fees.max_fee_per_gas),
                .max_priority_fee_per_gas = @max(
                    replaced.fees.max_priority_fee_per_gas,
                    slot.fees.max_priority_fee_per_gas,
                ),
            };
            replaced.blob_fee = @max(replaced.blob_fee, slot.blob_fee);
            manager.replaced = replaced;
        }
        manager.next_nonce = null;
        manager.gap_since_ms = null;
        assert(manager.pending_count() == 0);
    }

    /// Whether the next new transaction carries blobs.
    pub fn sends_blobs(manager: *const TxManager) bool {
        if (manager.prover == null) return false;
        return manager.config.data_availability == .blobs or manager.force_blobs;
    }

    fn replacement_bump_percent(manager: *const TxManager) u8 {
        if (manager.prover != null) return blob_tx.blob_bump_percent;
        return manager.config.bump_percent;
    }

    fn bump(manager: *TxManager, client: *rpc.Client, slot: *Slot) Error!void {
        const suggested = try manager.suggested_fees(client);
        if (slot.blob_count == 0) {
            slot.fees = txdata.bump_fees(slot.fees, suggested, manager.config.bump_percent);
            return;
        }
        // Blob replacements must double every fee (geth's blob pool rule).
        slot.fees = txdata.bump_fees(slot.fees, suggested, blob_tx.blob_bump_percent);
        const blob_fee = try manager.suggested_blob_fee(client);
        slot.blob_fee = @max(slot.blob_fee *| 2, blob_fee);
        assert(slot.blob_fee > 0);
    }

    /// Signs `slot` and returns its raw network encoding (in `raw_buffer`).
    fn sign_slot(manager: *TxManager, slot: *Slot) Error!struct { []u8, primitives.B256 } {
        if (slot.blob_count == 0) {
            const data = slot.data[0..slot.data_length];
            const envelope = try txdata.sign_eip1559(.{
                .chain_id = manager.config.chain_id,
                .nonce = slot.nonce,
                .fees = slot.fees,
                .gas_limit = txdata.calldata_gas(data),
                .to = manager.config.to,
                .data = data,
            }, manager.config.private_key);
            return .{ txdata.encode_raw(envelope, manager.raw_buffer), envelope.hash() };
        }
        const count = slot.blob_count;
        assert(count >= 1 and count <= blobs_per_tx_max);
        var hashes: [blobs_per_tx_max][32]u8 = undefined;
        var blob_list: [blobs_per_tx_max]*const kzg.Blob = undefined;
        for (0..count) |index| {
            hashes[index] = kzg.versioned_hash(&slot.commitments[index]);
            blob_list[index] = slot.blobs[index].?;
        }
        var hash_buffer: [33 * blobs_per_tx_max]u8 = undefined;
        const envelope = try blob_tx.sign(.{
            .chain_id = manager.config.chain_id,
            .nonce = slot.nonce,
            .fees = slot.fees,
            .blob_fee_wei = slot.blob_fee,
            .to = manager.config.to,
            .versioned_hashes = hashes[0..count],
        }, &hash_buffer, manager.config.private_key);
        const sidecar: blob_tx.Sidecar = .{
            .blobs = blob_list[0..count],
            .commitments = slot.commitments[0..count],
            .proofs = slot.proofs[0..count],
        };
        return .{ blob_tx.encode_network(envelope, sidecar, manager.raw_buffer), envelope.hash() };
    }

    fn send(manager: *TxManager, client: *rpc.Client, slot: *Slot, now_ms: u64) Error!void {
        const raw, const hash = try manager.sign_slot(slot);
        const params = std.fmt.bufPrint(manager.params_buffer, "[\"0x{x}\"]", .{raw}) catch
            unreachable; // params_buffer holds twice the largest raw transaction.
        slot.sent_at_ms = now_ms;
        slot.attempts += 1;
        slot.hash = hash;
        slot.replace_now = false;
        slot.retry_at_ms = null;
        _ = client.call("eth_sendRawTransaction", params) catch |err| switch (err) {
            // Known benign answers: already mined, already pooled, or the previous
            // attempt still wins; `poll` decides what happens next.
            error.RpcError => {
                const message = client.last_error();
                if (contains_ignore_case(message, "nonce too high") and slot.retries_left > 0) {
                    slot.retries_left -= 1;
                    slot.retry_at_ms = now_ms + manager.config.publish_retry_delay_ms;
                    return;
                }
                if (!benign_send_error(message)) return err;
                slot.replace_now = contains_ignore_case(message, "underpriced");
            },
            else => return err,
        };
    }

    /// The account nonce as of `confirmations - 1` blocks below the head: txs below it
    /// are buried deep enough to free their slots.
    fn nonce_buried(manager: *TxManager, client: *rpc.Client, mined_nonce: u64) Error!u64 {
        const depth = manager.config.confirmations;
        if (depth <= 1) return mined_nonce;
        const head = try rpc.quantity(u64, try client.call("eth_blockNumber", "[]"));
        if (head + 1 < depth) return 0; // Nothing is buried deep enough yet.
        var tag_buffer: [24]u8 = undefined;
        const tag = std.fmt.bufPrint(&tag_buffer, "0x{x}", .{head + 1 - depth}) catch
            unreachable; // A u64 quantity fits.
        return manager.account_nonce(client, tag);
    }

    fn account_nonce(manager: *TxManager, client: *rpc.Client, tag: []const u8) Error!u64 {
        var buffer: [96]u8 = undefined;
        const params = std.fmt.bufPrint(&buffer, "[\"0x{x}\",\"{s}\"]", .{
            &manager.config.from.bytes,
            tag,
        }) catch unreachable; // Fixed-size content.
        return rpc.quantity(u64, try client.call("eth_getTransactionCount", params));
    }

    fn suggested_fees(manager: *TxManager, client: *rpc.Client) Error!txdata.Fees {
        const head = try client.call("eth_getBlockByNumber", "[\"latest\",false]");
        const base_fee = @max(
            try rpc.quantity(u128, try rpc.field(head, "baseFeePerGas")),
            manager.config.min_base_fee_wei,
        );
        const tip = blk: {
            const value = client.call("eth_maxPriorityFeePerGas", "[]") catch
                break :blk manager.config.tip_wei_default;
            break :blk rpc.quantity(u128, value) catch manager.config.tip_wei_default;
        };
        return txdata.suggest_fees(base_fee, @max(tip, manager.config.min_tip_wei, 1));
    }

    /// Twice the current blob base fee (`eth_blobBaseFee`, else from `excessBlobGas`).
    fn suggested_blob_fee(manager: *TxManager, client: *rpc.Client) Error!u128 {
        assert(manager.prover != null);
        const base = blk: {
            if (client.call("eth_blobBaseFee", "[]")) |value| {
                if (rpc.quantity(u128, value)) |fee| break :blk fee else |_| {}
            } else |_| {}
            const head = try client.call("eth_getBlockByNumber", "[\"latest\",false]");
            const excess = try rpc.quantity(u64, try rpc.field(head, "excessBlobGas"));
            break :blk blob_tx.blob_base_fee(excess);
        };
        return @max(base *| 2, blob_tx.blob_base_fee_min);
    }
};

/// A `FrameSource` over one payload.
const SingleFrame = struct {
    frame: ?[]const u8,

    fn source(single: *SingleFrame) FrameSource {
        return .{ .context = single, .next_fn = next };
    }

    fn next(context: *anyopaque) ?[]const u8 {
        const single: *SingleFrame = @ptrCast(@alignCast(context));
        defer single.frame = null;
        return single.frame;
    }
};

fn contains_ignore_case(message: []const u8, needle: []const u8) bool {
    var lower_buffer: [256]u8 = undefined;
    const lower = std.ascii.lowerString(&lower_buffer, message[0..@min(message.len, 256)]);
    return std.mem.indexOf(u8, lower, needle) != null;
}

fn benign_send_error(message: []const u8) bool {
    const benign = [_][]const u8{
        "nonce too low",
        "already known",
        "known transaction",
        "replacement transaction underpriced",
    };
    var lower_buffer: [256]u8 = undefined;
    const lower = std.ascii.lowerString(&lower_buffer, message[0..@min(message.len, 256)]);
    for (benign) |needle| {
        if (std.mem.indexOf(u8, lower, needle) != null) return true;
    }
    return false;
}

const testing = std.testing;
const consensus = @import("../../common/consensus/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const accounts = @import("../devnet/accounts.zig");

/// Scripted L1: tracks the mined nonce and records sent transactions.
const FakeL1 = struct {
    mined_nonce: u64 = 5,
    sends: u32 = 0,
    reject_with: ?[]const u8 = null,
    /// First bytes of the last sent raw transaction (enough for a blob tx body).
    last_raw_prefix: [600]u8 = undefined,

    fn transport(l1: *FakeL1) rpc.Transport {
        return .{ .context = l1, .send_fn = send };
    }

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const l1: *FakeL1 = @ptrCast(@alignCast(context));
        const id_start = std.mem.indexOf(u8, body, "\"id\":").? + 5;
        const id = body[id_start..][0..std.mem.indexOfScalar(u8, body[id_start..], ',').?];
        var result_buffer: [64]u8 = undefined;
        const result: []const u8 = if (std.mem.indexOf(u8, body, "eth_getTransactionCount")) |_|
            std.fmt.bufPrint(&result_buffer, "\"0x{x}\"", .{l1.mined_nonce}) catch unreachable
        else if (std.mem.indexOf(u8, body, "eth_getBlockByNumber")) |_|
            "{\"baseFeePerGas\":\"0x64\"}"
        else if (std.mem.indexOf(u8, body, "eth_maxPriorityFeePerGas")) |_|
            "\"0x2\""
        else if (std.mem.indexOf(u8, body, "eth_blobBaseFee")) |_|
            "\"0x3\""
        else blk: {
            l1.sends += 1;
            const hex_start = std.mem.indexOf(u8, body, "[\"0x").? + 4;
            const hex_end = std.mem.indexOfScalarPos(u8, body, hex_start, '"').?;
            const hex_length = @min(hex_end - hex_start, 2 * l1.last_raw_prefix.len);
            _ = std.fmt.hexToBytes(&l1.last_raw_prefix, body[hex_start..][0..hex_length]) catch
                unreachable; // The manager writes lowercase hex.
            if (l1.reject_with) |message| {
                const text = std.fmt.bufPrint(response, "{{\"jsonrpc\":\"2.0\",\"id\":{s}," ++
                    "\"error\":{{\"code\":-32000,\"message\":\"{s}\"}}}}", .{ id, message }) catch
                    return error.ResponseTooLarge;
                return text.len;
            }
            break :blk "\"0x00\"";
        };
        const envelope = "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":{s}}}";
        const text = std.fmt.bufPrint(response, envelope, .{ id, result }) catch
            return error.ResponseTooLarge;
        return text.len;
    }
};

test "txmgr: nonce too high retries the same tx after the delay, then surfaces" {
    const batcher = accounts.derive_dev(@backingInt(accounts.Role.batcher));
    var l1: FakeL1 = .{ .reject_with = "nonce too high" };
    var client = try rpc.Client.init(testing.allocator, l1.transport(), .{
        .request_bytes_max = 8192,
        .response_bytes_max = 4096,
        .parse_bytes_max = 64 * 1024,
    });
    defer client.deinit(testing.allocator);
    var manager = try TxManager.init(testing.allocator, .{
        .chain_id = 900,
        .private_key = batcher.private_key,
        .from = batcher.address,
        .to = .{ .bytes = @splat(0xff) },
        .slots_max = 2,
        .tx_data_bytes_max = 1024,
        .resubmit_after_ms = 100_000,
        .publish_max_retries = 2,
        .publish_retry_delay_ms = 50,
    });
    defer manager.deinit(testing.allocator);
    try manager.submit(&client, "\x00frame-a", 0);
    const hash = manager.slots[0].hash;
    const fees = manager.slots[0].fees;
    try testing.expectEqual(@as(?u64, 50), manager.slots[0].retry_at_ms);
    // Not due yet: nothing is sent.
    _ = try manager.poll(&client, 49);
    try testing.expectEqual(@as(u32, 1), l1.sends);
    // Due: the same signed tx (same fees, same hash) goes out again.
    _ = try manager.poll(&client, 50);
    try testing.expectEqual(@as(u32, 2), l1.sends);
    try testing.expectEqual(hash, manager.slots[0].hash);
    try testing.expectEqual(fees, manager.slots[0].fees);
    // Retries exhausted: the error surfaces and the slot waits for normal resubmission.
    try testing.expectError(error.RpcError, manager.poll(&client, 100));
    try testing.expectEqual(@as(?u64, null), manager.slots[0].retry_at_ms);
    try testing.expectEqual(@as(u32, 3), l1.sends);
    _ = try manager.poll(&client, 10_000);
    try testing.expectEqual(@as(u32, 3), l1.sends);
    // The backend catches up: the next retry would succeed; a new tx gets fresh retries.
    l1.reject_with = null;
    try manager.submit(&client, "\x00frame-b", 10_000);
    try testing.expectEqual(@as(u8, 2), manager.slots[1].retries_left);
    try testing.expectEqual(@as(?u64, null), manager.slots[1].retry_at_ms);
}

test "txmgr: seeded fuzz of nonce-too-high retry bounds" {
    const batcher = accounts.derive_dev(@backingInt(accounts.Role.batcher));
    var prng = Prng.init(0x2a11);
    var l1: FakeL1 = .{};
    var client = try rpc.Client.init(testing.allocator, l1.transport(), .{
        .request_bytes_max = 8192,
        .response_bytes_max = 4096,
        .parse_bytes_max = 64 * 1024,
    });
    defer client.deinit(testing.allocator);
    for (0..20) |_| {
        const retries: u8 = @intCast(prng.below(6));
        var manager = try TxManager.init(testing.allocator, .{
            .chain_id = 900,
            .private_key = batcher.private_key,
            .from = batcher.address,
            .to = .{ .bytes = @splat(0xff) },
            .slots_max = 1,
            .tx_data_bytes_max = 1024,
            .resubmit_after_ms = 1_000_000,
            .publish_max_retries = retries,
            .publish_retry_delay_ms = prng.range(1, 100),
        });
        defer manager.deinit(testing.allocator);
        l1 = .{ .reject_with = "nonce too high" };
        manager.submit(&client, "\x00frame", 0) catch {};
        var now_ms: u64 = 0;
        for (0..40) |_| {
            now_ms += prng.range(0, 120);
            if (prng.chance(1, 8)) l1.reject_with = null;
            _ = manager.poll(&client, now_ms) catch {};
        }
        // The first send, `retries` retries, and the send that surfaces the error; nothing
        // more before normal resubmission.
        try testing.expect(l1.sends <= 2 + @as(u32, retries));
        try testing.expect(manager.slots[0].retries_left <= retries);
    }
}

test "txmgr: fuzz nonce-too-high retry bounds" {
    try testing.fuzz({}, fuzz_publish_retries, .{});
}

/// Byte 0: retries; byte 1: delay; then per byte, a time step (low 7 bits) and whether
/// the backend caught up (high bit).
fn fuzz_publish_retries(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [64]u8 = @splat(0);
    const length = smith.slice(&bytes);
    const batcher = accounts.derive_dev(@backingInt(accounts.Role.batcher));
    var l1: FakeL1 = .{ .reject_with = "nonce too high" };
    var client = try rpc.Client.init(testing.allocator, l1.transport(), .{
        .request_bytes_max = 8192,
        .response_bytes_max = 4096,
        .parse_bytes_max = 64 * 1024,
    });
    defer client.deinit(testing.allocator);
    const retries: u8 = bytes[0] % 8;
    var manager = try TxManager.init(testing.allocator, .{
        .chain_id = 900,
        .private_key = batcher.private_key,
        .from = batcher.address,
        .to = .{ .bytes = @splat(0xff) },
        .slots_max = 1,
        .tx_data_bytes_max = 1024,
        .resubmit_after_ms = 1_000_000,
        .publish_max_retries = retries,
        .publish_retry_delay_ms = @as(u64, bytes[1]) + 1,
    });
    defer manager.deinit(testing.allocator);
    manager.submit(&client, "\x00frame", 0) catch {};
    var now_ms: u64 = 0;
    for (bytes[2..@max(2, length)]) |byte| {
        now_ms += byte & 0x7f;
        if (byte & 0x80 != 0) l1.reject_with = null;
        _ = manager.poll(&client, now_ms) catch {};
    }
    try testing.expect(l1.sends <= 2 + @as(u32, retries));
    try testing.expect(manager.slots[0].retries_left <= retries);
}

test "txmgr: nonces, confirmation, resubmission with bumped fees" {
    const batcher = accounts.derive_dev(@backingInt(accounts.Role.batcher));
    var l1: FakeL1 = .{};
    var client = try rpc.Client.init(testing.allocator, l1.transport(), .{
        .request_bytes_max = 8192,
        .response_bytes_max = 4096,
        .parse_bytes_max = 64 * 1024,
    });
    defer client.deinit(testing.allocator);
    var manager = try TxManager.init(testing.allocator, .{
        .chain_id = 900,
        .private_key = batcher.private_key,
        .from = batcher.address,
        .to = .{ .bytes = @splat(0xff) },
        .slots_max = 2,
        .tx_data_bytes_max = 1024,
        .resubmit_after_ms = 1000,
    });
    defer manager.deinit(testing.allocator);

    try manager.submit(&client, "\x00frame-a", 0);
    try manager.submit(&client, "\x00frame-b", 0);
    try testing.expect(!manager.has_capacity());
    try testing.expectError(error.NoFreeSlot, manager.submit(&client, "\x00c", 0));
    try testing.expectEqual(@as(u64, 5), manager.slots[0].nonce);
    try testing.expectEqual(@as(u64, 6), manager.slots[1].nonce);
    try testing.expectEqual(@as(u32, 2), l1.sends);

    // Nothing mined, not stale yet: no resend.
    try testing.expectEqual(@as(u32, 0), try manager.poll(&client, 500));
    try testing.expectEqual(@as(u32, 2), l1.sends);
    // First mined; second stale: resent with at least 10% higher fees.
    l1.mined_nonce = 6;
    const fee_before = manager.slots[1].fees.max_fee_per_gas;
    try testing.expectEqual(@as(u32, 1), try manager.poll(&client, 1500));
    try testing.expectEqual(@as(u32, 3), l1.sends);
    try testing.expect(manager.slots[1].fees.max_fee_per_gas * 10 >= fee_before * 11);
    try testing.expectEqual(@as(u32, 2), manager.slots[1].attempts);
    // Benign node errors keep the slot; others surface.
    l1.reject_with = "replacement transaction underpriced";
    try testing.expectEqual(@as(u32, 0), try manager.poll(&client, 3000));
    l1.reject_with = "insufficient funds";
    try testing.expectError(error.RpcError, manager.poll(&client, 4500));
    l1.reject_with = null;
    l1.mined_nonce = 7;
    try testing.expectEqual(@as(u32, 1), try manager.poll(&client, 5000));
    try testing.expectEqual(@as(u32, 0), manager.pending_count());
}

test "txmgr: blob mode sends a 4844 tx committing to the frame and doubles fees on bump" {
    const rlp = @import("../../common/rlp/root.zig");
    const batcher = accounts.derive_dev(@backingInt(accounts.Role.batcher));
    var l1: FakeL1 = .{ .mined_nonce = 0 };
    var client = try rpc.Client.init(testing.allocator, l1.transport(), .{
        .request_bytes_max = 300 * 1024,
        .response_bytes_max = 4096,
        .parse_bytes_max = 64 * 1024,
    });
    defer client.deinit(testing.allocator);
    var manager = try TxManager.init(testing.allocator, .{
        .chain_id = 900,
        .private_key = batcher.private_key,
        .from = batcher.address,
        .to = .{ .bytes = @splat(0xff) },
        .slots_max = 1,
        .tx_data_bytes_max = 4096,
        .resubmit_after_ms = 1000,
        .data_availability = .blobs,
    });
    defer manager.deinit(testing.allocator);
    try manager.submit(&client, "\x00frame-in-a-blob", 0);
    const slot = &manager.slots[0];
    try testing.expectEqual(@as(u128, 6), slot.blob_fee);
    const decoded_data = try testing.allocator.alloc(u8, blobs.blob_data_length_max);
    defer testing.allocator.free(decoded_data);
    const decoded = try blobs.decode(slot.blobs[0].?, decoded_data);
    try testing.expectEqualStrings("\x00frame-in-a-blob", decoded);

    // The network form's body is a signed 4844 tx naming the blob's versioned hash.
    try testing.expectEqual(@as(u8, 0x03), l1.last_raw_prefix[0]);
    // Only a prefix was captured, so read the long list header by hand.
    const list_prefix = l1.last_raw_prefix[1];
    try testing.expect(list_prefix > 0xf7);
    const outer_header_length: usize = 1 + list_prefix - 0xf7;
    var typed: [600]u8 = undefined;
    typed[0] = 0x03;
    var outer = rlp.Decoder.init(l1.last_raw_prefix[1 + outer_header_length ..]);
    const body = try outer.raw();
    @memcpy(typed[1..][0..body.len], body);
    const envelope = try consensus.Envelope.decode(typed[0 .. body.len + 1]);
    const versioned = envelope.eip4844.tx.blob_versioned_hashes.get(0);
    try testing.expectEqualSlices(u8, &kzg.versioned_hash(&slot.commitments[0]), &versioned.bytes);
    try testing.expect(envelope.hash().eql(slot.hash));

    // Stale: every fee at least doubles.
    const fees_before = slot.fees;
    try testing.expectEqual(@as(u32, 0), try manager.poll(&client, 1500));
    try testing.expectEqual(@as(u32, 2), l1.sends);
    try testing.expectEqual(@as(u128, 12), slot.blob_fee);
    try testing.expect(slot.fees.max_fee_per_gas >= 2 * fees_before.max_fee_per_gas);
    const tip_before = fees_before.max_priority_fee_per_gas;
    try testing.expect(slot.fees.max_priority_fee_per_gas >= 2 * tip_before);
}

const ListFrames = struct {
    frames: []const []const u8,
    next_index: usize = 0,

    fn source(list: *ListFrames) FrameSource {
        return .{ .context = list, .next_fn = next };
    }

    fn next(context: *anyopaque) ?[]const u8 {
        const list: *ListFrames = @ptrCast(@alignCast(context));
        if (list.next_index == list.frames.len) return null;
        defer list.next_index += 1;
        return list.frames[list.next_index];
    }
};

test "txmgr: blob mode packs up to blobs_per_tx frames per transaction" {
    const batcher = accounts.derive_dev(@backingInt(accounts.Role.batcher));
    var l1: FakeL1 = .{ .mined_nonce = 0 };
    var client = try rpc.Client.init(testing.allocator, l1.transport(), .{
        .request_bytes_max = 600 * 1024,
        .response_bytes_max = 4096,
        .parse_bytes_max = 64 * 1024,
    });
    defer client.deinit(testing.allocator);
    var manager = try TxManager.init(testing.allocator, .{
        .chain_id = 900,
        .private_key = batcher.private_key,
        .from = batcher.address,
        .to = .{ .bytes = @splat(0xff) },
        .slots_max = 2,
        .tx_data_bytes_max = 4096,
        .data_availability = .blobs,
        .blobs_per_tx = 2,
    });
    defer manager.deinit(testing.allocator);
    var list: ListFrames = .{ .frames = &.{ "\x00one", "\x00two", "\x00three" } };
    try testing.expect(try manager.submit_from(&client, list.source(), 0));
    try testing.expect(try manager.submit_from(&client, list.source(), 0));
    try testing.expectEqual(@as(u8, 2), manager.slots[0].blob_count);
    try testing.expectEqual(@as(u8, 1), manager.slots[1].blob_count);
    try testing.expectEqual(@as(u64, 1), manager.slots[1].nonce);
    const commitments = manager.slots[0].commitments;
    try testing.expect(!std.mem.eql(u8, &commitments[0], &commitments[1]));
    try testing.expectError(error.NoFreeSlot, manager.submit_from(&client, list.source(), 0));
    l1.mined_nonce = 2;
    try testing.expectEqual(@as(u32, 2), try manager.poll(&client, 0));
    try testing.expect(!try manager.submit_from(&client, list.source(), 0));
    try testing.expectEqual(@as(u32, 2), l1.sends);
}

test "txmgr: forced blobs switch new txs only; pending txs keep their type" {
    const batcher = accounts.derive_dev(@backingInt(accounts.Role.batcher));
    var l1: FakeL1 = .{ .mined_nonce = 0 };
    var client = try rpc.Client.init(testing.allocator, l1.transport(), .{
        .request_bytes_max = 600 * 1024,
        .response_bytes_max = 4096,
        .parse_bytes_max = 64 * 1024,
    });
    defer client.deinit(testing.allocator);
    var manager = try TxManager.init(testing.allocator, .{
        .chain_id = 900,
        .private_key = batcher.private_key,
        .from = batcher.address,
        .to = .{ .bytes = @splat(0xff) },
        .slots_max = 3,
        .tx_data_bytes_max = 4096,
        .resubmit_after_ms = 1000,
        .blobs_per_tx = 2,
        .blob_override = true,
    });
    defer manager.deinit(testing.allocator);
    try testing.expect(!manager.sends_blobs());
    var list: ListFrames = .{ .frames = &.{ "\x00one", "\x00two", "\x00three", "\x00four" } };
    try testing.expect(try manager.submit_from(&client, list.source(), 0));
    try testing.expectEqual(@as(u8, 0), manager.slots[0].blob_count);
    try testing.expectEqual(@as(u8, 0x02), l1.last_raw_prefix[0]); // EIP-1559 calldata.
    manager.force_blobs = true;
    try testing.expect(manager.sends_blobs());
    try testing.expect(try manager.submit_from(&client, list.source(), 0));
    try testing.expectEqual(@as(u8, 2), manager.slots[1].blob_count);
    try testing.expectEqual(@as(u8, 0x03), l1.last_raw_prefix[0]); // EIP-4844 blobs.
    manager.force_blobs = false;
    try testing.expect(try manager.submit_from(&client, list.source(), 0));
    try testing.expectEqual(@as(u8, 0), manager.slots[2].blob_count);
    // Resubmissions re-sign each slot as its original type.
    const sends = l1.sends;
    _ = try manager.poll(&client, 5_000);
    try testing.expectEqual(sends + 3, l1.sends);
    try testing.expectEqual(@as(u8, 0), manager.slots[0].blob_count);
    try testing.expectEqual(@as(u8, 2), manager.slots[1].blob_count);
    try testing.expectEqual(@as(u128, 0), manager.slots[0].blob_fee);
    try testing.expect(manager.slots[1].blob_fee > 0);
}

/// An L1 with a nonce-indexed pool, reorgs, and tx loss. `fees[n]` is the max fee of the
/// tx known at nonce n (0: none); those at n >= `mined` are pooled. Mining advances over
/// contiguous pooled nonces; a reorg returns mined txs to the pool; a loss evicts pooled
/// txs. A same-nonce send must outbid the pooled tx by 10% (geth's replacement rule).
const LossyL1 = struct {
    mined: u64 = 0,
    fees: [pool_size]u128 = @splat(0),
    sends: u32 = 0,
    /// Every `mine` call produces a block; `nonce_at[b]` is the account nonce after it.
    head: u64 = 0,
    nonce_at: [history_size]u64 = @splat(0),

    const pool_size = 512;
    const history_size = 4096;

    fn transport(l1: *LossyL1) rpc.Transport {
        return .{ .context = l1, .send_fn = send };
    }

    fn mine(l1: *LossyL1, count_max: u64) void {
        var count: u64 = 0;
        while (count < count_max and l1.mined < pool_size and l1.fees[l1.mined] > 0) {
            l1.mined += 1;
            count += 1;
        }
        l1.head = @min(l1.head + 1, history_size - 1);
        l1.nonce_at[@intCast(l1.head)] = l1.mined;
    }

    /// Unmines the top `depth` txs back into the pool, then evicts each pooled tx with
    /// probability `loss_percent`.
    fn reorg_and_lose(l1: *LossyL1, prng: *Prng, depth: u64, loss_percent: u64) void {
        l1.mined -= @min(depth, l1.mined);
        for (l1.nonce_at[0..@intCast(l1.head + 1)]) |*nonce| nonce.* = @min(nonce.*, l1.mined);
        for (l1.fees[@intCast(l1.mined)..]) |*fee| {
            if (fee.* > 0 and prng.chance(loss_percent, 100)) fee.* = 0;
        }
    }

    fn pending_nonce(l1: *const LossyL1) u64 {
        var nonce = l1.mined;
        while (nonce < pool_size and l1.fees[nonce] > 0) nonce += 1;
        return nonce;
    }

    fn send(context: *anyopaque, body: []const u8, response: []u8) rpc.TransportError!usize {
        const l1: *LossyL1 = @ptrCast(@alignCast(context));
        const id_start = std.mem.indexOf(u8, body, "\"id\":").? + 5;
        const id = body[id_start..][0..std.mem.indexOfScalar(u8, body[id_start..], ',').?];
        var buffer: [64]u8 = undefined;
        const is_nonce_query = std.mem.indexOf(u8, body, "eth_getTransactionCount") != null;
        const result: []const u8 = if (is_nonce_query) blk: {
            const latest = std.mem.indexOf(u8, body, "\"latest\"") != null;
            const pending = std.mem.indexOf(u8, body, "\"pending\"") != null;
            const at_block = !latest and !pending;
            const nonce = if (latest) l1.mined else if (pending) l1.pending_nonce() else blk2: {
                const tag_start = std.mem.lastIndexOf(u8, body, ",\"0x").? + 4;
                const tag_end = std.mem.indexOfScalarPos(u8, body, tag_start, '"').?;
                const block = std.fmt.parseInt(u64, body[tag_start..tag_end], 16) catch
                    return error.TransportFailed;
                break :blk2 l1.nonce_at[@intCast(@min(block, history_size - 1))];
            };
            assert(!at_block or nonce <= l1.mined);
            break :blk std.fmt.bufPrint(&buffer, "\"0x{x}\"", .{nonce}) catch unreachable;
        } else if (std.mem.indexOf(u8, body, "eth_blockNumber")) |_|
            std.fmt.bufPrint(&buffer, "\"0x{x}\"", .{l1.head}) catch unreachable
        else if (std.mem.indexOf(u8, body, "eth_getBlockByNumber")) |_|
            "{\"baseFeePerGas\":\"0x64\"}"
        else if (std.mem.indexOf(u8, body, "eth_maxPriorityFeePerGas")) |_|
            "\"0x2\""
        else blk: {
            l1.sends += 1;
            const tx = sent_tx(body) catch return error.TransportFailed;
            if (tx.nonce >= pool_size) return error.TransportFailed;
            const error_message = l1.accept(tx.nonce, tx.fee) orelse break :blk "\"0x00\"";
            const text = std.fmt.bufPrint(response, "{{\"jsonrpc\":\"2.0\",\"id\":{s}," ++
                "\"error\":{{\"code\":-32000,\"message\":\"{s}\"}}}}", .{ id, error_message }) catch
                return error.ResponseTooLarge;
            return text.len;
        };
        const envelope = "{{\"jsonrpc\":\"2.0\",\"id\":{s},\"result\":{s}}}";
        const text = std.fmt.bufPrint(response, envelope, .{ id, result }) catch
            return error.ResponseTooLarge;
        return text.len;
    }

    /// Pools the tx, or returns geth's error message.
    fn accept(l1: *LossyL1, nonce: u64, fee: u128) ?[]const u8 {
        if (nonce < l1.mined) return "nonce too low";
        const pooled = l1.fees[@intCast(nonce)];
        if (pooled > 0 and fee * 100 < pooled * 110) return "replacement transaction underpriced";
        l1.fees[@intCast(nonce)] = fee;
        return null;
    }

    fn sent_tx(body: []const u8) !struct { nonce: u64, fee: u128 } {
        const hex_start = std.mem.indexOf(u8, body, "[\"0x").? + 4;
        const hex_end = std.mem.indexOfScalarPos(u8, body, hex_start, '"').?;
        var raw: [2048]u8 = undefined;
        const bytes = try std.fmt.hexToBytes(&raw, body[hex_start..hex_end]);
        const tx = (try consensus.Envelope.decode(bytes)).eip1559.tx;
        return .{ .nonce = tx.nonce, .fee = tx.max_fee_per_gas };
    }
};

fn lossy_manager(l1: *LossyL1, client: *rpc.Client) !TxManager {
    const batcher = accounts.derive_dev(@backingInt(accounts.Role.batcher));
    client.* = try rpc.Client.init(testing.allocator, l1.transport(), .{
        .request_bytes_max = 8192,
        .response_bytes_max = 4096,
        .parse_bytes_max = 64 * 1024,
    });
    errdefer client.deinit(testing.allocator);
    return TxManager.init(testing.allocator, .{
        .chain_id = 900,
        .private_key = batcher.private_key,
        .from = batcher.address,
        .to = .{ .bytes = @splat(0xff) },
        .slots_max = 4,
        .tx_data_bytes_max = 256,
        .resubmit_after_ms = 1000,
    });
}

test "txmgr: a confirmed tx reorged out and lost is detected and its nonce refilled" {
    var l1: LossyL1 = .{};
    var client: rpc.Client = undefined;
    var manager = try lossy_manager(&l1, &client);
    defer manager.deinit(testing.allocator);
    defer client.deinit(testing.allocator);
    try manager.submit(&client, "\x00a", 0);
    try manager.submit(&client, "\x00b", 0);
    l1.mine(2);
    try testing.expectEqual(@as(u32, 2), try manager.poll(&client, 100));
    // Nonce 1 is reorged out and the pool loses it; nonce 2 then waits forever.
    var prng = Prng.init(1);
    l1.reorg_and_lose(&prng, 1, 100);
    try testing.expectEqual(@as(u64, 1), l1.mined);
    try manager.submit(&client, "\x00c", 200);
    try testing.expectEqual(@as(u64, 2), manager.slots[0].nonce);
    _ = try manager.poll(&client, 300);
    try testing.expect(!manager.needs_reset(300)); // A reorged tx may still return.
    _ = try manager.poll(&client, 1300);
    try testing.expect(manager.needs_reset(1300));
    const dropped_fee = manager.slots[0].fees.max_fee_per_gas;
    manager.reset();
    try testing.expect(!manager.needs_reset(1300));
    // The requeued data goes out under the lost nonce, outbidding the dropped tx.
    try manager.submit(&client, "\x00b-again", 1400);
    try testing.expectEqual(@as(u64, 1), manager.slots[0].nonce);
    try testing.expect(manager.slots[0].fees.max_fee_per_gas > dropped_fee);
    try manager.submit(&client, "\x00c-again", 1400);
    l1.mine(8);
    try testing.expectEqual(@as(u64, 3), l1.mined);
    try testing.expectEqual(@as(u32, 2), try manager.poll(&client, 1500));
    try testing.expect(manager.replaced == null or manager.next_nonce.? > 2);
}

test "txmgr: seeded fuzz over reorgs and tx loss keeps the nonce stream live" {
    for (0..12) |seed| {
        var prng = Prng.init(0x10_55 + seed);
        var l1: LossyL1 = .{};
        var client: rpc.Client = undefined;
        var manager = try lossy_manager(&l1, &client);
        defer manager.deinit(testing.allocator);
        defer client.deinit(testing.allocator);
        manager.config.confirmations = 1 + seed % 3;
        var now_ms: u64 = 0;
        // Faulty phase, then a quiet phase in which mining must make progress.
        for (0..160) |round| {
            now_ms += prng.range(50, 600);
            const faulty = round < 100;
            if (manager.has_capacity() and prng.chance(2, 3)) {
                try manager.submit(&client, "\x00f", now_ms);
            }
            if (prng.chance(1, 2)) l1.mine(prng.range(1, 3));
            if (faulty and prng.chance(1, 10)) l1.reorg_and_lose(&prng, prng.range(1, 3), 50);
            _ = try manager.poll(&client, now_ms);
            if (manager.needs_reset(now_ms)) manager.reset();
            try testing.expect(manager.pending_count() <= manager.slots.len);
        }
        const mined_before = l1.mined;
        for (0..60) |_| {
            now_ms += 500;
            if (manager.has_capacity()) try manager.submit(&client, "\x00q", now_ms);
            l1.mine(4);
            _ = try manager.poll(&client, now_ms);
            if (manager.needs_reset(now_ms)) manager.reset();
        }
        try testing.expect(l1.mined >= mined_before + 40);
    }
}

test "txmgr: fuzz reorg and loss schedules" {
    try testing.fuzz({}, fuzz_lossy, .{});
}

fn fuzz_lossy(_: void, smith: *testing.Smith) anyerror!void {
    var events: [128]u8 = undefined;
    const length = smith.slice(&events);
    var l1: LossyL1 = .{};
    var client: rpc.Client = undefined;
    var manager = try lossy_manager(&l1, &client);
    defer manager.deinit(testing.allocator);
    defer client.deinit(testing.allocator);
    var prng = Prng.init(length);
    var now_ms: u64 = 0;
    for (events[0..length]) |event| {
        now_ms += 300;
        switch (event % 4) {
            0 => if (manager.has_capacity()) try manager.submit(&client, "\x00z", now_ms),
            1 => l1.mine(1 + event / 64),
            2 => l1.reorg_and_lose(&prng, event / 64, 50),
            else => {},
        }
        _ = try manager.poll(&client, now_ms);
        if (manager.needs_reset(now_ms)) manager.reset();
    }
    // Quiet tail: the stream must move again.
    const mined_before = l1.mined;
    for (0..40) |_| {
        now_ms += 500;
        if (manager.has_capacity()) try manager.submit(&client, "\x00q", now_ms);
        l1.mine(4);
        _ = try manager.poll(&client, now_ms);
        if (manager.needs_reset(now_ms)) manager.reset();
    }
    try testing.expect(l1.mined >= mined_before + 20);
}

test "txmgr: a restart replaces untracked pooled txs; an eviction cannot stall it" {
    var l1: LossyL1 = .{};
    // A previous run left txs at nonces 0 and 1 in the pool, with high fees.
    l1.fees[0] = 1_000;
    l1.fees[1] = 1_000;
    var client: rpc.Client = undefined;
    var manager = try lossy_manager(&l1, &client);
    defer manager.deinit(testing.allocator);
    defer client.deinit(testing.allocator);
    try manager.submit(&client, "\x00a", 0);
    try manager.submit(&client, "\x00b", 0);
    // Starting at `latest` (0), not `pending` (2): the old txs are not adopted.
    try testing.expectEqual(@as(u64, 0), manager.slots[0].nonce);
    try testing.expectEqual(@as(u64, 1), manager.slots[1].nonce);
    try testing.expect(manager.slots[0].replace_now); // Underpriced against the old tx.
    // Each poll bumps and resends at once until ours outbids the old tx at nonce 0.
    var now_ms: u64 = 10;
    for (0..40) |_| {
        _ = try manager.poll(&client, now_ms);
        now_ms += 10;
        if (!manager.slots[0].replace_now) break;
    }
    try testing.expect(l1.fees[0] > 1_000);
    // L1 evicts the old tx at nonce 1 before ours replaced it: nothing adopted it, so our
    // slot is resent there after its resubmit period, and the stream does not stall.
    l1.fees[1] = 0;
    for (0..40) |_| {
        l1.mine(2);
        _ = try manager.poll(&client, now_ms);
        now_ms += 500;
        if (manager.pending_count() == 0) break;
    }
    try testing.expectEqual(@as(u64, 2), l1.mined);
    try testing.expectEqual(@as(u32, 0), manager.pending_count());
    try testing.expect(l1.fees[1] != 1_000);
}

test "txmgr: confirmations hold slots until buried and skip resubmitting mined txs" {
    var l1: LossyL1 = .{};
    var client: rpc.Client = undefined;
    var manager = try lossy_manager(&l1, &client);
    defer manager.deinit(testing.allocator);
    defer client.deinit(testing.allocator);
    manager.config.confirmations = 3;
    try manager.submit(&client, "\x00a", 0);
    l1.mine(1); // Included in block 1.
    try testing.expectEqual(@as(u32, 0), try manager.poll(&client, 5_000));
    try testing.expectEqual(@as(u32, 1), l1.sends); // Mined: no resubmission.
    l1.mine(1);
    try testing.expectEqual(@as(u32, 0), try manager.poll(&client, 6_000));
    l1.mine(1); // Block 3: the tx has 3 confirmations.
    try testing.expectEqual(@as(u32, 1), try manager.poll(&client, 7_000));
    try testing.expectEqual(@as(u32, 0), manager.pending_count());
}

test "txmgr: minimum tip and base fee floor the suggested fees" {
    var l1: LossyL1 = .{};
    var client: rpc.Client = undefined;
    var manager = try lossy_manager(&l1, &client);
    defer manager.deinit(testing.allocator);
    defer client.deinit(testing.allocator);
    const plain = try manager.suggested_fees(&client);
    try testing.expectEqual(@as(u128, 2), plain.max_priority_fee_per_gas); // Node: 2, base 100.
    try testing.expectEqual(@as(u128, 202), plain.max_fee_per_gas);
    manager.config.min_tip_wei = 50;
    manager.config.min_base_fee_wei = 1_000;
    const floored = try manager.suggested_fees(&client);
    try testing.expectEqual(@as(u128, 50), floored.max_priority_fee_per_gas);
    try testing.expectEqual(@as(u128, 2_050), floored.max_fee_per_gas);
}
