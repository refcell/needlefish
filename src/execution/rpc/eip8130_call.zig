//! EIP-8130 `eth_call` / `eth_estimateGas` (base/base `eip8130-rpc` and
//! `BaseTransactionRequest::to_eip8130_simulation_tx`).
//!
//! A request carrying any EIP-8130 field, or `type: 0x79`, runs one read-only
//! `eip8130_simulate` at the requested block instead of the plain call. Authentication is
//! priced from the declared blob shapes: a supplied blob keeps the bytes that select its
//! authenticator and every other byte becomes 0xff (calldata prices a zero byte below a
//! non-zero one), and an absent blob is a 65-byte secp256k1 stub. `eth_estimateGas` searches
//! only the call pool inside the simulation. A phase revert is "execution reverted", as for a
//! plain call. Not ported: state and block overrides, and the keystore actor hint.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const rpc_types = @import("../../common/rpc_types/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const node = @import("../node/root.zig");
const eth = @import("eth.zig");
const state_view = @import("state_view.zig");
const eth_proof = @import("eth_proof.zig");

const aa = consensus.eip8130;
pub const Mode = @import("../evm/eip8130_simulate.zig").Mode;
const Address = primitives.Address;
const Request = rpc_types.request.TransactionRequest;
const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;

pub const stub_fill: u8 = 0xff;
pub const selector_length = 20;
/// The delegate selector, the delegate account, and the nested selector.
pub const delegate_prefix_length = 3 * selector_length;
pub const secp256k1_auth_length = 65;
pub const auth_data_bytes_max = 8_192;

const eip8130_fields = [_][]const u8{
    "nonceKey", "validAfter", "validBefore", "metadata",       "sender",
    "payer",    "senderAuth", "payerAuth",   "accountChanges", "calls",
};

/// Whether the call object `raw` is an EIP-8130 request (any EIP-8130 field, or
/// `type: 0x79`). Malformed JSON is not: the plain parser reports it.
pub fn is_request(raw: []const u8) bool {
    var scanner = json.Scanner.init(raw);
    const first = scanner.next() catch return false;
    if (first.tag != .object_begin) return false;
    var fields: u32 = 0;
    while (fields < 256) : (fields += 1) {
        const name = scanner.next() catch return false;
        if (name.tag != .string) return false;
        const value = scanner.next() catch return false;
        if (value.tag != .null) {
            for (eip8130_fields) |field| if (std.mem.eql(u8, name.bytes, field)) return true;
            if (std.mem.eql(u8, name.bytes, "type") and value.tag == .string) {
                const tx_type = json.parse_quantity(u8, value.bytes) catch return false;
                if (tx_type == aa.tx_type) return true;
            }
        }
        scanner.skip(value) catch return false;
    }
    return false;
}

pub const BuildError = error{
    MissingSender,
    SenderFromMismatch,
    SenderAuthTooLarge,
    PayerAuthTooLarge,
    UnrecognizedPayerAuthenticator,
    CallsAndSingleCall,
    SingleCallMissingTo,
    OutOfMemory,
};

fn selector_of(blob: []const u8) ?Address {
    if (blob.len < selector_length) return null;
    return .{ .bytes = blob[0..selector_length].* };
}

fn is_prefixed(blob: []const u8) bool {
    const selector = selector_of(blob) orelse return false;
    return selector.eql(aa.k1_authenticator) or aa.contracts.is_canonical_authenticator(selector);
}

fn auth_fits(blob: []const u8, prefixed: bool) bool {
    const data_length = if (prefixed) blob.len -| selector_length else blob.len;
    return data_length <= auth_data_bytes_max;
}

/// `blob` with every byte past its authenticator selection set to `stub_fill`.
fn stub_supplied(arena: std.mem.Allocator, blob: []const u8, prefixed: bool) ![]const u8 {
    var kept: usize = 0;
    if (prefixed) {
        const delegate = aa.contracts.delegate_authenticator;
        const is_delegate = selector_of(blob).?.eql(delegate);
        kept = if (is_delegate) delegate_prefix_length else selector_length;
    }
    const stub = try arena.dupe(u8, blob);
    if (kept < stub.len) @memset(stub[kept..], stub_fill);
    assert(stub.len == blob.len);
    return stub;
}

fn default_bare(arena: std.mem.Allocator) ![]const u8 {
    const blob = try arena.alloc(u8, secp256k1_auth_length);
    @memset(blob, stub_fill);
    return blob;
}

fn default_prefixed(arena: std.mem.Allocator) ![]const u8 {
    const blob = try arena.alloc(u8, selector_length + secp256k1_auth_length);
    blob[0..selector_length].* = aa.k1_authenticator.bytes;
    @memset(blob[selector_length..], stub_fill);
    return blob;
}

pub const Built = struct { signed: aa.Signed, account: Address };

/// The simulation transaction for `request` (base/base `to_eip8130_simulation_tx`).
pub fn build(
    arena: std.mem.Allocator,
    request: Request,
    chain_id: u64,
    gas_cap: u64,
) BuildError!Built {
    const account = request.sender orelse request.from orelse return error.MissingSender;
    if (request.sender != null and request.from != null) {
        if (!request.sender.?.eql(request.from.?)) return error.SenderFromMismatch;
    }
    var sender: ?Address = null;
    var sender_auth: []const u8 = undefined;
    if (request.sender_auth) |blob| {
        const prefixed = is_prefixed(blob);
        if (!auth_fits(blob, prefixed)) return error.SenderAuthTooLarge;
        if (prefixed) sender = account;
        sender_auth = try stub_supplied(arena, blob, prefixed);
    } else if (request.sender != null) {
        sender = account;
        sender_auth = try default_prefixed(arena);
    } else {
        sender_auth = try default_bare(arena);
    }
    const payer_auth = try build_payer_auth(arena, request);
    const tx: aa.TxEip8130 = .{
        .chain_id = chain_id,
        .sender = sender,
        .nonce_key = request.nonce_key orelse 0,
        .valid_after = request.valid_after orelse 0,
        .valid_before = request.valid_before orelse 0,
        .max_priority_fee_per_gas = request.max_priority_fee_per_gas orelse 0,
        .max_fee_per_gas = request.max_fee_per_gas orelse 0,
        .gas_limit = @min(request.gas orelse gas_cap, gas_cap),
        .account_changes = request.account_changes orelse .empty,
        .calls = try calls_of(arena, request),
        .metadata = request.metadata orelse &.{},
        .payer = request.payer,
    };
    assert(tx.gas_limit <= gas_cap);
    return .{
        .signed = .{ .tx = tx, .sender_auth = sender_auth, .payer_auth = payer_auth },
        .account = account,
    };
}

fn build_payer_auth(arena: std.mem.Allocator, request: Request) BuildError![]const u8 {
    const payer = request.payer orelse return &.{};
    const named = !payer.eql(aa.open_payer);
    const blob = request.payer_auth orelse {
        // An open payer that has not signed yet is priced as a bare 65-byte signature.
        return if (named) try default_prefixed(arena) else try default_bare(arena);
    };
    if (named and !is_prefixed(blob)) return error.UnrecognizedPayerAuthenticator;
    if (!auth_fits(blob, named)) return error.PayerAuthTooLarge;
    // An open payer is whoever its signature recovers to, so its bytes are kept.
    return if (named) try stub_supplied(arena, blob, true) else blob;
}

/// `calls`, or one call from the top-level `to` / `value` / `data` (zero value and empty
/// data count as unset); both is ambiguous.
fn calls_of(arena: std.mem.Allocator, request: Request) BuildError!aa.Calls {
    const value = request.value orelse 0;
    const data = request.input orelse &.{};
    const single = request.to != null or value != 0 or data.len > 0;
    if (request.calls) |calls| {
        if (single) return error.CallsAndSingleCall;
        return calls;
    }
    if (!single) return .empty;
    const to = request.to orelse return error.SingleCallMissingTo;
    const call: aa.Call = .{ .to = to, .value = value, .data = data };
    const phase_bytes = try arena.alloc(u8, rlp.length(call));
    const phase = aa.Phase.build(phase_bytes, &.{call});
    const calls_bytes = try arena.alloc(u8, rlp.length(phase));
    return aa.Calls.build(calls_bytes, &.{phase});
}

/// Runs the EIP-8130 request `call_raw` at `view` and writes the call output (`.call`) or the
/// gas (`.estimate`).
pub fn handle(
    api: *Api,
    call: *Call,
    call_raw: []const u8,
    view: state_view.View,
    mode: Mode,
) HandlerError!void {
    const space = switch (view) {
        .head => api.scratch,
        .historical => api.scratch[0 .. eth.proof_tail_offset(api) orelse {
            return call.fail(rpc.code.internal_error, "proof scratch too small");
        }],
    };
    var buffer: std.heap.FixedBufferAllocator = .init(space);
    const arena = buffer.allocator();
    const value = std.json.parseFromSliceLeaky(std.json.Value, arena, call_raw, .{}) catch {
        return error.InvalidParams;
    };
    const request = rpc_types.request.parse_transaction_request(arena, value) catch {
        return error.InvalidParams;
    };
    const header = eth.view_header(api, view);
    var env = node.chain.env_of(&header);
    env.number += 1;
    env.timestamp += 1;
    env.parent_hash = header.hash().bytes;
    if (!api.spec.is_upgrade_active(.everest, env.timestamp)) {
        return call.fail(rpc.code.invalid_params, "EIP-8130 is not active before Everest");
    }
    const executor = api.chain.executor;
    const gas_cap = executor.default_call_gas(&env);
    const built = build(arena, request, api.spec.chain_id, gas_cap) catch |err| {
        return call.fail(rpc.code.invalid_params, @errorName(err));
    };
    consensus.eip8130_structure.validate(built.signed) catch |err| {
        return call.fail(rpc.code.invalid_params, @errorName(err));
    };
    built.signed.validate_timestamp(env.timestamp * 1_000) catch |err| {
        return call.fail(rpc.code.invalid_params, @errorName(err));
    };
    const envelope_buffer = arena.alloc(u8, built.signed.encoded_length()) catch {
        return call.fail(rpc.code.invalid_params, "request too large");
    };
    const simulation: node.executor.Executor.Eip8130Call = .{
        .signed = &built.signed,
        .envelope = built.signed.encode_to(envelope_buffer),
        .from = built.account.bytes,
        .mode = mode,
    };
    const result = try run(api, call, &env, simulation, view);
    switch (result) {
        .rejected => |reason| return call.fail(rpc.code.server_error, reason),
        .executed => |executed| {
            if (!executed.success) return call.fail(3, "execution reverted");
            switch (mode) {
                .call => try call.writer.data(executed.output),
                .estimate => try call.writer.quantity(executed.gas),
            }
        },
    }
}

fn run(
    api: *Api,
    call: *Call,
    env: *const node.executor.BlockEnv,
    simulation: node.executor.Executor.Eip8130Call,
    view: state_view.View,
) HandlerError!node.executor.Executor.Eip8130Simulated {
    const executor = api.chain.executor;
    const block = switch (view) {
        .head => {
            api.chain.ensure_head_state() catch {
                return call.fail(rpc.code.internal_error, "head state unavailable");
            };
            return executor.simulate_eip8130(env, simulation, null) catch |err| {
                return call.fail(rpc.code.internal_error, @errorName(err));
            };
        },
        .historical => |block| block,
    };
    const offset = eth.proof_tail_offset(api).?; // Checked before parsing.
    const proofs: *eth_proof.Scratch = @ptrCast(@alignCast(api.scratch[offset..].ptr));
    var history: node.HistoryDatabase = .{
        .chain = api.chain,
        .hash = block.hash,
        .number = block.number,
        .account_proof = &proofs.account,
        .storage_proof = &proofs.storage,
    };
    return executor.simulate_eip8130(env, simulation, history.database()) catch |err| {
        if (history.failure) |failure| return eth_proof.fail_history(call, failure);
        return call.fail(rpc.code.internal_error, @errorName(err));
    };
}

// ---- Tests ------------------------------------------------------------------------

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "eip8130 call: request detection" {
    try testing.expect(is_request("{\"nonceKey\":\"0x1\"}"));
    try testing.expect(is_request("{\"to\":\"0x00\",\"type\":\"0x79\"}"));
    try testing.expect(is_request("{\"x\":{\"calls\":1},\"calls\":[]}"));
    try testing.expect(!is_request("{\"to\":\"0x00\",\"type\":\"0x2\"}"));
    try testing.expect(!is_request("{\"calls\":null}"));
    try testing.expect(!is_request("{\"x\":{\"calls\":[]}}"));
    try testing.expect(!is_request("[1]"));
    try testing.expect(!is_request("{\"nonceKey\""));
}

test "eip8130 call: auth stubs keep the authenticator selection" {
    var storage: [4096]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&storage);
    const arena = fixed.allocator();
    const sender: Address = .{ .bytes = @splat(0x11) };
    var blob: [selector_length + 70]u8 = @splat(0);
    blob[0..selector_length].* = aa.k1_authenticator.bytes;
    const built = try build(arena, .{ .sender = sender, .sender_auth = &blob }, 1, 100);
    try testing.expect(built.signed.tx.sender.?.eql(sender));
    try testing.expectEqualSlices(u8, &aa.k1_authenticator.bytes, built.signed.sender_auth[0..20]);
    for (built.signed.sender_auth[selector_length..]) |byte| {
        try testing.expectEqual(stub_fill, byte);
    }
    // No sender and no auth: a bare 65-byte stub and no declared sender.
    const bare = try build(arena, .{ .from = sender }, 1, 100);
    try testing.expect(bare.signed.tx.sender == null);
    try testing.expectEqual(@as(usize, secp256k1_auth_length), bare.signed.sender_auth.len);
    try testing.expectEqual(@as(u64, 100), bare.signed.tx.gas_limit);
    // A named payer needs a recognized authenticator; an open payer keeps its bytes.
    const named: Address = .{ .bytes = @splat(0x22) };
    const raw_auth: [65]u8 = @splat(7);
    try testing.expectError(error.UnrecognizedPayerAuthenticator, build(arena, .{
        .from = sender,
        .payer = named,
        .payer_auth = &raw_auth,
    }, 1, 100));
    const open = try build(arena, .{
        .from = sender,
        .payer = aa.open_payer,
        .payer_auth = &raw_auth,
    }, 1, 100);
    try testing.expectEqualSlices(u8, &raw_auth, open.signed.payer_auth);
}

fn random_build(seed: u64) !void {
    var prng = Prng.init(seed);
    var storage: [1 << 15]u8 = undefined;
    var fixed: std.heap.FixedBufferAllocator = .init(&storage);
    const arena = fixed.allocator();
    var blob: [selector_length * 3 + 64]u8 = undefined;
    prng.fill(&blob);
    const length = prng.below(blob.len + 1);
    if (prng.chance(1, 2) and length >= selector_length) {
        blob[0..selector_length].* = aa.k1_authenticator.bytes;
    }
    var request: Request = .{
        .from = .{ .bytes = @splat(@intCast(prng.below(3))) },
        .gas = if (prng.chance(1, 2)) prng.below(1 << 30) else null,
        .value = prng.below(3),
    };
    if (prng.chance(1, 2)) request.sender = .{ .bytes = @splat(@intCast(prng.below(3))) };
    if (prng.chance(1, 2)) request.sender_auth = blob[0..length];
    if (prng.chance(1, 2)) request.to = .{ .bytes = @splat(0x55) };
    if (prng.chance(1, 3)) request.payer = if (prng.chance(1, 2)) aa.open_payer else .{
        .bytes = @splat(0x66),
    };
    if (prng.chance(1, 2)) request.payer_auth = blob[0..length];
    const cap: u64 = prng.range(21_000, 1 << 24);
    const built = build(arena, request, 8453, cap) catch return;
    try testing.expect(built.signed.tx.gas_limit <= cap);
    if (request.sender_auth) |supplied| {
        try testing.expectEqual(supplied.len, built.signed.sender_auth.len);
    }
    _ = consensus.eip8130_structure.validate(built.signed) catch {};
    var encoded: [1 << 13]u8 = undefined;
    if (built.signed.encoded_length() <= encoded.len) _ = built.signed.encode_to(&encoded);
}

test "eip8130 call: seeded fuzz of simulation transaction building" {
    for (0..512) |seed| try random_build(seed);
}

fn fuzz_detect(_: void, smith: *testing.Smith) anyerror!void {
    var bytes: [64]u8 = undefined;
    for (&bytes) |*byte| byte.* = smith.value(u8);
    _ = is_request(&bytes);
    try random_build(smith.value(u64));
}

test "eip8130 call: fuzz detection and building" {
    try testing.fuzz({}, fuzz_detect, .{});
}
