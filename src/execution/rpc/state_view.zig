//! Which state a block parameter names, and account/storage reads against it.
//!
//! The head state is read from the in-memory tables. Older canonical blocks are read
//! from the chain's history (`Chain.proof_at`: a durable node's database window, or the
//! in-memory `--proofs-history` window) by walking proofs into the eth_getProof scratch.
//! Without history, or outside the window, older blocks fail with "historical state
//! unavailable" like before.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../../utilities/rpc/root.zig");
const trie_node = @import("../trie/node.zig");
const eth = @import("eth.zig");
const eth_proof = @import("eth_proof.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Hash = [32]u8;

pub const View = union(enum) {
    head,
    historical: eth_proof.Block,
};

pub const Account = struct {
    nonce: u64 = 0,
    balance: u256 = 0,
    code_hash: Hash = trie_node.empty_code_hash,
};

/// Resolves an optional block parameter (absent means latest) to a readable state.
pub fn resolve(api: *Api, call: *Call, raw: ?[]const u8) HandlerError!View {
    if (try eth_proof.historical_block(api, call, raw)) |block| {
        assert(!std.mem.eql(u8, &block.hash, &api.chain.head_hash()));
        return .{ .historical = block };
    }
    try eth.require_head_state(api, call, raw);
    return .head;
}

pub fn account(api: *Api, call: *Call, view: View, address: [20]u8) HandlerError!?Account {
    switch (view) {
        .head => {
            const found = api.chain.db.get_account(address) orelse return null;
            return .{
                .nonce = found.nonce,
                .balance = found.balance,
                .code_hash = found.code_hash,
            };
        },
        .historical => |block| {
            const scratch = try scratch_of(api, call);
            const result = api.chain.proof_at(
                block.hash,
                block.number,
                address,
                &.{},
                &scratch.account,
                &.{},
                &.{},
            );
            const found = result catch |err| return eth_proof.fail_history(call, err);
            const state = found orelse return null;
            return .{
                .nonce = state.nonce,
                .balance = state.balance,
                .code_hash = state.code_hash,
            };
        },
    }
}

pub fn storage(
    api: *Api,
    call: *Call,
    view: View,
    address: [20]u8,
    slot: u256,
) HandlerError!u256 {
    switch (view) {
        .head => return api.chain.db.get_storage(address, slot),
        .historical => |block| {
            const scratch = try scratch_of(api, call);
            const slots = [1]u256{slot};
            var values: [1]u256 = .{0};
            const proofs = (&scratch.storage)[0..1];
            const result = api.chain.proof_at(
                block.hash,
                block.number,
                address,
                &slots,
                &scratch.account,
                proofs,
                &values,
            );
            _ = result catch |err| return eth_proof.fail_history(call, err);
            return values[0];
        },
    }
}

/// Contract code by hash. Code is content addressed and never deleted, so the head's
/// code store serves every block.
pub fn code(api: *Api, code_hash: Hash) []const u8 {
    if (std.mem.eql(u8, &code_hash, &trie_node.empty_code_hash)) return &.{};
    return api.chain.db.code(code_hash) orelse &.{};
}

fn scratch_of(api: *Api, call: *Call) HandlerError!*eth_proof.Scratch {
    return eth_proof.scratch_of(api) orelse
        call.fail(rpc.code.internal_error, "proof scratch too small");
}

comptime {
    assert(@sizeOf(View) > @sizeOf(Hash));
}
