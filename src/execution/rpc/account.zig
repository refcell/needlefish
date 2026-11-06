//! reth's account reads (served by base/base nodes): `eth_getAccount(address, block)`
//! returns `{balance, nonce, codeHash, storageRoot}` or null for an absent account, and
//! `eth_getAccountInfo(address, block)` returns `{balance, nonce, code}` (zeros and empty
//! code for an absent account). Head and historical views as eth_getBalance.
//! `eth_getHeaderByNumber` / `eth_getHeaderByHash` return a block's header fields (as
//! eth_getBlockBy*, without the body; `size` is the header's RLP length), or null.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const trie = @import("../trie/root.zig");
const eth = @import("eth.zig");
const eth_proof = @import("eth_proof.zig");
const state_view = @import("state_view.zig");
const format = @import("format.zig");
const node = @import("../node/root.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Hash = [32]u8;

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "eth_getAccount", .handler = get_account },
    .{ .name = "eth_getAccountInfo", .handler = get_account_info },
    .{ .name = "eth_getHeaderByNumber", .handler = get_header_by_number },
    .{ .name = "eth_getHeaderByHash", .handler = get_header_by_hash },
};

const Full = struct {
    nonce: u64,
    balance: u256,
    code_hash: Hash,
    storage_root: Hash,
};

/// The account with its storage root at `view` (null when absent).
fn full_account(api: *Api, call: *Call, view: state_view.View, address: [20]u8) HandlerError!?Full {
    switch (view) {
        .head => {
            const found = api.chain.db.get_account(address) orelse return null;
            const address_hash = primitives.keccak256(&address).bytes;
            return .{
                .nonce = found.nonce,
                .balance = found.balance,
                .code_hash = found.code_hash,
                .storage_root = api.chain.db.trie().storage_root(address_hash),
            };
        },
        .historical => |block| {
            const scratch = eth_proof.scratch_of(api) orelse
                return call.fail(rpc.code.internal_error, "proof scratch too small");
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
                .storage_root = state.storage_root,
            };
        },
    }
}

fn get_account(api: *Api, call: *Call) HandlerError!void {
    const address = try call.params.fixed(20);
    const view = try state_view.resolve(api, call, try call.params.optional_raw());
    try call.params.finish();
    const account = try full_account(api, call, view, address) orelse
        return call.writer.null_value();
    assert(!std.mem.eql(u8, &account.storage_root, &@as(Hash, @splat(0))));
    const w = call.writer;
    try w.begin_object();
    try w.key("balance");
    try w.quantity(account.balance);
    try w.key("nonce");
    try w.quantity(account.nonce);
    try w.key("codeHash");
    try w.data(&account.code_hash);
    try w.key("storageRoot");
    try w.data(&account.storage_root);
    try w.end_object();
}

fn get_account_info(api: *Api, call: *Call) HandlerError!void {
    const address = try call.params.fixed(20);
    const view = try state_view.resolve(api, call, try call.params.optional_raw());
    try call.params.finish();
    const account = try state_view.account(api, call, view, address) orelse
        state_view.Account{};
    const w = call.writer;
    try w.begin_object();
    try w.key("balance");
    try w.quantity(account.balance);
    try w.key("nonce");
    try w.quantity(account.nonce);
    try w.key("code");
    try w.data(state_view.code(api, account.code_hash));
    try w.end_object();
}

fn write_header(api: *Api, call: *Call, hash: Hash) HandlerError!void {
    const bytes = api.chain.store.record(hash) orelse return call.writer.null_value();
    const record = node.chain.Record.decode(bytes) catch unreachable; // Stored by the chain.
    const header = &record.header;
    assert(std.mem.eql(u8, &header.hash().bytes, &hash));
    const w = call.writer;
    try w.begin_object();
    try format.header_fields(w, header, hash, header.rlp_length());
    if (format.timestamp_ms(record)) |ms| try format.field_quantity(w, "timestampMs", ms);
    try w.end_object();
}

fn get_header_by_number(api: *Api, call: *Call) HandlerError!void {
    const raw = try call.params.raw();
    try call.params.finish();
    const hash = eth.resolve_block(api, call, raw) catch |err| switch (err) {
        error.Failed => return call.writer.null_value(),
        else => return err,
    };
    try write_header(api, call, hash);
}

fn get_header_by_hash(api: *Api, call: *Call) HandlerError!void {
    const hash = try call.params.fixed(32);
    try call.params.finish();
    try write_header(api, call, hash);
}

comptime {
    assert(trie.empty_root.len == 32);
}
