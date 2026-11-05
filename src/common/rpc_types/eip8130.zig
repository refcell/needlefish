//! EIP-8130 (0x79) JSON forms, matching base/base serde: transaction fields with
//! `type`-tagged account changes and nested call phases, and the receipt's
//! `phaseStatuses`.

const std = @import("std");
const assert = std.debug.assert;
const consensus = @import("../consensus/root.zig");
const json = @import("json.zig");
const Object = json.Object;
const Error = json.Error;
const Writer = std.Io.Writer;
const aa = consensus.eip8130;

/// The fields of a signed 0x79 transaction (the caller writes `type`, `hash`, `from`).
pub fn write_fields(object: *Object, signed: aa.Signed, effective_gas_price: ?u128) Error!void {
    const t = signed.tx;
    try object.quantity("chainId", t.chain_id);
    try object.address_or_null("sender", t.sender);
    try object.quantity("nonceKey", t.nonce_key);
    try object.quantity("nonce", t.nonce_sequence);
    try object.quantity("validAfter", t.valid_after);
    try object.quantity("validBefore", t.valid_before);
    try object.quantity("maxPriorityFeePerGas", t.max_priority_fee_per_gas);
    try object.quantity("maxFeePerGas", t.max_fee_per_gas);
    try object.quantity("gasPrice", effective_gas_price orelse t.max_fee_per_gas);
    try object.quantity("gas", t.gas_limit);
    try object.key("accountChanges");
    try write_account_changes(object.w, t.account_changes);
    try object.key("calls");
    try write_calls(object.w, t.calls);
    try object.data("metadata", t.metadata);
    try object.address_or_null("payer", t.payer);
    try object.data("senderAuth", signed.sender_auth);
    try object.data("payerAuth", signed.payer_auth);
    // Generic-transaction view: no single recipient, value or input.
    try object.address_or_null("to", null);
    try object.quantity("value", @as(u8, 0));
    try object.data("input", &.{});
}

fn write_calls(w: *Writer, calls: aa.Calls) Error!void {
    try w.writeByte('[');
    var phases = calls.iterator();
    var phase_index: usize = 0;
    while (phases.next()) |phase| : (phase_index += 1) {
        if (phase_index > 0) try w.writeByte(',');
        try w.writeByte('[');
        var iterator = phase.iterator();
        var call_index: usize = 0;
        while (iterator.next()) |call| : (call_index += 1) {
            if (call_index > 0) try w.writeByte(',');
            var object = try Object.begin(w);
            try object.address("to", call.to);
            try object.quantity("value", call.value);
            try object.data("data", call.data);
            try object.end();
        }
        try w.writeByte(']');
    }
    try w.writeByte(']');
}

fn write_account_changes(w: *Writer, changes: aa.AccountChanges) Error!void {
    try w.writeByte('[');
    var iterator = changes.iterator();
    var index: usize = 0;
    while (iterator.next()) |change| : (index += 1) {
        if (index > 0) try w.writeByte(',');
        var object = try Object.begin(w);
        try object.quantity("type", @backingInt(std.meta.activeTag(change)));
        switch (change) {
            .delegation => |target| try object.address("target", target),
            .create => |entry| try write_create(&object, entry),
            .config => |config| try write_config(&object, config),
        }
        try object.end();
    }
    try w.writeByte(']');
}

fn write_create(object: *Object, entry: aa.CreateEntry) Error!void {
    try object.fixed("userSalt", entry.user_salt);
    try object.data("code", entry.code);
    try object.key("initialActors");
    try object.w.writeByte('[');
    var iterator = entry.initial_actors.iterator();
    var index: usize = 0;
    while (iterator.next()) |actor| : (index += 1) {
        if (index > 0) try object.w.writeByte(',');
        var item = try Object.begin(object.w);
        try item.fixed("actorId", actor.actor_id);
        try item.address("authenticator", actor.authenticator);
        try item.quantity("scope", actor.scope);
        try item.data("policyData", actor.policy_data);
        try item.end();
    }
    try object.w.writeByte(']');
}

fn write_config(object: *Object, config: aa.ConfigChange) Error!void {
    try object.quantity("channel", @backingInt(config.channel));
    try object.quantity("sequence", config.sequence);
    try object.key("changes");
    try object.w.writeByte('[');
    var iterator = config.changes.iterator();
    var index: usize = 0;
    while (iterator.next()) |change| : (index += 1) {
        if (index > 0) try object.w.writeByte(',');
        var item = try Object.begin(object.w);
        try item.quantity("changeType", @backingInt(change.change_type));
        try item.data("payload", change.payload);
        try item.end();
    }
    try object.w.writeByte(']');
    try object.data("signature", config.signature);
}

/// `phaseStatuses`: one quantity per call phase, `0x1` for committed phases (which are
/// a prefix). Written only for 0x79 receipts.
pub fn write_phase_statuses(
    object: *Object,
    receipt: consensus.receipt.Receipt,
    phase_count: ?u64,
) Error!void {
    if (receipt.tx_type != .eip8130) return;
    const count = phase_count.?;
    assert(count <= aa.max_call_phases_per_tx);
    assert(receipt.committed_phases.? <= count);
    try object.key("phaseStatuses");
    try object.w.writeByte('[');
    for (0..count) |index| {
        if (index > 0) try object.w.writeByte(',');
        const committed = receipt.phase_committed(index);
        try object.w.writeAll(if (committed) "\"0x1\"" else "\"0x0\"");
    }
    try object.w.writeByte(']');
}
