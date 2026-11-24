//! geth's `4byteTracer` and `flatCallTracer` from the recorded call frames (`trace.Recorder`),
//! as reth serves them from revm-inspectors 0.44 (`FourByteInspector`, and
//! `ParityTraceBuilder::into_localized_transaction_traces` with `from_flat_call_config`).
//!
//! 4byteTracer counts `0x<selector>-<calldata size - 4>` over every CALL-family frame with
//! at least 4 input bytes whose target is not a precompile (creations are not calls); keys
//! sort as strings (alloy's `BTreeMap<String, u64>`).
//!
//! flatCallTracer writes one parity trace per frame in call order: precompile calls with no
//! value below the top frame are left out unless `includePrecompiles` (and count as nobody's
//! subtrace); a DELEGATECALL reports its parent's value; the top frame reports the
//! transaction's gas limit (its `gasUsed` stays the frame's own); a SELFDESTRUCT is a
//! `suicide` trace after its frame's calls; errors use parity's wording and a failure other
//! than a revert has a null `result`.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");
const trace = @import("trace.zig");

const Frame = trace.Frame;
const Hash = [32]u8;

/// Where a transaction's traces sit (alloy's `TransactionInfo`); a call has no block hash
/// or transaction.
pub const Locator = struct {
    block_hash: ?Hash = null,
    block_number: u64,
    transaction_hash: ?Hash = null,
    transaction_position: ?u32 = null,
};

// ---- 4byteTracer ------------------------------------------------------------------

fn counted(frame: *const Frame) bool {
    const call = switch (frame.kind) {
        .call, .callcode, .delegatecall, .staticcall => true,
        .create, .create2, .selfdestruct => false,
    };
    // A deposit rejected before any frame entered none: no selector is counted.
    const entered = frame.exit != .deposit_system_tx and frame.exit != .deposit_intrinsic_gas;
    return call and entered and frame.input.len >= 4 and !frame.precompile;
}

fn decimal_less(a: usize, b: usize) bool {
    var buffer_a: [20]u8 = undefined;
    var buffer_b: [20]u8 = undefined;
    const text_a = std.fmt.bufPrint(&buffer_a, "{d}", .{a}) catch unreachable; // 20 digits.
    const text_b = std.fmt.bufPrint(&buffer_b, "{d}", .{b}) catch unreachable; // 20 digits.
    return std.mem.order(u8, text_a, text_b) == .lt;
}

/// Counted frames first, in key order (the selector's hex, then the size's decimal text).
fn four_byte_less(_: void, a: Frame, b: Frame) bool {
    const a_counted = counted(&a);
    const b_counted = counted(&b);
    if (a_counted != b_counted) return a_counted;
    if (!a_counted) return false;
    return switch (std.mem.order(u8, a.input[0..4], b.input[0..4])) {
        .lt => true,
        .gt => false,
        .eq => decimal_less(a.input.len - 4, b.input.len - 4),
    };
}

fn same_key(a: *const Frame, b: *const Frame) bool {
    return std.mem.eql(u8, a.input[0..4], b.input[0..4]) and a.input.len == b.input.len;
}

/// Writes the 4byteTracer object of one transaction's frames (reordered in place).
pub fn write_four_byte(w: *json.Writer, frames: []Frame) json.Writer.WriteError!void {
    std.mem.sort(Frame, frames, {}, four_byte_less);
    try w.begin_object();
    var index: usize = 0;
    while (index < frames.len and counted(&frames[index])) {
        var run: u64 = 1;
        while (index + run < frames.len and counted(&frames[index + run]) and
            same_key(&frames[index], &frames[index + run])) run += 1;
        const frame = &frames[index];
        var key: [2 + 8 + 1 + 20]u8 = undefined;
        var selector: [8]u8 = undefined;
        json.hex_encode(&selector, frame.input[0..4]);
        const text = std.fmt.bufPrint(&key, "0x{s}-{d}", .{ selector, frame.input.len - 4 }) catch
            unreachable; // Sized for the longest key.
        try w.key(text);
        try w.integer(run);
        index += run;
    }
    assert(index <= frames.len);
    try w.end_object();
}

// ---- flatCallTracer ---------------------------------------------------------------

pub const Flat = struct {
    /// One transaction's frames, in call order.
    frames: []const Frame,
    top: trace.TopGas,
    locator: Locator,
    include_precompiles: bool,
};

fn excluded(flat: *const Flat, frame: *const Frame, depth: u32, value: u256) bool {
    return frame.precompile and !flat.include_precompiles and depth > 0 and value == 0;
}

/// The value a frame reports: a DELEGATECALL's parent's (`parent_value`).
fn value_of(frame: *const Frame, depth: u32, parent_value: u256) u256 {
    return if (frame.kind == .delegatecall and depth > 0) parent_value else frame.value;
}

/// Calls of frame `index` (relative depth `depth`, reporting `value`) that are traced.
fn subtraces_of(flat: *const Flat, index: usize, value: u256) u32 {
    const frames = flat.frames;
    const depth = frames[index].depth;
    var count: u32 = 0;
    var child = index + 1;
    while (child < frames.len and frames[child].depth > depth) : (child += 1) {
        if (frames[child].depth != depth + 1) continue;
        const child_value = value_of(&frames[child], 1, value);
        count += @intFromBool(!excluded(flat, &frames[child], 1, child_value));
    }
    return count;
}

/// Writes the flatCallTracer list of one transaction's frames.
pub fn write_flat(w: *json.Writer, flat: Flat) json.Writer.WriteError!void {
    try w.begin_array();
    var values: [trace.depth_max]u256 = undefined;
    var children: [trace.depth_max]u32 = undefined;
    var path: [trace.depth_max]u32 = undefined;
    const base = if (flat.frames.len > 0) flat.frames[0].depth else 0;
    for (flat.frames, 0..) |*frame, index| {
        assert(frame.depth >= base and frame.depth - base < trace.depth_max);
        const depth: u32 = frame.depth - base;
        assert(index == 0 or depth > 0);
        const value = value_of(frame, depth, if (depth > 0) values[depth - 1] else 0);
        values[depth] = value;
        children[depth] = 0;
        if (excluded(&flat, frame, depth, value)) continue;
        if (depth > 0) {
            path[depth - 1] = children[depth - 1];
            children[depth - 1] += 1;
        }
        const subtraces = subtraces_of(&flat, index, value);
        const gas = if (index == 0) flat.top.limit else frame.gas;
        try write_trace(w, &flat, frame, .{
            .value = value,
            .gas = gas,
            .subtraces = subtraces,
            .address = path[0..depth],
        });
    }
    try w.end_array();
}

const Placed = struct { value: u256, gas: u64, subtraces: u32, address: []const u32 };

fn write_trace(
    w: *json.Writer,
    flat: *const Flat,
    frame: *const Frame,
    placed: Placed,
) json.Writer.WriteError!void {
    const locator = flat.locator;
    try w.begin_object();
    try w.key("action");
    try write_action(w, frame, placed);
    if (locator.block_hash) |*hash| {
        try w.key("blockHash");
        try w.data(hash);
    }
    try w.key("blockNumber");
    try w.integer(locator.block_number);
    const text = parity_error(frame);
    if (text) |message| {
        try w.key("error");
        try w.string(message);
    }
    try w.key("result");
    try write_output(w, frame);
    try w.key("subtraces");
    try w.integer(placed.subtraces);
    try w.key("traceAddress");
    try w.begin_array();
    for (placed.address) |position| try w.integer(position);
    try w.end_array();
    try w.key("transactionHash");
    if (locator.transaction_hash) |*hash| try w.data(hash) else try w.null_value();
    try w.key("transactionPosition");
    if (locator.transaction_position) |position| try w.integer(position) else try w.null_value();
    try w.key("type");
    try w.string(switch (frame.kind) {
        .call, .callcode, .delegatecall, .staticcall => "call",
        .create, .create2 => "create",
        .selfdestruct => "suicide",
    });
    try w.end_object();
}

fn write_action(w: *json.Writer, frame: *const Frame, placed: Placed) json.Writer.WriteError!void {
    try w.begin_object();
    switch (frame.kind) {
        .call, .callcode, .delegatecall, .staticcall => {
            try w.key("from");
            try w.data(&frame.from);
            try w.key("callType");
            try w.string(@tagName(frame.kind));
            try w.key("gas");
            try w.quantity(placed.gas);
            try w.key("input");
            try w.data(frame.input);
            try w.key("to");
            try w.data(&frame.to);
            try w.key("value");
            try w.quantity(placed.value);
        },
        .create, .create2 => {
            try w.key("from");
            try w.data(&frame.from);
            try w.key("gas");
            try w.quantity(placed.gas);
            try w.key("init");
            try w.data(frame.input);
            try w.key("value");
            try w.quantity(placed.value);
            try w.key("creationMethod");
            try w.string(@tagName(frame.kind));
        },
        .selfdestruct => {
            try w.key("address");
            try w.data(&frame.from);
            try w.key("balance");
            try w.quantity(frame.value);
            try w.key("refundAddress");
            try w.data(&frame.to);
        },
    }
    try w.end_object();
}

/// A revert with no gas used and no output never ran code: revm fails the call's depth or
/// balance check (a REVERT instruction costs gas).
fn failed_check(frame: *const Frame) bool {
    return frame.exit == .revert and frame.gas_used == 0 and frame.output.len == 0 and
        frame.kind != .selfdestruct;
}

/// A revert proper (revm's `Revert`); failed checks are not.
fn reverted(frame: *const Frame) bool {
    return frame.exit == .revert and !failed_check(frame);
}

/// revm-inspectors' parity error text (`fmt_error_msg` with `TraceStyle::Parity`).
pub fn parity_error(frame: *const Frame) ?[]const u8 {
    return switch (frame.exit) {
        .stop, .return_, .self_destruct => null,
        .revert => if (!failed_check(frame))
            "Reverted"
        else if (frame.depth > 1024)
            "Max call depth exceeded"
        else
            "Insufficient balance for transfer",
        .out_of_gas, .code_size_limit, .precompile_out_of_gas => "Out of gas",
        .invalid_opcode, .invalid_fe_opcode => "Bad instruction",
        .stack_underflow => "Stack underflow",
        .stack_overflow => "Out of stack",
        .invalid_jump => "Bad jump destination",
        .static_violation => "Mutable Call In Static Context",
        .return_data_out_of_bounds => "Out of bounds",
        .invalid_code_prefix => "Invalid code",
        .create_collision => "Contract address collision",
        .precompile_failure => "Built-in failed",
        .out_of_funds => "Insufficient balance for transfer",
        .deposit_system_tx => "failed deposit: system deposit after Regolith",
        .deposit_intrinsic_gas => "failed deposit: intrinsic gas too low",
        .call, .create, .fatal => "internal error",
    };
}

fn write_output(w: *json.Writer, frame: *const Frame) json.Writer.WriteError!void {
    if (frame.kind == .selfdestruct) return w.null_value();
    // A failure other than a revert has no result.
    if (parity_error(frame) != null and !reverted(frame)) return w.null_value();
    try w.begin_object();
    const creation = frame.kind == .create or frame.kind == .create2;
    if (creation and !reverted(frame)) {
        try w.key("address");
        try w.data(&frame.to);
        try w.key("code");
        try w.data(frame.output);
        try w.key("gasUsed");
        try w.quantity(frame.gas_used);
    } else {
        try w.key("gasUsed");
        try w.quantity(frame.gas_used);
        try w.key("output");
        try w.data(frame.output);
    }
    try w.end_object();
}

// ---- Tests ------------------------------------------------------------------------

const testing = std.testing;

fn test_frame(kind: @import("../evm/root.zig").evm.TraceKind, depth: u16, input: []const u8) Frame {
    return .{
        .kind = kind,
        .from = @splat(1),
        .to = @splat(2),
        .value = 0,
        .gas = 1000,
        .gas_used = 10,
        .input = input,
        .exit = .return_,
        .depth = depth,
        .transaction = 0,
    };
}

test "flat_call: 4byte keys count calls and sort as strings" {
    const long = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd } ++ @as([100]u8, @splat(0));
    const short = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd } ++ @as([36]u8, @splat(0));
    const low = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    var all = [_]Frame{
        test_frame(.call, 0, &long),
        test_frame(.create, 1, &long), // Creations are not counted.
        test_frame(.staticcall, 1, &short),
        test_frame(.delegatecall, 1, &long),
        test_frame(.call, 1, low[0..3]), // Under 4 bytes.
        test_frame(.call, 1, &low),
        test_frame(.staticcall, 1, &low),
    };
    all[6].precompile = true; // Precompile calls are not counted.
    var out: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out);
    var w: json.Writer = .init(&writer);
    try write_four_byte(&w, &all);
    // "100" sorts before "36" as text.
    try testing.expectEqualStrings(
        "{\"0x01020304-0\":1,\"0xaabbccdd-100\":2,\"0xaabbccdd-36\":1}",
        writer.buffered(),
    );
}

test "flat_call: parity errors and results" {
    var frame = test_frame(.call, 1, &.{});
    try testing.expect(parity_error(&frame) == null);
    frame.exit = .revert;
    try testing.expectEqualStrings("Reverted", parity_error(&frame).?);
    frame.gas_used = 0;
    try testing.expectEqualStrings("Insufficient balance for transfer", parity_error(&frame).?);
    frame.depth = 1025;
    try testing.expectEqualStrings("Max call depth exceeded", parity_error(&frame).?);
    frame.exit = .out_of_gas;
    try testing.expectEqualStrings("Out of gas", parity_error(&frame).?);
    var out: [64]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out);
    var w: json.Writer = .init(&writer);
    try write_output(&w, &frame);
    try testing.expectEqualStrings("null", writer.buffered());
}
