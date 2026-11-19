//! geth's default struct logger (`debug_trace*` without a `tracer`), as reth serves it from
//! revm-inspectors 0.44 (`TracingInspector` with `from_geth_config`, `GethTraceBuilder::
//! geth_traces`) and alloy's `DefaultFrame`/`StructLog` JSON.
//!
//! The evm's step hooks (`Tracer.step`, `Tracer.step_end`) feed a `Logger`: `step` writes the
//! state before the instruction (stack, return data, memory: whichever the config enables)
//! into a bounded fragment, `step_end` writes the whole struct log object (program counter,
//! op name, gas before, gas cost, depth, error, the fragment, the storage snapshot, the
//! refund counter) straight into the response. The transaction's result (`failed`,
//! `returnValue`) comes from its top frame's outcome once it ends, so its head is built in
//! the fragment and slid in front of the logs. The fragment, slots and output are carved
//! from scratch at the start; a full one marks the logger `full` and the request fails.
//! The response bounds the logs: the RPC router's writer grows it (an HTTP response moves
//! into a large send buffer once, `rpc.response_bytes_max`); an entry past that marks the
//! logger `overflow`, and the request fails as an oversized response.
//!
//! revm-inspectors semantics kept here:
//!   - `gas` is the frame's gas before the instruction, `gasCost` what it left the frame
//!     with (a CALL or CREATE includes the gas it forwards); an out-of-gas halt spends the
//!     frame's gas (except a memory expansion, which reports the static cost only),
//!   - `error` is revm's `InstructionResult` debug text (`Some(OutOfGas)`) on a halting
//!     instruction, never on STOP/RETURN/REVERT,
//!   - `refund` is the frame's refund counter, always written; `depth` starts at 1,
//!   - `storage` is written on every SLOAD and SSTORE: the slots of the executing account
//!     seen so far in the transaction (sorted), where an SLOAD records a slot it warmed and an
//!     SSTORE a slot it warmed or changed (revm's journal entries),
//!   - stack on unless `disableStack`, storage on unless `disableStorage`, memory only with
//!     `enableMemory` (or `disableMemory: false`), return data only with `enableReturnData`
//!     (or `disableReturnData: false`); `limit` caps the steps per transaction.

const std = @import("std");
const assert = std.debug.assert;

const json = @import("../../utilities/json/root.zig");
const evm = @import("../evm/root.zig");

const Address = [20]u8;
const Exit = evm.evm.Exit;
const op = evm.opcode;

pub const Config = struct {
    stack: bool = true,
    memory: bool = false,
    storage: bool = true,
    return_data: bool = false,
    /// Steps recorded per transaction; 0 records all.
    limit: u64 = 0,
};

pub const Slot = struct { address: Address, key: u256, value: u256 };

/// The slot an SLOAD or SSTORE is about to touch, read before it runs.
const Pending = struct {
    key: u256 = 0,
    /// SSTORE's new value.
    value: u256 = 0,
    cold: bool = false,
    /// The slot's present value before an SSTORE, when cached.
    present: ?u256 = null,
};

/// Frames open at once: the call depth bound and the SELFDESTRUCT pseudo-frame.
const open_max = 1026;

/// The result head's bytes beyond its hex output.
const head_fields_max = 128;

pub const Logger = struct {
    config: Config,
    /// The response: the transaction's struct logs, comma separated, from `logs_start`.
    out: *std.Io.Writer,
    logs_start: usize = 0,
    /// The current instruction's pre-execution fields (`,"stack":[...]` and so on).
    fragment: std.Io.Writer,
    slots: []Slot,
    slot_count: u32 = 0,
    /// The top frame's output.
    output: []u8,
    output_len: usize = 0,
    step_count: u64 = 0,
    open_count: u32 = 0,
    /// The top frame has exited.
    top_done: bool = false,
    /// As revm-inspectors: a transaction without frames reports its (default) root failed.
    failed: bool = true,
    /// A bound was hit; the result is incomplete and must not be served.
    full: bool = false,
    /// The response had no room left for an entry.
    overflow: bool = false,
    /// The current instruction is being recorded.
    recording: bool = false,
    pc: u32 = 0,
    opcode: u8 = 0,
    gas: u64 = 0,
    depth: u64 = 0,
    refund: i64 = 0,
    pending: Pending = .{},

    /// Carves the logger's buffers out of `space`, writing to `out`; null when `space` is
    /// too small. The fragment takes most: a step's memory is its largest part.
    pub fn init(space: []u8, config: Config, out: *std.Io.Writer) ?Logger {
        const carve = @import("trace.zig").carve;
        var used: usize = 0;
        const slots = carve(Slot, space, &used, space.len / 16 / @sizeOf(Slot)) orelse return null;
        const output = carve(u8, space, &used, space.len / 8) orelse return null;
        const fragment = space[used..];
        if (slots.len == 0 or fragment.len < 1024) return null;
        // The result head (hex output and a few fields) is built in the fragment.
        assert(fragment.len >= 2 * output.len + head_fields_max);
        return .{
            .config = config,
            .out = out,
            .fragment = .fixed(fragment),
            .slots = slots,
            .output = output,
        };
    }

    /// Resets the per-transaction state and starts its result as the next value of `w`
    /// (which writes to `out`); call before each traced transaction.
    pub fn begin_transaction(logger: *Logger, w: *json.Writer) json.Writer.WriteError!void {
        assert(logger.open_count == 0);
        assert(w.out == logger.out);
        assert(!logger.full and !logger.overflow);
        try w.raw(""); // The separator; the result is written raw from here on.
        logger.logs_start = logger.out.end;
        logger.slot_count = 0;
        logger.output_len = 0;
        logger.step_count = 0;
        logger.top_done = false;
        logger.failed = true;
        logger.recording = false;
        assert(logger.out.end == logger.logs_start);
    }

    pub fn tracer(logger: *Logger) evm.evm.Tracer {
        return .{
            .context = logger,
            .enter = on_enter,
            .exit = on_exit,
            .log = on_log,
            .step = on_step,
            .step_end = on_step_end,
        };
    }

    fn of(context: *anyopaque) *Logger {
        return @ptrCast(@alignCast(context));
    }

    fn on_enter(context: *anyopaque, frame: evm.evm.TraceFrame) void {
        const logger = of(context);
        assert(logger.open_count < open_max);
        assert(frame.depth < open_max);
        logger.open_count += 1;
    }

    fn on_exit(context: *anyopaque, outcome: evm.evm.Outcome) void {
        const logger = of(context);
        assert(logger.open_count > 0);
        logger.open_count -= 1;
        if (logger.open_count > 0 or logger.top_done) return;
        logger.top_done = true;
        logger.failed = outcome.status != .success;
        if (outcome.output.len > logger.output.len) {
            logger.full = true;
            return;
        }
        @memcpy(logger.output[0..outcome.output.len], outcome.output);
        logger.output_len = outcome.output.len;
    }

    fn on_log(_: *anyopaque, _: Address, _: []const [32]u8, _: []const u8) void {}

    fn on_step(context: *anyopaque, frame: *const evm.evm.Frame, machine: *const evm.evm.Evm) void {
        const logger = of(context);
        logger.recording = false;
        if (logger.full or logger.overflow) return;
        if (logger.config.limit != 0 and logger.step_count >= logger.config.limit) return;
        assert(frame.pc < frame.analyzed.code.len);
        logger.recording = true;
        logger.step_count += 1;
        logger.pc = frame.pc;
        logger.opcode = frame.analyzed.code[frame.pc];
        logger.gas = frame.gas;
        logger.depth = @as(u64, frame.depth) + 1;
        logger.refund = frame.refund;
        logger.write_fragment(frame, machine) catch {
            logger.full = true;
            logger.recording = false;
            return;
        };
        const touches_storage = logger.opcode == op.SLOAD or logger.opcode == op.SSTORE;
        if (logger.config.storage and touches_storage) logger.pending = pending_of(frame, machine);
    }

    fn on_step_end(
        context: *anyopaque,
        frame: *const evm.evm.Frame,
        machine: *const evm.evm.Evm,
        end: evm.evm.StepEnd,
    ) void {
        const logger = of(context);
        if (!logger.recording) return;
        logger.recording = false;
        assert(logger.opcode == frame.analyzed.code[logger.pc]);
        const result = step_result(logger.opcode, logger.gas, frame.gas, end);
        const touches_storage = logger.opcode == op.SLOAD or logger.opcode == op.SSTORE;
        if (logger.config.storage and touches_storage) {
            logger.record_slot(frame, machine, end.exit);
        }
        logger.write_log(frame, result);
    }

    fn write_fragment(
        logger: *Logger,
        frame: *const evm.evm.Frame,
        machine: *const evm.evm.Evm,
    ) std.Io.Writer.Error!void {
        const w = &logger.fragment;
        w.end = 0;
        if (logger.config.stack) {
            try w.writeAll(",\"stack\":[");
            var buffer: [2 + 64]u8 = undefined;
            for (frame.stack.items[0..frame.stack.len], 0..) |value, index| {
                if (index > 0) try w.writeByte(',');
                try w.writeByte('"');
                try w.writeAll(json.format_quantity(value, &buffer));
                try w.writeByte('"');
            }
            try w.writeByte(']');
        }
        if (logger.config.return_data) {
            try w.writeAll(",\"returnData\":\"0x");
            try json.write_hex(w, machine.return_data());
            try w.writeByte('"');
        }
        if (logger.config.memory) {
            const memory = frame.memory.bytes[0..frame.memory.len];
            assert(memory.len % 32 == 0);
            try w.writeAll(",\"memory\":[");
            var offset: usize = 0;
            while (offset < memory.len) : (offset += 32) {
                if (offset > 0) try w.writeByte(',');
                try w.writeAll("\"0x");
                try json.write_hex(w, memory[offset..][0..32]);
                try w.writeByte('"');
            }
            try w.writeByte(']');
        }
    }

    /// Updates the transaction's storage view after an SLOAD or SSTORE, as revm-inspectors
    /// does from the journal entry the instruction left (a warmed or changed slot).
    fn record_slot(
        logger: *Logger,
        frame: *const evm.evm.Frame,
        machine: *const evm.evm.Evm,
        exit: ?Exit,
    ) void {
        const pending = logger.pending;
        if (logger.opcode == op.SLOAD) {
            if (exit != null or !pending.cold) return;
            assert(frame.stack.len > 0);
            logger.put_slot(frame.address, pending.key, frame.stack.items[frame.stack.len - 1]);
            return;
        }
        assert(logger.opcode == op.SSTORE);
        // revm writes the slot once the stipend check passes and the slot loads; an
        // out-of-gas charge afterwards leaves the write journaled.
        if (exit != null and exit.? != .out_of_gas) return;
        if (logger.gas <= evm.gas.call_stipend) return;
        const state = machine.state;
        if (!state.is_slot_warm(frame.account, pending.key)) return;
        const present = pending.present orelse present: {
            const key = evm.state.StorageKey{ .address = frame.address, .slot = pending.key };
            const slot = state.slots.getPtr(key) orelse return;
            break :present slot.original;
        };
        if (!pending.cold and present == pending.value) return;
        logger.put_slot(frame.address, pending.key, pending.value);
    }

    /// Inserts or updates a slot, keeping `slots` sorted by address and key.
    fn put_slot(logger: *Logger, address: Address, key: u256, value: u256) void {
        const slots = logger.slots[0..logger.slot_count];
        var index: usize = 0;
        while (index < slots.len and slot_less(&slots[index], &address, key)) index += 1;
        if (index < slots.len and std.mem.eql(u8, &slots[index].address, &address) and
            slots[index].key == key)
        {
            slots[index].value = value;
            return;
        }
        if (logger.slot_count == logger.slots.len) {
            logger.full = true;
            return;
        }
        std.mem.copyBackwards(
            Slot,
            logger.slots[index + 1 .. slots.len + 1],
            logger.slots[index..slots.len],
        );
        logger.slots[index] = .{ .address = address, .key = key, .value = value };
        logger.slot_count += 1;
        assert(logger.slot_count <= logger.slots.len);
    }

    /// Appends the instruction's entry to the response; marks the logger `overflow` when
    /// the response has no room left (it grows on its own as far as it can).
    fn write_log(logger: *Logger, frame: *const evm.evm.Frame, result: StepResult) void {
        const start = logger.out.end;
        logger.write_entry(frame, result) catch {
            logger.out.end = start;
            logger.overflow = true;
        };
    }

    fn write_entry(
        logger: *Logger,
        frame: *const evm.evm.Frame,
        result: StepResult,
    ) std.Io.Writer.Error!void {
        const w = logger.out;
        if (w.end > logger.logs_start) try w.writeByte(',');
        try w.print("{{\"pc\":{d},\"op\":\"{s}\",\"gas\":{d},\"gasCost\":{d},\"depth\":{d}", .{
            logger.pc,
            op_name(logger.opcode),
            logger.gas,
            result.cost,
            logger.depth,
        });
        if (result.error_text) |text| try w.print(",\"error\":\"{s}\"", .{text});
        try w.writeAll(logger.fragment.buffered());
        const touches_storage = logger.opcode == op.SLOAD or logger.opcode == op.SSTORE;
        if (logger.config.storage and touches_storage) try logger.write_storage(frame.address);
        try w.print(",\"refund\":{d}}}", .{@as(u64, @bitCast(logger.refund))});
    }

    /// `,"storage":{...}`: the slots of `address` seen so far, in key order.
    fn write_storage(logger: *Logger, address: Address) std.Io.Writer.Error!void {
        const w = logger.out;
        try w.writeAll(",\"storage\":{");
        var written: u32 = 0;
        for (logger.slots[0..logger.slot_count]) |*slot| {
            if (!std.mem.eql(u8, &slot.address, &address)) continue;
            if (written > 0) try w.writeByte(',');
            var key: [32]u8 = undefined;
            var value: [32]u8 = undefined;
            std.mem.writeInt(u256, &key, slot.key, .big);
            std.mem.writeInt(u256, &value, slot.value, .big);
            try w.writeAll("\"0x");
            try json.write_hex(w, &key);
            try w.writeAll("\":\"0x");
            try json.write_hex(w, &value);
            try w.writeByte('"');
            written += 1;
        }
        try w.writeByte('}');
    }

    /// Completes the transaction's `DefaultFrame` around its logs: `gas` is its receipt gas
    /// used. The head (`failed`, `gas`, `returnValue`) is slid in front of the logs.
    pub fn write(logger: *Logger, gas: u64) std.Io.Writer.Error!void {
        assert(!logger.full and !logger.overflow);
        assert(logger.open_count == 0);
        const head = &logger.fragment;
        head.end = 0;
        try head.print("{{\"failed\":{s},\"gas\":{d},\"returnValue\":\"0x", .{
            if (logger.failed) "true" else "false",
            gas,
        });
        try json.write_hex(head, logger.output[0..logger.output_len]);
        try head.writeAll("\",\"structLogs\":[");
        const out = logger.out;
        try out.ensureUnusedCapacity(head.end + 2);
        const logs = out.end - logger.logs_start;
        const buffer = out.buffer;
        assert(out.end + head.end + 2 <= buffer.len);
        std.mem.copyBackwards(
            u8,
            buffer[logger.logs_start + head.end ..][0..logs],
            buffer[logger.logs_start..][0..logs],
        );
        @memcpy(buffer[logger.logs_start..][0..head.end], head.buffered());
        out.end += head.end;
        try out.writeAll("]}");
    }
};

fn slot_less(slot: *const Slot, address: *const Address, key: u256) bool {
    return switch (std.mem.order(u8, &slot.address, address)) {
        .lt => true,
        .gt => false,
        .eq => slot.key < key,
    };
}

fn pending_of(frame: *const evm.evm.Frame, machine: *const evm.evm.Evm) Pending {
    const stack = frame.stack.items[0..frame.stack.len];
    if (stack.len == 0) return .{};
    const key = stack[stack.len - 1];
    const state = machine.state;
    var pending: Pending = .{ .key = key, .cold = !state.is_slot_warm(frame.account, key) };
    if (stack.len >= 2) pending.value = stack[stack.len - 2];
    const storage_key = evm.state.StorageKey{ .address = frame.address, .slot = key };
    if (state.slots.getPtr(storage_key)) |slot| {
        if (slot.epoch == frame.account.storage_epoch) pending.present = slot.present;
    }
    return pending;
}

const StepResult = struct { cost: u64, error_text: ?[]const u8 };

/// revm's gas cost and error text for an instruction that started with `gas_before` and
/// left the frame `gas_after` (wrapped after an out-of-gas halt).
fn step_result(opcode: u8, gas_before: u64, gas_after: u64, end: evm.evm.StepEnd) StepResult {
    const spent = gas_before -| gas_after;
    const exit = end.exit orelse return .{ .cost = spent, .error_text = null };
    const static_unpaid = gas_before < end.static_cost;
    const all: StepResult = .{ .cost = gas_before, .error_text = "Some(OutOfGas)" };
    return switch (exit) {
        .stop, .return_, .revert, .self_destruct, .call, .create => .{
            .cost = spent,
            .error_text = null,
        },
        .out_of_gas => if (!static_unpaid and memory_only(opcode))
            .{ .cost = end.static_cost, .error_text = "Some(MemoryOOG)" }
        else
            all,
        // revm charges the static gas before it checks the stack.
        .stack_underflow => if (static_unpaid)
            all
        else
            .{ .cost = end.static_cost, .error_text = "Some(StackUnderflow)" },
        .stack_overflow => if (static_unpaid)
            all
        else
            .{ .cost = end.static_cost, .error_text = "Some(StackOverflow)" },
        .invalid_opcode, .invalid_fe_opcode => .{ .cost = 0, .error_text = invalid_text(opcode) },
        .invalid_jump => .{ .cost = spent, .error_text = "Some(InvalidJump)" },
        .static_violation => .{ .cost = spent, .error_text = if (opcode == op.CALL)
            "Some(CallNotAllowedInsideStatic)"
        else
            "Some(StateChangeDuringStaticCall)" },
        .return_data_out_of_bounds => .{ .cost = spent, .error_text = "Some(OutOfOffset)" },
        .code_size_limit,
        .invalid_code_prefix,
        .create_collision,
        .precompile_failure,
        .precompile_out_of_gas,
        .out_of_funds,
        .deposit_system_tx,
        .deposit_intrinsic_gas,
        .fatal,
        => .{ .cost = spent, .error_text = null },
    };
}

/// Instructions whose only dynamic gas is memory expansion (revm: `MemoryOOG`).
fn memory_only(opcode: u8) bool {
    return switch (opcode) {
        op.MLOAD, op.MSTORE, op.MSTORE8, op.RETURN, op.REVERT => true,
        else => false,
    };
}

fn invalid_text(opcode: u8) []const u8 {
    if (opcode == op.INVALID) return "Some(InvalidFEOpcode)";
    if (named(opcode)) return "Some(NotActivated)";
    return "Some(OpcodeNotFound)";
}

/// Whether revm's opcode table names `opcode` (revm-bytecode 43).
fn named(opcode: u8) bool {
    return !std.mem.eql(u8, op_name(opcode), "Unknown");
}

const names_low = [_][]const u8{
    "STOP",        "ADD",            "MUL",            "SUB",
    "DIV",         "SDIV",           "MOD",            "SMOD",
    "ADDMOD",      "MULMOD",         "EXP",            "SIGNEXTEND",
    "",            "",               "",               "",
    "LT",          "GT",             "SLT",            "SGT",
    "EQ",          "ISZERO",         "AND",            "OR",
    "XOR",         "NOT",            "BYTE",           "SHL",
    "SHR",         "SAR",            "CLZ",            "",
    "KECCAK256",   "",               "",               "",
    "",            "",               "",               "",
    "",            "",               "",               "",
    "",            "",               "",               "",
    "ADDRESS",     "BALANCE",        "ORIGIN",         "CALLER",
    "CALLVALUE",   "CALLDATALOAD",   "CALLDATASIZE",   "CALLDATACOPY",
    "CODESIZE",    "CODECOPY",       "GASPRICE",       "EXTCODESIZE",
    "EXTCODECOPY", "RETURNDATASIZE", "RETURNDATACOPY", "EXTCODEHASH",
    "BLOCKHASH",   "COINBASE",       "TIMESTAMP",      "NUMBER",
    "DIFFICULTY",  "GASLIMIT",       "CHAINID",        "SELFBALANCE",
    "BASEFEE",     "BLOBHASH",       "BLOBBASEFEE",    "SLOTNUM",
    "",            "",               "",               "",
    "POP",         "MLOAD",          "MSTORE",         "MSTORE8",
    "SLOAD",       "SSTORE",         "JUMP",           "JUMPI",
    "PC",          "MSIZE",          "GAS",            "JUMPDEST",
    "TLOAD",       "TSTORE",         "MCOPY",          "PUSH0",
};
comptime {
    assert(names_low.len == 0x60);
}

const push_names = names: {
    var names: [32][]const u8 = undefined;
    for (&names, 1..) |*name, size| name.* = std.fmt.comptimePrint("PUSH{d}", .{size});
    break :names names;
};
const dup_names = numbered("DUP");
const swap_names = numbered("SWAP");

fn numbered(comptime prefix: []const u8) [16][]const u8 {
    var names: [16][]const u8 = undefined;
    for (&names, 1..) |*name, index| name.* = std.fmt.comptimePrint("{s}{d}", .{ prefix, index });
    return names;
}

/// revm's opcode name (`OpCode::as_str`), or "Unknown" for bytes it does not define.
pub fn op_name(opcode: u8) []const u8 {
    const name: []const u8 = switch (opcode) {
        0x00...0x5f => names_low[opcode],
        0x60...0x7f => push_names[opcode - 0x60],
        0x80...0x8f => dup_names[opcode - 0x80],
        0x90...0x9f => swap_names[opcode - 0x90],
        0xa0 => "LOG0",
        0xa1 => "LOG1",
        0xa2 => "LOG2",
        0xa3 => "LOG3",
        0xa4 => "LOG4",
        0xe6 => "DUPN",
        0xe7 => "SWAPN",
        0xe8 => "EXCHANGE",
        0xf0 => "CREATE",
        0xf1 => "CALL",
        0xf2 => "CALLCODE",
        0xf3 => "RETURN",
        0xf4 => "DELEGATECALL",
        0xf5 => "CREATE2",
        0xfa => "STATICCALL",
        0xfd => "REVERT",
        0xfe => "INVALID",
        0xff => "SELFDESTRUCT",
        else => "",
    };
    return if (name.len == 0) "Unknown" else name;
}

// ---- Tests ------------------------------------------------------------------------

const testing = std.testing;

test "struct_log: opcode names follow revm" {
    try testing.expectEqualStrings("STOP", op_name(0x00));
    try testing.expectEqualStrings("KECCAK256", op_name(0x20));
    try testing.expectEqualStrings("DIFFICULTY", op_name(0x44));
    try testing.expectEqualStrings("PUSH0", op_name(0x5f));
    try testing.expectEqualStrings("PUSH1", op_name(0x60));
    try testing.expectEqualStrings("PUSH32", op_name(0x7f));
    try testing.expectEqualStrings("DUP16", op_name(0x8f));
    try testing.expectEqualStrings("SWAP1", op_name(0x90));
    try testing.expectEqualStrings("Unknown", op_name(0x0c));
    try testing.expectEqualStrings("Unknown", op_name(0xb0));
    try testing.expectEqualStrings("Unknown", op_name(0xef));
    try testing.expectEqualStrings("SELFDESTRUCT", op_name(0xff));
}

test "struct_log: step gas costs and errors follow revm" {
    const plain = step_result(op.ADD, 100, 97, .{ .exit = null, .static_cost = 3 });
    try testing.expectEqual(@as(u64, 3), plain.cost);
    try testing.expect(plain.error_text == null);
    // An out-of-gas halt spends everything, a memory expansion only the static cost.
    const halt = step_result(op.SLOAD, 50, 50, .{ .exit = .out_of_gas, .static_cost = 0 });
    try testing.expectEqual(@as(u64, 50), halt.cost);
    try testing.expectEqualStrings("Some(OutOfGas)", halt.error_text.?);
    const memory = step_result(op.MSTORE, 50, 47, .{ .exit = .out_of_gas, .static_cost = 3 });
    try testing.expectEqual(@as(u64, 3), memory.cost);
    try testing.expectEqualStrings("Some(MemoryOOG)", memory.error_text.?);
    const unpaid = step_result(op.MSTORE, 2, 2, .{ .exit = .out_of_gas, .static_cost = 3 });
    try testing.expectEqual(@as(u64, 2), unpaid.cost);
    const under = step_result(op.ADD, 10, 10, .{ .exit = .stack_underflow, .static_cost = 3 });
    try testing.expectEqual(@as(u64, 3), under.cost);
    try testing.expectEqualStrings("Some(StackUnderflow)", under.error_text.?);
    const revert = step_result(op.REVERT, 10, 10, .{ .exit = .revert, .static_cost = 0 });
    try testing.expect(revert.error_text == null);
    const invalid = step_result(0xfe, 10, 10, .{ .exit = .invalid_opcode, .static_cost = 0 });
    try testing.expectEqualStrings("Some(InvalidFEOpcode)", invalid.error_text.?);
    const unknown = step_result(0x0c, 10, 10, .{ .exit = .invalid_opcode, .static_cost = 0 });
    try testing.expectEqualStrings("Some(OpcodeNotFound)", unknown.error_text.?);
}

test "struct_log: storage view stays sorted by address and key" {
    var space: [1 << 16]u8 = undefined;
    var out_buffer: [1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buffer);
    var logger = Logger.init(&space, .{}, &out).?;
    logger.put_slot(@splat(2), 5, 1);
    logger.put_slot(@splat(1), 9, 2);
    logger.put_slot(@splat(2), 3, 3);
    logger.put_slot(@splat(2), 5, 4); // Updates in place.
    try testing.expectEqual(@as(u32, 3), logger.slot_count);
    try testing.expectEqual(@as(u256, 9), logger.slots[0].key);
    try testing.expectEqual(@as(u256, 3), logger.slots[1].key);
    try testing.expectEqual(@as(u256, 4), logger.slots[2].value);
    try logger.write_storage(@splat(2));
    const zeros = "00000000000000000000000000000000000000000000000000000000000000";
    try testing.expectEqualStrings(
        ",\"storage\":{\"0x" ++ zeros ++ "03\":\"0x" ++ zeros ++ "03\",\"0x" ++ zeros ++
            "05\":\"0x" ++ zeros ++ "04\"}",
        out.buffered(),
    );
}
