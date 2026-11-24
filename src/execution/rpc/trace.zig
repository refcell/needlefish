//! `debug_traceTransaction`, `debug_traceBlockByNumber`, `debug_traceBlockByHash`,
//! `debug_traceBlock` and `debug_traceCall` with geth's `callTracer` (config `onlyTopCall`,
//! `withLog`) and the other built-in tracers.
//!
//! The block is re-executed on its parent's state (`HistoryDatabase`, so the history window
//! bounds what can be traced) in an executor session that commits nothing; the evm's
//! call-frame hook (`evm.Tracer`) feeds a `Recorder` that keeps frames flat, in call order
//! with their depth, copying inputs, outputs and logs into a bounded arena carved from the
//! API scratch. It holds one transaction: each traced transaction's result is written into
//! the response as soon as it has run, and the response grows as far as the router lets it
//! (`rpc.response_bytes_max`, then jsonrpsee's oversized-response error). The nested JSON
//! is written from that list with an explicit stack (no recursion). As geth: the top frame
//! reports the transaction's gas limit and gas used, logs of failed frames (and their
//! descendants) are dropped, and `revertReason` decodes `Error(string)`. An EIP-8130
//! transaction's later top-level phase calls nest under its first. The same frames feed
//! `4byteTracer`, `noopTracer` and `flatCallTracer` (`flat_call.zig`); `prestateTracer`
//! (`prestate.zig`) and the default struct logger (`struct_log.zig`, no `tracer`) run their
//! own loops. Other names fail as reth does: muxTracer, erc7562Tracer and stateGasTracer as
//! unsupported, anything else as a JavaScript tracer. `debug_traceCall` runs the call as
//! `eth_call` does (same view, gas default and simulation) with the tracer attached.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const json = @import("../../utilities/json/root.zig");
const rpc = @import("../../utilities/rpc/root.zig");
const evm = @import("../evm/root.zig");
const node = @import("../node/root.zig");
const eth = @import("eth.zig");
const call_fees = @import("call_fees.zig");
const eth_proof = @import("eth_proof.zig");
const prestate = @import("prestate.zig");
const struct_log = @import("struct_log.zig");
const flat_call = @import("flat_call.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Hash = [32]u8;
const Address = [20]u8;

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "debug_traceTransaction", .handler = trace_transaction },
    .{ .name = "debug_traceBlockByNumber", .handler = trace_block_by_number },
    .{ .name = "debug_traceBlockByHash", .handler = trace_block_by_hash },
    .{ .name = "debug_traceCall", .handler = trace_call },
    .{ .name = "debug_traceBlock", .handler = trace_raw_block },
};

/// Call depth bound (EIP-150 caps it at 1024; one more for the top frame and a phase shift).
pub const depth_max = 1026;
comptime {
    // A tree takes two writer levels per frame, inside the response envelope's few.
    assert(2 * depth_max + 8 <= json.writer_depth_max);
}

pub const Frame = struct {
    kind: evm.evm.TraceKind,
    from: Address,
    to: Address,
    value: u256,
    gas: u64,
    gas_used: u64 = 0,
    input: []const u8,
    output: []const u8 = &.{},
    exit: evm.evm.Exit = .stop,
    depth: u16,
    /// The transaction this frame belongs to (block traces).
    transaction: u32,
    /// A call to a precompile or native contract (4byteTracer and flatCallTracer skip them).
    precompile: bool = false,
};

pub const Log = struct {
    frame: u32,
    address: Address,
    topics: [4]Hash,
    topic_count: u8,
    data: []const u8,
    /// Child calls the frame had made before the log (geth `position`).
    position: u32,
};

/// Collects the frames of every traced transaction; `full` once any bound is hit.
pub const Recorder = struct {
    frames: []Frame,
    frame_count: u32 = 0,
    logs: []Log,
    log_count: u32 = 0,
    bytes: []u8,
    bytes_used: usize = 0,
    open: [depth_max]u32 = undefined,
    /// Child calls made so far by each open frame.
    children: [depth_max]u32 = undefined,
    open_count: u16 = 0,
    transaction: u32 = 0,
    /// Index of the current transaction's first frame (null before it enters).
    root: ?u32 = null,
    /// 1 once an EIP-8130 transaction starts a second top-level call.
    shift: u16 = 0,
    with_logs: bool = false,
    full: bool = false,

    /// Forgets the previous transaction's frames, logs and bytes (they are written).
    pub fn begin_transaction(recorder: *Recorder, index: u32) void {
        assert(recorder.open_count == 0);
        assert(!recorder.full);
        recorder.frame_count = 0;
        recorder.log_count = 0;
        recorder.bytes_used = 0;
        recorder.transaction = index;
        recorder.root = null;
        recorder.shift = 0;
    }

    fn copy(recorder: *Recorder, data: []const u8) []const u8 {
        if (recorder.bytes.len - recorder.bytes_used < data.len) {
            recorder.full = true;
            return &.{};
        }
        const out = recorder.bytes[recorder.bytes_used..][0..data.len];
        @memcpy(out, data);
        recorder.bytes_used += data.len;
        return out;
    }

    pub fn tracer(recorder: *Recorder) evm.evm.Tracer {
        return .{ .context = recorder, .enter = on_enter, .exit = on_exit, .log = on_log };
    }

    fn of(context: *anyopaque) *Recorder {
        return @ptrCast(@alignCast(context));
    }

    fn on_enter(context: *anyopaque, frame: evm.evm.TraceFrame) void {
        const recorder = of(context);
        if (frame.depth == 0 and recorder.root != null) recorder.shift = 1;
        // Opened even when full, so exits stay matched.
        assert(recorder.open_count < depth_max);
        if (recorder.open_count > 0) recorder.children[recorder.open_count - 1] += 1;
        const index = recorder.frame_count;
        recorder.open[recorder.open_count] = index;
        recorder.children[recorder.open_count] = 0;
        recorder.open_count += 1;
        if (index == recorder.frames.len) {
            recorder.full = true;
            return;
        }
        if (recorder.root == null) recorder.root = index;
        recorder.frames[index] = .{
            .kind = frame.kind,
            .from = frame.from,
            .to = frame.to,
            .value = frame.value,
            .gas = frame.gas,
            .input = recorder.copy(frame.input),
            .depth = frame.depth + recorder.shift,
            .transaction = recorder.transaction,
            .precompile = frame.precompile,
        };
        recorder.frame_count += 1;
    }

    fn on_exit(context: *anyopaque, outcome: evm.evm.Outcome) void {
        const recorder = of(context);
        assert(recorder.open_count > 0);
        recorder.open_count -= 1;
        const index = recorder.open[recorder.open_count];
        if (index >= recorder.frame_count) return; // Not recorded (full).
        const frame = &recorder.frames[index];
        frame.gas_used = frame.gas -| outcome.gas_remaining;
        frame.output = recorder.copy(outcome.output);
        frame.exit = outcome.exit;
        if (outcome.created) |created| frame.to = created;
    }

    fn on_log(
        context: *anyopaque,
        address: Address,
        topics: []const [32]u8,
        data: []const u8,
    ) void {
        const recorder = of(context);
        if (!recorder.with_logs) return;
        assert(recorder.open_count > 0 and topics.len <= 4);
        const frame = recorder.open[recorder.open_count - 1];
        if (frame >= recorder.frame_count or recorder.log_count == recorder.logs.len) {
            recorder.full = true;
            return;
        }
        var item: Log = .{
            .frame = frame,
            .address = address,
            .topics = undefined,
            .topic_count = @intCast(topics.len),
            .data = recorder.copy(data),
            .position = recorder.children[recorder.open_count - 1],
        };
        for (topics, 0..) |topic, position| item.topics[position] = topic;
        recorder.logs[recorder.log_count] = item;
        recorder.log_count += 1;
    }
};

/// Carves a recorder's frames, logs and bytes out of `space`; null when it is too small.
/// A quarter goes to frames, an eighth to logs, the rest to the frames' and logs' bytes.
pub fn recorder_in(space: []u8) ?Recorder {
    var used: usize = 0;
    const frames = carve(Frame, space, &used, space.len / 4 / @sizeOf(Frame)) orelse return null;
    const logs = carve(Log, space, &used, space.len / 8 / @sizeOf(Log)) orelse return null;
    const bytes = space[used..];
    if (frames.len == 0 or logs.len == 0) return null;
    assert(@intFromPtr(bytes.ptr) + bytes.len == @intFromPtr(space.ptr) + space.len);
    return .{ .frames = frames, .logs = logs, .bytes = bytes };
}

/// `count` items of `T` from `space` at `used.*` (aligned), advancing `used`; null when they
/// do not fit. Unlike an allocator it leaves the bytes untouched, so carving a large lazily
/// committed scratch does not make it resident (safe builds fill allocations).
pub fn carve(comptime T: type, space: []u8, used: *usize, count: usize) ?[]T {
    assert(used.* <= space.len);
    const base = @intFromPtr(space.ptr);
    const start = std.mem.alignForward(usize, base + used.*, @alignOf(T)) - base;
    const size = std.math.mul(usize, count, @sizeOf(T)) catch return null;
    if (start > space.len or space.len - start < size) return null;
    used.* = start + size;
    const items: [*]T = @ptrCast(@alignCast(space[start..].ptr));
    return items[0..count];
}

// ---- Output -----------------------------------------------------------------------

fn kind_name(kind: evm.evm.TraceKind) []const u8 {
    return switch (kind) {
        .call => "CALL",
        .callcode => "CALLCODE",
        .delegatecall => "DELEGATECALL",
        .staticcall => "STATICCALL",
        .create => "CREATE",
        .create2 => "CREATE2",
        .selfdestruct => "SELFDESTRUCT",
    };
}

/// geth's error text for a failed frame; null on success.
pub fn error_text(exit: evm.evm.Exit) ?[]const u8 {
    return switch (exit) {
        .stop, .return_, .self_destruct => null,
        .revert => "execution reverted",
        .out_of_gas => "out of gas",
        .invalid_opcode, .invalid_fe_opcode => "invalid opcode",
        .stack_underflow => "stack underflow",
        .stack_overflow => "stack limit reached 1024",
        .invalid_jump => "invalid jump destination",
        .static_violation => "write protection",
        .return_data_out_of_bounds => "return data out of bounds",
        .code_size_limit => "max code size exceeded",
        .invalid_code_prefix => "invalid code: must not begin with 0xef",
        .create_collision => "contract address collision",
        .precompile_failure, .precompile_out_of_gas => "precompile failed",
        .out_of_funds => "insufficient balance for transfer",
        .deposit_system_tx => "failed deposit: system deposit after Regolith",
        .deposit_intrinsic_gas => "failed deposit: intrinsic gas too low",
        .call, .create, .fatal => "internal error",
    };
}

/// The message of an ABI `Error(string)` revert payload, when well formed.
pub fn revert_reason(output: []const u8) ?[]const u8 {
    const selector = [4]u8{ 0x08, 0xc3, 0x79, 0xa0 };
    if (output.len < 4 + 64 or !std.mem.eql(u8, output[0..4], &selector)) return null;
    const body = output[4..];
    const offset = std.mem.readInt(u256, body[0..32], .big);
    if (offset > body.len - 32) return null;
    const at: usize = @intCast(offset);
    const length = std.mem.readInt(u256, body[at..][0..32], .big);
    if (length > body.len - at - 32) return null;
    const text = body[at + 32 ..][0..@intCast(length)];
    if (!std.unicode.utf8ValidateSlice(text)) return null;
    return text;
}

/// The top frame's gas limit and gas used, from the transaction (geth reports these).
pub const TopGas = struct { limit: u64, used: u64 };

/// One frame's fields; `value` is what it reports (a DELEGATECALL's parent's value). As
/// revm-inspectors' `geth_empty_call_frame`, only a STATICCALL omits `value` (a zero value
/// is written as "0x0").
fn write_fields(
    w: *json.Writer,
    frame: *const Frame,
    value: u256,
    top: ?TopGas,
) json.Writer.WriteError!void {
    try w.key("type");
    try w.string(kind_name(frame.kind));
    try w.key("from");
    try w.data(&frame.from);
    // geth's `processOutput` clears a failed CREATE's `to`: no account was created.
    const is_create = frame.kind == .create or frame.kind == .create2;
    if (!is_create or error_text(frame.exit) == null) {
        try w.key("to");
        try w.data(&frame.to);
    }
    if (frame.kind != .staticcall) {
        try w.key("value");
        try w.quantity(value);
    }
    try w.key("gas");
    try w.quantity(if (top) |gas| gas.limit else frame.gas);
    try w.key("gasUsed");
    try w.quantity(if (top) |gas| gas.used else frame.gas_used);
    try w.key("input");
    try w.data(frame.input);
    if (frame.output.len > 0) {
        try w.key("output");
        try w.data(frame.output);
    }
    if (error_text(frame.exit)) |text| {
        try w.key("error");
        try w.string(text);
        if (frame.exit == .revert) if (revert_reason(frame.output)) |reason| {
            try w.key("revertReason");
            try w.string(reason);
        };
    }
}

fn write_logs(w: *json.Writer, recorder: *const Recorder, frame: u32) json.Writer.WriteError!void {
    if (!recorder.with_logs) return;
    var count: u32 = 0;
    for (recorder.logs[0..recorder.log_count]) |item| count += @intFromBool(item.frame == frame);
    if (count == 0) return;
    try w.key("logs");
    try w.begin_array();
    for (recorder.logs[0..recorder.log_count]) |item| {
        if (item.frame != frame) continue;
        try w.begin_object();
        try w.key("address");
        try w.data(&item.address);
        try w.key("topics");
        try w.begin_array();
        for (item.topics[0..item.topic_count]) |*topic| try w.data(topic);
        try w.end_array();
        try w.key("data");
        try w.data(item.data);
        try w.key("position");
        try w.quantity(item.position);
        try w.end_object();
    }
    try w.end_array();
}

/// Writes the call tree of the frames `first..end` (one transaction, in call order).
pub fn write_tree(
    w: *json.Writer,
    recorder: *const Recorder,
    first: u32,
    end: u32,
    top: TopGas,
    only_top_call: bool,
) json.Writer.WriteError!void {
    assert(first < end and end <= recorder.frame_count);
    const frames = recorder.frames;
    var stack: [depth_max]struct { frame: u32, failed: bool, value: u256 } = undefined;
    var stack_count: u32 = 0;
    const last = if (only_top_call) first + 1 else end;
    var index = first;
    while (index < last) : (index += 1) {
        const frame = &frames[index];
        while (stack_count > 0 and frames[stack[stack_count - 1].frame].depth >= frame.depth) {
            stack_count -= 1;
            try w.end_array();
            try w.end_object();
        }
        const parent_failed = stack_count > 0 and stack[stack_count - 1].failed;
        const failed = parent_failed or error_text(frame.exit) != null;
        // revm-inspectors gives a DELEGATECALL its parent's value.
        const inherits = frame.kind == .delegatecall and stack_count > 0;
        const value = if (inherits) stack[stack_count - 1].value else frame.value;
        try w.begin_object();
        try write_fields(w, frame, value, if (index == first) top else null);
        if (!failed) try write_logs(w, recorder, index);
        const has_children = index + 1 < last and frames[index + 1].depth > frame.depth;
        if (has_children) {
            try w.key("calls");
            try w.begin_array();
            stack[stack_count] = .{ .frame = index, .failed = failed, .value = value };
            stack_count += 1;
        } else {
            try w.end_object();
        }
    }
    while (stack_count > 0) : (stack_count -= 1) {
        try w.end_array();
        try w.end_object();
    }
}

// ---- Handlers ---------------------------------------------------------------------

pub const TracerKind = enum { call, prestate, struct_log, four_byte, noop, flat_call };

pub const Options = struct {
    /// No `tracer` (or an empty one) selects geth's default struct logger.
    tracer: TracerKind = .struct_log,
    only_top_call: bool = false,
    with_logs: bool = false,
    diff_mode: bool = false,
    /// flatCallTracer `includePrecompiles`.
    include_precompiles: bool = false,
    /// prestateTracer `disableCode` and `disableStorage`.
    disable_code: bool = false,
    disable_storage: bool = false,
    /// Read and type checked as alloy's `FlatCallConfig` does; not applied (flatCallTracer
    /// parity text).
    convert_parity_errors: bool = false,
    struct_log: struct_log.Config = .{},
};

pub const OptionsError = error{
    InvalidParams,
    /// The selected tracer's `tracerConfig` does not deserialize into its config struct
    /// (reth: `InvalidTracerConfig`, refused while tracing).
    InvalidConfig,
    /// A built-in tracer reth serves that needlefish does not (muxTracer, erc7562Tracer,
    /// stateGasTracer).
    Unsupported,
    /// Any other name: reth reads it as JavaScript, which base/base builds without.
    JsTracer,
};

/// The struct logger's flags as alloy's `GethDefaultTracingOptions` reads them (unset
/// until given).
const DefaultFlags = struct {
    enable_memory: ?bool = null,
    disable_memory: ?bool = null,
    disable_stack: ?bool = null,
    disable_storage: ?bool = null,
    enable_return_data: ?bool = null,
    disable_return_data: ?bool = null,
    /// Type checked only.
    debug: ?bool = null,
    limit: u64 = 0,

    fn config(flags: DefaultFlags) struct_log.Config {
        const memory = flags.enable_memory orelse
            if (flags.disable_memory) |disable| !disable else false;
        const return_data = flags.enable_return_data orelse
            if (flags.disable_return_data) |disable| !disable else false;
        return .{
            .stack = !(flags.disable_stack orelse false),
            .memory = memory,
            .storage = !(flags.disable_storage orelse false),
            .return_data = return_data,
            .limit = flags.limit,
        };
    }
};

/// Parses geth tracing options: `tracer`, its `tracerConfig`, and the struct logger's
/// flags (absent options: the struct logger with its defaults). A malformed field fails
/// first (serde rejects the whole object), then an unservable tracer, then a config that
/// is not the selected tracer's (`InvalidConfig`).
pub fn parse_options(raw: ?[]const u8) OptionsError!Options {
    var options: Options = .{};
    const text = raw orelse return options;
    var scanner = json.Scanner.init(text);
    const first = scanner.next() catch return error.InvalidParams;
    if (first.tag == .null) return options;
    if (first.tag != .object_begin) return error.InvalidParams;
    var flags: DefaultFlags = .{};
    var tracer: OptionsError!TracerKind = .struct_log;
    var config: ?[]const u8 = null;
    while (true) {
        const name = scanner.next() catch return error.InvalidParams;
        if (name.tag == .object_end) break;
        if (name.tag != .string) return error.InvalidParams;
        const value = scanner.next() catch return error.InvalidParams;
        const start = value_start(&scanner, value);
        if (std.mem.eql(u8, name.bytes, "tracer")) {
            if (value.tag != .null and value.tag != .string) return error.InvalidParams;
            tracer = tracer_of(value);
        } else if (std.mem.eql(u8, name.bytes, "timeout")) {
            if (value.tag != .null and value.tag != .string) return error.InvalidParams;
        } else if (!try parse_flag(&flags, name.bytes, value)) {
            scanner.skip(value) catch return error.InvalidParams;
            if (std.mem.eql(u8, name.bytes, "tracerConfig")) {
                config = text[start..scanner.offset()];
            }
        }
    }
    options.tracer = try tracer;
    options.struct_log = flags.config();
    try parse_config(config, &options);
    return options;
}

/// Where the value whose first token is `value` starts in the scanner's input.
fn value_start(scanner: *const json.Scanner, value: json.Token) u32 {
    const input_start = @intFromPtr(scanner.input.ptr);
    return switch (value.tag) {
        .object_begin, .array_begin => scanner.offset() - 1,
        .string => @intCast(@intFromPtr(value.bytes.ptr) - input_start - 1),
        .number => @intCast(@intFromPtr(value.bytes.ptr) - input_start),
        .true, .null => scanner.offset() - 4,
        .false => scanner.offset() - 5,
        .object_end, .array_end, .end => unreachable,
    };
}

fn tracer_of(value: json.Token) OptionsError!TracerKind {
    if (value.tag == .null) return .struct_log;
    assert(value.tag == .string);
    var buffer: [32]u8 = undefined;
    // Longer than every built-in name: JavaScript.
    const text = json.unescape(value, &buffer) catch return error.JsTracer;
    const names = [_]struct { []const u8, TracerKind }{
        .{ "", .struct_log },
        .{ "callTracer", .call },
        .{ "prestateTracer", .prestate },
        .{ "4byteTracer", .four_byte },
        .{ "noopTracer", .noop },
        .{ "flatCallTracer", .flat_call },
    };
    for (names) |entry| if (std.mem.eql(u8, text, entry[0])) return entry[1];
    const unsupported = [_][]const u8{ "muxTracer", "erc7562Tracer", "stateGasTracer" };
    for (unsupported) |name| if (std.mem.eql(u8, text, name)) return error.Unsupported;
    return error.JsTracer;
}

/// Reads one struct logger flag; false when `name` is not one (the caller skips it).
fn parse_flag(flags: *DefaultFlags, name: []const u8, value: json.Token) OptionsError!bool {
    if (std.mem.eql(u8, name, "limit")) {
        if (value.tag == .null) return true;
        if (value.tag != .number) return error.InvalidParams;
        flags.limit = std.fmt.parseInt(u64, value.bytes, 10) catch return error.InvalidParams;
        return true;
    }
    const fields = [_]struct { []const u8, *?bool }{
        .{ "enableMemory", &flags.enable_memory },
        .{ "disableMemory", &flags.disable_memory },
        .{ "disableStack", &flags.disable_stack },
        .{ "disableStorage", &flags.disable_storage },
        .{ "enableReturnData", &flags.enable_return_data },
        .{ "disableReturnData", &flags.disable_return_data },
        .{ "debug", &flags.debug },
    };
    for (fields) |field| {
        if (!std.mem.eql(u8, name, field[0])) continue;
        field[1].* = switch (value.tag) {
            .true => true,
            .false => false,
            .null => null,
            else => return error.InvalidParams,
        };
        return true;
    }
    return false;
}

/// The `Option<bool>` fields of the selected tracer's alloy config struct, in declaration
/// order (a JSON array fills them by position); none for tracers that never read it.
fn config_names(tracer: TracerKind) []const []const u8 {
    return switch (tracer) {
        .call => &.{ "onlyTopCall", "withLog" },
        .prestate => &.{ "diffMode", "disableCode", "disableStorage" },
        .flat_call => &.{ "convertParityErrors", "includePrecompiles" },
        .struct_log, .four_byte, .noop => &.{},
    };
}

/// Reads `tracerConfig` as serde reads the selected tracer's config from a JSON value:
/// null is the default, an object sets the fields it names (others ignored, the last of a
/// repeated one wins), an array sets them by position, and a field that is not a bool or
/// null (or any other value) fails.
fn parse_config(raw: ?[]const u8, options: *Options) OptionsError!void {
    const names = config_names(options.tracer);
    if (names.len == 0) return;
    const text = raw orelse return;
    const targets: [3]*bool = switch (options.tracer) {
        .call => .{ &options.only_top_call, &options.with_logs, undefined },
        .prestate => .{ &options.diff_mode, &options.disable_code, &options.disable_storage },
        .flat_call => .{
            &options.convert_parity_errors,
            &options.include_precompiles,
            undefined,
        },
        .struct_log, .four_byte, .noop => unreachable, // No config names.
    };
    var scanner = json.Scanner.init(text);
    const first = scanner.next() catch return error.InvalidParams;
    switch (first.tag) {
        .null => {},
        .object_begin => try config_object(&scanner, names, targets[0..names.len]),
        .array_begin => try config_array(&scanner, targets[0..names.len]),
        else => return error.InvalidConfig,
    }
}

fn config_object(
    scanner: *json.Scanner,
    names: []const []const u8,
    targets: []const *bool,
) OptionsError!void {
    assert(names.len == targets.len);
    // Every member takes at least one byte.
    var members: u32 = 0;
    while (members <= scanner.input.len) : (members += 1) {
        const name = scanner.next() catch return error.InvalidParams;
        if (name.tag == .object_end) return;
        assert(name.tag == .string);
        const value = scanner.next() catch return error.InvalidParams;
        var buffer: [32]u8 = undefined;
        // Longer than every field name: ignored.
        const text = json.unescape(name, &buffer) catch "";
        const index = for (names, 0..) |field, index| {
            if (std.mem.eql(u8, text, field)) break index;
        } else null;
        if (index) |field| {
            targets[field].* = try config_bool(value);
        } else {
            scanner.skip(value) catch return error.InvalidParams;
        }
    }
    unreachable;
}

fn config_array(scanner: *json.Scanner, targets: []const *bool) OptionsError!void {
    assert(targets.len > 0);
    for (0..targets.len + 1) |index| {
        const value = scanner.next() catch return error.InvalidParams;
        if (value.tag == .array_end) return;
        // serde: "invalid length", more elements than the struct has fields.
        if (index == targets.len) return error.InvalidConfig;
        targets[index].* = try config_bool(value);
    }
    unreachable;
}

/// An `Option<bool>` config field: null reads as absent (false).
fn config_bool(value: json.Token) OptionsError!bool {
    return switch (value.tag) {
        .true => true,
        .false, .null => false,
        else => error.InvalidConfig,
    };
}

/// Trace options, or the refusal of a tracer reth only refuses while tracing, after the
/// block or transaction is found; a malformed config fails with the params.
const Deferred = union(enum) {
    options: Options,
    refused: struct { code: i32, message: []const u8 },
};

/// reth: `EthApiError::Unsupported` is an internal error, `InvalidTracerConfig` invalid
/// params.
fn options_deferred(raw: ?[]const u8) HandlerError!Deferred {
    const options = parse_options(raw) catch |err| return switch (err) {
        error.InvalidParams => error.InvalidParams,
        error.InvalidConfig => .{ .refused = .{
            .code = rpc.code.invalid_params,
            .message = "invalid tracer config",
        } },
        error.Unsupported => .{ .refused = .{
            .code = rpc.code.internal_error,
            .message = "unsupported tracer",
        } },
        error.JsTracer => .{ .refused = .{
            .code = rpc.code.internal_error,
            .message = "JS Tracer is not enabled",
        } },
    };
    return .{ .options = options };
}

fn options_or_refuse(call: *Call, deferred: Deferred) HandlerError!Options {
    return switch (deferred) {
        .options => |options| options,
        .refused => |refused| call.fail(refused.code, refused.message),
    };
}

fn trace_transaction(api: *Api, call: *Call) HandlerError!void {
    const tx_hash = try call.params.hash();
    const deferred = try options_deferred(try call.params.optional_raw());
    try call.params.finish();
    const location = api.chain.find_transaction(tx_hash) orelse {
        return call.fail(rpc.code.server_error, "transaction not found");
    };
    const options = try options_or_refuse(call, deferred);
    try trace(api, call, location.block_hash, location.index, options);
}

fn trace_block_by_number(api: *Api, call: *Call) HandlerError!void {
    const raw = try call.params.raw();
    const deferred = try options_deferred(try call.params.optional_raw());
    try call.params.finish();
    // Nethermind: the pending block is the head's alias, not a next-block candidate.
    if (std.mem.eql(u8, raw, "\"pending\"")) {
        return call.fail(rpc.code.server_error, "pending block is not available");
    }
    const hash = eth.resolve_block(api, call, raw) catch |err| switch (err) {
        error.Failed => return call.fail(rpc.code.server_error, "block not found"),
        else => return err,
    };
    assert(api.chain.store.ref(hash) != null);
    try trace(api, call, hash, null, try options_or_refuse(call, deferred));
}

fn trace_block_by_hash(api: *Api, call: *Call) HandlerError!void {
    const hash = try call.params.hash();
    const deferred = try options_deferred(try call.params.optional_raw());
    try call.params.finish();
    if (api.chain.record(hash) == null) return call.fail(rpc.code.server_error, "block not found");
    try trace(api, call, hash, null, try options_or_refuse(call, deferred));
}

fn trace_call(api: *Api, call: *Call) HandlerError!void {
    try eth.refuse_incomplete_deposit(call);
    var request = try eth.parse_call_request(api, call);
    const config = try call.params.optional_raw();
    const deferred = try options_deferred(config);
    try call.params.finish();
    // geth reads `stateOverrides` and `blockOverrides` from the trace config.
    if (config) |text| {
        const state_overrides = json.find_path(text, &.{"stateOverrides"}) catch
            return error.InvalidParams;
        const block_overrides = json.find_path(text, &.{"blockOverrides"}) catch
            return error.InvalidParams;
        try eth.set_overrides(api, call, &request, state_overrides, block_overrides);
    }
    // reth builds the tracer once the call's env is prepared (`prepare_call_env`).
    const options = try options_or_refuse(call, deferred);
    if (call_fees.tip_without_cap(request.fees)) |tip| {
        const gas = @min(request.message.gas orelse eth.rpc_gas_cap, eth.rpc_gas_cap);
        return eth.fail_tip_above_cap(api, call, request.message.from, tip, .trace, gas);
    }
    // The recorder sits between the request's scratch (call data, override code) and the
    // proof tail.
    const data_end = eth.scratch_used(api, &request);
    const end = switch (request.view) {
        .head => api.scratch.len,
        .historical => eth.proof_tail_offset(api).?, // Checked by `parse_call_request`.
    };
    if (data_end >= end) return call.fail(rpc.code.internal_error, "scratch too small");
    const space = api.scratch[data_end..end];
    return switch (options.tracer) {
        .prestate => trace_call_prestate(api, call, request, space, options),
        .struct_log => trace_call_struct(api, call, request, space, options),
        .call, .four_byte, .noop, .flat_call => trace_call_frames(
            api,
            call,
            request,
            space,
            options,
        ),
    };
}

fn trace_call_frames(
    api: *Api,
    call: *Call,
    request: eth.CallRequest,
    space: []u8,
    options: Options,
) HandlerError!void {
    var recorder = recorder_in(space) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    recorder.with_logs = options.with_logs;
    const tracer = recorder.tracer();
    const executor = api.chain.executor;
    executor.machine.tracer = &tracer;
    const simulated = eth.simulate(api, call, request);
    executor.machine.tracer = null;
    const executed = switch (try simulated) {
        .invalid => |reason| return eth.fail_invalid(call, reason),
        .executed => |executed| executed,
    };
    if (recorder.full) return call.fail(rpc.code.server_error, "trace exceeds the trace buffers");
    const env = try eth.request_env(api, call, &request);
    // The gas `eth.simulate` ran with: the request's, else the RPC gas cap (or what a priced
    // caller can afford), as reth's `prepare_call_env` sets it.
    assert(executed.gas_limit <= eth.rpc_gas_cap);
    const top: TopGas = .{ .limit = executed.gas_limit, .used = executed.gas_used };
    // A call has no block hash or transaction; it runs in the block `eth.simulate` uses.
    const locator: flat_call.Locator = .{ .block_number = env.number };
    const range: Range = .{ .first = 0, .end = recorder.frame_count };
    try write_frames(call.writer, &recorder, range, top, locator, options);
}

fn trace_call_struct(
    api: *Api,
    call: *Call,
    request: eth.CallRequest,
    space: []u8,
    options: Options,
) HandlerError!void {
    var logger = struct_log.Logger.init(space, options.struct_log, call.writer.out) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    try logger.begin_transaction(call.writer);
    const tracer = logger.tracer();
    const executor = api.chain.executor;
    executor.machine.tracer = &tracer;
    const simulated = eth.simulate(api, call, request);
    executor.machine.tracer = null;
    const executed = switch (try simulated) {
        .invalid => |reason| return eth.fail_invalid(call, reason),
        .executed => |executed| executed,
    };
    if (logger.full) return call.fail(rpc.code.server_error, "trace exceeds the trace buffers");
    if (logger.overflow) return error.WriteFailed;
    try logger.write(executed.gas_used);
}

/// `debug_traceBlock(rlp, options)`: traces an RLP block (canonical or not) on its
/// parent's state, which must be in the history window.
fn trace_raw_block(api: *Api, call: *Call) HandlerError!void {
    const tail = eth.proof_tail_offset(api) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    // The block's bytes take the first quarter of the scratch; the traces use the rest.
    const raw = try call.params.data(api.scratch[0 .. tail / 4]);
    const deferred = try options_deferred(try call.params.optional_raw());
    try call.params.finish();
    const block = consensus.block.Block.decode(raw) catch
        return call.fail(rpc.code.invalid_params, "invalid block RLP");
    // Nethermind refuses a genesis block given as RLP, whatever its number.
    if (block.header.number == api.chain.genesis_number) {
        return call.fail(rpc.code.server_error, "genesis is not traceable");
    }
    if (api.chain.header(block.header.parent_hash.bytes) == null) {
        return call.fail(rpc.code.server_error, "parent block not found");
    }
    const reserved = @intFromPtr(raw.ptr) - @intFromPtr(api.scratch.ptr) + raw.len;
    const transactions = rlp.Decoder.init(block.body.transactions.payload);
    const options = try options_or_refuse(call, deferred);
    try trace_block(api, call, &block.header, transactions, null, options, reserved);
}

/// Re-executes block `hash` up to transaction `only` (or all of it), tracing `only` (or
/// every transaction), and writes the result.
fn trace(api: *Api, call: *Call, hash: Hash, only: ?u32, options: Options) HandlerError!void {
    const stored = api.chain.record(hash) orelse {
        return call.fail(rpc.code.server_error, "block not found");
    };
    try trace_block(api, call, &stored.header, stored.transactions, only, options, 0);
}

/// Nethermind refuses block 0, but replays a later genesis on the empty pre-genesis state:
/// it has no transactions, so it has no traces.
fn trace_genesis(call: *Call, header: *const consensus.Header, only: ?u32) HandlerError!void {
    if (header.number == 0) return call.fail(rpc.code.server_error, "genesis is not traceable");
    assert(only == null);
    try call.writer.begin_array();
    try call.writer.end_array();
}

/// Re-executes a block (`header` and its transactions, which may live in the first
/// `reserved` scratch bytes) on its parent's state and writes the traces.
fn trace_block(
    api: *Api,
    call: *Call,
    header: *const consensus.Header,
    transactions_in: rlp.Decoder,
    only: ?u32,
    options: Options,
    reserved: usize,
) HandlerError!void {
    const chain = api.chain;
    if (header.number <= chain.genesis_number) return trace_genesis(call, header, only);
    var list = transactions_in;
    var count: u32 = 0;
    while (!list.is_empty()) : (count += 1) {
        if (count == chain.transactions_buffer.len) {
            return call.fail(rpc.code.invalid_params, "too many transactions");
        }
        // Block RLP carries legacy transactions as lists and typed ones as strings.
        const is_list = (list.peek_header() catch
            return call.fail(rpc.code.invalid_params, "invalid transaction list")).list;
        const item = if (is_list) list.raw() else list.bytes();
        chain.transactions_buffer[count] = item catch
            return call.fail(rpc.code.invalid_params, "invalid transaction list");
    }
    if (only) |index| assert(index < count);
    const run_count = if (only) |index| index + 1 else count;
    const transactions = chain.transactions_buffer[0..run_count];
    const tail = eth.proof_tail_offset(api) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    if (reserved >= tail) return call.fail(rpc.code.internal_error, "scratch too small");
    const space = api.scratch[reserved..tail];
    chain.ensure_head_state() catch {
        return call.fail(rpc.code.internal_error, "head state unavailable");
    };
    const proofs: *eth_proof.Scratch = @ptrCast(@alignCast(api.scratch[tail..].ptr));
    var history: node.HistoryDatabase = .{
        .chain = chain,
        .hash = header.parent_hash.bytes,
        .number = header.number - 1,
        .account_proof = &proofs.account,
        .storage_proof = &proofs.storage,
    };
    const env = node.chain.env_of(header);
    const database = history.database();
    // These two run their own execution loops.
    if (options.tracer == .prestate or options.tracer == .struct_log) {
        const run = if (options.tracer == .prestate) &trace_prestate else &trace_struct;
        return run(api, call, &env, transactions, only, options, &history, space);
    }
    var recorder = recorder_in(space) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    recorder.with_logs = options.with_logs;
    // flatCallTracer locates each trace in its block.
    const block: Block = .{
        .hash = if (options.tracer == .flat_call) header.hash().bytes else @splat(0),
        .number = header.number,
    };
    const run: Run = .{ .env = &env, .transactions = transactions, .only = only };
    execute(chain.executor, run, &recorder, database, call.writer, block, options) catch |err| {
        if (history.failure) |failure| return eth_proof.fail_history(call, failure);
        return switch (err) {
            error.WriteFailed => error.WriteFailed,
            error.TraceFull => call.fail(rpc.code.server_error, "trace exceeds the trace buffers"),
            else => call.fail(rpc.code.server_error, @errorName(err)),
        };
    };
}

/// A block re-execution: transactions up to `only` (or all of them), tracing `only` (or
/// every one).
const Run = struct {
    env: *const node.executor.BlockEnv,
    transactions: []const []const u8,
    only: ?u32,
};

/// Re-executes the block, writing each traced transaction's result as soon as it has run
/// (the recorder holds one transaction's frames at a time).
fn execute(
    executor: *node.executor.Executor,
    run: Run,
    recorder: *Recorder,
    database: evm.state.Database,
    w: *json.Writer,
    block: Block,
    options: Options,
) !void {
    const session = executor.session_begin(database);
    defer executor.session_end(session);
    try executor.recover_all(run.transactions);
    var building = try executor.begin_block(run.env);
    const tracer = recorder.tracer();
    defer executor.machine.tracer = null;
    defer executor.known_sender = null;
    if (run.only == null) try w.begin_array();
    for (run.transactions, 0..) |raw, index| {
        const traced = run.only == null or run.only.? == index;
        recorder.begin_transaction(@intCast(index));
        executor.machine.tracer = if (traced) &tracer else null;
        executor.known_sender = executor.senders[index];
        const before = building.gas_used;
        try executor.apply(&building, raw);
        if (!traced) continue;
        if (recorder.full) return error.TraceFull;
        const envelope = consensus.Envelope.decode(raw) catch unreachable; // Applied.
        const top: TopGas = .{ .limit = envelope.gas_limit(), .used = building.gas_used - before };
        const hash = primitives.keccak256(raw).bytes;
        const locator: flat_call.Locator = .{
            .block_hash = block.hash,
            .block_number = block.number,
            .transaction_hash = hash,
            .transaction_position = @intCast(index),
        };
        if (run.only == null) {
            try w.begin_object();
            try w.key("txHash");
            try w.data(&hash);
            try w.key("result");
        }
        const range: Range = .{ .first = 0, .end = recorder.frame_count };
        try write_frames(w, recorder, range, top, locator, options);
        if (run.only == null) try w.end_object();
    }
    if (run.only == null) try w.end_array();
}

/// The traced block's hash (computed for flatCallTracer only) and number.
const Block = struct { hash: Hash, number: u64 };

/// A transaction's frames in the recorder: `first..end`.
pub const Range = struct { first: u32, end: u32 };

/// Writes one transaction's result for the tracers built from call frames.
/// alloy's `CallFrame::default()`: an empty type, the zero sender, no gas, empty input.
fn write_empty_frame(w: *json.Writer) json.Writer.WriteError!void {
    try w.begin_object();
    try w.key("type");
    try w.string("");
    try w.key("from");
    try w.data(&@as(Address, @splat(0)));
    try w.key("gas");
    try w.quantity(@as(u64, 0));
    try w.key("gasUsed");
    try w.quantity(@as(u64, 0));
    try w.key("input");
    try w.data(&.{});
    try w.end_object();
}

fn write_frames(
    w: *json.Writer,
    recorder: *const Recorder,
    range: Range,
    top: TopGas,
    locator: flat_call.Locator,
    options: Options,
) json.Writer.WriteError!void {
    assert(range.first <= range.end and range.end <= recorder.frame_count);
    switch (options.tracer) {
        .call => {
            // Only a deposit failing before execution (a system deposit, gas below intrinsic)
            // applies with no frame: revm-inspectors then writes alloy's default frame.
            if (range.first == range.end) return write_empty_frame(w);
            try write_tree(w, recorder, range.first, range.end, top, options.only_top_call);
        },
        .four_byte => try flat_call.write_four_byte(w, recorder.frames[range.first..range.end]),
        .noop => {
            try w.begin_object();
            try w.end_object();
        },
        .flat_call => try flat_call.write_flat(w, .{
            .frames = recorder.frames[range.first..range.end],
            .top = top,
            .locator = locator,
            .include_precompiles = options.include_precompiles,
        }),
        .prestate, .struct_log => unreachable, // Written by their own paths.
    }
}

// ---- Tests ------------------------------------------------------------------------

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "trace: revert reasons decode Error(string) only when well formed" {
    var payload: [4 + 96]u8 = @splat(0);
    payload[0..4].* = .{ 0x08, 0xc3, 0x79, 0xa0 };
    payload[4 + 31] = 0x20;
    payload[4 + 63] = 2;
    payload[4 + 64] = 'n';
    payload[4 + 65] = 'o';
    try testing.expectEqualStrings("no", revert_reason(&payload).?);
    payload[4 + 63] = 200; // Length past the payload.
    try testing.expect(revert_reason(&payload) == null);
    try testing.expect(revert_reason(payload[0..10]) == null);
    try testing.expectEqualStrings("execution reverted", error_text(.revert).?);
    try testing.expect(error_text(.return_) == null);
}

test "trace: options select callTracer and its config" {
    const parsed = try parse_options(
        "{\"tracer\":\"callTracer\",\"tracerConfig\":{\"onlyTopCall\":true,\"withLog\":false}}",
    );
    try testing.expect(parsed.tracer == .call);
    try testing.expect(parsed.only_top_call and !parsed.with_logs);
    // No tracer (or an empty one) is the struct logger: stack and storage on, memory and
    // return data off.
    for ([_]?[]const u8{ null, "{}", "null", "{\"tracer\":\"\"}" }) |raw| {
        const default = try parse_options(raw);
        try testing.expect(default.tracer == .struct_log);
        try testing.expect(default.struct_log.stack and default.struct_log.storage);
        try testing.expect(!default.struct_log.memory and !default.struct_log.return_data);
        try testing.expectEqual(@as(u64, 0), default.struct_log.limit);
    }
    const flags = try parse_options("{\"disableStack\":true,\"disableStorage\":true," ++
        "\"enableMemory\":true,\"disableReturnData\":false,\"limit\":5,\"timeout\":\"1s\"}");
    try testing.expect(!flags.struct_log.stack and !flags.struct_log.storage);
    try testing.expect(flags.struct_log.memory and flags.struct_log.return_data);
    try testing.expectEqual(@as(u64, 5), flags.struct_log.limit);
    // `enableMemory` wins over `disableMemory`.
    const memory = try parse_options("{\"enableMemory\":false,\"disableMemory\":false}");
    try testing.expect(!memory.struct_log.memory);
    try testing.expect((try parse_options("{\"tracer\":\"4byteTracer\"}")).tracer == .four_byte);
    try testing.expect((try parse_options("{\"tracer\":\"noopTracer\"}")).tracer == .noop);
    const flat = try parse_options(
        "{\"tracer\":\"flatCallTracer\",\"tracerConfig\":{\"includePrecompiles\":true}}",
    );
    try testing.expect(flat.tracer == .flat_call and flat.include_precompiles);
    try testing.expectError(error.Unsupported, parse_options("{\"tracer\":\"muxTracer\"}"));
    try testing.expectError(error.JsTracer, parse_options("{\"tracer\":\"{step: 1}\"}"));
    try testing.expectError(error.InvalidParams, parse_options("{\"tracer\":1}"));
    try testing.expectError(error.InvalidParams, parse_options("{\"disableStack\":1}"));
    const pre = try parse_options(
        "{\"tracer\":\"prestateTracer\",\"tracerConfig\":{\"diffMode\":true}}",
    );
    try testing.expect(pre.tracer == .prestate and pre.diff_mode);
    try testing.expectError(error.InvalidParams, parse_options("[1]"));
    // A malformed field fails before the tracer is refused, the tracer before its config.
    try testing.expectError(error.InvalidParams, parse_options(
        "{\"tracer\":\"muxTracer\",\"disableStack\":1}",
    ));
    try testing.expectError(error.Unsupported, parse_options(
        "{\"tracerConfig\":1,\"tracer\":\"muxTracer\"}",
    ));
    try testing.expectError(error.InvalidConfig, parse_options(
        "{\"tracerConfig\":{\"only\\u0054opCall\":1},\"tracer\":\"callTracer\"}",
    ));
    const positional = try parse_options(
        "{\"tracer\":\"prestateTracer\",\"tracerConfig\":[true,null,true]}",
    );
    try testing.expect(positional.diff_mode and !positional.disable_code);
    try testing.expect(positional.disable_storage);
}

/// Random frame trees (each depth at most one more than the previous) write valid JSON.
fn random_tree(seed: u64) !void {
    var prng = Prng.init(seed);
    var frames: [64]Frame = undefined;
    var logs: [8]Log = undefined;
    var bytes: [64]u8 = undefined;
    var recorder: Recorder = .{ .frames = &frames, .logs = &logs, .bytes = &bytes };
    recorder.with_logs = prng.chance(1, 2);
    const count = prng.range(1, frames.len);
    var depth: u16 = 0;
    const exits = [_]evm.evm.Exit{ .stop, .return_, .revert, .out_of_gas, .invalid_jump };
    for (frames[0..count], 0..) |*frame, index| {
        if (index > 0) depth = @intCast(prng.range(1, depth + 1));
        frame.* = .{
            .kind = @fromBackingInt(@intCast(prng.below(7))),
            .from = @splat(1),
            .to = @splat(2),
            .value = prng.below(10),
            .gas = prng.below(1 << 20),
            .gas_used = prng.below(1 << 20),
            .input = bytes[0..prng.below(8)],
            .output = bytes[0..prng.below(8)],
            .exit = exits[prng.below(exits.len)],
            .depth = depth,
            .transaction = 0,
        };
        if (recorder.with_logs and recorder.log_count < logs.len and prng.chance(1, 3)) {
            logs[recorder.log_count] = .{
                .frame = @intCast(index),
                .address = @splat(3),
                .topics = undefined,
                .topic_count = 0,
                .data = &.{},
                .position = 0,
            };
            recorder.log_count += 1;
        }
    }
    recorder.frame_count = @intCast(count);
    var out: [1 << 16]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&out);
    var w: json.Writer = .init(&writer);
    const top: TopGas = .{ .limit = 1, .used = 1 };
    try write_tree(&w, &recorder, 0, @intCast(count), top, prng.chance(1, 4));
    try json.validate(writer.buffered());
}

test "trace: seeded fuzz of call trees" {
    for (0..256) |seed| try random_tree(seed);
}

test "trace: a call tree as deep as the EVM allows writes in full" {
    // Frames at depths 0..1024, each the only child of the one before (a 90-deep tree used
    // to trip the writer's 64-level bound and abort the node).
    const count = depth_max - 1;
    const frames = try testing.allocator.alloc(Frame, count);
    defer testing.allocator.free(frames);
    for (frames, 0..) |*frame, index| {
        frame.* = .{
            .kind = @fromBackingInt(0),
            .from = @splat(1),
            .to = @splat(2),
            .value = 0,
            .gas = 100,
            .gas_used = 100,
            .input = &.{},
            .output = &.{},
            .exit = if (index + 1 == count) .out_of_gas else .return_,
            .depth = @intCast(index),
            .transaction = 0,
        };
    }
    var recorder: Recorder = .{ .frames = frames, .logs = &.{}, .bytes = &.{} };
    recorder.frame_count = count;
    const out = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(out);
    var writer: std.Io.Writer = .fixed(out);
    var w: json.Writer = .init(&writer);
    try write_tree(&w, &recorder, 0, count, .{ .limit = 1, .used = 1 }, false);
    const text = writer.buffered();
    try testing.expectEqual(count, std.mem.count(u8, text, "{"));
    try testing.expectEqual(count, std.mem.count(u8, text, "}"));
    try testing.expectEqual(count - 1, std.mem.count(u8, text, "\"calls\":["));
    const tail = text[text.len - 2 * (count - 1) ..];
    for (0..count - 1) |index| try testing.expectEqualStrings("]}", tail[2 * index ..][0..2]);
    try testing.expectEqual(@as(u32, 0), w.depth);
}

fn fuzz_trace(_: void, smith: *testing.Smith) anyerror!void {
    var text: [48]u8 = undefined;
    for (&text) |*byte| byte.* = smith.value(u8);
    _ = parse_options(&text) catch {};
    _ = revert_reason(&text);
    try random_tree(smith.value(u64));
}

test "trace: fuzz options, revert reasons and trees" {
    try testing.fuzz({}, fuzz_trace, .{});
}

fn trace_call_prestate(
    api: *Api,
    call: *Call,
    request_in: eth.CallRequest,
    space: []u8,
    options: Options,
) HandlerError!void {
    var collected = prestate.Collected.init(space) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    var request = request_in;
    collected.authorities = request.message.authorization_list orelse &.{};
    collected.callee = request.message.to;
    collected.sender = request.message.from;
    request.message.inspect = collected.inspect();
    switch (try eth.simulate(api, call, request)) {
        .invalid => |reason| return eth.fail_invalid(call, reason),
        .executed => {},
    }
    if (collected.failed) return call.fail(rpc.code.internal_error, "state read failed");
    if (collected.full) return call.fail(rpc.code.server_error, "trace exceeds the trace buffers");
    try prestate.write(call.writer, &collected, prestate_config(options));
}

fn prestate_config(options: Options) prestate.Config {
    assert(options.tracer == .prestate);
    return .{
        .diff = options.diff_mode,
        .code = !options.disable_code,
        .storage = !options.disable_storage,
    };
}

/// prestateTracer over a stored block: each traced transaction's result is written into
/// the response as soon as it has run (the state moves on); a failure later rewinds the
/// whole response.
fn trace_prestate(
    api: *Api,
    call: *Call,
    env: *const node.executor.BlockEnv,
    transactions: []const []const u8,
    only: ?u32,
    options: Options,
    history: *node.HistoryDatabase,
    space: []u8,
) HandlerError!void {
    var collected = prestate.Collected.init(space) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    const executor = api.chain.executor;
    run_prestate(
        executor,
        env,
        transactions,
        only,
        options,
        &collected,
        call.writer,
        history.database(),
    ) catch |err| {
        if (history.failure) |failure| return eth_proof.fail_history(call, failure);
        return switch (err) {
            error.WriteFailed => error.WriteFailed,
            error.TraceFull => call.fail(rpc.code.server_error, "trace exceeds the trace buffers"),
            error.StateReadFailed => call.fail(rpc.code.internal_error, "state read failed"),
            else => call.fail(rpc.code.server_error, @errorName(err)),
        };
    };
}

fn run_prestate(
    executor: *node.executor.Executor,
    env: *const node.executor.BlockEnv,
    transactions: []const []const u8,
    only: ?u32,
    options: Options,
    collected: *prestate.Collected,
    w: *json.Writer,
    database: evm.state.Database,
) !void {
    const session = executor.session_begin(database);
    defer executor.session_end(session);
    try executor.recover_all(transactions);
    var building = try executor.begin_block(env);
    defer executor.known_sender = null;
    if (only == null) try w.begin_array();
    for (transactions, 0..) |raw, index| {
        const traced = only == null or only.? == index;
        if (traced) collected.take_snapshot(executor.state);
        executor.known_sender = executor.senders[index];
        try executor.apply(&building, raw);
        if (!traced) continue;
        collected.collect(executor.state);
        add_lookups(collected, executor, raw, executor.senders[index]);
        // Nethermind's tracer looks up the beneficiary for every transaction.
        _ = collected.add_account(executor.state, env.beneficiary);
        if (collected.full) return error.TraceFull;
        if (collected.failed) return error.StateReadFailed;
        if (only == null) {
            try w.begin_object();
            try w.key("txHash");
            try w.data(&primitives.keccak256(raw).bytes);
            try w.key("result");
        }
        try prestate.write(w, collected, prestate_config(options));
        if (only == null) try w.end_object();
    }
    if (only == null) try w.end_array();
}

/// Lists a stored transaction's callee with its pre-transaction EIP-7702 delegate (or the
/// address a creation makes), and the
/// recoverable authorities of an EIP-7702 transaction (Nethermind's prestateTracer lists
/// them even when their authorization was invalid).
fn add_lookups(
    collected: *prestate.Collected,
    executor: *node.executor.Executor,
    raw: []const u8,
    sender: ?primitives.Address,
) void {
    const envelope = consensus.Envelope.decode(raw) catch unreachable; // Stored by the chain.
    // An EIP-8130 transaction's calls live in its phases.
    if (envelope != .eip8130) switch (envelope.kind()) {
        .call => |to| collected.add_callee(executor.state, to.bytes),
        // geth's OnTxStart looks up the address a creation makes (a failed deposit never
        // loads it), counted created.
        .create => if (sender) |from| collected.add_created_by(executor.state, from.bytes),
    };
    if (envelope != .eip7702) return;
    var authorizations = envelope.eip7702.tx.authorization_list.iterator();
    var count: u32 = 0;
    while (authorizations.next()) |authorization| : (count += 1) {
        const authority = authorization.recover_authority(executor.recoverer) orelse continue;
        _ = collected.add_account(executor.state, authority.bytes);
    }
    assert(count == envelope.eip7702.tx.authorization_list.count);
}

/// The struct logger over a stored block: each traced transaction's logs stream into the
/// response while it executes, and its result head (`failed`, `gas`, `returnValue`) is
/// slid in front of them after (a failure later rewinds the whole response).
fn trace_struct(
    api: *Api,
    call: *Call,
    env: *const node.executor.BlockEnv,
    transactions: []const []const u8,
    only: ?u32,
    options: Options,
    history: *node.HistoryDatabase,
    space: []u8,
) HandlerError!void {
    var logger = struct_log.Logger.init(space, options.struct_log, call.writer.out) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    const executor = api.chain.executor;
    const database = history.database();
    run_struct(executor, env, transactions, only, &logger, call.writer, database) catch |err| {
        if (history.failure) |failure| return eth_proof.fail_history(call, failure);
        return switch (err) {
            error.WriteFailed, error.TraceOverflow => error.WriteFailed,
            error.TraceFull => call.fail(rpc.code.server_error, "trace exceeds the trace buffers"),
            else => call.fail(rpc.code.server_error, @errorName(err)),
        };
    };
}

fn run_struct(
    executor: *node.executor.Executor,
    env: *const node.executor.BlockEnv,
    transactions: []const []const u8,
    only: ?u32,
    logger: *struct_log.Logger,
    w: *json.Writer,
    database: evm.state.Database,
) !void {
    const session = executor.session_begin(database);
    defer executor.session_end(session);
    try executor.recover_all(transactions);
    var building = try executor.begin_block(env);
    defer executor.known_sender = null;
    const tracer = logger.tracer();
    defer executor.machine.tracer = null;
    if (only == null) try w.begin_array();
    for (transactions, 0..) |raw, index| {
        const traced = only == null or only.? == index;
        if (traced and only == null) {
            try w.begin_object();
            try w.key("txHash");
            try w.data(&primitives.keccak256(raw).bytes);
            try w.key("result");
        }
        if (traced) try logger.begin_transaction(w);
        executor.known_sender = executor.senders[index];
        executor.machine.tracer = if (traced) &tracer else null;
        const before = building.gas_used;
        try executor.apply(&building, raw);
        if (!traced) continue;
        if (logger.full) return error.TraceFull;
        if (logger.overflow) return error.TraceOverflow;
        try logger.write(building.gas_used - before);
        if (only == null) try w.end_object();
    }
    if (only == null) try w.end_array();
}
