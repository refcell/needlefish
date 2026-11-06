//! `debug_traceTransaction`, `debug_traceBlockByNumber` and `debug_traceBlockByHash` with
//! geth's `callTracer` (config `onlyTopCall`, `withLog`).
//!
//! The block is re-executed on its parent's state (`HistoryDatabase`, so the history window
//! bounds what can be traced) in an executor session that commits nothing; the evm's
//! call-frame hook (`evm.Tracer`) feeds a `Recorder` that keeps frames flat, in call order
//! with their depth, copying inputs, outputs and logs into a bounded arena. The nested JSON
//! is written from that list with an explicit stack (no recursion). As geth: the top frame
//! reports the transaction's gas limit and gas used, logs of failed frames (and their
//! descendants) are dropped, and `revertReason` decodes `Error(string)`. An EIP-8130
//! transaction's later top-level phase calls nest under its first. Other tracers
//! (struct logger, prestateTracer) are not supported. `debug_traceCall` runs the call as
//! `eth_call` does (same view, gas default and simulation) with the recorder attached.

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
const eth_proof = @import("eth_proof.zig");
const prestate = @import("prestate.zig");

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

    pub fn begin_transaction(recorder: *Recorder, index: u32) void {
        assert(recorder.open_count == 0);
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
pub fn recorder_in(space: []u8) ?Recorder {
    const frame_bytes = space.len / 4;
    const log_bytes = space.len / 8;
    var fixed: std.heap.FixedBufferAllocator = .init(space);
    const allocator = fixed.allocator();
    const frames = allocator.alloc(Frame, frame_bytes / @sizeOf(Frame)) catch return null;
    const logs = allocator.alloc(Log, log_bytes / @sizeOf(Log)) catch return null;
    const rest = space.len - fixed.end_index;
    const bytes = allocator.alloc(u8, rest) catch return null;
    if (frames.len == 0) return null;
    return .{ .frames = frames, .logs = logs, .bytes = bytes };
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
        .invalid_opcode => "invalid opcode",
        .stack_underflow => "stack underflow",
        .stack_overflow => "stack limit reached 1024",
        .invalid_jump => "invalid jump destination",
        .static_violation => "write protection",
        .return_data_out_of_bounds => "return data out of bounds",
        .code_size_limit => "max code size exceeded",
        .invalid_code_prefix => "invalid code: must not begin with 0xef",
        .create_collision => "contract address collision",
        .precompile_failure => "precompile failed",
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

fn write_fields(w: *json.Writer, frame: *const Frame, top: ?TopGas) json.Writer.WriteError!void {
    try w.key("type");
    try w.string(kind_name(frame.kind));
    try w.key("from");
    try w.data(&frame.from);
    try w.key("to");
    try w.data(&frame.to);
    if (frame.kind != .staticcall and frame.kind != .delegatecall) {
        try w.key("value");
        try w.quantity(frame.value);
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
    var stack: [depth_max]struct { frame: u32, failed: bool } = undefined;
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
        try w.begin_object();
        try write_fields(w, frame, if (index == first) top else null);
        if (!failed) try write_logs(w, recorder, index);
        const has_children = index + 1 < last and frames[index + 1].depth > frame.depth;
        if (has_children) {
            try w.key("calls");
            try w.begin_array();
            stack[stack_count] = .{ .frame = index, .failed = failed };
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

pub const Options = struct {
    tracer: enum { call, prestate } = .call,
    only_top_call: bool = false,
    with_logs: bool = false,
    diff_mode: bool = false,
};

/// Parses `{"tracer":"callTracer","tracerConfig":{...}}` (absent: an error, since the
/// default struct logger is not supported).
pub fn parse_options(raw: ?[]const u8) error{ InvalidParams, Unsupported }!Options {
    const text = raw orelse return error.Unsupported;
    var options: Options = .{};
    var scanner = json.Scanner.init(text);
    if ((scanner.next() catch return error.InvalidParams).tag != .object_begin) {
        return error.InvalidParams;
    }
    var named = false;
    while (true) {
        const name = scanner.next() catch return error.InvalidParams;
        if (name.tag == .object_end) break;
        const value = scanner.next() catch return error.InvalidParams;
        if (std.mem.eql(u8, name.bytes, "tracer")) {
            if (value.tag != .string) return error.InvalidParams;
            named = true;
            if (std.mem.eql(u8, value.bytes, "prestateTracer")) {
                options.tracer = .prestate;
            } else if (!std.mem.eql(u8, value.bytes, "callTracer")) {
                return error.Unsupported;
            }
        } else if (std.mem.eql(u8, name.bytes, "tracerConfig") and value.tag == .object_begin) {
            try parse_config(&scanner, &options);
        } else {
            scanner.skip(value) catch return error.InvalidParams;
        }
    }
    if (!named) return error.Unsupported;
    return options;
}

fn parse_config(scanner: *json.Scanner, options: *Options) error{InvalidParams}!void {
    while (true) {
        const name = scanner.next() catch return error.InvalidParams;
        if (name.tag == .object_end) return;
        const value = scanner.next() catch return error.InvalidParams;
        const flag = value.tag == .true;
        if (std.mem.eql(u8, name.bytes, "onlyTopCall")) {
            options.only_top_call = flag;
        } else if (std.mem.eql(u8, name.bytes, "withLog")) {
            options.with_logs = flag;
        } else if (std.mem.eql(u8, name.bytes, "diffMode")) {
            options.diff_mode = flag;
        } else {
            scanner.skip(value) catch return error.InvalidParams;
        }
    }
}

fn options_of(call: *Call, raw: ?[]const u8) HandlerError!Options {
    return parse_options(raw) catch |err| switch (err) {
        error.InvalidParams => return error.InvalidParams,
        error.Unsupported => {
            return call.fail(rpc.code.invalid_params, "only callTracer and prestateTracer");
        },
    };
}

fn trace_transaction(api: *Api, call: *Call) HandlerError!void {
    const tx_hash = try call.params.fixed(32);
    const options = try options_of(call, try call.params.optional_raw());
    try call.params.finish();
    const location = api.chain.find_transaction(tx_hash) orelse {
        return call.fail(rpc.code.server_error, "transaction not found");
    };
    try trace(api, call, location.block_hash, location.index, options);
}

fn trace_block_by_number(api: *Api, call: *Call) HandlerError!void {
    const raw = try call.params.raw();
    const options = try options_of(call, try call.params.optional_raw());
    try call.params.finish();
    const hash = eth.resolve_block(api, call, raw) catch |err| switch (err) {
        error.Failed => return call.fail(rpc.code.server_error, "block not found"),
        else => return err,
    };
    try trace(api, call, hash, null, options);
}

fn trace_block_by_hash(api: *Api, call: *Call) HandlerError!void {
    const hash = try call.params.fixed(32);
    const options = try options_of(call, try call.params.optional_raw());
    try call.params.finish();
    if (api.chain.record(hash) == null) return call.fail(rpc.code.server_error, "block not found");
    try trace(api, call, hash, null, options);
}

fn trace_call(api: *Api, call: *Call) HandlerError!void {
    var request = try eth.parse_call_request(api, call);
    const config = try call.params.optional_raw();
    const options = try options_of(call, config);
    try call.params.finish();
    // geth reads `stateOverrides` and `blockOverrides` from the trace config.
    const state_overrides = json.find_path(config.?, &.{"stateOverrides"}) catch
        return error.InvalidParams;
    const block_overrides = json.find_path(config.?, &.{"blockOverrides"}) catch
        return error.InvalidParams;
    try eth.set_overrides(api, call, &request, state_overrides, block_overrides);
    // The recorder sits between the request's scratch (call data, override code) and the
    // proof tail.
    const data_end = eth.scratch_used(api, &request);
    const end = switch (request.view) {
        .head => api.scratch.len,
        .historical => eth.proof_tail_offset(api).?, // Checked by `parse_call_request`.
    };
    if (data_end >= end) return call.fail(rpc.code.internal_error, "scratch too small");
    if (options.tracer == .prestate) {
        return trace_call_prestate(api, call, request, api.scratch[data_end..end], options);
    }
    var recorder = recorder_in(api.scratch[data_end..end]) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    recorder.with_logs = options.with_logs;
    const tracer = recorder.tracer();
    const executor = api.chain.executor;
    executor.machine.tracer = &tracer;
    const simulated = eth.simulate(api, call, request);
    executor.machine.tracer = null;
    const executed = switch (try simulated) {
        .invalid => |reason| return call.fail(rpc.code.server_error, @tagName(reason)),
        .executed => |executed| executed,
    };
    if (recorder.full) return call.fail(rpc.code.server_error, "trace exceeds the trace buffers");
    if (recorder.frame_count == 0) return call.writer.null_value();
    var header = eth.view_header(api, request.view);
    var env = node.chain.env_of(&header);
    env.timestamp += 1; // As `eth.simulate` runs it.
    const limit = request.message.gas orelse executor.default_call_gas(&env);
    const top: TopGas = .{ .limit = limit, .used = executed.gas_used };
    try write_tree(call.writer, &recorder, 0, recorder.frame_count, top, options.only_top_call);
}

/// `debug_traceBlock(rlp, options)`: traces an RLP block (canonical or not) on its
/// parent's state, which must be in the history window.
fn trace_raw_block(api: *Api, call: *Call) HandlerError!void {
    const tail = eth.proof_tail_offset(api) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    // The block's bytes take the first quarter of the scratch; the traces use the rest.
    const raw = try call.params.data(api.scratch[0 .. tail / 4]);
    const options = try options_of(call, try call.params.optional_raw());
    try call.params.finish();
    const block = consensus.block.Block.decode(raw) catch
        return call.fail(rpc.code.invalid_params, "invalid block RLP");
    if (api.chain.header(block.header.parent_hash.bytes) == null) {
        return call.fail(rpc.code.server_error, "parent block not found");
    }
    const reserved = @intFromPtr(raw.ptr) - @intFromPtr(api.scratch.ptr) + raw.len;
    const transactions = rlp.Decoder.init(block.body.transactions.payload);
    try trace_block(api, call, &block.header, transactions, null, options, reserved);
}

/// Per-transaction results of a re-execution: frame ranges and gas.
const Ranges = struct {
    first: [*]u32,
    gas: [*]u64,
};

/// Re-executes block `hash` up to transaction `only` (or all of it), tracing `only` (or
/// every transaction), and writes the result.
fn trace(api: *Api, call: *Call, hash: Hash, only: ?u32, options: Options) HandlerError!void {
    const stored = api.chain.record(hash) orelse {
        return call.fail(rpc.code.server_error, "block not found");
    };
    try trace_block(api, call, &stored.header, stored.transactions, only, options, 0);
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
    if (header.number == 0) return call.fail(rpc.code.invalid_params, "genesis has no parent");
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
    if (options.tracer == .prestate) {
        return trace_prestate(api, call, &env, transactions, only, options, &history, space);
    }
    const per_transaction = run_count * (@sizeOf(u32) + @sizeOf(u64)) + 16;
    if (per_transaction >= space.len) {
        return call.fail(rpc.code.internal_error, "scratch too small");
    }
    const ranges = carve_ranges(space[0..per_transaction], run_count + 1);
    var recorder = recorder_in(space[per_transaction..]) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    recorder.with_logs = options.with_logs;
    execute(chain.executor, &env, transactions, only, &recorder, ranges, database) catch |err| {
        if (history.failure) |failure| return eth_proof.fail_history(call, failure);
        return call.fail(rpc.code.server_error, @errorName(err));
    };
    if (recorder.full) return call.fail(rpc.code.server_error, "trace exceeds the trace buffers");
    try write_result(call.writer, &recorder, transactions, only, ranges, options);
}

fn carve_ranges(space: []u8, count: usize) Ranges {
    var fixed: std.heap.FixedBufferAllocator = .init(space);
    const allocator = fixed.allocator();
    const gas = allocator.alloc(u64, count) catch unreachable; // Sized by the caller.
    const first = allocator.alloc(u32, count) catch unreachable;
    return .{ .first = first.ptr, .gas = gas.ptr };
}

fn execute(
    executor: *node.executor.Executor,
    env: *const node.executor.BlockEnv,
    transactions: []const []const u8,
    only: ?u32,
    recorder: *Recorder,
    ranges: Ranges,
    database: evm.state.Database,
) node.executor.Error!void {
    const session = executor.session_begin(database);
    defer executor.session_end(session);
    try executor.recover_all(transactions);
    var building = try executor.begin_block(env);
    const tracer = recorder.tracer();
    defer executor.machine.tracer = null;
    defer executor.known_sender = null;
    for (transactions, 0..) |raw, index| {
        const traced = only == null or only.? == index;
        recorder.begin_transaction(@intCast(index));
        ranges.first[index] = recorder.frame_count;
        executor.machine.tracer = if (traced) &tracer else null;
        executor.known_sender = executor.senders[index];
        const before = building.gas_used;
        try executor.apply(&building, raw);
        ranges.gas[index] = building.gas_used - before;
    }
    ranges.first[transactions.len] = recorder.frame_count;
}

fn write_result(
    w: *json.Writer,
    recorder: *const Recorder,
    transactions: []const []const u8,
    only: ?u32,
    ranges: Ranges,
    options: Options,
) json.Writer.WriteError!void {
    if (only) |index| return write_one(w, recorder, transactions[index], index, ranges, options);
    try w.begin_array();
    for (transactions, 0..) |raw, index| {
        try w.begin_object();
        try w.key("txHash");
        try w.data(&primitives.keccak256(raw).bytes);
        try w.key("result");
        try write_one(w, recorder, raw, @intCast(index), ranges, options);
        try w.end_object();
    }
    try w.end_array();
}

fn write_one(
    w: *json.Writer,
    recorder: *const Recorder,
    raw: []const u8,
    index: u32,
    ranges: Ranges,
    options: Options,
) json.Writer.WriteError!void {
    const first = ranges.first[index];
    const end = ranges.first[index + 1];
    // A transaction that made no call (an invalid one never applies) has no frames.
    if (first == end) return w.null_value();
    const envelope = consensus.Envelope.decode(raw) catch unreachable; // Executed.
    const top: TopGas = .{ .limit = envelope.gas_limit(), .used = ranges.gas[index] };
    try write_tree(w, recorder, first, end, top, options.only_top_call);
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
    try testing.expect(parsed.only_top_call and !parsed.with_logs);
    try testing.expectError(error.Unsupported, parse_options(null));
    try testing.expectError(error.Unsupported, parse_options("{\"tracer\":\"4byteTracer\"}"));
    try testing.expectError(error.Unsupported, parse_options("{}"));
    const pre = try parse_options(
        "{\"tracer\":\"prestateTracer\",\"tracerConfig\":{\"diffMode\":true}}",
    );
    try testing.expect(pre.tracer == .prestate and pre.diff_mode);
    try testing.expectError(error.InvalidParams, parse_options("[1]"));
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
    request.message.inspect = collected.inspect();
    const tracer = collected.tracer();
    const executor = api.chain.executor;
    executor.machine.tracer = &tracer;
    const simulated = eth.simulate(api, call, request);
    executor.machine.tracer = null;
    switch (try simulated) {
        .invalid => |reason| return call.fail(rpc.code.server_error, @tagName(reason)),
        .executed => {},
    }
    if (collected.failed) return call.fail(rpc.code.internal_error, "state read failed");
    if (collected.full) return call.fail(rpc.code.server_error, "trace exceeds the trace buffers");
    try prestate.write(call.writer, &collected, options.diff_mode);
}

/// prestateTracer over a stored block: each traced transaction's result is staged in
/// scratch as it executes (the state moves on), then written in one piece.
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
    const half = space.len / 2;
    var collected = prestate.Collected.init(space[0..half]) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    var staging: std.Io.Writer = .fixed(space[half..]);
    var staged: json.Writer = .init(&staging);
    const executor = api.chain.executor;
    run_prestate(
        executor,
        env,
        transactions,
        only,
        options,
        &collected,
        &staged,
        history.database(),
    ) catch |err| {
        if (history.failure) |failure| return eth_proof.fail_history(call, failure);
        const too_large = "trace exceeds the trace buffers";
        return switch (err) {
            error.WriteFailed => call.fail(rpc.code.server_error, too_large),
            error.TraceFull => call.fail(rpc.code.server_error, too_large),
            error.StateReadFailed => call.fail(rpc.code.internal_error, "state read failed"),
            else => call.fail(rpc.code.server_error, @errorName(err)),
        };
    };
    try call.writer.raw(staging.buffered());
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
    const tracer = collected.tracer();
    defer executor.machine.tracer = null;
    if (only == null) try w.begin_array();
    for (transactions, 0..) |raw, index| {
        const traced = only == null or only.? == index;
        if (traced) collected.take_snapshot(executor.state);
        executor.known_sender = executor.senders[index];
        executor.machine.tracer = if (traced) &tracer else null;
        try executor.apply(&building, raw);
        if (!traced) continue;
        collected.collect(executor.state);
        if (collected.full) return error.TraceFull;
        if (collected.failed) return error.StateReadFailed;
        if (only == null) {
            try w.begin_object();
            try w.key("txHash");
            try w.data(&primitives.keccak256(raw).bytes);
            try w.key("result");
        }
        try prestate.write(w, collected, options.diff_mode);
        if (only == null) try w.end_object();
    }
    if (only == null) try w.end_array();
}
