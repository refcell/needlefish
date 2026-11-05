//! The EVM driver: an explicit frame stack (no recursion) that runs messages.
//!
//! The interpreter runs the top frame until it exits. A CALL/CREATE exit pushes a
//! child frame (or resolves immediately: precompile, empty code, failed checks); any
//! other exit pops the frame and delivers its outcome to the parent. All buffers
//! (frames, stacks, memory, code analyses, return data) are allocated in `init`.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const stack_module = @import("stack.zig");
const memory_module = @import("memory.zig");
const bytecode = @import("bytecode.zig");
const state_module = @import("state.zig");
const env = @import("env.zig");
const gas = @import("gas.zig");
const interpreter = @import("interpreter.zig");
const precompiles = @import("precompiles.zig");
const crypto = @import("../../common/crypto/root.zig");
const native = @import("native.zig");
const Fork = @import("fork.zig").Fork;
const Address = primitives.Address;
const State = state_module.State;
const Account = state_module.Account;

pub const Error = state_module.Error || error{CodeArenaFull};

pub const Exit = enum(u8) {
    stop,
    return_,
    self_destruct,
    revert,
    out_of_gas,
    invalid_opcode,
    stack_underflow,
    stack_overflow,
    invalid_jump,
    static_violation,
    return_data_out_of_bounds,
    code_size_limit,
    invalid_code_prefix,
    create_collision,
    precompile_failure,
    call,
    create,
    fatal,

    pub fn status(exit: Exit) Status {
        return switch (exit) {
            .stop, .return_, .self_destruct => .success,
            .revert => .revert,
            .call, .create, .fatal => unreachable, // Proof: never a frame outcome.
            else => .halt,
        };
    }
};

pub const Status = enum { success, revert, halt };

pub const CallKind = enum { call, callcode, delegatecall, staticcall };

pub const CallRequest = struct {
    kind: CallKind,
    target: Address,
    /// Account whose code runs (differs from `target` for EIP-7702 delegations).
    code_address: Address,
    value: u256,
    input: []const u8,
    gas_limit: u64,
    return_offset: u64 = 0,
    return_size: u64 = 0,
};

pub const CreateRequest = struct {
    is_create2: bool,
    caller: Address,
    value: u256,
    init_code: []const u8,
    salt: u256,
    gas_limit: u64,
};

pub const Pending = union(enum) {
    none,
    call: CallRequest,
    create: CreateRequest,
};

pub const FrameKind = enum { call, create };

pub const Frame = struct {
    analyzed: bytecode.Analyzed,
    pc: u32 = 0,
    gas: u64,
    refund: i64 = 0,
    stack: stack_module.Stack,
    memory: memory_module.Memory,
    memory_base: u32,
    input: []const u8,
    address: Address,
    /// Storage owner (`address`), a stable pointer into the state cache.
    account: *Account,
    caller: Address,
    value: u256,
    is_static: bool,
    depth: u16,
    kind: FrameKind,
    checkpoint: state_module.Checkpoint,
    arena_mark: usize,
    /// Set by RETURN/REVERT: output range in this frame's memory.
    output_offset: u64 = 0,
    output_size: u64 = 0,
    /// Set when this frame waits on a child.
    awaiting: FrameKind = .call,
    return_offset: u64 = 0,
    return_size: u64 = 0,
};

/// A top-level message from the transaction layer.
pub const Message = struct {
    kind: FrameKind,
    caller: Address,
    /// Callee (ignored for creates).
    target: Address = primitives.address_zero,
    value: u256 = 0,
    /// Calldata, or init code for creates.
    input: []const u8 = &.{},
    gas_limit: u64,
    is_static: bool = false,
};

pub const Outcome = struct {
    status: Status,
    exit: Exit,
    gas_remaining: u64,
    gas_refund: i64,
    /// Return or revert data; points into the EVM's return buffer.
    output: []const u8,
    created: ?Address = null,
};

const Step = union(enum) { frame, done: Outcome };

pub const Evm = struct {
    config: env.Config,
    state: *State,
    block: env.BlockEnv = .{},
    tx: env.TxContext = .{},
    frames: []Frame,
    frames_len: u32 = 0,
    stacks: [][stack_module.limit]u256,
    shared_memory: memory_module.SharedMemory,
    arena: bytecode.Arena,
    return_buffer: []u8,
    precompile_scratch: []u64,
    return_len: u32 = 0,
    pending: Pending = .none,
    fatal_error: ?Error = null,

    pub fn init(allocator: std.mem.Allocator, config: env.Config, state: *State) !Evm {
        config.validate();
        const frame_count = @as(usize, config.depth_max) + 1;
        const frames = try allocator.alloc(Frame, frame_count);
        errdefer allocator.free(frames);
        const stacks = try allocator.alloc([stack_module.limit]u256, frame_count);
        errdefer allocator.free(stacks);
        var shared_memory = try memory_module.SharedMemory.init(allocator, config.memory_bytes_max);
        errdefer shared_memory.deinit(allocator);
        var arena = try bytecode.Arena.init(allocator, config.code_arena_bytes);
        errdefer arena.deinit(allocator);
        const return_buffer = try allocator.alloc(u8, config.memory_bytes_max);
        errdefer allocator.free(return_buffer);
        const scratch_limbs = crypto.modexp.scratch_limbs_needed(config.modexp_modulus_bytes_max);
        const precompile_scratch = try allocator.alloc(u64, @intCast(scratch_limbs));
        return .{
            .config = config,
            .state = state,
            .frames = frames,
            .stacks = stacks,
            .shared_memory = shared_memory,
            .arena = arena,
            .return_buffer = return_buffer,
            .precompile_scratch = precompile_scratch,
        };
    }

    pub fn deinit(evm: *Evm, allocator: std.mem.Allocator) void {
        allocator.free(evm.frames);
        allocator.free(evm.stacks);
        evm.shared_memory.deinit(allocator);
        evm.arena.deinit(allocator);
        allocator.free(evm.return_buffer);
        allocator.free(evm.precompile_scratch);
        evm.* = undefined;
    }

    pub fn return_data(evm: *const Evm) []const u8 {
        return evm.return_buffer[0..evm.return_len];
    }

    /// Record a fatal (non-consensus) error and stop the interpreter.
    pub fn fail(evm: *Evm, err: Error) Exit {
        evm.fatal_error = err;
        return .fatal;
    }

    /// Run a top-level message to completion.
    pub fn execute(evm: *Evm, fork: Fork, message: Message) Error!Outcome {
        return switch (fork) {
            inline else => |comptime_fork| evm.execute_fork(comptime_fork, message),
        };
    }

    pub fn execute_fork(evm: *Evm, comptime fork: Fork, message: Message) Error!Outcome {
        assert(evm.frames_len == 0);
        evm.return_len = 0;
        evm.fatal_error = null;
        errdefer {
            evm.frames_len = 0;
            evm.arena.release(0);
        }
        var step: Step = switch (message.kind) {
            .call => try evm.start_call(fork, .{
                .kind = if (message.is_static) .staticcall else .call,
                .target = message.target,
                .code_address = try evm.resolve_code_address(fork, message.target),
                .value = message.value,
                .input = message.input,
                .gas_limit = message.gas_limit,
            }, null, message.caller),
            .create => try evm.start_create(fork, .{
                .is_create2 = false,
                .caller = message.caller,
                .value = message.value,
                .init_code = message.input,
                .salt = 0,
                .gas_limit = message.gas_limit,
            }, null),
        };
        while (true) {
            switch (step) {
                .done => |outcome| {
                    if (evm.frames_len == 0) return outcome;
                    evm.resume_parent(outcome);
                },
                .frame => {},
            }
            const frame = &evm.frames[evm.frames_len - 1];
            const exit = interpreter.run(fork, evm, frame);
            step = switch (exit) {
                .fatal => return evm.fatal_error.?,
                .call => try evm.start_call(fork, evm.pending.call, frame, frame.address),
                .create => try evm.start_create(fork, evm.pending.create, frame),
                else => .{ .done = try evm.finish_frame(fork, exit) },
            };
        }
    }

    /// EIP-7702: a top-level call to a delegated EOA runs the delegate's code.
    fn resolve_code_address(evm: *Evm, comptime fork: Fork, target: Address) Error!Address {
        if (!fork.at_least(.prague)) return target;
        const account = try evm.state.load(target);
        const code = try evm.state.code(account);
        const delegate = bytecode.delegation_target(code) orelse return target;
        _ = try evm.state.access(delegate);
        return delegate;
    }

    /// OP Stack rules of the current block, or null on Ethereum.
    pub fn op_upgrade(evm: *const Evm) ?@import("op.zig").Upgrade {
        const context = evm.block.op orelse return null;
        return context.upgrade;
    }

    fn failed(gas_remaining: u64, exit: Exit) Step {
        return .{ .done = .{
            .status = exit.status(),
            .exit = exit,
            .gas_remaining = gas_remaining,
            .gas_refund = 0,
            .output = &.{},
        } };
    }

    fn start_call(
        evm: *Evm,
        comptime fork: Fork,
        request: CallRequest,
        parent: ?*Frame,
        caller_address: Address,
    ) Error!Step {
        const depth: u16 = if (parent) |p| p.depth + 1 else 0;
        if (parent) |p| {
            p.awaiting = .call;
            p.return_offset = request.return_offset;
            p.return_size = request.return_size;
        }
        if (depth > evm.config.depth_max) return failed(request.gas_limit, .revert);
        const inherits = request.kind == .callcode or request.kind == .delegatecall;
        const address = if (inherits) parent.?.address else request.target;
        const caller = if (request.kind == .delegatecall) parent.?.caller else caller_address;
        const value = if (request.kind == .delegatecall) parent.?.value else request.value;
        const is_static = request.kind == .staticcall or (parent != null and parent.?.is_static);
        const checkpoint = evm.state.checkpoint();
        const account = try evm.state.load(address);
        if (request.kind != .delegatecall) {
            const from = try evm.state.load(caller_address);
            if (!try evm.state.transfer(from, account, request.value)) {
                evm.state.revert(checkpoint);
                return failed(request.gas_limit, .revert);
            }
        }
        // EIP-7702: a delegation to a precompile (or native contract) runs that account's
        // empty code, as in revm, so dispatch keys off the undelegated address only.
        const delegated = !std.mem.eql(u8, &request.code_address, &request.target);
        if (!delegated) {
            if (precompiles.lookup(fork, evm.op_upgrade(), request.target)) |precompile| {
                return evm.run_precompile(precompile, request, checkpoint);
            }
            if (native.lookup(evm.op_upgrade(), request.target)) |contract| {
                const call = NativeCall{ .caller = caller, .value = value, .is_static = is_static };
                return evm.run_native(contract, request, checkpoint, call);
            }
        }
        const code_account = try evm.state.load(request.code_address);
        const code = try evm.state.code(code_account);
        if (code.len == 0) {
            return .{ .done = .{
                .status = .success,
                .exit = .stop,
                .gas_remaining = request.gas_limit,
                .gas_refund = 0,
                .output = &.{},
            } };
        }
        try evm.push_frame(.{
            .kind = .call,
            .code = code,
            .gas = request.gas_limit,
            .input = request.input,
            .address = address,
            .account = account,
            .caller = caller,
            .value = value,
            .is_static = is_static,
            .depth = depth,
            .checkpoint = checkpoint,
        }, parent);
        return .frame;
    }

    fn run_precompile(
        evm: *Evm,
        precompile: precompiles.Precompile,
        request: CallRequest,
        checkpoint: state_module.Checkpoint,
    ) Step {
        const result = precompile(request.input, request.gas_limit, .{
            .out = evm.return_buffer,
            .scratch = evm.precompile_scratch,
        });
        if (result.status != .success) {
            evm.state.revert(checkpoint);
            return failed(0, .precompile_failure);
        }
        assert(result.gas_used <= request.gas_limit);
        return .{ .done = .{
            .status = .success,
            .exit = .return_,
            .gas_remaining = request.gas_limit - result.gas_used,
            .gas_refund = 0,
            .output = evm.return_buffer[0..result.output_len],
        } };
    }

    const NativeCall = struct { caller: Address, value: u256, is_static: bool };

    /// Base native precompile: runs against the journal; a revert or halt rolls back.
    fn run_native(
        evm: *Evm,
        contract: native.Native,
        request: CallRequest,
        checkpoint: state_module.Checkpoint,
        call: NativeCall,
    ) Error!Step {
        var context = native.Context{
            .state = evm.state,
            .upgrade = evm.op_upgrade().?,
            .activation_admin = evm.block.op.?.activation_admin,
            .address = request.code_address,
            .caller = call.caller,
            .origin = evm.tx.origin,
            .value = call.value,
            .is_static = call.is_static,
            .gas_limit = request.gas_limit,
            .chain_id = evm.config.chain_id,
            .timestamp = evm.block.timestamp,
            .out = evm.return_buffer,
        };
        const is_direct = request.kind == .call or request.kind == .staticcall;
        const result = try native.run(contract, &context, request.input, is_direct);
        assert(result.gas_used <= request.gas_limit);
        if (result.status != .success) evm.state.revert(checkpoint);
        const exit: Exit = switch (result.status) {
            .success => .return_,
            .revert => .revert,
            .halt => .out_of_gas,
        };
        return .{ .done = .{
            .status = exit.status(),
            .exit = exit,
            .gas_remaining = request.gas_limit - result.gas_used,
            .gas_refund = result.refund,
            .output = result.output,
        } };
    }

    fn start_create(
        evm: *Evm,
        comptime fork: Fork,
        request: CreateRequest,
        parent: ?*Frame,
    ) Error!Step {
        const depth: u16 = if (parent) |p| p.depth + 1 else 0;
        if (parent) |p| p.awaiting = .create;
        if (depth > evm.config.depth_max) return failed(request.gas_limit, .revert);
        const caller = try evm.state.load(request.caller);
        if (caller.info.balance < request.value) return failed(request.gas_limit, .revert);
        if (caller.info.nonce == std.math.maxInt(u64)) return failed(request.gas_limit, .revert);
        const nonce = caller.info.nonce;
        try evm.state.set_nonce(caller, nonce + 1);
        const address = if (request.is_create2)
            create2_address(request.caller, request.salt, request.init_code)
        else
            create_address(request.caller, nonce);
        const access = try evm.state.access(address);
        const checkpoint = evm.state.checkpoint();
        const account = access.account;
        const stored = account.storage_epoch == 0 and account.info.has_storage;
        if (account.info.nonce != 0 or account.info.has_code() or stored) {
            return failed(0, .create_collision);
        }
        try evm.state.create_account(account, fork);
        const moved = try evm.state.transfer(caller, account, request.value);
        assert(moved);
        try evm.push_frame(.{
            .kind = .create,
            .code = request.init_code,
            .gas = request.gas_limit,
            .input = &.{},
            .address = address,
            .account = account,
            .caller = request.caller,
            .value = request.value,
            .is_static = false,
            .depth = depth,
            .checkpoint = checkpoint,
        }, parent);
        return .frame;
    }

    const FrameSpec = struct {
        kind: FrameKind,
        code: []const u8,
        gas: u64,
        input: []const u8,
        address: Address,
        account: *Account,
        caller: Address,
        value: u256,
        is_static: bool,
        depth: u16,
        checkpoint: state_module.Checkpoint,
    };

    fn push_frame(evm: *Evm, spec: FrameSpec, parent: ?*Frame) Error!void {
        const index = evm.frames_len;
        assert(index < evm.frames.len);
        assert(index == spec.depth);
        const memory_base: u32 = if (parent) |p| p.memory_base + p.memory.len else 0;
        const arena_mark = evm.arena.mark();
        const analyzed = try evm.arena.analyze_code(spec.code);
        evm.frames[index] = .{
            .analyzed = analyzed,
            .gas = spec.gas,
            .stack = stack_module.Stack.init(&evm.stacks[index]),
            .memory = evm.shared_memory.frame(memory_base),
            .memory_base = memory_base,
            .input = spec.input,
            .address = spec.address,
            .account = spec.account,
            .caller = spec.caller,
            .value = spec.value,
            .is_static = spec.is_static,
            .depth = spec.depth,
            .kind = spec.kind,
            .checkpoint = spec.checkpoint,
            .arena_mark = arena_mark,
        };
        evm.frames_len += 1;
    }

    /// Pop the top frame, applying create code deposit and journal rules.
    fn finish_frame(evm: *Evm, comptime fork: Fork, exit_initial: Exit) Error!Outcome {
        assert(evm.frames_len > 0);
        const frame = &evm.frames[evm.frames_len - 1];
        var exit = exit_initial;
        var output: []const u8 = if (exit == .return_ or exit == .revert)
            frame.memory.slice(frame.output_offset, frame.output_size)
        else
            &.{};
        if (frame.kind == .create and exit.status() == .success) {
            exit = try evm.deposit_code(fork, frame, output);
            output = &.{};
        }
        const status = exit.status();
        if (status != .success) evm.state.revert(frame.checkpoint);
        if (status == .halt) output = &.{};
        // The return buffer never overlaps frame memory, so this copy is safe.
        @memcpy(evm.return_buffer[0..output.len], output);
        const outcome = Outcome{
            .status = status,
            .exit = exit,
            .gas_remaining = if (status == .halt) 0 else frame.gas,
            .gas_refund = if (status == .success) frame.refund else 0,
            .output = evm.return_buffer[0..output.len],
            .created = if (frame.kind == .create and status == .success) frame.address else null,
        };
        evm.arena.release(frame.arena_mark);
        evm.frames_len -= 1;
        return outcome;
    }

    fn deposit_code(evm: *Evm, comptime fork: Fork, frame: *Frame, code: []const u8) Error!Exit {
        if (fork.at_least(.spurious_dragon) and code.len > evm.config.code_size_max) {
            return .code_size_limit;
        }
        if (fork.at_least(.london) and code.len > 0 and code[0] == 0xef) {
            return .invalid_code_prefix;
        }
        const cost = gas.code_deposit_byte * @as(u64, code.len);
        if (frame.gas < cost) {
            // Frontier: an unpaid deposit still succeeds, leaving empty code.
            return if (fork.at_least(.homestead)) .out_of_gas else .stop;
        }
        frame.gas -= cost;
        if (code.len > 0) try evm.state.set_code(frame.account, code);
        return .return_;
    }

    /// Deliver a child's outcome to the frame on top of the stack.
    fn resume_parent(evm: *Evm, outcome: Outcome) void {
        assert(evm.frames_len > 0);
        const parent = &evm.frames[evm.frames_len - 1];
        parent.gas += outcome.gas_remaining;
        if (outcome.status == .success) parent.refund += outcome.gas_refund;
        const output = outcome.output;
        if (output.len > 0 and output.ptr != evm.return_buffer.ptr) {
            std.mem.copyForwards(u8, evm.return_buffer[0..output.len], output);
        }
        evm.return_len = @intCast(output.len);
        switch (parent.awaiting) {
            .call => {
                parent.stack.push(@intFromBool(outcome.status == .success));
                const count = @min(output.len, parent.return_size);
                const destination = parent.memory.slice(parent.return_offset, count);
                @memcpy(destination, evm.return_buffer[0..count]);
            },
            .create => {
                const created = outcome.created orelse primitives.address_zero;
                parent.stack.push(if (outcome.created != null)
                    primitives.address_to_u256(created)
                else
                    0);
                if (outcome.status == .success) evm.return_len = 0;
            },
        }
    }
};

/// CREATE address: keccak256(rlp([sender, nonce]))[12..].
pub fn create_address(sender: Address, nonce: u64) Address {
    var buffer: [1 + 21 + 9]u8 = undefined;
    var nonce_bytes: [9]u8 = undefined;
    const nonce_len = rlp_u64(nonce, &nonce_bytes);
    const payload_len = 21 + nonce_len;
    buffer[0] = 0xc0 + @as(u8, @intCast(payload_len));
    buffer[1] = 0x80 + 20;
    @memcpy(buffer[2..22], &sender);
    @memcpy(buffer[22..][0..nonce_len], nonce_bytes[0..nonce_len]);
    const hash = primitives.keccak256(buffer[0 .. 1 + payload_len]);
    return hash[12..32].*;
}

fn rlp_u64(value: u64, out: *[9]u8) usize {
    if (value == 0) {
        out[0] = 0x80;
        return 1;
    }
    if (value < 0x80) {
        out[0] = @intCast(value);
        return 1;
    }
    const byte_count: u8 = @intCast(8 - @clz(value) / 8);
    out[0] = 0x80 + byte_count;
    var i: u8 = 0;
    while (i < byte_count) : (i += 1) {
        out[1 + i] = @truncate(value >> @intCast(8 * (byte_count - 1 - i)));
    }
    return 1 + byte_count;
}

/// CREATE2 address: keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[12..].
pub fn create2_address(sender: Address, salt: u256, init_code: []const u8) Address {
    var buffer: [1 + 20 + 32 + 32]u8 = undefined;
    buffer[0] = 0xff;
    @memcpy(buffer[1..21], &sender);
    std.mem.writeInt(u256, buffer[21..53], salt, .big);
    buffer[53..85].* = primitives.keccak256(init_code);
    const hash = primitives.keccak256(&buffer);
    return hash[12..32].*;
}

test "evm: create addresses match known vectors" {
    // From the Ethereum yellow paper / EIP-1014 examples.
    const sender = primitives.hex_to_address("6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0");
    const expected0 = primitives.hex_to_address("cd234a471b72ba2f1ccf0a70fcaba648a5eecd8d");
    const expected1 = primitives.hex_to_address("343c43a37d37dff08ae8c4a11544c718abb4fcf8");
    try std.testing.expectEqualSlices(u8, &expected0, &create_address(sender, 0));
    try std.testing.expectEqualSlices(u8, &expected1, &create_address(sender, 1));
    const expected2 = primitives.hex_to_address("4d1a2e2bb4f88f0250f26ffff098b0b30b26bf38");
    try std.testing.expectEqualSlices(
        u8,
        &expected2,
        &create2_address(primitives.address_zero, 0, &.{0x00}),
    );
}
