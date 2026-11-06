//! Chain reads for the withdrawer over the injected-transport JSON-RPC clients (base/base
//! `operation.rs` `read`, `verify_output`, `Withdrawal::from_receipt`): answers the status
//! and game-search `Read`s with `eth_call`s and block lookups, loads the withdrawals of an
//! L2 receipt, and fetches and verifies a game's header and message passer proof.
//!
//! Results borrow the client's arena only until the next call, so everything kept is copied
//! into buffers allocated at init: the latest `eth_call` return data, withdrawal calldata, and
//! the verified storage proof nodes (valid until the next `verify`).

const std = @import("std");
const assert = std.debug.assert;

const rpc = @import("../../batcher/rpc/root.zig");
const header_json = @import("../../consensus/sources/header_json.zig");
const registry_module = @import("../../proof/contracts/anchor_state_registry.zig");
const factory_module = @import("../../proof/contracts/dispute_game_factory.zig");
const abi = @import("../../proof/contracts/abi.zig");
const calldata = @import("calldata.zig");
const status_module = @import("status.zig");
const withdrawal_module = @import("withdrawal.zig");

const Address = withdrawal_module.Address;
const Hash = withdrawal_module.Hash;
const Withdrawal = withdrawal_module.Withdrawal;
const Read = status_module.Read;
const Answer = status_module.Answer;

pub const Contracts = struct {
    portal: Address,
    factory: Address,
    registry: Address,
};

pub const Error = rpc.Error || rpc.DecodeError || abi.DecodeError || withdrawal_module.Error ||
    error{ MissingReceipt, MissingBlock, ValueOverflow, ZeroContract, TooLarge };

pub const Limits = struct {
    return_bytes_max: u32 = 64 * 1024,
    proof_bytes_max: u32 = 128 * 1024,
    header_bytes_max: u32 = 16 * 1024,
    logs_max: u32 = 256,
};

/// Logs of one receipt: at most this many topics per log are kept.
const topics_max = 4;

pub const Reader = struct {
    l1: *rpc.Client,
    l2: *rpc.Client,
    contracts: Contracts,
    submitter: Address,
    limits: Limits,
    return_buffer: []u8,
    proof_buffer: []u8,
    header_buffer: []u8,
    data_buffer: []u8,
    /// Proof nodes of the last successful `verify`, in the portal's shape.
    proof_nodes: withdrawal_module.ProofNodes = .{},
    output: ?withdrawal_module.OutputRootProof = null,

    pub fn init(
        allocator: std.mem.Allocator,
        l1: *rpc.Client,
        l2: *rpc.Client,
        portal: Address,
        submitter: Address,
        limits: Limits,
    ) !Reader {
        assert(limits.return_bytes_max >= 64 and limits.proof_bytes_max >= 1024);
        const return_buffer = try allocator.alloc(u8, limits.return_bytes_max);
        errdefer allocator.free(return_buffer);
        const proof_buffer = try allocator.alloc(u8, limits.proof_bytes_max);
        errdefer allocator.free(proof_buffer);
        const header_buffer = try allocator.alloc(u8, limits.header_bytes_max);
        errdefer allocator.free(header_buffer);
        const data_bytes = withdrawal_module.withdrawals_max * withdrawal_module.data_bytes_max;
        const data_buffer = try allocator.alloc(u8, data_bytes);
        return .{
            .l1 = l1,
            .l2 = l2,
            .contracts = .{ .portal = portal, .factory = @splat(0), .registry = @splat(0) },
            .submitter = submitter,
            .limits = limits,
            .return_buffer = return_buffer,
            .proof_buffer = proof_buffer,
            .header_buffer = header_buffer,
            .data_buffer = data_buffer,
        };
    }

    pub fn deinit(reader: *Reader, allocator: std.mem.Allocator) void {
        allocator.free(reader.data_buffer);
        allocator.free(reader.header_buffer);
        allocator.free(reader.proof_buffer);
        allocator.free(reader.return_buffer);
        reader.* = undefined;
    }

    /// Reads the portal's dispute game factory and anchor state registry (base/base
    /// `resolve_proof_system`); a zero address is a misconfigured portal.
    pub fn resolve_contracts(reader: *Reader) Error!Contracts {
        var buffer: [4]u8 = undefined;
        const portal = reader.contracts.portal;
        buffer = calldata.dispute_game_factory;
        reader.contracts.factory = try calldata.decode_address(try reader.call(portal, &buffer));
        buffer = calldata.anchor_state_registry;
        reader.contracts.registry = try calldata.decode_address(try reader.call(portal, &buffer));
        if (std.mem.allEqual(u8, &reader.contracts.factory, 0)) return error.ZeroContract;
        if (std.mem.allEqual(u8, &reader.contracts.registry, 0)) return error.ZeroContract;
        assert(!std.mem.allEqual(u8, &reader.contracts.portal, 0));
        return reader.contracts;
    }

    /// `eth_call` at the latest L1 block. The result is valid until the next call.
    pub fn call(reader: *Reader, to: Address, input: []const u8) Error![]const u8 {
        assert(input.len >= 4);
        var params_buffer: [512]u8 = undefined;
        const params = std.fmt.bufPrint(
            &params_buffer,
            "[{{\"to\":\"0x{x}\",\"data\":\"0x{x}\"}},\"latest\"]",
            .{ &to, input },
        ) catch return error.TooLarge;
        const result = try reader.l1.call("eth_call", params);
        const returned = try rpc.data(result, reader.return_buffer);
        assert(returned.len <= reader.return_buffer.len);
        return returned;
    }

    /// `eth_call` that may revert: false on an execution revert, an error otherwise.
    pub fn call_succeeds(reader: *Reader, to: Address, input: []const u8) Error!bool {
        _ = reader.call(to, input) catch |err| switch (err) {
            error.RpcError => {
                const message = reader.l1.last_error();
                if (reader.l1.last_error_code == 3) return false;
                if (std.mem.indexOf(u8, message, "revert") != null) return false;
                return err;
            },
            else => return err,
        };
        return true;
    }

    fn call_bool(reader: *Reader, to: Address, input: []const u8) Error!Answer {
        return .{ .boolean = try calldata.decode_bool(try reader.call(to, input)) };
    }

    fn call_uint(reader: *Reader, to: Address, input: []const u8) Error!Answer {
        const value = calldata.decode_uint(u64, try reader.call(to, input)) catch |err|
            switch (err) {
                error.TypeCheck => return error.ValueOverflow,
                else => return err,
            };
        return .{ .uint = value };
    }

    fn registry_query(reader: *Reader, function: [4]u8, game: Address) Error!Answer {
        var buffer: [36]u8 = undefined;
        const input = registry_module.encode_game_query(&buffer, function, game) catch
            unreachable; // 36 bytes fit.
        return reader.call_bool(reader.contracts.registry, input);
    }

    /// Performs one status or game-search read for `withdrawal`.
    pub fn answer(reader: *Reader, withdrawal: *const Withdrawal, read: Read) Error!Answer {
        const contracts = reader.contracts;
        const hash = withdrawal.hash();
        var buffer: [68]u8 = undefined;
        return switch (read) {
            .finalized_withdrawal => reader.call_bool(
                contracts.portal,
                calldata.encode_finalized_withdrawals(&buffer, hash) catch unreachable,
            ),
            .proven_withdrawal => .{ .proven = try calldata.decode_proven_withdrawal(
                try reader.call(contracts.portal, calldata.encode_proven_withdrawals(
                    &buffer,
                    hash,
                    reader.submitter,
                ) catch unreachable),
            ) },
            .check_withdrawal => .{ .boolean = try reader.call_succeeds(
                contracts.portal,
                calldata.encode_check_withdrawal(&buffer, hash, reader.submitter) catch
                    unreachable,
            ) },
            .withdrawal_timestamp => .{ .uint = try reader.l2_timestamp(withdrawal.block_number) },
            .verify => |candidate| .{ .verify = reader.verify(withdrawal, candidate) },
            else => reader.answer_contract(read),
        };
    }

    fn answer_contract(reader: *Reader, read: Read) Error!Answer {
        const contracts = reader.contracts;
        const registry = registry_module;
        return switch (read) {
            .registry_paused => reader.call_bool(contracts.registry, &registry.paused),
            .game_blacklisted => |game| reader.registry_query(registry.is_game_blacklisted, game),
            .game_retired => |game| reader.registry_query(registry.is_game_retired, game),
            .game_proper => |game| reader.registry_query(registry.is_game_proper, game),
            .game_respected => |game| reader.registry_query(registry.is_game_respected, game),
            .game_finalized => |game| reader.registry_query(registry.is_game_finalized, game),
            .game_status => |game| .{ .game_status = try calldata.decode_game_status(
                try reader.call(game, &calldata.game_status),
            ) },
            .proof_maturity_delay => reader.call_uint(
                contracts.portal,
                &calldata.proof_maturity_delay_seconds,
            ),
            .game_resolved_at => |game| reader.call_uint(game, &calldata.game_resolved_at),
            .finality_delay => reader.call_uint(
                contracts.registry,
                &registry.dispute_game_finality_delay_seconds,
            ),
            .l1_timestamp => .{ .uint = try latest_timestamp(reader.l1) },
            .game_count => reader.call_uint(contracts.factory, &factory_module.game_count),
            .game_at_index => |index| reader.game_at_index(index),
            .game_extra_data => |game| .{ .claimed_block = try calldata.decode_extra_data_block(
                try reader.call(game, &calldata.game_extra_data),
            ) },
            .game_root_claim => |game| .{ .root = try calldata.decode_hash(
                try reader.call(game, &calldata.game_root_claim),
            ) },
            else => unreachable, // Handled by `answer`.
        };
    }

    fn game_at_index(reader: *Reader, index: u64) Error!Answer {
        var buffer: [36]u8 = undefined;
        const input = abi.encode_call(&buffer, factory_module.game_at_index, &.{
            .{ .uint = index },
        }) catch unreachable; // 36 bytes fit.
        const game = try factory_module.decode_game_at_index(
            try reader.call(reader.contracts.factory, input),
        );
        assert(input.len == 36);
        return .{ .game = .{ .timestamp = game.timestamp, .proxy = game.proxy } };
    }

    fn l2_timestamp(reader: *Reader, number: u64) Error!u64 {
        var params: [64]u8 = undefined;
        const text = std.fmt.bufPrint(&params, "[\"0x{x}\",false]", .{number}) catch
            unreachable; // Fixed-size content.
        const block = try reader.l2.call("eth_getBlockByNumber", text);
        if (block == .null) return error.MissingBlock;
        return rpc.quantity(u64, try rpc.field(block, "timestamp"));
    }

    /// Fetches and verifies the header and message passer proof of `candidate`'s block
    /// against its root claim. `proof_nodes` and `output` hold the result on `ok`.
    pub fn verify(
        reader: *Reader,
        withdrawal: *const Withdrawal,
        candidate: status_module.Candidate,
    ) status_module.Verify {
        reader.output = null;
        reader.proof_nodes = .{};
        const block = reader.fetch_header(candidate.block_number) catch |err| return switch (err) {
            error.RpcError, error.TransportFailed, error.ResponseTooLarge => .rpc_error,
            else => .unusable,
        };
        const output = reader.fetch_and_verify(withdrawal, candidate, block) catch |err|
            return switch (err) {
                error.RpcError, error.TransportFailed, error.ResponseTooLarge => .rpc_error,
                else => .unusable,
            };
        reader.output = output;
        assert(reader.proof_nodes.count > 0);
        return .ok;
    }

    const FetchError = Error || header_json.DecodeError;

    fn fetch_header(reader: *Reader, number: u64) FetchError!withdrawal_module.BlockCommitment {
        var params: [64]u8 = undefined;
        const text = std.fmt.bufPrint(&params, "[\"0x{x}\",false]", .{number}) catch
            unreachable; // Fixed-size content.
        const block = try reader.l2.call("eth_getBlockByNumber", text);
        if (block == .null) return error.MissingBlock;
        const header_text = try header_object(block, reader.header_buffer);
        var extra: [header_json.extra_data_size_max]u8 = undefined;
        const decoded = try header_json.decode(header_text, &extra);
        if (decoded.header.number != number) return error.MissingBlock;
        return .{ .state_root = decoded.header.state_root.bytes, .block_hash = decoded.hash.bytes };
    }

    fn fetch_and_verify(
        reader: *Reader,
        withdrawal: *const Withdrawal,
        candidate: status_module.Candidate,
        block: withdrawal_module.BlockCommitment,
    ) FetchError!withdrawal_module.OutputRootProof {
        var params: [256]u8 = undefined;
        const text = std.fmt.bufPrint(&params, "[\"0x{x}\",[\"0x{x}\"],\"0x{x}\"]", .{
            &withdrawal_module.message_passer,
            &withdrawal.slot(),
            candidate.block_number,
        }) catch unreachable; // Fixed-size content.
        const value = try reader.l2.call("eth_getProof", text);
        var nodes: [2 * withdrawal_module.proof_nodes_max][]const u8 = undefined;
        var storage: [1]withdrawal_module.StorageProof = undefined;
        const proof = try parse_proof(value, reader.proof_buffer, &nodes, &storage);
        const output = try withdrawal_module.verify_proof(
            withdrawal,
            block,
            &proof,
            candidate.root,
            &reader.proof_nodes,
        );
        assert(std.mem.eql(u8, &output.root(), &candidate.root));
        return output;
    }

    /// Loads every withdrawal of an L2 receipt in log order; calldata is copied.
    pub fn load_withdrawals(
        reader: *Reader,
        transaction: Hash,
        out: []Withdrawal,
    ) Error![]Withdrawal {
        assert(out.len > 0);
        var params: [80]u8 = undefined;
        const text = std.fmt.bufPrint(&params, "[\"0x{x}\"]", .{&transaction}) catch
            unreachable; // Fixed-size content.
        const receipt = try reader.l2.call("eth_getTransactionReceipt", text);
        if (receipt == .null) return error.MissingReceipt;
        const number_value = rpc.field(receipt, "blockNumber") catch return error.MissingBlock;
        var block_number: ?u64 = null;
        if (number_value != .null) block_number = try rpc.quantity(u64, number_value);
        const logs = try rpc.field(receipt, "logs");
        if (logs != .array) return error.MalformedResponse;
        var count: usize = 0;
        var data_used: usize = 0;
        for (logs.array.items) |log_value| {
            var topics: [topics_max]Hash = undefined;
            const log = try parse_log(log_value, &topics, reader.data_buffer[data_used..]) orelse
                continue;
            const number = block_number orelse return error.MissingBlockNumber;
            const withdrawal = try withdrawal_module.decode_message_passed(log, number) orelse
                continue;
            if (count == out.len) return error.TooManyWithdrawals;
            out[count] = withdrawal;
            count += 1;
            data_used += log.data.len;
        }
        if (count == 0) return error.NoWithdrawals;
        return out[0..count];
    }
};

/// Timestamp of the latest block of `client`'s chain.
pub fn latest_timestamp(client: *rpc.Client) Error!u64 {
    const block = try client.call("eth_getBlockByNumber", "[\"latest\",false]");
    if (block == .null) return error.MissingBlock;
    return rpc.quantity(u64, try rpc.field(block, "timestamp"));
}

/// Re-serializes the header fields of a block object (dropping its transaction list, which
/// can be large) for the strict header decoder.
fn header_object(block: std.json.Value, out: []u8) Error![]const u8 {
    if (block != .object) return error.MalformedResponse;
    var writer: std.Io.Writer = .fixed(out);
    var stringify: std.json.Stringify = .{ .writer = &writer };
    stringify.beginObject() catch return error.TooLarge;
    var iterator = block.object.iterator();
    while (iterator.next()) |entry| {
        const key = entry.key_ptr.*;
        const skip = std.mem.eql(u8, key, "transactions") or std.mem.eql(u8, key, "uncles") or
            std.mem.eql(u8, key, "withdrawals");
        if (skip) continue;
        stringify.objectField(key) catch return error.TooLarge;
        stringify.write(entry.value_ptr.*) catch return error.TooLarge;
    }
    stringify.endObject() catch return error.TooLarge;
    assert(writer.buffered().len >= 2);
    return writer.buffered();
}

/// A receipt log; returns null for logs with more topics than any event here uses.
fn parse_log(
    value: std.json.Value,
    topics: *[topics_max]Hash,
    data_out: []u8,
) Error!?withdrawal_module.Log {
    const topic_values = try rpc.field(value, "topics");
    if (topic_values != .array) return error.MalformedResponse;
    if (topic_values.array.items.len > topics_max) return null;
    for (topic_values.array.items, 0..) |topic, index| topics[index] = try rpc.fixed(32, topic);
    const data_value = try rpc.field(value, "data");
    const data = rpc.data(data_value, data_out) catch |err| {
        // Too large for the remaining buffer: not a withdrawal this tool can hold.
        if (data_value == .string and data_value.string.len / 2 > data_out.len) {
            return error.DataTooLarge;
        }
        return err;
    };
    return .{
        .address = try rpc.fixed(20, try rpc.field(value, "address")),
        .topics = topics[0..topic_values.array.items.len],
        .data = data,
    };
}

/// The logs of an L1 receipt, for the finalization event check.
pub fn receipt_logs(
    receipt: std.json.Value,
    out: []withdrawal_module.Log,
    topics: [][topics_max]Hash,
    data_buffer: []u8,
) Error![]withdrawal_module.Log {
    assert(out.len == topics.len);
    const logs = try rpc.field(receipt, "logs");
    if (logs != .array) return error.MalformedResponse;
    var count: usize = 0;
    var used: usize = 0;
    for (logs.array.items) |log_value| {
        if (count == out.len) return error.TooLarge;
        const log = try parse_log(log_value, &topics[count], data_buffer[used..]) orelse continue;
        out[count] = log;
        used += log.data.len;
        count += 1;
    }
    return out[0..count];
}

/// Decodes an `eth_getProof` result; node bytes go into `buffer`.
fn parse_proof(
    value: std.json.Value,
    buffer: []u8,
    nodes: *[2 * withdrawal_module.proof_nodes_max][]const u8,
    storage: *[1]withdrawal_module.StorageProof,
) Error!withdrawal_module.AccountProof {
    var used: usize = 0;
    var node_count: usize = 0;
    const account_values = try rpc.field(value, "accountProof");
    const account_nodes = try decode_nodes(account_values, buffer, &used, nodes, &node_count);
    const storage_values = try rpc.field(value, "storageProof");
    if (storage_values != .array) return error.MalformedResponse;
    if (storage_values.array.items.len != 1) return error.StorageProofCount;
    const entry = storage_values.array.items[0];
    storage[0] = .{
        .key = try rpc.fixed(32, try rpc.field(entry, "key")),
        .value = try rpc.quantity(u256, try rpc.field(entry, "value")),
        .proof = try decode_nodes(try rpc.field(entry, "proof"), buffer, &used, nodes, &node_count),
    };
    const proof: withdrawal_module.AccountProof = .{
        .address = try rpc.fixed(20, try rpc.field(value, "address")),
        .nonce = try rpc.quantity(u64, try rpc.field(value, "nonce")),
        .balance = try rpc.quantity(u256, try rpc.field(value, "balance")),
        .storage_hash = try rpc.fixed(32, try rpc.field(value, "storageHash")),
        .code_hash = try rpc.fixed(32, try rpc.field(value, "codeHash")),
        .account_proof = account_nodes,
        .storage_proof = storage,
    };
    assert(used <= buffer.len);
    return proof;
}

fn decode_nodes(
    value: std.json.Value,
    buffer: []u8,
    used: *usize,
    nodes: *[2 * withdrawal_module.proof_nodes_max][]const u8,
    node_count: *usize,
) Error![]const []const u8 {
    if (value != .array) return error.MalformedResponse;
    const start = node_count.*;
    if (value.array.items.len > nodes.len - start) return error.ProofTooLong;
    for (value.array.items) |item| {
        const node = rpc.data(item, buffer[used.*..]) catch return error.TooLarge;
        nodes[node_count.*] = node;
        node_count.* += 1;
        used.* += node.len;
    }
    assert(node_count.* - start == value.array.items.len);
    return nodes[start..node_count.*];
}
