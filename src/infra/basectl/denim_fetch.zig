//! `basectl denim` over JSON-RPC: resolve `latest` once, pin every read to that block hash,
//! gather `denim.Observations`, walk the cadence, and probe the HTTP timestamp wire fields
//! (base/base `DenimChecker::check`, minus the WebSocket subscription checks).
//!
//! RPC results borrow the client's buffers until the next call, so each response is
//! reduced to owned facts (`BlockView`, words, notes) before the next request.

const std = @import("std");
const assert = std.debug.assert;
const json = std.json;
const rpc = @import("../../batcher/rpc/root.zig");
const keccak = @import("../../common/crypto/keccak.zig");
const types = @import("types.zig");
const denim = @import("denim.zig");

const Note = denim.Note;
const note = denim.note;
const Failure = types.Failure;
const CommandFailure = types.CommandFailure;

pub const cadence_blocks_max: u32 = 256;
pub const cadence_blocks_default: u32 = 20;

/// base/base log discovery bounds: how far back and how many `eth_getLogs` calls.
const log_lookback_blocks: u64 = 200_000;
const log_discovery_calls: u32 = 16;
const log_window_initial: u64 = 32;
const log_window_max: u64 = 32_768;

pub const Options = struct {
    /// Parent-child edges the cadence walk checks below the snapshot.
    cadence_blocks: u32 = cadence_blocks_default,
};

/// The facts of one block fetched by hash (full transactions).
pub const BlockView = struct {
    facts: denim.BlockFacts,
    /// The header's `timestampMs` field, when served and well-formed.
    timestamp_ms_field: ?u64,
    metadata: denim.MetadataError!u16,
    /// Hash of tx[1], when the block has one.
    second_hash: ?[32]u8,
    /// Hash of the transaction at the requested index, when asked for and present.
    wanted_hash: ?[32]u8,
};

/// Reduces a full block object to its facts; null when it is not a block object.
pub fn parse_block(value: json.Value, wanted_index: ?u64) ?BlockView {
    if (value != .object) return null;
    const number = denim.string_quantity(value, "number") orelse return null;
    const timestamp = denim.string_quantity(value, "timestamp") orelse return null;
    const transactions_value = value.object.get("transactions") orelse return null;
    if (transactions_value != .array) return null;
    const transactions = transactions_value.array.items;
    const second: ?json.Value = if (transactions.len > 1) transactions[1] else null;
    const metadata = denim.metadata_from_json(second, number);
    var view: BlockView = .{
        .facts = .{
            .number = number,
            .hash = denim.string_hash(value, "hash") orelse return null,
            .parent_hash = denim.string_hash(value, "parentHash") orelse return null,
            .timestamp = timestamp,
            .timestamp_ms = if (metadata) |part|
                denim.expected_timestamp_ms(timestamp, part)
            else |_|
                null,
        },
        .timestamp_ms_field = denim.string_quantity(value, "timestampMs"),
        .metadata = metadata,
        .second_hash = if (second) |tx| denim.string_hash(tx, "hash") else null,
        .wanted_hash = null,
    };
    if (wanted_index) |index| {
        if (index < transactions.len) {
            view.wanted_hash = denim.string_hash(transactions[index], "hash");
        }
    }
    assert(view.facts.timestamp == timestamp);
    return view;
}

fn hash_hex(hash: [32]u8) [66]u8 {
    const value: types.Hash = .{ .bytes = hash };
    return value.hex();
}

fn address_hex(address: [20]u8) [42]u8 {
    const value: types.Address = .{ .bytes = address };
    return value.hex();
}

/// Calls `method` and classifies a failure: -32601 and transport problems are
/// unavailable (indeterminate), any other JSON-RPC error is a method error (fail).
pub fn raw(client: *rpc.Client, method: []const u8, params: []const u8) denim.Outcome {
    assert(method.len > 0);
    const value = client.call(method, params) catch |err| {
        if (err == error.RpcError) {
            if (client.last_error_code == types.method_not_found_code) {
                return .{ .unavailable = note("method not served: {s}", .{client.last_error()}) };
            }
            return .{ .method_error = note("{s}", .{client.last_error()}) };
        }
        return .{ .unavailable = note("{s}", .{types.failure_of(client, err).text()}) };
    };
    return .{ .value = value };
}

/// Formats request params into `buffer`. Every caller sizes its buffer for its format:
/// the inputs are fixed-width hex (hashes, addresses, u64 quantities) or bounded ids.
fn print(buffer: []u8, comptime format: []const u8, args: anytype) []const u8 {
    assert(buffer.len >= format.len);
    // Proof: see above; overflow would be a sizing bug caught by the tests.
    const text = std.fmt.bufPrint(buffer, format, args) catch unreachable;
    assert(text.len <= buffer.len);
    return text;
}

fn call_failure(client: *const rpc.Client, err: rpc.Error) Failure {
    return types.failure_of(client, err);
}

/// The block with hash `hash`, verified to be that block.
fn block_by_hash(
    client: *rpc.Client,
    hash: [32]u8,
    wanted_index: ?u64,
) error{Unavailable}!BlockView {
    var buffer: [96]u8 = undefined;
    const params = print(&buffer, "[\"{s}\",true]", .{hash_hex(hash)});
    const value = client.call("eth_getBlockByHash", params) catch return error.Unavailable;
    const view = parse_block(value, wanted_index) orelse return error.Unavailable;
    if (!std.mem.eql(u8, &view.facts.hash, &hash)) return error.Unavailable;
    assert(std.mem.eql(u8, &view.facts.hash, &hash));
    return view;
}

// ------------------------------------------------------------------------- fetch

pub fn fetch(context: *const types.Context, options: Options) types.Fetched(denim.Report) {
    assert(options.cadence_blocks <= cadence_blocks_max);
    assert(context.network.len > 0);
    const activation = switch (types.probe(
        ?u64,
        context.rollup.client,
        "optimism_rollupConfig",
        "[]",
        decode_activation,
    )) {
        .ok => |value| value,
        // No consensus RPC configured: Denim counts as not scheduled.
        .failed => |failure| if (failure == .not_configured) null else return .{ .failed = .{
            .what = "rollup rpc (optimism_rollupConfig)",
            .failure = failure,
        } },
    };
    const client = context.l2.client orelse
        return .{ .failed = .{ .what = "l2 rpc", .failure = .not_configured } };
    const latest = types.probe(
        types.Hash,
        client,
        "eth_getBlockByNumber",
        "[\"latest\",false]",
        decode_block_hash,
    );
    const hash = switch (latest) {
        .ok => |value| value.bytes,
        .failed => |failure| return .{ .failed = .{ .what = "latest block", .failure = failure } },
    };
    const snapshot = block_by_hash(client, hash, null) catch
        return .{ .failed = .{ .what = "snapshot block by hash", .failure = .malformed } };
    var observations: denim.Observations = undefined;
    if (read_observations(client, &snapshot, activation, &observations)) |failed| {
        return .{ .failed = failed };
    }
    observations.network = context.network;
    var report = denim.evaluate(&observations);
    add_cadence(client, &report, &snapshot, options.cadence_blocks);
    add_object_checks(client, &report, &snapshot);
    add_log_checks(client, &report);
    assert(report.checks.count == report.checks.slice().len);
    return .{ .ok = report };
}

/// `base.denim` from `optimism_rollupConfig`; absent means not scheduled.
pub fn decode_activation(value: json.Value) types.DecodeError!?u64 {
    const base = try types.optional_field(value, "base") orelse return null;
    const denim_value = try types.optional_field(base, "denim") orelse return null;
    const activation = try rpc.number(denim_value);
    assert(value == .object);
    return activation;
}

fn decode_block_hash(value: json.Value) types.DecodeError!types.Hash {
    if (value != .object) return error.MalformedResponse;
    return types.decode_hash(try rpc.field(value, "hash"));
}

/// Fills `out` with the state reads pinned to the snapshot hash; returns the failed
/// required read, if any.
fn read_observations(
    client: *rpc.Client,
    snapshot: *const BlockView,
    activation: ?u64,
    out: *denim.Observations,
) ?CommandFailure {
    const facts = &snapshot.facts;
    const pin = pin_text(facts.hash);
    const proxy_code = code_hash(client, denim.proxy_address, &pin) catch |err|
        return .{ .what = "eth_getCode(BaseTime proxy)", .failure = call_failure(client, err) };
    const admin = storage(client, denim.admin_slot, &pin) catch |err|
        return .{ .what = "eth_getStorageAt(admin slot)", .failure = call_failure(client, err) };
    const implementation = storage(client, denim.implementation_slot, &pin) catch |err|
        return .{
            .what = "eth_getStorageAt(implementation slot)",
            .failure = call_failure(client, err),
        };
    const millis_word = storage(client, denim.millis_part_slot, &pin) catch |err|
        return .{ .what = "eth_getStorageAt(slot 0)", .failure = call_failure(client, err) };
    const zero: [32]u8 = @splat(0);
    const is_address = std.mem.allEqual(u8, implementation[0..12], 0);
    var implementation_code: ?[32]u8 = null;
    if (is_address and !std.mem.eql(u8, &implementation, &zero)) {
        implementation_code = code_hash(client, implementation[12..].*, &pin) catch |err|
            return .{ .what = "eth_getCode(implementation)", .failure = call_failure(client, err) };
    }
    out.* = .{
        .activation = activation,
        .block_number = facts.number,
        .block_hash = facts.hash,
        .timestamp = facts.timestamp,
        .timestamp_ms = snapshot.timestamp_ms_field,
        .proxy_code_hash = proxy_code,
        .admin = admin,
        .implementation = implementation,
        .implementation_code_hash = implementation_code,
        .storage_millis_part = denim.decode_millis_part(millis_word),
        .metadata = .none,
        .metadata_receipt_valid = null,
        .getter_millis_part = .none,
        .getter_timestamp_ms = .none,
    };
    if (denim.schedule_at(activation, facts.timestamp) != .active) return null;
    out.metadata = if (snapshot.metadata) |part| .{ .ok = part } else |err| .{
        .failed = note("{s}", .{denim.metadata_error_text(err)}),
    };
    out.metadata_receipt_valid = receipt_valid(client, snapshot) catch |err|
        return .{ .what = "eth_getBlockReceipts(snapshot)", .failure = call_failure(client, err) };
    out.getter_millis_part = getter(u16, client, denim.timestamp_millis_part_selector, &pin);
    out.getter_timestamp_ms = getter(u64, client, denim.timestamp_ms_selector, &pin);
    return null;
}

/// The EIP-1898 block parameter `{"blockHash":"0x…"}`.
fn pin_text(hash: [32]u8) [82]u8 {
    var out: [82]u8 = undefined;
    // 14 + 66 + 2 = 82 bytes exactly.
    const text = print(&out, "{{\"blockHash\":\"{s}\"}}", .{hash_hex(hash)});
    assert(text.len == out.len);
    return out;
}

fn code_hash(client: *rpc.Client, address: [20]u8, pin: []const u8) rpc.Error![32]u8 {
    var buffer: [160]u8 = undefined;
    const params = print(&buffer, "[\"{s}\",{s}]", .{ address_hex(address), pin });
    const value = try client.call("eth_getCode", params);
    return hash_code(value) catch error.MalformedResponse;
}

/// keccak256 of hex code, hashed in chunks so code of any size needs no buffer.
pub fn hash_code(value: json.Value) types.DecodeError![32]u8 {
    if (value != .string) return error.MalformedResponse;
    const text = value.string;
    if (text.len < 2 or text[0] != '0' or text[1] != 'x' or text.len % 2 != 0) {
        return error.MalformedResponse;
    }
    var hasher = keccak.Hasher.init();
    var chunk: [256]u8 = undefined;
    var offset: usize = 2;
    while (offset < text.len) {
        const length = @min(chunk.len * 2, text.len - offset);
        const bytes = std.fmt.hexToBytes(&chunk, text[offset..][0..length]) catch
            return error.MalformedResponse;
        hasher.update(bytes);
        offset += length;
    }
    assert(offset == text.len);
    return hasher.final();
}

fn storage(client: *rpc.Client, slot: [32]u8, pin: []const u8) rpc.Error![32]u8 {
    var buffer: [256]u8 = undefined;
    var slot_buffer: [66]u8 = undefined;
    const params = print(&buffer, "[\"{s}\",\"{s}\",{s}]", .{
        address_hex(denim.proxy_address), slot_quantity(&slot_buffer, slot), pin,
    });
    const value = try client.call("eth_getStorageAt", params);
    return decode_word(value) catch error.MalformedResponse;
}

/// The slot as a minimal hex quantity (`0x0`, `0x3608…`), as alloy sends a U256 slot;
/// some nodes reject a zero-padded 32-byte key.
pub fn slot_quantity(buffer: *[66]u8, slot: [32]u8) []const u8 {
    const digits = std.fmt.bytesToHex(slot, .lower);
    const first = std.mem.indexOfNone(u8, &digits, "0") orelse digits.len - 1;
    const text = print(buffer, "0x{s}", .{digits[first..]});
    assert(text.len >= 3 and (text.len == 3 or text[2] != '0'));
    return text;
}

/// A 32-byte storage word; shorter hex is left-padded (some nodes trim leading zeros).
pub fn decode_word(value: json.Value) types.DecodeError![32]u8 {
    if (value != .string) return error.MalformedResponse;
    const text = value.string;
    if (text.len < 3 or text[0] != '0' or text[1] != 'x') return error.MalformedResponse;
    const digits = text[2..];
    if (digits.len > 64) return error.MalformedResponse;
    var padded: [64]u8 = @splat('0');
    @memcpy(padded[64 - digits.len ..], digits);
    var word: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&word, &padded) catch return error.MalformedResponse;
    assert(digits.len <= 64);
    return word;
}

/// Whether tx[1]'s receipt in the snapshot is successful and pinned to index 1.
fn receipt_valid(client: *rpc.Client, snapshot: *const BlockView) rpc.Error!bool {
    var buffer: [96]u8 = undefined;
    const params = print(&buffer, "[\"{s}\"]", .{hash_hex(snapshot.facts.hash)});
    const value = try client.call("eth_getBlockReceipts", params);
    const tx_hash = snapshot.second_hash orelse return false;
    if (value != .array or value.array.items.len < 2) return false;
    const receipt = value.array.items[1];
    const hash_ok = if (denim.string_hash(receipt, "transactionHash")) |hash|
        std.mem.eql(u8, &hash, &tx_hash)
    else
        false;
    const block_ok = if (denim.string_hash(receipt, "blockHash")) |hash|
        std.mem.eql(u8, &hash, &snapshot.facts.hash)
    else
        false;
    return hash_ok and block_ok and denim.string_quantity(receipt, "status") == 1 and
        denim.string_quantity(receipt, "blockNumber") == snapshot.facts.number and
        denim.string_quantity(receipt, "transactionIndex") == 1;
}

/// `eth_call` of a no-argument getter returning one ABI word that must fit in `T`.
fn getter(
    comptime T: type,
    client: *rpc.Client,
    selector: [4]u8,
    pin: []const u8,
) denim.Observed(T) {
    var buffer: [192]u8 = undefined;
    const params = print(&buffer, "[{{\"to\":\"{s}\",\"data\":\"0x{x}\"}},{s}]", .{
        address_hex(denim.proxy_address), &selector, pin,
    });
    const value = client.call("eth_call", params) catch |err| {
        if (err == error.RpcError) return .{ .failed = note("{s}", .{client.last_error()}) };
        return .{ .failed = note("{s}", .{types.failure_of(client, err).text()}) };
    };
    var word: [33]u8 = undefined;
    const bytes = rpc.data(value, &word) catch
        return .{ .failed = note("malformed return data", .{}) };
    if (bytes.len != 32) {
        return .{ .failed = note("return data is {d} bytes, want 32", .{bytes.len}) };
    }
    const number = std.mem.readInt(u256, bytes[0..32], .big);
    const result = std.math.cast(T, number) orelse
        return .{ .failed = note("return value does not fit {s}", .{@typeName(T)}) };
    return .{ .ok = result };
}

// ------------------------------------------------------------------------- cadence

fn add_cadence(
    client: *rpc.Client,
    report: *denim.Report,
    snapshot: *const BlockView,
    edges_max: u32,
) void {
    assert(edges_max <= cadence_blocks_max);
    var blocks: [cadence_blocks_max + 1]denim.BlockFacts = undefined;
    blocks[0] = snapshot.facts;
    var count: usize = 1;
    var complete = true;
    while (count <= edges_max) {
        const child = blocks[count - 1];
        const active = report.activation != null and child.timestamp >= report.activation.?;
        // Stop at the first legacy block, at genesis, and at missing metadata (a fail).
        if (!active or child.number == 0 or child.timestamp_ms == null) break;
        const parent = block_by_hash(client, child.parent_hash, null) catch {
            complete = false;
            break;
        };
        blocks[count] = parent.facts;
        count += 1;
    }
    assert(count <= edges_max + 1);
    const cadence = denim.evaluate_cadence(report.activation, blocks[0..count], complete);
    report.add(denim.cadence_check, cadence.status, note("{s}", .{denim.cadence_expected}), note(
        "{s} ({d} edges checked)",
        .{ cadence.observed(), cadence.edges },
    ));
}

// ------------------------------------------------------------------------- wire objects

fn add_object_checks(client: *rpc.Client, report: *denim.Report, snapshot: *const BlockView) void {
    // Before activation a timestamp field cannot be required (base/base `evaluate`).
    if (report.schedule != .active) return denim.add_indeterminate(
        report,
        denim.object_checks,
        "canonical metadata timestamp",
        "Denim is not active at the snapshot",
    );
    const part = snapshot.metadata catch return denim.add_indeterminate(
        report,
        denim.object_checks,
        "canonical metadata timestamp",
        "canonical BaseTime metadata unavailable",
    );
    const expected_ms = denim.expected_timestamp_ms(snapshot.facts.timestamp, part);
    const hash = hash_hex(snapshot.facts.hash);
    var number_buffer: [24]u8 = undefined;
    const number = print(&number_buffer, "0x{x}", .{snapshot.facts.number});
    const identity = [_]denim.Identity{
        .{ .field = "hash", .expected = .{ .hash = snapshot.facts.hash } },
        .{ .field = "number", .expected = .{ .quantity = snapshot.facts.number } },
    };
    const calls = [_]struct { []const u8, []const u8, []const u8 }{
        .{ denim.object_checks[0], "eth_getBlockByHash", ",false" },
        .{ denim.object_checks[1], "eth_getBlockByNumber", ",false" },
        .{ denim.object_checks[2], "eth_getHeaderByHash", "" },
        .{ denim.object_checks[3], "eth_getHeaderByNumber", "" },
    };
    for (calls, 0..) |entry, index| {
        var buffer: [128]u8 = undefined;
        const id: []const u8 = if (index % 2 == 0) &hash else number;
        const params = print(&buffer, "[\"{s}\"{s}]", .{ id, entry[2] });
        const outcome = raw(client, entry[1], params);
        denim.check_wire_object(report, entry[0], outcome, "timestampMs", expected_ms, &identity);
    }
    add_transaction_checks(client, report, snapshot, expected_ms, &hash, number);
}

fn add_transaction_checks(
    client: *rpc.Client,
    report: *denim.Report,
    snapshot: *const BlockView,
    expected_ms: u64,
    hash: []const u8,
    number: []const u8,
) void {
    const names = denim.object_checks[4..7];
    const tx_hash = snapshot.second_hash orelse
        return denim.add_indeterminate(report, names, "tx[1] of the snapshot", "tx[1] has no hash");
    const tx_hex = hash_hex(tx_hash);
    const identity = [_]denim.Identity{
        .{ .field = "hash", .expected = .{ .hash = tx_hash } },
        .{ .field = "blockHash", .expected = .{ .hash = snapshot.facts.hash } },
        .{ .field = "blockNumber", .expected = .{ .quantity = snapshot.facts.number } },
        .{ .field = "transactionIndex", .expected = .{ .quantity = 1 } },
    };
    const calls = [_]struct { []const u8, []const u8, []const u8, []const u8 }{
        .{ names[0], "eth_getTransactionByHash", &tx_hex, "" },
        .{ names[1], "eth_getTransactionByBlockHashAndIndex", hash, ",\"0x1\"" },
        .{ names[2], "eth_getTransactionByBlockNumberAndIndex", number, ",\"0x1\"" },
    };
    for (calls) |entry| {
        var buffer: [128]u8 = undefined;
        const params = print(&buffer, "[\"{s}\"{s}]", .{ entry[2], entry[3] });
        const outcome = raw(client, entry[1], params);
        const field = "blockTimestampMs";
        denim.check_wire_object(report, entry[0], outcome, field, expected_ms, &identity);
    }
    assert(names.len == calls.len);
}

// ------------------------------------------------------------------------- wire logs

pub const Evidence = struct {
    number: u64,
    transaction_index: u64,
    block_hash: [32]u8,
    transaction_hash: [32]u8,
};

const Discovery = union(enum) { found: Evidence, missing: Note };

/// The newest log at or below the snapshot: windows grow 4x per empty scan and shrink
/// when the server rejects a range (base/base log discovery).
fn discover_evidence(client: *rpc.Client, snapshot_number: u64) Discovery {
    const floor = snapshot_number -| log_lookback_blocks;
    var upper = snapshot_number;
    var window = log_window_initial;
    var window_max = log_window_max;
    var reason = note("no post-Denim log found within scan bounds", .{});
    for (0..log_discovery_calls) |_| {
        assert(upper >= floor and window >= 1);
        const width = @min(window, upper - floor + 1);
        const lower = upper - (width - 1);
        var buffer: [96]u8 = undefined;
        const range = "[{{\"fromBlock\":\"0x{x}\",\"toBlock\":\"0x{x}\"}}]";
        const params = print(&buffer, range, .{ lower, upper });
        switch (raw(client, "eth_getLogs", params)) {
            .value => |value| {
                if (value != .array) {
                    return .{ .missing = note("eth_getLogs returned an invalid log array", .{}) };
                }
                if (newest_log(value.array.items, lower, upper)) |evidence| {
                    return .{ .found = evidence };
                }
                if (value.array.items.len > 0) {
                    return .{ .missing = note("eth_getLogs returned malformed log identity", .{}) };
                }
                if (lower == floor) break;
                upper = lower - 1;
                window = @min(window *| 4, window_max);
            },
            .method_error => |text| {
                reason = text;
                if (width <= 1) break;
                window_max = @max(width / 4, 1);
                window = window_max;
            },
            .unavailable => |text| return .{ .missing = text },
        }
    }
    return .{ .missing = reason };
}

fn newest_log(logs: []const json.Value, lower: u64, upper: u64) ?Evidence {
    assert(lower <= upper);
    var best: ?Evidence = null;
    for (logs) |log| {
        const candidate: Evidence = .{
            .number = denim.string_quantity(log, "blockNumber") orelse continue,
            .transaction_index = denim.string_quantity(log, "transactionIndex") orelse continue,
            .block_hash = denim.string_hash(log, "blockHash") orelse continue,
            .transaction_hash = denim.string_hash(log, "transactionHash") orelse continue,
        };
        if (candidate.number < lower or candidate.number > upper) continue;
        if (best) |current| {
            const same_block = candidate.number == current.number;
            const newer = candidate.number > current.number or
                (same_block and candidate.transaction_index > current.transaction_index);
            if (!newer) continue;
        }
        best = candidate;
    }
    return best;
}

const log_evidence_expected = "post-Denim log evidence";

fn add_log_checks(client: *rpc.Client, report: *denim.Report) void {
    if (report.schedule != .active) return denim.add_indeterminate(
        report,
        denim.log_checks,
        log_evidence_expected,
        "Denim is not active at the snapshot",
    );
    const evidence = switch (discover_evidence(client, report.block_number)) {
        .found => |found| found,
        .missing => |reason| return denim.add_indeterminate(
            report,
            denim.log_checks,
            log_evidence_expected,
            reason.slice(),
        ),
    };
    const expected_ms = evidence_timestamp_ms(client, report.activation.?, evidence) catch |err| {
        const reason = switch (err) {
            error.Unavailable => "log evidence block unavailable",
            error.Inactive => "newest log predates Denim activation",
            error.Mismatch => "log evidence no longer matches its canonical transaction",
            error.NoMetadata => "log evidence block has invalid BaseTime metadata",
        };
        return denim.add_indeterminate(report, denim.log_checks, log_evidence_expected, reason);
    };
    const hash = hash_hex(evidence.block_hash);
    var filter_buffer: [96]u8 = undefined;
    const filter = print(&filter_buffer, "[{{\"blockHash\":\"{s}\"}}]", .{hash});
    const outcome = raw(client, "eth_getLogs", filter);
    denim.check_wire_logs(report, denim.log_checks[0], outcome, expected_ms, evidence.block_hash);
    add_filter_checks(client, report, filter, expected_ms, evidence.block_hash);
    add_receipt_check(client, report, evidence, expected_ms);
    add_block_receipts_check(client, report, evidence, expected_ms);
}

fn evidence_timestamp_ms(
    client: *rpc.Client,
    activation: u64,
    evidence: Evidence,
) error{ Unavailable, Inactive, Mismatch, NoMetadata }!u64 {
    const block = block_by_hash(client, evidence.block_hash, evidence.transaction_index) catch
        return error.Unavailable;
    if (block.facts.timestamp < activation) return error.Inactive;
    if (block.facts.number != evidence.number) return error.Mismatch;
    const wanted = block.wanted_hash orelse return error.Mismatch;
    if (!std.mem.eql(u8, &wanted, &evidence.transaction_hash)) return error.Mismatch;
    const timestamp_ms = block.facts.timestamp_ms orelse return error.NoMetadata;
    assert(block.facts.timestamp >= activation);
    return timestamp_ms;
}

fn add_filter_checks(
    client: *rpc.Client,
    report: *denim.Report,
    filter: []const u8,
    expected_ms: u64,
    hash: [32]u8,
) void {
    const names = denim.log_checks[1..3];
    var id_buffer: [96]u8 = undefined;
    const id_params = switch (raw(client, "eth_newFilter", filter)) {
        .value => |value| if (valid_filter_id(value))
            print(&id_buffer, "[\"{s}\"]", .{value.string})
        else
            return add_both(report, names, .fail, note("invalid filter identifier", .{})),
        .method_error => |text| return add_both(report, names, .fail, text),
        .unavailable => |text| return add_both(report, names, .indeterminate, text),
    };
    const changes = raw(client, "eth_getFilterChanges", id_params);
    denim.check_wire_logs(report, names[0], changes, expected_ms, hash);
    const logs = raw(client, "eth_getFilterLogs", id_params);
    denim.check_wire_logs(report, names[1], logs, expected_ms, hash);
    const cleanup = raw(client, "eth_uninstallFilter", id_params);
    const removed = cleanup == .value and cleanup.value == .bool and cleanup.value.bool;
    if (removed) return;
    for (names) |name| {
        const check = report.find(name).?;
        check.status = .fail;
        check.observed = note("filter cleanup failed", .{});
    }
}

/// A filter id short enough for the params buffer and safe to embed in JSON.
fn valid_filter_id(value: json.Value) bool {
    if (value != .string) return false;
    const text = value.string;
    return text.len > 0 and text.len < 64 and std.mem.indexOfAny(u8, text, "\"\\") == null;
}

fn add_both(
    report: *denim.Report,
    names: []const []const u8,
    status: denim.Status,
    reason: Note,
) void {
    assert(names.len == 2);
    for (names) |name| report.add(name, status, note("blockHash filter", .{}), reason);
}

fn add_receipt_check(
    client: *rpc.Client,
    report: *denim.Report,
    evidence: Evidence,
    expected_ms: u64,
) void {
    var buffer: [96]u8 = undefined;
    const params = print(&buffer, "[\"{s}\"]", .{hash_hex(evidence.transaction_hash)});
    var outcome = raw(client, "eth_getTransactionReceipt", params);
    if (outcome == .value) {
        const receipt = outcome.value;
        const pinned = receipt_pinned(receipt, evidence) and
            hash_equals(receipt, "transactionHash", evidence.transaction_hash);
        const logs = if (receipt == .object) receipt.object.get("logs") else null;
        outcome = .{ .value = if (pinned and logs != null) logs.? else .null };
    }
    denim.check_wire_logs(report, denim.log_checks[3], outcome, expected_ms, evidence.block_hash);
}

fn receipt_pinned(receipt: json.Value, evidence: Evidence) bool {
    return hash_equals(receipt, "blockHash", evidence.block_hash) and
        denim.string_quantity(receipt, "blockNumber") == evidence.number;
}

fn hash_equals(value: json.Value, field: []const u8, expected: [32]u8) bool {
    const actual = denim.string_hash(value, field) orelse return false;
    return std.mem.eql(u8, &actual, &expected);
}

fn add_block_receipts_check(
    client: *rpc.Client,
    report: *denim.Report,
    evidence: Evidence,
    expected_ms: u64,
) void {
    const name = denim.log_checks[4];
    var buffer: [96]u8 = undefined;
    const params = print(&buffer, "[\"{s}\"]", .{hash_hex(evidence.block_hash)});
    const hash = evidence.block_hash;
    const outcome = raw(client, "eth_getBlockReceipts", params);
    if (outcome != .value) return denim.check_wire_logs(report, name, outcome, expected_ms, hash);
    const receipts = outcome.value;
    const invalid: denim.Outcome = .{ .value = .null };
    if (receipts != .array) return denim.check_wire_logs(report, name, invalid, expected_ms, hash);
    var tally: denim.LogTally = .{};
    for (receipts.array.items) |receipt| {
        const logs = if (receipt == .object) receipt.object.get("logs") else null;
        if (!receipt_pinned(receipt, evidence) or logs == null or logs.? != .array) {
            return denim.check_wire_logs(report, name, invalid, expected_ms, evidence.block_hash);
        }
        tally.add(logs.?.array.items, expected_ms, evidence.block_hash);
    }
    denim.finish_logs(report, name, tally);
}
