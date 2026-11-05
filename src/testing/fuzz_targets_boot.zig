//! Model-based fuzz target for fault-proof boot info (`proof/program/boot.zig`). The host
//! serves the program's inputs as local preimages; a dishonest or buggy host must not
//! crash the program or make it run with a value other than the one served, and must not
//! smuggle in a rollup config that disagrees with the built-in chain.
//!
//! Each local key is served as a valid value, empty, too short, or too long; the chain id
//! is the devnet's, mainnet's (with a devnet rollup config), or unknown; the rollup config
//! JSON is valid, has one byte flipped, or is garbage. A model walks the keys in load
//! order and predicts the exact first error, or every loaded value. Flipped JSON may
//! still parse, so it only narrows the outcome to a config error or a devnet success.

const std = @import("std");
const assert = std.debug.assert;
const Smith = std.testing.Smith;
const fuzz = @import("fuzz.zig");
const Prng = @import("prng.zig").Prng;
const preimage = @import("../proof/preimage/root.zig");
const boot = @import("../proof/program/boot.zig");
const chains = @import("../common/chains/root.zig");
const protocol = @import("../consensus/protocol/root.zig");
const json = @import("../utilities/json/root.zig");

const LocalKey = boot.LocalKey;
const Store = preimage.MemoryStore(16, 32 * 1024);
const Error = boot.Error;

const Shape = enum { valid, empty, short, long };

/// What the host serves for one fixed-size key.
const Served = struct {
    shape: Shape,
    bytes: [40]u8 = undefined,
    len: usize = 0,
};

fn serve(prng: *Prng, size: usize, valid_bias: u64) Served {
    var served: Served = .{ .shape = .valid };
    if (!prng.chance(valid_bias, 10)) served.shape = @fromBackingInt(@intCast(prng.range(1, 3)));
    served.len = switch (served.shape) {
        .valid => size,
        .empty => 0,
        .short => @intCast(prng.range(1, size - 1)),
        .long => @intCast(prng.range(size + 1, served.bytes.len)),
    };
    prng.fill(served.bytes[0..served.len]);
    return served;
}

fn serve_u64(prng: *Prng, value: u64) Served {
    var served = serve(prng, 8, 8);
    if (served.shape == .valid) std.mem.writeInt(u64, served.bytes[0..8], value, .big);
    return served;
}

/// The error `get_exact` of a 32-byte hash reports, or null.
fn hash_error(served: Served) ?Error {
    return if (served.len == 32) null else error.BufferLengthMismatch;
}

/// The outcome of `read_u64`: the value, null when empty, or an error.
fn u64_outcome(served: Served) Error!?u64 {
    if (served.len == 0) return null;
    if (served.len > 8) return error.BufferTooSmall;
    if (served.len != 8) return error.InvalidBootValue;
    return std.mem.readInt(u64, served.bytes[0..8], .big);
}

const Chain = enum { devnet, mainnet, unknown };
const ConfigText = enum { valid, flipped, garbage };

const Inputs = struct {
    hashes: [3]Served,
    claim_block: Served,
    chain_id: Served,
    chain: Chain,
    config_text: ConfigText,
    proposer: Served,
    interval: Served,
    l1_head_number: Served,
    schedule: Served,
};

fn random_inputs(prng: *Prng) Inputs {
    const chain: Chain = @fromBackingInt(@intCast(prng.below(3)));
    const chain_id: u64 = switch (chain) {
        .devnet => chains.devnet.chain_id,
        .mainnet => chains.mainnet.chain_id,
        .unknown => 0xdead_0000 + prng.below(1000),
    };
    const proposer = serve(prng, 20, 6); // Empty is valid too: the proposer is optional.
    var interval_value = prng.int(u64);
    if (prng.chance(1, 8)) interval_value = 0;
    return .{
        .hashes = .{ serve(prng, 32, 9), serve(prng, 32, 9), serve(prng, 32, 9) },
        .claim_block = serve_u64(prng, prng.int(u64)),
        .chain_id = serve_u64(prng, chain_id),
        .chain = chain,
        .config_text = @fromBackingInt(@intCast(if (prng.chance(7, 10)) 0 else prng.range(1, 2))),
        .proposer = proposer,
        .interval = serve_u64(prng, interval_value),
        .l1_head_number = serve_u64(prng, prng.int(u64)),
        .schedule = serve_u64(prng, if (prng.chance(1, 4)) 0 else prng.int(u64)),
    };
}

fn fill(store: *Store, inputs: *const Inputs, prng: *Prng, json_buffer: []u8) !void {
    const hash_keys = [_]LocalKey{ .l1_head, .l2_output_root, .l2_claim };
    for (hash_keys, &inputs.hashes) |local, *served| {
        try store.put(local.key(), served.bytes[0..served.len]);
    }
    try store.put(LocalKey.l2_claim_block_number.key(), slice(&inputs.claim_block));
    try store.put(LocalKey.l2_chain_id.key(), slice(&inputs.chain_id));
    // Always a devnet config: for mainnet's chain id it must be rejected as a mismatch.
    const config: protocol.RollupConfig = .{
        .l1_chain_id = chains.l1_devnet.chain_id,
        .l2_chain_id = switch (inputs.chain) {
            .mainnet => chains.mainnet.chain_id,
            .devnet, .unknown => chains.devnet.chain_id,
        },
    };
    var out: std.Io.Writer = .fixed(json_buffer);
    var writer = json.Writer.init(&out);
    try protocol.rollup_json.write(&writer, &config);
    const text = out.buffered();
    switch (inputs.config_text) {
        .valid => {},
        .flipped => text[@intCast(prng.below(text.len))] ^= @intCast(prng.range(1, 255)),
        .garbage => prng.fill(text[0..@min(text.len, 64)]),
    }
    const text_len = if (inputs.config_text == .garbage) @min(text.len, 64) else text.len;
    try store.put(LocalKey.l2_rollup_config.key(), text[0..text_len]);
    try store.put(LocalKey.proposer.key(), slice(&inputs.proposer));
    try store.put(LocalKey.intermediate_block_interval.key(), slice(&inputs.interval));
    try store.put(LocalKey.l1_head_number.key(), slice(&inputs.l1_head_number));
    try store.put(LocalKey.l2_schedule_block_number.key(), slice(&inputs.schedule));
}

fn slice(served: *const Served) []const u8 {
    return served.bytes[0..served.len];
}

fn load(store: *Store) Error!boot.BootInfo {
    var harness: preimage.InProcess = undefined;
    harness.init(std.testing.allocator, store.fetcher(), preimage.in_process.ignore_hints, .{
        .channel_bytes = 1 << 16,
    }) catch unreachable; // Test allocator with ample memory.
    defer harness.deinit(std.testing.allocator);
    var scratch: [boot.rollup_config_bytes_max]u8 = undefined;
    return boot.BootInfo.load(harness.oracle_reader(), &scratch);
}

fn fuzz_boot(_: void, smith: *Smith) anyerror!void {
    var prng = Prng.init(smith.value(u64));
    const inputs = random_inputs(&prng);
    var store: Store = .{};
    var json_buffer: [8192]u8 = undefined;
    try fill(&store, &inputs, &prng, &json_buffer);
    const result = load(&store);
    try check(&inputs, result);
}

/// Walks the keys in `BootInfo.load` order: the first bad one decides the error.
fn check(inputs: *const Inputs, result: Error!boot.BootInfo) !void {
    const testing = std.testing;
    for (&inputs.hashes) |*served| {
        if (hash_error(served.*)) |err| return testing.expectError(err, result);
    }
    const claim_block = u64_outcome(inputs.claim_block) catch |err| {
        return testing.expectError(err, result);
    } orelse return testing.expectError(error.InvalidBootValue, result);
    _ = u64_outcome(inputs.chain_id) catch |err| {
        return testing.expectError(err, result);
    } orelse return testing.expectError(error.InvalidBootValue, result);
    switch (inputs.config_text) {
        .garbage => return testing.expectError(error.RollupConfigInvalid, result),
        .flipped => {
            // A flip may still parse; past the config only devnet can succeed.
            _ = result catch |err| {
                if (err == error.RollupConfigInvalid or err == error.RollupConfigMismatch or
                    err == error.MissingL1ChainConfig) return;
                if (err == error.InvalidBootValue or err == error.BufferTooSmall) return;
                return err;
            };
            return testing.expect(inputs.chain == .devnet);
        },
        .valid => {},
    }
    // An unknown chain id is a custom chain; its (devnet) rollup config names another id.
    if (inputs.chain == .unknown) return testing.expectError(error.RollupConfigMismatch, result);
    if (inputs.chain == .mainnet) return testing.expectError(error.RollupConfigMismatch, result);
    return check_tail(inputs, claim_block, result);
}

fn check_tail(inputs: *const Inputs, claim_block: u64, result: Error!boot.BootInfo) !void {
    const testing = std.testing;
    const proposer_len = inputs.proposer.len;
    if (proposer_len != 0 and proposer_len != 20) {
        return testing.expectError(error.InvalidBootValue, result);
    }
    const interval = u64_outcome(inputs.interval) catch |err| {
        return testing.expectError(err, result);
    } orelse return testing.expectError(error.InvalidBootValue, result);
    if (interval == 0) return testing.expectError(error.InvalidBootValue, result);
    const l1_head_number = u64_outcome(inputs.l1_head_number) catch |err| {
        return testing.expectError(err, result);
    } orelse 0;
    const schedule = u64_outcome(inputs.schedule) catch |err| {
        return testing.expectError(err, result);
    } orelse 0;
    const info = try result;
    try testing.expectEqualSlices(u8, slice(&inputs.hashes[0]), &info.l1_head);
    try testing.expectEqualSlices(u8, slice(&inputs.hashes[1]), &info.agreed_l2_output_root);
    try testing.expectEqualSlices(u8, slice(&inputs.hashes[2]), &info.claimed_l2_output_root);
    try testing.expectEqual(claim_block, info.claimed_l2_block_number);
    try testing.expectEqual(chains.devnet.chain_id, info.chain_id);
    var proposer: [20]u8 = @splat(0);
    if (proposer_len == 20) proposer = inputs.proposer.bytes[0..20].*;
    try testing.expectEqual(proposer, info.proposer);
    try testing.expectEqual(interval, info.intermediate_block_interval);
    try testing.expectEqual(l1_head_number, info.l1_head_number);
    const schedule_expected = if (schedule == 0) claim_block else schedule;
    try testing.expectEqual(schedule_expected, info.schedule_block_number);
}

test "fuzz_targets_boot: boot info loads exactly what the host served or the first error" {
    try fuzz.run({}, fuzz_boot, .{ .iterations = 1024 });
}
