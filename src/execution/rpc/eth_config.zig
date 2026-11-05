//! `eth_config` (EIP-7910): the fork configuration in force at the head (`current`), the
//! next scheduled fork (`next`) and the last scheduled fork (`last`), as reth builds it
//! with base/base's L2 adjustments: on L2 the blob schedule is all zero and only the
//! beacon roots (Ecotone) and history storage (Isthmus) system contracts are listed.
//!
//! Forks are the distinct non-null activation times of the chain spec's schedule. The
//! fork id is EIP-2124's CRC32 of the genesis hash, folded with every activation time
//! after genesis up to the fork's own (all chains here start with their block forks).
//! Precompiles are the ones the evm activates at that fork, named as EIP-7910.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const chainspec = @import("../chainspec/root.zig");
const evm = @import("../evm/root.zig");
const node = @import("../node/root.zig");
const eth = @import("eth.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Hash = [32]u8;
const ChainSpec = chainspec.ChainSpec;

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "eth_config", .handler = config },
};

/// Upper bound on scheduled forks (both schedules together are far smaller).
const forks_max = 32;

pub const Forks = struct {
    times: [forks_max]u64 = undefined,
    len: u32 = 0,

    pub fn slice(forks: *const Forks) []const u64 {
        return forks.times[0..forks.len];
    }
};

/// The distinct activation times of the chain's schedule, ascending.
pub fn fork_times(spec: *const ChainSpec) Forks {
    var forks: Forks = .{};
    const schedule: []const ?u64 = switch (spec.mode) {
        .l1 => &spec.ethereum_forks,
        .l2 => &spec.upgrades,
    };
    assert(schedule.len <= forks_max);
    for (schedule) |entry| {
        const time = entry orelse continue;
        if (std.mem.indexOfScalar(u64, forks.slice(), time) != null) continue;
        forks.times[forks.len] = time;
        forks.len += 1;
    }
    std.sort.pdq(u64, forks.times[0..forks.len], {}, std.sort.asc(u64));
    return forks;
}

/// EIP-2124 fork hash at `timestamp`: CRC32 of the genesis hash, then each activation
/// time in `(genesis_time, timestamp]` as 8 big-endian bytes.
pub fn fork_hash(genesis: Hash, genesis_time: u64, times: []const u64, timestamp: u64) u32 {
    var hash = std.hash.Crc32.hash(&genesis);
    var previous: ?u64 = null;
    for (times) |time| {
        assert(previous == null or previous.? < time);
        previous = time;
        if (time <= genesis_time or time > timestamp) continue;
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, time, .big);
        var crc: std.hash.Crc32 = .{ .crc = ~hash }; // Continue from the checksum.
        crc.update(&bytes);
        hash = crc.final();
    }
    return hash;
}

fn config(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    const head = eth.head_header(api);
    const forks = fork_times(api.spec);
    const times = forks.slice();
    // The newest fork at or before the head.
    var current: ?usize = null;
    for (times, 0..) |time, index| {
        if (time <= head.timestamp) current = index;
    }
    const index = current orelse {
        return call.fail(rpc.code.internal_error, "no active timestamp fork found");
    };
    const w = call.writer;
    try w.begin_object();
    try w.key("current");
    try write_fork(api, w, times[index]);
    try w.key("next");
    if (index + 1 < times.len) try write_fork(api, w, times[index + 1]) else try w.null_value();
    try w.key("last");
    if (index + 1 < times.len) try write_fork(api, w, times[times.len - 1]) else try w.null_value();
    try w.end_object();
}

fn write_fork(api: *Api, w: *json.Writer, timestamp: u64) HandlerError!void {
    const spec = api.spec;
    try w.begin_object();
    try w.key("activationTime");
    try w.integer(timestamp);
    try w.key("blobSchedule");
    const params = spec.blob_params_at(timestamp);
    try w.begin_object();
    try w.key("baseFeeUpdateFraction");
    try w.integer(if (params) |p| p.update_fraction else 0);
    try w.key("max");
    try w.integer(if (params) |p| p.max_blob_count else 0);
    try w.key("target");
    try w.integer(if (params) |p| p.target_blob_count else 0);
    try w.end_object();
    try w.key("chainId");
    try w.quantity(spec.chain_id);
    try w.key("forkId");
    const chain = api.chain;
    const times = fork_times(spec);
    const hash = fork_hash(chain.genesis_hash, chain.genesis_timestamp, times.slice(), timestamp);
    var hash_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &hash_bytes, hash, .big);
    try w.data(&hash_bytes);
    try w.key("precompiles");
    try write_precompiles(spec, w, timestamp);
    try w.key("systemContracts");
    try write_system_contracts(spec, w, timestamp);
    try w.end_object();
}

const Named = struct { name: []const u8, number: u16 };

/// EIP-7910 names, sorted by name (the map order reth's BTreeMap gives).
const precompile_names = [_]Named{
    .{ .name = "BLAKE2F", .number = 0x09 },
    .{ .name = "BLS12_G1ADD", .number = 0x0b },
    .{ .name = "BLS12_G1MSM", .number = 0x0c },
    .{ .name = "BLS12_G2ADD", .number = 0x0d },
    .{ .name = "BLS12_G2MSM", .number = 0x0e },
    .{ .name = "BLS12_MAP_FP2_TO_G2", .number = 0x11 },
    .{ .name = "BLS12_MAP_FP_TO_G1", .number = 0x10 },
    .{ .name = "BLS12_PAIRING_CHECK", .number = 0x0f },
    .{ .name = "BN254_ADD", .number = 0x06 },
    .{ .name = "BN254_MUL", .number = 0x07 },
    .{ .name = "BN254_PAIRING", .number = 0x08 },
    .{ .name = "ECREC", .number = 0x01 },
    .{ .name = "ID", .number = 0x04 },
    .{ .name = "KZG_POINT_EVALUATION", .number = 0x0a },
    .{ .name = "MODEXP", .number = 0x05 },
    .{ .name = "P256VERIFY", .number = 0x100 },
    .{ .name = "RIPEMD160", .number = 0x03 },
    .{ .name = "SHA256", .number = 0x02 },
};

comptime {
    for (precompile_names[1..], 0..) |entry, index| {
        assert(std.mem.order(u8, precompile_names[index].name, entry.name) == .lt);
    }
}

/// Whether the evm runs a precompile at `address` in a block at `timestamp`.
pub fn precompile_active(spec: *const ChainSpec, timestamp: u64, address: [20]u8) bool {
    const op_upgrade = if (node.executor_op.context(spec, timestamp)) |context|
        context.upgrade
    else
        null;
    return switch (node.executor.evm_fork(spec.spec_at(timestamp))) {
        inline else => |fork| evm.precompiles.is_precompile(fork, op_upgrade, address),
    };
}

fn write_precompiles(spec: *const ChainSpec, w: *json.Writer, timestamp: u64) HandlerError!void {
    try w.begin_object();
    for (precompile_names) |entry| {
        const address = evm.primitives.address_from_int(entry.number);
        if (!precompile_active(spec, timestamp, address)) continue;
        try w.key(entry.name);
        try w.string(&primitives.checksum(.{ .bytes = address }, null));
    }
    try w.end_object();
}

fn write_system_contracts(
    spec: *const ChainSpec,
    w: *json.Writer,
    timestamp: u64,
) HandlerError!void {
    const cancun = spec.is_ethereum_fork_active(.cancun, timestamp);
    const prague = spec.is_ethereum_fork_active(.prague, timestamp);
    // L2 keeps only the contracts Base deploys (no EIP-7002/7251 request contracts).
    const requests = prague and spec.mode == .l1;
    const executor = node.executor;
    try w.begin_object();
    if (cancun) try write_contract(w, "BEACON_ROOTS_ADDRESS", executor.beacon_roots_address);
    if (requests) {
        const consolidation = executor.consolidation_request_address;
        try write_contract(w, "CONSOLIDATION_REQUEST_PREDEPLOY_ADDRESS", consolidation);
    }
    if (prague) try write_contract(w, "HISTORY_STORAGE_ADDRESS", executor.history_storage_address);
    if (requests) {
        const withdrawal = executor.withdrawal_request_address;
        try write_contract(w, "WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS", withdrawal);
    }
    try w.end_object();
}

fn write_contract(w: *json.Writer, name: []const u8, address: [20]u8) HandlerError!void {
    try w.key(name);
    try w.string(&primitives.checksum(.{ .bytes = address }, null));
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

test "eth_config: EIP-2124 fork hash of the mainnet genesis" {
    // EIP-2124 vector: mainnet genesis hash -> 0xfc64ec04 (no forks folded).
    const genesis = primitives.hex.decode_array(
        32,
        "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
    ) catch unreachable;
    try testing.expectEqual(@as(u32, 0xfc64ec04), fork_hash(genesis, 0, &.{}, 0));
    // Homestead (block 1150000) folded: 0x97c2c34c.
    try testing.expectEqual(@as(u32, 0x97c2c34c), fork_hash(genesis, 0, &.{1_150_000}, 1_150_000));
    // Forks at or before genesis, and after the timestamp, are not folded.
    const at_genesis = fork_hash(genesis, 1_150_000, &.{1_150_000}, 2_000_000);
    try testing.expectEqual(@as(u32, 0xfc64ec04), at_genesis);
    try testing.expectEqual(@as(u32, 0xfc64ec04), fork_hash(genesis, 0, &.{1_150_000}, 1_149_999));
}

test "eth_config: fork times are distinct and ascending" {
    const forks = fork_times(&ChainSpec.presets.base_mainnet);
    try testing.expect(forks.len > 4);
    for (forks.slice()[1..], 0..) |time, index| try testing.expect(forks.slice()[index] < time);
}

fn check_fork_times(seed: u64) !void {
    var prng = Prng.init(seed);
    var spec = ChainSpec.presets.base_mainnet;
    var time: u64 = prng.range(0, 1000);
    for (&spec.upgrades) |*entry| {
        if (prng.chance(1, 4)) {
            entry.* = null;
            continue;
        }
        time += prng.range(0, 3); // Ties allowed: they collapse into one fork.
        entry.* = time;
    }
    const forks = fork_times(&spec);
    for (forks.slice()[1..], 0..) |value, index| try testing.expect(forks.slice()[index] < value);
    for (spec.upgrades) |entry| {
        if (entry) |at| try testing.expect(std.mem.indexOfScalar(u64, forks.slice(), at) != null);
    }
    const genesis: Hash = @splat(@intCast(prng.below(256)));
    const all = fork_hash(genesis, 0, forks.slice(), std.math.maxInt(u64));
    const none = fork_hash(genesis, std.math.maxInt(u64), forks.slice(), 0);
    try testing.expectEqual(std.hash.Crc32.hash(&genesis), none);
    if (forks.len > 0 and forks.times[forks.len - 1] > 0) try testing.expect(all != none);
}

test "eth_config: seeded fuzz of fork schedules" {
    for (0..64) |seed| try check_fork_times(seed + 0xc0f);
}

fn fuzz_fork_times(_: void, smith: *testing.Smith) anyerror!void {
    try check_fork_times(smith.value(u64));
}

test "eth_config: fuzz" {
    try testing.fuzz({}, fuzz_fork_times, .{});
}
