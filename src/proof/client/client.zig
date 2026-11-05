//! The fault-proof client. Port of base/base `crates/proof/client/src/{prologue,driver,
//! epilogue}.rs`.
//!
//! Prologue: load the boot info, find the agreed safe head from the agreed output root,
//! open the oracle-backed L1 / blob / L2 providers, the stateless builder and the
//! derivation pipeline. Driver: derive and execute up to the claimed block (or until L1
//! runs out). Epilogue: the claim holds iff the computed output root equals it.

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../preimage/root.zig");
const mpt = @import("../mpt/root.zig");
const executor = @import("../executor/root.zig");
const program = @import("../program/root.zig");
const driver_module = @import("../driver/root.zig");
const kzg = @import("../../common/crypto/kzg/root.zig");
const chains = @import("../../common/chains/root.zig");
const chainspec = @import("../../execution/chainspec/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const derive = @import("../../consensus/derive/root.zig");

const Hash = [32]u8;
const Allocator = std.mem.Allocator;
const L1BlobSchedule = protocol.l1_info.L1BlobSchedule;

/// Limits sized for real L2 blocks (the CLI default); tests pass smaller ones.
pub const default_builder_config: executor.builder.Config = .{
    .sparse = .{
        .nodes_max = 1 << 18,
        .node_bytes_max = 1 << 27,
        .codes_max = 4096,
        .code_bytes_max = 1 << 27,
        .headers_max = 256,
        .trie_nodes_max = 1 << 19,
        .storage_tries_max = 1 << 14,
    },
    .changeset = .{
        .accounts_max = 1 << 16,
        .storage_max = 1 << 18,
        .codes_max = 4096,
        .code_bytes_max = 1 << 26,
    },
    .executor = .{
        .scratch_bytes = 1 << 26,
        .transactions_max = 1 << 14,
        .evm = .{ .memory_bytes_max = 1 << 26, .code_arena_bytes = 1 << 26 },
        .limits = .{
            .accounts_max = 1 << 16,
            .slots_max = 1 << 18,
            .transient_slots_max = 1 << 14,
            .journal_entries_max = 1 << 20,
            .logs_max = 1 << 16,
            .log_data_bytes_max = 1 << 24,
            .code_bytes_max = 1 << 26,
        },
    },
    .resolver = .{ .bytes_max = 1 << 28, .entries_max = 1 << 20 },
};

pub const Options = struct {
    builder: executor.builder.Config,
    resolver: mpt.oracle_resolver.Options = .{ .bytes_max = 64 << 20, .entries_max = 1 << 18 },
    l1: program.l1_chain_provider.Options = .{},
    l2: program.l2_chain_provider.Options = .{},
    blobs: program.l1_blob_provider.Options = .{},
    /// Owned by the caller (about 1 MiB together).
    kzg_settings: *const kzg.blob.Settings,
    kzg_workspace: *kzg.blob.Workspace,
};

pub const Error = driver_module.driver.Error || program.boot.Error || program.sync.Error ||
    program.l1_chain_provider.Failure || program.l1_blob_provider.Failure || Allocator.Error ||
    error{ UnknownChainSpec, InvalidClaimedBlock };

pub const Outcome = struct {
    block_number: u64,
    output_root: Hash,
    /// True when L1 ran out before the claimed block.
    exhausted: bool,
};

/// Runs the program and returns the computed output root at the claimed block.
pub fn run(allocator: Allocator, client: Client.Io, options: Options) Error!Outcome {
    var scratch: [program.boot.rollup_config_bytes_max]u8 = undefined;
    const boot = try program.BootInfo.load(client.oracle, &scratch);
    const safe_hash = try program.sync.safe_head_hash(client.oracle, boot.agreed_l2_output_root);
    const state = try allocator.create(Client);
    defer allocator.destroy(state);
    try state.init(allocator, client, &boot, safe_hash, options);
    defer state.deinit(allocator);
    return state.run(&boot);
}

/// The epilogue: true when the computed output root is the claimed one.
pub fn claim_holds(boot: *const program.BootInfo, outcome: *const Outcome) bool {
    return std.mem.eql(u8, &outcome.output_root, &boot.claimed_l2_output_root);
}

/// The execution chain spec of an L2 chain id.
pub fn spec_for(chain_id: u64) ?*const chainspec.ChainSpec {
    const presets = &chainspec.ChainSpec.presets;
    const all = [_]*const chainspec.ChainSpec{
        &presets.base_mainnet,
        &presets.base_sepolia,
        &presets.base_devnet,
    };
    for (all) |spec| if (spec.chain_id == chain_id) return spec;
    return null;
}

/// The execution spec of a custom chain from its rollup config: each upgrade activates at
/// the earliest of its own time and the times of the upgrades that imply it (the OP
/// cascade), fee parameters from `chain_op_config`, gas limit from the genesis system
/// config.
pub fn custom_spec(boot: *const program.BootInfo) error{UnknownChainSpec}!chainspec.ChainSpec {
    assert(boot.custom);
    const rollup = &boot.rollup_config;
    var spec: chainspec.ChainSpec = .{
        .chain_id = boot.chain_id,
        .mode = .l2,
        .base_fee_params = .init(boot.chain_op.denominator, boot.chain_op.elasticity),
        .base_fee_params_canyon = .init(boot.chain_op.denominator_canyon, boot.chain_op.elasticity),
        .gas_limit = if (rollup.genesis.system_config) |config| config.gas_limit else 0,
    };
    if (spec.gas_limit == 0) return error.UnknownChainSpec;
    const names = @typeInfo(chainspec.Upgrade).@"enum".field_names;
    inline for (names, 0..) |name, index| {
        const upgrade = @field(protocol.Upgrade, name);
        spec.upgrades[index] = cascade_activation(rollup, upgrade);
    }
    spec.validate() catch return error.UnknownChainSpec;
    assert(spec.mode == .l2);
    return spec;
}

fn cascade_activation(rollup: *const protocol.RollupConfig, upgrade: protocol.Upgrade) ?u64 {
    var earliest: ?u64 = null;
    var current: ?protocol.Upgrade = upgrade;
    for (0..protocol.Upgrade.count) |_| {
        const step = current orelse break;
        if (rollup.upgrades.get(step)) |at| earliest = @min(earliest orelse at, at);
        current = step.implied_by();
    } else unreachable; // Proof: implied_by strictly increases the enum value.
    return earliest;
}

/// The L1 blob fee schedule of an L1 fork config.
pub fn blob_schedule_of(
    config: *const chains.L1Config,
    bpo: *[2]L1BlobSchedule.Entry,
) L1BlobSchedule {
    var count: usize = 0;
    if (config.bpo1) |timestamp| {
        bpo[count] = .{ .timestamp = timestamp, .update_fraction = 8_346_193 };
        count += 1;
    }
    if (config.bpo2) |timestamp| {
        bpo[count] = .{ .timestamp = timestamp, .update_fraction = 11_684_671 };
        count += 1;
    }
    return .{ .prague_time = config.prague, .osaka_time = config.osaka, .bpo = bpo[0..count] };
}

pub const Client = struct {
    rollup: protocol.RollupConfig,
    bpo: [2]L1BlobSchedule.Entry,
    blob_schedule: L1BlobSchedule,
    custom_spec: chainspec.ChainSpec = undefined,
    resolver: mpt.OracleResolver,
    l1: program.L1ChainProvider,
    blobs: program.L1BlobProvider,
    l2: program.L2ChainProvider,
    builder: executor.Builder,
    pipeline: derive.pipeline.Pipeline,
    tip: driver_module.Tip,

    pub const Io = struct {
        oracle: preimage.OracleReader,
        hints: preimage.HintWriter,
    };

    fn init(
        self: *Client,
        allocator: Allocator,
        io: Io,
        boot: *const program.BootInfo,
        safe_hash: Hash,
        options: Options,
    ) Error!void {
        const spec = if (boot.custom) custom: {
            self.custom_spec = try custom_spec(boot);
            break :custom &self.custom_spec;
        } else spec_for(boot.chain_id) orelse return error.UnknownChainSpec;
        self.rollup = boot.rollup_config;
        self.blob_schedule = blob_schedule_of(&boot.l1_config, &self.bpo);
        self.resolver = try .init(allocator, io.oracle, options.resolver);
        errdefer self.resolver.deinit(allocator);
        const rollup = &self.rollup;
        self.l2 = try .init(allocator, &self.resolver, io.hints, rollup, safe_hash, options.l2);
        errdefer self.l2.deinit(allocator);
        const safe_header = try self.l2.fetch_header(safe_hash);
        const safe_info = self.l2.l2_block_info_by_hash(.{ .bytes = safe_hash }) catch
            return error.ProviderFailed;
        self.tip = .{
            .info = safe_info,
            .header = safe_header,
            .output_root = boot.agreed_l2_output_root,
        };
        var l1_options = options.l1;
        l1_options.recover_to = self.rollup.batch_inbox_address;
        self.l1 = try .init(allocator, &self.resolver, io.hints, boot.l1_head, l1_options);
        errdefer self.l1.deinit(allocator);
        const settings = options.kzg_settings;
        const workspace = options.kzg_workspace;
        self.blobs = try .init(allocator, io.oracle, io.hints, settings, workspace, options.blobs);
        errdefer self.blobs.deinit(allocator);
        try self.builder.init(allocator, spec, io.oracle, io.hints, options.builder);
        errdefer self.builder.deinit(allocator);
        const origin = self.l1.l1_block_info_by_number(safe_info.l1_origin.number) catch
            return error.ProviderFailed;
        self.pipeline = .init(allocator, &self.rollup, &self.blob_schedule, origin);
    }

    fn deinit(self: *Client, allocator: Allocator) void {
        self.pipeline.deinit();
        self.builder.deinit(allocator);
        self.blobs.deinit(allocator);
        self.l1.deinit(allocator);
        self.l2.deinit(allocator);
        self.resolver.deinit(allocator);
        self.* = undefined;
    }

    fn run(self: *Client, boot: *const program.BootInfo) Error!Outcome {
        const safe_number = self.tip.info.block_info.number;
        if (boot.claimed_l2_block_number < safe_number) return error.InvalidClaimedBlock;
        var driver: driver_module.Driver = .{
            .rollup = &self.rollup,
            .pipeline = &self.pipeline,
            .l1 = &self.l1,
            .blobs = &self.blobs,
            .l2 = &self.l2,
            .builder = &self.builder,
            .resolver = &self.resolver,
            .tip = self.tip,
        };
        if (boot.claimed_l2_block_number > safe_number) {
            try driver.reset();
            try driver.advance_to_target(boot.claimed_l2_block_number);
        }
        self.tip = driver.tip;
        assert(self.tip.info.block_info.number >= safe_number);
        return .{
            .block_number = self.tip.info.block_info.number,
            .output_root = self.tip.output_root,
            .exhausted = driver.exhausted,
        };
    }
};

test "client: a custom chain's spec follows the OP upgrade cascade" {
    var boot: program.BootInfo = undefined;
    boot.custom = true;
    boot.chain_id = 901;
    boot.chain_op = .{};
    boot.rollup_config = .{ .l2_chain_id = 901 };
    boot.rollup_config.genesis.system_config = .{ .gas_limit = 30_000_000 };
    boot.rollup_config.upgrades.set(.holocene, 100);
    boot.rollup_config.upgrades.set(.isthmus, 50);
    const spec = try custom_spec(&boot);
    const at = &spec.upgrades;
    try std.testing.expectEqual(@as(?u64, 50), at[@backingInt(chainspec.Upgrade.regolith)]);
    try std.testing.expectEqual(@as(?u64, 50), at[@backingInt(chainspec.Upgrade.holocene)]);
    try std.testing.expectEqual(@as(?u64, null), at[@backingInt(chainspec.Upgrade.jovian)]);
    try std.testing.expect(spec.is_upgrade_active(.ecotone, 60));
    boot.rollup_config.genesis.system_config = null;
    try std.testing.expectError(error.UnknownChainSpec, custom_spec(&boot));
}
