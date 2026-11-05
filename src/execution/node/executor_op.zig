//! OP Stack / Base block rules for the executor: the evm's per-block OP context from the
//! chain's upgrade schedule, the irregular transition-block state changes, and the Jovian
//! DA footprint. Mirrors base/base `crates/common/evm2` (`executor.rs`, `canyon.rs`) and
//! `crates/common/evm/src/everest.rs`.

const std = @import("std");
const assert = std.debug.assert;
const evm = @import("../evm/root.zig");
const chainspec = @import("../chainspec/root.zig");

const Upgrade = chainspec.Upgrade;

/// The evm upgrade in force for a chain upgrade. Delta (span batches) and the Pectra
/// blob schedule change no execution rules, so they map to their predecessor.
fn evm_upgrade(upgrade: Upgrade) evm.op.Upgrade {
    return switch (upgrade) {
        .regolith => .regolith,
        .canyon, .delta => .canyon,
        .ecotone => .ecotone,
        .fjord => .fjord,
        .granite => .granite,
        .holocene, .pectra_blob_schedule => .holocene,
        .isthmus => .isthmus,
        .jovian => .jovian,
        .azul => .azul,
        .beryl => .beryl,
        .cobalt => .cobalt,
        .denim => .denim,
        .everest => .everest,
    };
}

/// The OP context for a block at `timestamp`; null in L1 mode.
pub fn context(spec: *const chainspec.ChainSpec, timestamp: u64) ?evm.op.Context {
    if (spec.mode != .l2) return null;
    var latest: evm.op.Upgrade = .bedrock;
    const upgrades = @typeInfo(Upgrade).@"enum".field_names;
    inline for (upgrades) |name| {
        const upgrade = @field(Upgrade, name);
        if (spec.is_upgrade_active(upgrade, timestamp)) latest = evm_upgrade(upgrade);
    }
    return .{ .upgrade = latest };
}

/// Irregular state changes before the first transaction: the Canyon create2 deployer
/// on the first Canyon block (base/base's "active now but not at `timestamp - 2`"
/// heuristic), and the Everest system-account stub on every Everest block (idempotent).
pub fn apply_transitions(
    state: *evm.State,
    spec: *const chainspec.ChainSpec,
    timestamp: u64,
) evm.state.Error!void {
    if (spec.mode != .l2) return;
    const canyon_now = spec.is_upgrade_active(.canyon, timestamp);
    const canyon_before = spec.is_upgrade_active(.canyon, timestamp -| 2);
    if (canyon_now and !canyon_before) {
        try evm.op.apply_transition(state, .canyon_create2_deployer);
    }
    if (spec.is_upgrade_active(.everest, timestamp)) {
        try evm.op.apply_transition(state, .everest_nonce_manager);
    }
}

/// Jovian+: the DA footprint of a non-deposit transaction (`raw` is its EIP-2718
/// encoding), with the scalar read from the L1Block predeploy as of the current state.
pub fn da_footprint(state: *evm.State, raw: []const u8) evm.state.Error!u64 {
    assert(raw.len > 0);
    assert(raw[0] != 0x7e);
    const params = try evm.op.load_params(state, .jovian);
    return params.jovian_da_footprint(raw);
}

const testing = std.testing;

test "executor op: context follows the upgrade schedule" {
    const l1 = &chainspec.ChainSpec.presets.l1_dev;
    try testing.expect(context(l1, 0) == null);
    var spec = chainspec.ChainSpec.presets.base_devnet;
    spec.upgrades = @splat(null);
    spec.upgrades[@backingInt(Upgrade.regolith)] = 0;
    spec.upgrades[@backingInt(Upgrade.canyon)] = 10;
    spec.upgrades[@backingInt(Upgrade.delta)] = 20;
    try testing.expectEqual(evm.op.Upgrade.regolith, context(&spec, 5).?.upgrade);
    try testing.expectEqual(evm.op.Upgrade.canyon, context(&spec, 10).?.upgrade);
    try testing.expectEqual(evm.op.Upgrade.canyon, context(&spec, 25).?.upgrade);
}
