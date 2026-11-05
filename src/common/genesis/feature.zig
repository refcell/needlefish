//! Base protocol feature registry, ported from base/base `common/genesis/src/feature.rs`:
//! independently meaningful behaviors and the network upgrade that introduces each one.
//! The registry says *what* is enabled; rollup, chain and EVM schedules keep their own
//! activation semantics (cascade, timestamp, ordinal).

const std = @import("std");
const assert = std.debug.assert;
const genesis = @import("root.zig");

/// Every OP Stack and Base network upgrade, in activation order (base/base `BaseUpgrade`).
pub const Upgrade = enum(u8) {
    bedrock,
    regolith,
    canyon,
    delta,
    ecotone,
    fjord,
    granite,
    holocene,
    pectra_blob_schedule,
    isthmus,
    jovian,
    azul,
    beryl,
    cobalt,
    denim,
    everest,
    zenith,

    pub const count = std.enums.values(Upgrade).len;
    /// base/base `BaseUpgrade::LATEST`.
    pub const latest: Upgrade = .beryl;

    /// Whether this upgrade includes `feature`, by ordinal (EVM spec semantics).
    pub fn is_feature_enabled(upgrade: Upgrade, feature: BaseFeature) bool {
        return @backingInt(feature.activation_upgrade()) <= @backingInt(upgrade);
    }

    /// The full upgrade for a Base-specific upgrade from the genesis `config.base` block.
    pub fn from_base(base_upgrade: genesis.BaseUpgrade) Upgrade {
        const upgrade: Upgrade = switch (base_upgrade) {
            .azul => .azul,
            .beryl => .beryl,
            .cobalt => .cobalt,
            .denim => .denim,
            .everest => .everest,
            .zenith => .zenith,
        };
        assert(@backingInt(upgrade) >= @backingInt(Upgrade.azul));
        return upgrade;
    }
};

pub const BaseFeature = enum(u8) {
    /// Require child block timestamps to advance, subject to the subsecond schedule exception.
    monotonic_block_timestamps,
    /// Enforce deposit gas limits and reject the legacy system-transaction flag.
    deposit_gas_accounting,
    /// Include the sender's pre-execution nonce in deposit receipts.
    deposit_nonce,
    /// Do not add the legacy signature-byte allowance to L1 data gas.
    actual_l1_signature_bytes,
    /// Include the version field in deposit receipts.
    deposit_receipt_version,
    /// Install the deterministic CREATE2 deployer at the transition.
    create2_deployer,
    /// Include empty withdrawals in block bodies and payload attributes.
    withdrawals,
    /// Use the revised EIP-1559 base fee change denominator.
    base_fee_denominator,
    /// Read the first ready channel rather than blocking on the oldest channel.
    ready_channel_selection,
    /// Publish and accept withdrawal-capable gossip payloads.
    gossip_payload_v2,
    /// Permit span batches in derivation.
    span_batches,
    /// Price L1 data with separate calldata and blob fee scalars, encode compact blob-aware L1
    /// attributes after the transition block, and validate blob-aware system config scalars
    /// while ignoring legacy overhead.
    blob_aware_l1_fees,
    /// Include blob gas fields in L2 headers, initially with zero values.
    blob_header,
    /// Include the parent beacon block root and apply the beacon-roots system call.
    beacon_roots,
    /// Set the L2 EVM blob base fee to the protocol's constant minimum.
    constant_blob_base_fee,
    /// Read blob batch data after the explicitly configured L1 timestamp boundary.
    blob_data_source,
    /// Use the blob-capable V3 Engine API payload methods.
    engine_api_v3,
    /// Inject the Ecotone contract-upgrade deposit bundle at the transition.
    ecotone_upgrade_transactions,
    /// Publish and accept blob-capable gossip payloads.
    gossip_payload_v3,
    /// Estimate compressed transaction size with FastLZ for L1 data fees.
    fast_lz_l1_fees,
    /// Verify secp256r1 signatures using the original RIP-7212 gas price.
    rip7212_precompile,
    /// Use the fixed 1800-second sequencer drift bound.
    fixed_sequencer_drift,
    /// Accept the larger decompressed channel byte limit.
    large_channels,
    /// Accept and produce Brotli-compressed batch channels.
    brotli_compression,
    /// Expand the buffered channel bank's maximum size.
    channel_bank_size_expansion,
    /// Inject the Fjord contract-upgrade deposit bundle at the transition.
    fjord_upgrade_transactions,
    /// Bound bn254 pairing input size before executing the precompile.
    bn254_pairing_input_limit,
    /// Use the shortened channel timeout.
    short_channel_timeout,
    /// Exclude transaction-pool transactions from the Granite transition block.
    granite_transition_no_tx_pool,
    /// Read dynamic EIP-1559 parameters from the block header extra data.
    dynamic_base_fee_parameters,
    /// Apply strict batch ordering and revised invalid-batch handling, assemble one channel at
    /// a time, drop out-of-order frames, and reset the pipeline when crossing into these rules.
    strict_derivation_ordering,
    /// Retry invalid execution payloads as deposits-only payloads.
    deposits_only_on_invalid_payload,
    /// Exclude transaction-pool transactions from the Holocene transition block.
    holocene_transition_no_tx_pool,
    /// Apply the optional L1 Pectra blob schedule correction.
    blob_schedule_correction,
    /// Charge the operator fee in addition to execution and L1 data fees, and include its
    /// fields in the L1 attributes deposit after the transition block.
    operator_fee,
    /// Bound BLS12-381 multi-scalar multiplication and pairing input sizes.
    bls_input_limits,
    /// Permit EIP-7702 set-code transactions in batches.
    eip7702,
    /// Apply the historical-block-hash storage system call.
    history_storage,
    /// Put the L2-to-L1 message-passer storage root in the header withdrawals root.
    l2_to_l1_message_root,
    /// Set the header requests hash to the empty execution-requests hash.
    empty_requests_hash,
    /// Use execution-request-capable V4 Engine API payload methods.
    engine_api_v4,
    /// Inject the Isthmus contract-upgrade deposit bundle at the transition.
    isthmus_upgrade_transactions,
    /// Publish and accept execution-request-capable gossip payloads.
    gossip_payload_v4,
    /// Reject proof derivation that exhausts its source before the claimed block.
    strict_proof_source_exhaustion,
    /// Scale the operator fee scalar component by 100 instead of dividing by one million.
    scaled_operator_fees,
    /// Meter transaction DA footprint against the block budget, and include the DA footprint
    /// scalar in L1 attributes after the transition block.
    da_footprint,
    /// Calculate the base fee from the larger of execution gas and DA footprint, with a floor.
    da_aware_base_fee,
    /// Tighten the bn254 pairing input limit.
    tight_bn254_pairing_input_limit,
    /// Tighten BLS12-381 multi-scalar multiplication and pairing input limits.
    tight_bls_input_limits,
    /// Enforce the minimum base fee carried in block extra data.
    min_base_fee,
    /// Inject the Jovian contract-upgrade deposit bundle at the transition.
    jovian_upgrade_transactions,
    /// Use the Osaka price for the secp256r1 signature verifier.
    repriced_p256_precompile,
    /// Configure the Osaka per-transaction gas limit cap in Base EVM environments.
    transaction_gas_limit_cap,
    /// Request V5 payload envelopes from the execution engine.
    engine_api_v5,
    /// Resolve dynamic B20 token addresses to their native precompile implementations.
    token_precompiles,
    /// Install the native activation registry for token and policy precompiles.
    activation_registry,
    /// Enable the first B20 asset contract implementation.
    asset_precompile,
    /// Enable the first B20 stablecoin contract implementation.
    stablecoin_precompile,
    /// Enable the first B20 policy contract implementation.
    policy_precompile,
    /// Enable the B20 factory contract implementation.
    token_factory_precompile,
    /// Use the second B20 asset contract implementation.
    asset_precompile_v2,
    /// Use the second B20 stablecoin contract implementation.
    stablecoin_precompile_v2,
    /// Use the second B20 policy contract implementation.
    policy_precompile_v2,
    /// Clear retired native-precompile dynamic storage slots and charge the preparatory reads.
    dynamic_storage_tail_cleanup,
    /// Return only the selector, without decoder diagnostics, for native-precompile ABI errors.
    compact_abi_decode_errors,
    /// Reject nonzero call value in activation registry calls.
    activation_registry_rejects_value,
    /// Read the activation administrator from storage, falling back to chain configuration.
    stateful_activation_admin,
    /// Install the transaction-context precompile backed by transient storage.
    transaction_context_precompile,
    /// Install the native two-dimensional nonce manager precompile.
    nonce_manager_precompile,
    /// Use the third B20 asset contract implementation.
    asset_precompile_v3,
    /// Use the third B20 stablecoin contract implementation.
    stablecoin_precompile_v3,
    /// Use the third B20 policy contract implementation.
    policy_precompile_v3,
    /// Use deterministic 200ms block timestamps and the Base time predeploy, scale legacy
    /// whole-second gas parameters, and retain the parent's L1 origin within the same second.
    subsecond_blocks,
    /// Use the extended six-hour sequencer drift bound.
    extended_sequencer_drift,
    /// Build and finalize payloads once instead of replacing them for higher fees.
    one_shot_payload_building,
    /// Reject span batches and encode only singular batches for subsecond blocks.
    singular_batches_only,
    /// Execute enshrined EIP-8130 account-abstraction transactions.
    eip8130,
    /// Expose EIP-8430 payer resolution RPC methods.
    eip8430,
    /// Plant a nonempty code stub on the native nonce manager to preserve its persistent state.
    native_nonce_manager,
    /// Bill transactions for their full gas limit rather than only the gas they use.
    gas_limit_billing,
    /// Enable experimental EIP-8130 keystore support on genesis-configured chains only.
    keystore,

    pub const count = std.enums.values(BaseFeature).len;

    /// The network upgrade that introduces this behavior.
    pub fn activation_upgrade(feature: BaseFeature) Upgrade {
        return activation_table[@backingInt(feature)];
    }

    /// Evaluates related features with one `is_active` read per distinct upgrade: features
    /// sharing an upgrade share its first observed state, in feature order. Use only where
    /// behavior previously shared one gate.
    pub fn activation_states(
        comptime n: usize,
        features: [n]BaseFeature,
        context: anytype,
        comptime is_active: fn (@TypeOf(context), BaseFeature) bool,
    ) [n]bool {
        comptime assert(n <= count);
        var active: [n]bool = @splat(false);
        for (features, 0..) |feature, index| {
            const upgrade = feature.activation_upgrade();
            const previous = for (features[0..index], 0..) |other, other_index| {
                if (other.activation_upgrade() == upgrade) break other_index;
            } else null;
            active[index] = if (previous) |shared| active[shared] else is_active(context, feature);
        }
        return active;
    }
};

const activation_table = [BaseFeature.count]Upgrade{
    .bedrock, // monotonic_block_timestamps
    .regolith, // deposit_gas_accounting
    .regolith, // deposit_nonce
    .regolith, // actual_l1_signature_bytes
    .canyon, // deposit_receipt_version
    .canyon, // create2_deployer
    .canyon, // withdrawals
    .canyon, // base_fee_denominator
    .canyon, // ready_channel_selection
    .canyon, // gossip_payload_v2
    .delta, // span_batches
    .ecotone, // blob_aware_l1_fees
    .ecotone, // blob_header
    .ecotone, // beacon_roots
    .ecotone, // constant_blob_base_fee
    .ecotone, // blob_data_source
    .ecotone, // engine_api_v3
    .ecotone, // ecotone_upgrade_transactions
    .ecotone, // gossip_payload_v3
    .fjord, // fast_lz_l1_fees
    .fjord, // rip7212_precompile
    .fjord, // fixed_sequencer_drift
    .fjord, // large_channels
    .fjord, // brotli_compression
    .fjord, // channel_bank_size_expansion
    .fjord, // fjord_upgrade_transactions
    .granite, // bn254_pairing_input_limit
    .granite, // short_channel_timeout
    .granite, // granite_transition_no_tx_pool
    .holocene, // dynamic_base_fee_parameters
    .holocene, // strict_derivation_ordering
    .holocene, // deposits_only_on_invalid_payload
    .holocene, // holocene_transition_no_tx_pool
    .pectra_blob_schedule, // blob_schedule_correction
    .isthmus, // operator_fee
    .isthmus, // bls_input_limits
    .isthmus, // eip7702
    .isthmus, // history_storage
    .isthmus, // l2_to_l1_message_root
    .isthmus, // empty_requests_hash
    .isthmus, // engine_api_v4
    .isthmus, // isthmus_upgrade_transactions
    .isthmus, // gossip_payload_v4
    .isthmus, // strict_proof_source_exhaustion
    .jovian, // scaled_operator_fees
    .jovian, // da_footprint
    .jovian, // da_aware_base_fee
    .jovian, // tight_bn254_pairing_input_limit
    .jovian, // tight_bls_input_limits
    .jovian, // min_base_fee
    .jovian, // jovian_upgrade_transactions
    .azul, // repriced_p256_precompile
    .azul, // transaction_gas_limit_cap
    .azul, // engine_api_v5
    .beryl, // token_precompiles
    .beryl, // activation_registry
    .beryl, // asset_precompile
    .beryl, // stablecoin_precompile
    .beryl, // policy_precompile
    .beryl, // token_factory_precompile
    .cobalt, // asset_precompile_v2
    .cobalt, // stablecoin_precompile_v2
    .cobalt, // policy_precompile_v2
    .cobalt, // dynamic_storage_tail_cleanup
    .cobalt, // compact_abi_decode_errors
    .cobalt, // activation_registry_rejects_value
    .cobalt, // stateful_activation_admin
    .cobalt, // transaction_context_precompile
    .cobalt, // nonce_manager_precompile
    .denim, // asset_precompile_v3
    .denim, // stablecoin_precompile_v3
    .denim, // policy_precompile_v3
    .denim, // subsecond_blocks
    .denim, // extended_sequencer_drift
    .denim, // one_shot_payload_building
    .denim, // singular_batches_only
    .everest, // eip8130
    .everest, // eip8430
    .everest, // native_nonce_manager
    .everest, // gas_limit_billing
    .zenith, // keystore
};

comptime {
    assert(BaseFeature.count == 81);
    assert(Upgrade.count == 17);
    // The registry is grouped by upgrade in activation order.
    for (activation_table[1..], activation_table[0 .. activation_table.len - 1]) |next, prior| {
        assert(@backingInt(next) >= @backingInt(prior));
    }
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

const LiveState = struct {
    state: bool,
    initial: bool,

    fn read(live: *LiveState, _: BaseFeature) bool {
        const observed = live.state;
        live.state = !live.initial;
        return observed;
    }
};

test "feature: related features share activation state, distinct upgrades do not" {
    for ([_]bool{ false, true }) |initial| {
        var live: LiveState = .{ .state = initial, .initial = initial };
        const states = BaseFeature.activation_states(3, .{
            .deposit_gas_accounting,
            .withdrawals,
            .deposit_nonce,
        }, &live, LiveState.read);
        try testing.expectEqual([3]bool{ initial, !initial, initial }, states);
    }
}

test "feature: activation upgrades match base/base" {
    try testing.expectEqual(Upgrade.bedrock, BaseFeature.monotonic_block_timestamps
        .activation_upgrade());
    try testing.expectEqual(Upgrade.fjord, BaseFeature.fast_lz_l1_fees.activation_upgrade());
    try testing.expectEqual(Upgrade.isthmus, BaseFeature.eip7702.activation_upgrade());
    try testing.expectEqual(Upgrade.everest, BaseFeature.eip8130.activation_upgrade());
    try testing.expectEqual(Upgrade.zenith, BaseFeature.keystore.activation_upgrade());
    try testing.expect(Upgrade.latest.is_feature_enabled(.token_precompiles));
    try testing.expect(!Upgrade.latest.is_feature_enabled(.nonce_manager_precompile));
    try testing.expectEqual(Upgrade.cobalt, Upgrade.from_base(.cobalt));
}

test "feature: seeded fuzz ordinal semantics" {
    var prng = Prng.init(0xfea7);
    for (0..1_000) |_| {
        const upgrade: Upgrade = @fromBackingInt(@intCast(prng.below(Upgrade.count)));
        const feature: BaseFeature = @fromBackingInt(@intCast(prng.below(BaseFeature.count)));
        const enabled = upgrade.is_feature_enabled(feature);
        const activation = feature.activation_upgrade();
        try testing.expectEqual(@backingInt(activation) <= @backingInt(upgrade), enabled);
        try testing.expect(activation.is_feature_enabled(feature));
        if (activation != .bedrock) {
            const prior: Upgrade = @fromBackingInt(@intCast(@backingInt(activation) - 1));
            try testing.expect(!prior.is_feature_enabled(feature));
        }
    }
}
