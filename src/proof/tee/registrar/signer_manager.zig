//! Signer lifecycle orchestration (base/base `registrar/src/signer_manager.rs`): validates
//! and authenticates a registration plan, checks onchain revocations and AWS CRLs, warms
//! or caches every certificate through `CertManager` with P-384 inverse hints, registers
//! the signer, and deregisters revoked and orphaned signers. Transactions retry with
//! exponential backoff, bounded by `max_tx_retries`.
//!
//! base/base runs registrations as concurrent tokio tasks with a hint-generation semaphore
//! and per-certificate async locks. Here the driver runs one registration at a time, so a
//! certificate shared by two signers is cached by the first and warm for the second; no
//! lock is needed. All buffers (TBS, hint streams, calldata, CRL bodies) are allocated once
//! in `init`. Reads, sends, time and sleeps go through `l1.zig`.

const std = @import("std");
const assert = std.debug.assert;

const types = @import("types.zig");
const planner = @import("planner.zig");
const hints_module = @import("hints.zig");
const crl = @import("crl.zig");
const l1 = @import("l1.zig");
const metrics = @import("metrics.zig");
const reconciler = @import("reconciler.zig");
const registry_abi = @import("../../contracts/tee_prover_registry.zig");
const cert_manager_abi = @import("../../contracts/cert_manager.zig");
const keccak256 = @import("../../../common/crypto/keccak.zig").keccak256;

const Address = types.Address;
const Hash = types.Hash;
const CertPlan = types.CertPlan;
const RegistrationPlan = types.RegistrationPlan;
const RegistrationHints = types.RegistrationHints;
const Cancel = l1.Cancel;

pub const default_max_tx_retries: u32 = 3;
pub const default_tx_retry_delay_ms: u64 = 5_000;
const tx_retry_backoff_ms_max: u64 = 60_000;
const attestation_nonce_domain = "base-proof-tee-registrar:attestation-nonce:v1";
const debug_mode_pcr0_hash =
    hex32("c980e59163ce244bb4bb6211f48c7b46f88a4f40943e84eb99bdc41e129bd293");

/// `registerSigner(bytes tbs, bytes signature, bytes hints)`: selector, three head words,
/// three length words, and each argument padded to a word.
pub const calldata_size_max: u32 = 4 + 6 * 32 + (planner.tbs_size_max + 31) +
    (96 + 31) + types.hint_stream_size_max;

comptime {
    assert(calldata_size_max > types.hint_stream_size_max + planner.attestation_size_max);
    assert(attestation_nonce_domain.len + 2 * 20 < 128);
}

pub const Error = error{
    /// The plan does not authenticate the expected signer, nonce, PCR0 or chain layout.
    InvalidAttestationProof,
    StaleAttestationProof,
    FutureAttestationProof,
    ExpiredCertificate,
    RevokedCertificate,
    /// A registration or deregistration was mined but reverted.
    ReceiptReverted,
    /// A certificate cache transaction was mined but reverted.
    CertificateCacheReverted,
    /// A transaction was never confirmed (permanent failure or retries exhausted).
    TransactionFailed,
    /// An L1 read failed.
    ContractCall,
    CalldataTooLarge,
} || planner.Error || hints_module.Error || crl.CrlError;

pub const Config = struct {
    registry_address: Address,
    cert_manager_address: Address,
    max_tx_retries: u32 = default_max_tx_retries,
    tx_retry_delay_ms: u64 = default_tx_retry_delay_ms,
    /// Maximum attestation age accepted before onchain submission (whole seconds, as
    /// base/base compares `Duration::as_secs`).
    max_attestation_age_s: u64,
    /// Enables fail-closed CRL checks and issuer/serial revocation transactions.
    crl_fetcher: ?crl.CrlFetcher = null,
    /// Tests only (asserted): accept an attestation whose nonce is `null`. The only public
    /// Nitro fixture encodes `nonce: null`, and nonces cannot be re-signed without an enclave.
    accept_null_nonce_for_tests: bool = false,
};

pub const World = struct {
    chain: l1.Chain,
    transactor: l1.Transactor,
    clock: l1.Clock,
};

/// What one certificate-cache transaction attempt did onchain; each maps to exactly one
/// terminal `cert_cache_tx` outcome.
pub const CacheTxAttempt = union(enum) {
    cached,
    observed_cached,
    cancelled,
    reverted: Error,
    failed: Error,
    retry,

    pub fn outcome(attempt: CacheTxAttempt) metrics.CacheTxOutcome {
        return switch (attempt) {
            .cached => .succeeded,
            .observed_cached => .observed_cached,
            .cancelled => .cancelled,
            .reverted => .reverted,
            .failed => .failed,
            .retry => .retry,
        };
    }
};

const Buffers = struct {
    tbs: [planner.tbs_size_max]u8,
    scratch: planner.AuthenticateScratch,
    hints: RegistrationHints,
    calldata: [calldata_size_max]u8,
    registered: [registry_abi.registered_signers_max]Address,
};

pub const SignerManager = struct {
    config: Config,
    world: World,
    stats: *metrics.Stats,
    buffers: *Buffers,
    /// CRL response buffer; empty without a fetcher.
    crl_body: []u8,

    pub fn init(
        allocator: std.mem.Allocator,
        config: Config,
        world: World,
        stats: *metrics.Stats,
    ) !SignerManager {
        assert(!std.mem.allEqual(u8, &config.registry_address, 0));
        assert(!std.mem.allEqual(u8, &config.cert_manager_address, 0));
        assert(config.tx_retry_delay_ms > 0);
        assert(config.max_attestation_age_s > 0);
        assert(!config.accept_null_nonce_for_tests or @import("builtin").is_test);
        const buffers = try allocator.create(Buffers);
        errdefer allocator.destroy(buffers);
        const crl_size: usize = if (config.crl_fetcher == null) 0 else crl.crl_response_size_max;
        const crl_body = try allocator.alloc(u8, crl_size);
        return .{
            .config = config,
            .world = world,
            .stats = stats,
            .buffers = buffers,
            .crl_body = crl_body,
        };
    }

    pub fn deinit(manager: *SignerManager, allocator: std.mem.Allocator) void {
        allocator.free(manager.crl_body);
        allocator.destroy(manager.buffers);
        manager.* = undefined;
    }

    /// The deterministic attestation nonce for a signer.
    pub fn attestation_nonce(manager: *const SignerManager, signer: Address) Hash {
        return attestation_nonce_for(manager.config.registry_address, signer);
    }

    /// `keccak256(domain ‖ registry ‖ signer)`.
    pub fn attestation_nonce_for(registry_address: Address, signer: Address) Hash {
        var input: [attestation_nonce_domain.len + 40]u8 = undefined;
        @memcpy(input[0..attestation_nonce_domain.len], attestation_nonce_domain);
        input[attestation_nonce_domain.len..][0..20].* = registry_address;
        input[attestation_nonce_domain.len + 20 ..][0..20].* = signer;
        const nonce = keccak256(&input);
        assert(!std.mem.allEqual(u8, &nonce, 0));
        return nonce;
    }

    /// `delay · 2^(retry-1)`, capped at max(60 s, delay).
    pub fn retry_delay_ms(manager: *const SignerManager, retry: u32) u64 {
        assert(retry >= 1);
        const delay_ms = manager.config.tx_retry_delay_ms;
        const shift: u6 = @intCast(@min(retry - 1, 63));
        const scaled_ms = delay_ms *| (@as(u64, 1) << shift);
        const result = @min(scaled_ms, @max(tx_retry_backoff_ms_max, delay_ms));
        assert(result >= delay_ms);
        return result;
    }

    pub fn validate_plan(
        manager: *const SignerManager,
        expected_signer: Address,
        plan: *const RegistrationPlan,
    ) Error!void {
        assert(plan.cert_count <= types.cert_plan_count_max);
        if (!std.mem.eql(u8, &plan.signer, &expected_signer)) return error.InvalidAttestationProof;
        try manager.validate_nonce(expected_signer, plan.nonce);
        if (std.mem.eql(u8, &keccak256(&plan.pcr0), &debug_mode_pcr0_hash)) {
            return error.InvalidAttestationProof;
        }
        const pinned = &planner.pinned_root_cert_hash;
        if (!std.mem.eql(u8, &plan.root_cert_hash, pinned) or
            !std.mem.eql(u8, &keccak256(plan.root_cert), pinned))
        {
            return error.InvalidAttestationProof;
        }
        const certs = plan.cert_plans();
        if (certs.len == 0 or certs[certs.len - 1].kind != .leaf) {
            return error.InvalidAttestationProof;
        }
        var parent_hash = plan.root_cert_hash;
        for (certs, 0..) |*cert, index| {
            if (index + 1 < certs.len and cert.kind != .ca) return error.InvalidAttestationProof;
            if (!std.mem.eql(u8, &cert.parent_cert_hash, &parent_hash)) {
                return error.InvalidAttestationProof;
            }
            parent_hash = cert.cert_hash;
        }
        if (!std.mem.eql(u8, &plan.leaf_cert_hash, &parent_hash)) {
            return error.InvalidAttestationProof;
        }
        try manager.ensure_attestation_fresh(plan.timestamp_ms);
    }

    fn validate_nonce(
        manager: *const SignerManager,
        signer: Address,
        nonce: ?[]const u8,
    ) Error!void {
        const actual = nonce orelse {
            if (manager.config.accept_null_nonce_for_tests) return;
            return error.InvalidAttestationProof;
        };
        const expected = manager.attestation_nonce(signer);
        if (!std.mem.eql(u8, actual, &expected)) return error.InvalidAttestationProof;
        assert(actual.len == expected.len);
    }

    /// A same-second attestation is valid: the transaction executes in a later block, and
    /// the registry stays the authority on its block-timestamp boundary.
    pub fn ensure_attestation_fresh(manager: *const SignerManager, timestamp_ms: u64) Error!void {
        const now_s = manager.world.clock.now_unix_ms() / std.time.ms_per_s;
        const timestamp_s = timestamp_ms / std.time.ms_per_s;
        if (timestamp_s > now_s) return error.FutureAttestationProof;
        if (timestamp_s +| manager.config.max_attestation_age_s <= now_s) {
            return error.StaleAttestationProof;
        }
        assert(timestamp_s <= now_s);
    }

    /// Registers `signer` from a raw attestation unless it is already registered. Returns
    /// without error when cancelled.
    pub fn register_signer(
        manager: *SignerManager,
        signer: Address,
        attestation: []const u8,
        cancel: *const Cancel,
    ) Error!void {
        assert(attestation.len > 0);
        const plan = try planner.AttestationPlanner.prepare_registration_plan(
            attestation,
            &manager.buffers.tbs,
        );
        return manager.register_plan(signer, &plan, null, cancel);
    }

    /// Registers from a prepared plan; `prepared_hints` skips hint generation (tests).
    pub fn register_plan(
        manager: *SignerManager,
        signer: Address,
        plan: *const RegistrationPlan,
        prepared_hints: ?*const RegistrationHints,
        cancel: *const Cancel,
    ) Error!void {
        manager.register_plan_attempt(signer, plan, prepared_hints, cancel) catch |err| {
            // The freshness check also runs on the CRL revocation path, which swallows its
            // error per certificate, so classify the terminal error here.
            if (err == error.StaleAttestationProof) manager.stats.record_stage(.proof_stale);
            return err;
        };
    }

    fn register_plan_attempt(
        manager: *SignerManager,
        signer: Address,
        plan: *const RegistrationPlan,
        prepared_hints: ?*const RegistrationHints,
        cancel: *const Cancel,
    ) Error!void {
        try manager.validate_plan(signer, plan);
        if (cancel.is_cancelled()) return;
        // Revocation monitoring stays active for registered signers: persisting a newly
        // observed CRL entry protects every registration sharing the chain.
        if (!try manager.check_revocations(plan, cancel)) return;
        if (!try manager.check_crls(plan, cancel)) return;
        const registered = (try manager.read_registered(signer, cancel)) orelse return;
        if (registered) {
            manager.stats.record_stage(.already_registered);
            return;
        }
        if (!try manager.validate_root_cache(plan, cancel)) return;
        if (!try manager.authenticate_plan(plan, cancel)) return;
        const hints = prepared_hints orelse
            (try manager.generate_hints(plan, cancel)) orelse return;
        if (hints.cert_count != plan.cert_count) return error.InvalidAttestationProof;
        for (plan.cert_plans(), hints.cert_streams()) |*cert, *stream| {
            const kind: metrics.HintKind = if (cert.kind == .ca) .ca else .leaf;
            manager.stats.record_hint_size(kind, stream.length);
        }
        manager.stats.record_hint_size(.attestation, hints.attestation_hints.length);
        for (plan.cert_plans(), hints.cert_streams()) |*cert, *stream| {
            const cached = try manager.ensure_cert_cached(
                cert,
                stream.slice(),
                plan.timestamp_ms,
                cancel,
            );
            if (!cached) return;
        }
        return manager.submit_registration(signer, plan, hints, cancel);
    }

    fn generate_hints(
        manager: *SignerManager,
        plan: *const RegistrationPlan,
        cancel: *const Cancel,
    ) Error!?*const RegistrationHints {
        manager.stats.record_stage(.proof_started);
        if (cancel.is_cancelled()) {
            manager.stats.record_stage(.proof_cancelled);
            return null;
        }
        const out = &manager.buffers.hints;
        hints_module.P384Hints.for_registration_plan(plan.root_cert, plan, out) catch |err| {
            manager.stats.record_stage(.proof_failed);
            return err;
        };
        manager.stats.record_stage(.proof_succeeded);
        assert(out.cert_count == plan.cert_count);
        return out;
    }

    /// Re-derives every plan field from the signed attestation and the pinned chain.
    fn authenticate_plan(
        manager: *SignerManager,
        plan: *const RegistrationPlan,
        cancel: *const Cancel,
    ) Error!bool {
        if (cancel.is_cancelled()) return false;
        try planner.AttestationPlanner.authenticate_registration_plan(
            plan,
            &manager.buffers.scratch,
        );
        return !cancel.is_cancelled();
    }

    fn read_registered(
        manager: *SignerManager,
        signer: Address,
        cancel: *const Cancel,
    ) Error!?bool {
        if (cancel.is_cancelled()) return null;
        const registered = try manager.world.chain.is_registered_signer(signer);
        if (cancel.is_cancelled()) return null;
        return registered;
    }

    fn read_revoked(manager: *SignerManager, cert_id: Hash, cancel: *const Cancel) Error!?bool {
        if (cancel.is_cancelled()) return null;
        const revoked = try manager.world.chain.is_revoked(cert_id);
        if (cancel.is_cancelled()) return null;
        return revoked;
    }

    pub fn check_revocations(
        manager: *SignerManager,
        plan: *const RegistrationPlan,
        cancel: *const Cancel,
    ) Error!bool {
        assert(plan.cert_count <= types.cert_plan_count_max);
        var index: u32 = 0;
        while (index <= plan.cert_count) : (index += 1) {
            const cert_id = if (index == 0)
                plan.root_cert_hash
            else
                plan.certs[index - 1].revocation_id;
            manager.stats.onchain_revocation_checks += 1;
            const revoked = (try manager.read_revoked(cert_id, cancel)) orelse return false;
            if (!revoked) continue;
            manager.stats.onchain_revocations_detected += 1;
            if (!try manager.authenticate_plan(plan, cancel)) return false;
            manager.deregister_revoked_signer(plan.signer, cancel);
            return error.RevokedCertificate;
        }
        return true;
    }

    fn validate_root_cache(
        manager: *SignerManager,
        plan: *const RegistrationPlan,
        cancel: *const Cancel,
    ) Error!bool {
        const root: CertPlan = .{
            .kind = .ca,
            .label = types.Label.init("pinned root certificate") catch unreachable, // 23 bytes.
            .cert = plan.root_cert,
            .cert_hash = plan.root_cert_hash,
            .parent_cert_hash = @splat(0),
            .revocation_id = plan.root_cert_hash,
        };
        const cached = (try manager.validate_cached_cert(&root, cancel)) orelse return false;
        if (!cached) return error.InvalidAttestationProof;
        return true;
    }

    pub fn check_crls(
        manager: *SignerManager,
        plan: *const RegistrationPlan,
        cancel: *const Cancel,
    ) Error!bool {
        const fetcher = manager.config.crl_fetcher orelse return true;
        assert(manager.crl_body.len == crl.crl_response_size_max);
        manager.stats.crl_checks += 1;
        var infos_buffer: [types.cert_plan_count_max]crl.CertCrlInfo = undefined;
        const infos = crl.CertCrlInfo.from_cert_plans(plan.cert_plans(), &infos_buffer) catch |err|
            {
                manager.stats.record_crl_outcome(.indeterminate);
                return err;
            };
        if (cancel.is_cancelled()) return false;
        const result = crl.check_chain_against_crls(infos, fetcher, manager.crl_body);
        if (cancel.is_cancelled()) return false;
        if (result.error_count > 0) manager.stats.record_crl_outcome(.indeterminate);
        if (result.is_clean()) {
            manager.stats.record_crl_outcome(.clean);
            return true;
        }
        if (result.revoked_count == 0) return result.errors[0].err;
        manager.stats.record_crl_outcome(.revoked);
        manager.stats.crl_revocations_detected += result.revoked_count;
        if (!try manager.authenticate_plan(plan, cancel)) return false;
        for (result.revoked[0..result.revoked_count]) |info_index| {
            const cert_id = infos[info_index].revocation_id;
            manager.submit_revocation(cert_id, plan.timestamp_ms, cancel) catch {
                manager.stats.revoke_cert_tx_failures += 1;
            };
        }
        manager.deregister_revoked_signer(plan.signer, cancel);
        return error.RevokedCertificate;
    }

    /// Attempts deregistration after a confirmed revocation, counting failures.
    pub fn deregister_revoked_signer(
        manager: *SignerManager,
        signer: Address,
        cancel: *const Cancel,
    ) void {
        manager.submit_deregistration(signer, cancel) catch {
            manager.stats.processing_errors += 1;
        };
    }

    fn encode_deregister(manager: *SignerManager, signer: Address) []const u8 {
        const calldata = registry_abi.encode_signer_call(
            &manager.buffers.calldata,
            registry_abi.deregister_signer,
            signer,
        ) catch unreachable; // 36 bytes fit the calldata buffer.
        assert(calldata.len == 36);
        return calldata;
    }

    /// Deregisters a registered signer with bounded retries and cooperative cancellation.
    pub fn submit_deregistration(
        manager: *SignerManager,
        signer: Address,
        cancel: *const Cancel,
    ) Error!void {
        const registered = (try manager.read_registered(signer, cancel)) orelse return;
        if (!registered) return;
        const calldata = manager.encode_deregister(signer);
        const registry = manager.config.registry_address;
        var retry: u32 = 0;
        while (retry <= manager.config.max_tx_retries) : (retry += 1) {
            if (cancel.is_cancelled()) return;
            // Once sent, the transactor tracks the transaction even if cancelled.
            const outcome = manager.world.transactor.send(registry, calldata);
            if (outcome == .succeeded) {
                manager.stats.deregistrations += 1;
                return;
            }
            if (cancel.is_cancelled()) return;
            const observed = manager.world.chain.is_registered_signer(signer) catch null;
            if (cancel.is_cancelled()) return;
            if (observed == false) {
                manager.stats.deregistrations += 1;
                return;
            }
            switch (outcome) {
                .succeeded => unreachable, // Returned above.
                .reverted => return error.ReceiptReverted,
                .failed => |failure| {
                    if (!failure.retryable or retry == manager.config.max_tx_retries) {
                        return error.TransactionFailed;
                    }
                    if (!manager.sleep_before_retry(retry + 1, cancel)) return;
                },
            }
        }
        unreachable; // Every iteration with retry == max_tx_retries returns.
    }

    fn submit_revocation(
        manager: *SignerManager,
        cert_id: Hash,
        timestamp_ms: u64,
        cancel: *const Cancel,
    ) Error!void {
        const calldata = cert_manager_abi.encode_hash_call(
            &manager.buffers.calldata,
            cert_manager_abi.revoke_cert,
            cert_id,
        ) catch unreachable; // 36 bytes fit the calldata buffer.
        const cert_manager = manager.config.cert_manager_address;
        var retry: u32 = 0;
        while (retry <= manager.config.max_tx_retries) : (retry += 1) {
            if (cancel.is_cancelled()) return;
            try manager.ensure_attestation_fresh(timestamp_ms);
            const outcome = manager.world.transactor.send(cert_manager, calldata);
            const observed = (manager.read_revoked(cert_id, cancel) catch null) orelse false;
            if (observed) {
                manager.stats.revoke_cert_success += 1;
                return;
            }
            switch (outcome) {
                // Succeeded without setting revocation state.
                .succeeded => return error.InvalidAttestationProof,
                .reverted => {
                    manager.stats.revoke_cert_reverted += 1;
                    return error.ReceiptReverted;
                },
                .failed => |failure| {
                    if (!failure.retryable or retry == manager.config.max_tx_retries) {
                        return error.TransactionFailed;
                    }
                    if (!manager.sleep_before_retry(retry + 1, cancel)) return;
                },
            }
        }
        unreachable; // Every iteration with retry == max_tx_retries returns.
    }

    /// Ensures `cert` is cached and usable; false when cancelled.
    pub fn ensure_cert_cached(
        manager: *SignerManager,
        cert: *const CertPlan,
        signature_hints: []const u8,
        timestamp_ms: u64,
        cancel: *const Cancel,
    ) Error!bool {
        const cached = (try manager.validate_cached_cert(cert, cancel)) orelse return false;
        manager.stats.record_cache_lookup(cert.kind, cached);
        if (cached) return true;
        const function = switch (cert.kind) {
            .ca => cert_manager_abi.verify_ca_cert_with_hints,
            .leaf => cert_manager_abi.verify_client_cert_with_hints,
        };
        const calldata = cert_manager_abi.encode_verify(
            &manager.buffers.calldata,
            function,
            cert.cert,
            cert.parent_cert_hash,
            signature_hints,
        ) catch return error.CalldataTooLarge;
        var retry: u32 = 0;
        while (retry <= manager.config.max_tx_retries) : (retry += 1) {
            if (cancel.is_cancelled()) return false;
            try manager.ensure_attestation_fresh(timestamp_ms);
            manager.stats.record_cache_tx(cert.kind, .submitted);
            const attempt = manager.cache_tx_attempt(cert, calldata, retry, cancel);
            manager.stats.record_cache_tx(cert.kind, attempt.outcome());
            switch (attempt) {
                .cached, .observed_cached => return true,
                .cancelled => return false,
                .reverted, .failed => |err| return err,
                .retry => if (!manager.sleep_before_retry(retry + 1, cancel)) return false,
            }
        }
        unreachable; // `cache_tx_attempt` never retries the last attempt.
    }

    /// Sends one certificate-cache transaction and classifies what it did onchain.
    pub fn cache_tx_attempt(
        manager: *SignerManager,
        cert: *const CertPlan,
        calldata: []const u8,
        retry: u32,
        cancel: *const Cancel,
    ) CacheTxAttempt {
        assert(retry <= manager.config.max_tx_retries);
        const cert_manager = manager.config.cert_manager_address;
        const outcome = manager.world.transactor.send(cert_manager, calldata);
        var state_error: ?Error = null;
        if (manager.validate_cached_cert(cert, cancel)) |state| {
            const usable = state orelse return .cancelled;
            if (usable) return if (outcome == .succeeded) .cached else .observed_cached;
        } else |err| switch (err) {
            error.ExpiredCertificate,
            error.RevokedCertificate,
            error.InvalidAttestationProof,
            => return .{ .failed = err },
            else => state_error = err,
        }
        return switch (outcome) {
            .succeeded => .{ .failed = state_error orelse error.InvalidAttestationProof },
            .reverted => .{ .reverted = error.CertificateCacheReverted },
            .failed => |failure| if (failure.retryable and retry < manager.config.max_tx_retries)
                .retry
            else
                .{ .failed = error.TransactionFailed },
        };
    }

    /// Whether `cert` is cached, unrevoked, unexpired, of the right kind, and passes warm
    /// validation; null when cancelled.
    pub fn validate_cached_cert(
        manager: *SignerManager,
        cert: *const CertPlan,
        cancel: *const Cancel,
    ) Error!?bool {
        if (cancel.is_cancelled()) return null;
        const verified = try manager.world.chain.load_verified(cert.cert_hash);
        const revoked = (try manager.read_revoked(cert.revocation_id, cancel)) orelse return null;
        if (revoked) return error.RevokedCertificate;
        if (!verified.has_public_key) return false;
        const now_s = manager.world.clock.now_unix_ms() / std.time.ms_per_s;
        if (verified.not_after < now_s) return error.ExpiredCertificate;
        if (verified.ca != (cert.kind == .ca)) return error.InvalidAttestationProof;
        return manager.warm_validate(cert, cancel);
    }

    fn warm_validate(
        manager: *SignerManager,
        cert: *const CertPlan,
        cancel: *const Cancel,
    ) Error!?bool {
        if (cancel.is_cancelled()) return null;
        const chain = manager.world.chain;
        const consistent = switch (cert.kind) {
            .ca => if (chain.verify_ca_cert(cert.cert, cert.parent_cert_hash)) |hash|
                std.mem.eql(u8, &hash, &cert.cert_hash)
            else |err|
                return warm_error(err),
            .leaf => if (chain.verify_client_cert(cert.cert, cert.parent_cert_hash)) |returned|
                !returned.ca and returned.has_public_key
            else |err|
                return warm_error(err),
        };
        if (cancel.is_cancelled()) return null;
        if (!consistent) return error.InvalidAttestationProof;
        return true;
    }

    fn warm_error(err: l1.CallError) Error {
        return switch (err) {
            error.ContractReverted => error.InvalidAttestationProof,
            error.ContractCall => error.ContractCall,
        };
    }

    pub fn submit_registration(
        manager: *SignerManager,
        signer: Address,
        plan: *const RegistrationPlan,
        hints: *const RegistrationHints,
        cancel: *const Cancel,
    ) Error!void {
        const calldata = registry_abi.encode_register_signer(
            &manager.buffers.calldata,
            plan.attestation_tbs,
            &plan.signature,
            hints.attestation_hints.slice(),
        ) catch return error.CalldataTooLarge;
        var retry: u32 = 0;
        while (retry <= manager.config.max_tx_retries) : (retry += 1) {
            if (cancel.is_cancelled()) return;
            try manager.ensure_attestation_fresh(plan.timestamp_ms);
            const registered = (try manager.read_registered(signer, cancel)) orelse return;
            if (registered) {
                manager.stats.record_stage(.tx_observed_registered);
                return;
            }
            manager.stats.record_stage(.tx_submitted);
            const registry = manager.config.registry_address;
            const outcome = manager.world.transactor.send(registry, calldata);
            switch (outcome) {
                .succeeded => {
                    manager.stats.record_stage(.tx_succeeded);
                    manager.stats.registrations += 1;
                    return;
                },
                .reverted => {
                    if (manager.observed_registered(signer, cancel) != false) return;
                    manager.stats.record_stage(.tx_reverted);
                    return error.ReceiptReverted;
                },
                .failed => |failure| {
                    if (manager.observed_registered(signer, cancel) != false) return;
                    if (!failure.retryable or retry == manager.config.max_tx_retries) {
                        manager.stats.record_stage(.tx_failed);
                        return error.TransactionFailed;
                    }
                    manager.stats.record_stage(.tx_retry);
                    if (!manager.sleep_before_retry(retry + 1, cancel)) return;
                },
            }
        }
        unreachable; // Every iteration with retry == max_tx_retries returns.
    }

    /// Registration state after an ambiguous send; a failed read counts as unregistered,
    /// null when cancelled.
    fn observed_registered(manager: *SignerManager, signer: Address, cancel: *const Cancel) ?bool {
        if (cancel.is_cancelled()) return null;
        const registered = manager.world.chain.is_registered_signer(signer) catch return false;
        if (cancel.is_cancelled()) return null;
        if (registered) {
            manager.stats.record_stage(.tx_observed_registered);
            manager.stats.registrations += 1;
        }
        return registered;
    }

    fn sleep_before_retry(manager: *SignerManager, retry: u32, cancel: *const Cancel) bool {
        assert(retry >= 1 and retry <= manager.config.max_tx_retries);
        return manager.world.clock.sleep_ms(manager.retry_delay_ms(retry), cancel);
    }

    /// Reads the registered signers and deregisters every one not in `protected`.
    pub fn run_orphan_dereg(
        manager: *SignerManager,
        protected: *const reconciler.ProtectedSigners,
        cancel: *const Cancel,
    ) Error!void {
        if (cancel.is_cancelled()) return;
        const signers = try manager.world.chain.registered_signers(&manager.buffers.registered);
        if (cancel.is_cancelled()) return;
        for (signers) |signer| {
            if (cancel.is_cancelled()) break;
            if (protected.contains(&signer)) continue;
            const calldata = manager.encode_deregister(signer);
            switch (manager.world.transactor.send(manager.config.registry_address, calldata)) {
                .succeeded => manager.stats.deregistrations += 1,
                .reverted, .failed => manager.stats.processing_errors += 1,
            }
        }
        assert(signers.len <= registry_abi.registered_signers_max);
    }
};

fn hex32(comptime text: []const u8) Hash {
    var out: Hash = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable; // Literal constant.
    return out;
}

test {
    _ = @import("signer_manager_test.zig");
}
