//! The registrar's injected world (base/base `TEEProverRegistryClient`, `CertManagerClient`,
//! `TxManager`, tokio time and `CancellationToken`). Vtables keep `SignerManager` and the
//! driver deterministic state machines: tests and the simulation use in-memory fakes, the
//! binary uses the `rpc_l1.zig` adapters over `proof/rpc` and `proof/submission`.
//!
//! - `Chain`: synchronous `eth_call` reads of `TEEProverRegistry` and `CertManager`.
//! - `Transactor`: sends one transaction and blocks until its receipt or a failure.
//! - `Clock`: Unix time for attestation freshness and certificate expiry, and retry sleeps.
//! - `Cancel`: the cooperative shutdown flag checked between steps.

const std = @import("std");
const assert = std.debug.assert;

const types = @import("types.zig");

pub const Address = types.Address;
pub const Hash = types.Hash;

/// A read failed (transport, malformed answer). The caller retries next cycle.
pub const ReadError = error{ContractCall};
/// A warm-validation `eth_call` failed: a revert is distinguished from transport.
pub const CallError = error{ ContractCall, ContractReverted };

/// The `CertManager` cache metadata the registrar acts on (`loadVerified` and
/// `verifyClientCertWithHints` return values).
pub const CachedCert = struct {
    ca: bool,
    not_after: u64,
    /// An empty public key means the certificate is not cached.
    has_public_key: bool,
};

pub const Chain = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        is_registered_signer: *const fn (*anyopaque, Address) ReadError!bool,
        /// Fills `out` with `getRegisteredSigners()`.
        registered_signers: *const fn (*anyopaque, []Address) ReadError![]Address,
        load_verified: *const fn (*anyopaque, Hash) ReadError!CachedCert,
        is_revoked: *const fn (*anyopaque, Hash) ReadError!bool,
        /// `verifyCACertWithHints` as an `eth_call`: the returned cache key.
        verify_ca_cert: *const fn (*anyopaque, []const u8, Hash, []const u8) CallError!Hash,
        /// `verifyClientCertWithHints` as an `eth_call`.
        verify_client_cert: *const fn (
            *anyopaque,
            []const u8,
            Hash,
            []const u8,
        ) CallError!CachedCert,
    };

    pub fn is_registered_signer(chain: Chain, signer: Address) ReadError!bool {
        return chain.vtable.is_registered_signer(chain.context, signer);
    }

    pub fn registered_signers(chain: Chain, out: []Address) ReadError![]Address {
        assert(out.len > 0);
        const signers = try chain.vtable.registered_signers(chain.context, out);
        assert(signers.len <= out.len);
        return signers;
    }

    pub fn load_verified(chain: Chain, cert_hash: Hash) ReadError!CachedCert {
        return chain.vtable.load_verified(chain.context, cert_hash);
    }

    pub fn is_revoked(chain: Chain, cert_id: Hash) ReadError!bool {
        return chain.vtable.is_revoked(chain.context, cert_id);
    }

    pub fn verify_ca_cert(chain: Chain, cert: []const u8, parent: Hash) CallError!Hash {
        assert(cert.len > 0);
        return chain.vtable.verify_ca_cert(chain.context, cert, parent, "");
    }

    pub fn verify_client_cert(chain: Chain, cert: []const u8, parent: Hash) CallError!CachedCert {
        assert(cert.len > 0);
        return chain.vtable.verify_client_cert(chain.context, cert, parent, "");
    }
};

/// What a sent transaction did (base/base `SendResponse`).
pub const TxOutcome = union(enum) {
    /// Mined with a successful receipt.
    succeeded,
    /// Mined with a failed receipt.
    reverted,
    /// Never confirmed: estimation revert, broadcast or transport failure, dropped.
    /// `retryable` mirrors base/base `TxManagerError::is_retryable`.
    failed: struct { retryable: bool },
};

pub const Transactor = struct {
    context: *anyopaque,
    send_fn: *const fn (*anyopaque, Address, []const u8) TxOutcome,

    /// Sends `calldata` to `to` without value and waits for the outcome.
    pub fn send(transactor: Transactor, to: Address, calldata: []const u8) TxOutcome {
        assert(calldata.len >= 4);
        assert(!std.mem.allEqual(u8, &to, 0));
        return transactor.send_fn(transactor.context, to, calldata);
    }
};

/// Cooperative cancellation (base/base `CancellationToken`): set on shutdown, read between
/// steps. A read already in flight completes; its result is discarded.
pub const Cancel = struct {
    requested: bool = false,

    pub fn is_cancelled(cancel: *const Cancel) bool {
        return cancel.requested;
    }

    pub fn request(cancel: *Cancel) void {
        cancel.requested = true;
        assert(cancel.is_cancelled());
    }
};

pub const Clock = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        now_unix_ms: *const fn (*anyopaque) u64,
        /// Sleeps `ms`; false when `cancel` was requested before or during the sleep.
        sleep_ms: *const fn (*anyopaque, u64, *const Cancel) bool,
    };

    pub fn now_unix_ms(clock: Clock) u64 {
        const now_ms = clock.vtable.now_unix_ms(clock.context);
        assert(now_ms > 0);
        return now_ms;
    }

    pub fn sleep_ms(clock: Clock, ms: u64, cancel: *const Cancel) bool {
        assert(ms > 0);
        if (cancel.is_cancelled()) return false;
        return clock.vtable.sleep_ms(clock.context, ms, cancel);
    }
};

test "registrar l1: cancel and clock wrappers" {
    const Fake = struct {
        now_ms: u64 = 1_000,
        fn now(context: *anyopaque) u64 {
            const fake: *@This() = @ptrCast(@alignCast(context));
            return fake.now_ms;
        }
        fn sleep(context: *anyopaque, ms: u64, cancel: *const Cancel) bool {
            const fake: *@This() = @ptrCast(@alignCast(context));
            fake.now_ms += ms;
            return !cancel.is_cancelled();
        }
        const vtable: Clock.VTable = .{ .now_unix_ms = now, .sleep_ms = sleep };
    };
    var fake: Fake = .{};
    const clock: Clock = .{ .context = &fake, .vtable = &Fake.vtable };
    var cancel: Cancel = .{};
    try std.testing.expect(clock.sleep_ms(500, &cancel));
    try std.testing.expectEqual(@as(u64, 1_500), clock.now_unix_ms());
    cancel.request();
    try std.testing.expect(!clock.sleep_ms(500, &cancel));
    try std.testing.expectEqual(@as(u64, 1_500), clock.now_unix_ms());
}
