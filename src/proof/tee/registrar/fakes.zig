//! In-memory registrar world for tests and the driver simulation (base/base
//! `signer_manager.rs` `MockChain`/`MockRegistry`/`MockCertManager`/`MockTxManager`): one
//! ordered state shared by contract reads and transaction writes, a settable Unix clock
//! whose sleeps advance time, and canned CRL responses. Transactions are decoded from
//! their ABI calldata and applied the way the contracts would.

const std = @import("std");
const assert = std.debug.assert;

const types = @import("types.zig");
const l1 = @import("l1.zig");
const crl = @import("crl.zig");
const cbor = @import("cbor.zig");
const abi = @import("../../contracts/abi.zig");
const registry_abi = @import("../../contracts/tee_prover_registry.zig");
const cert_manager_abi = @import("../../contracts/cert_manager.zig");
const keccak256 = @import("../../../common/crypto/keccak.zig").keccak256;

const Address = types.Address;
const Hash = types.Hash;
const CachedCert = l1.CachedCert;

pub const registry_address: Address = @splat(0x11);
pub const cert_manager_address: Address = @splat(0x22);
pub const fixture_attestation = @embedFile("../nitro/testdata/attestation.bin");
/// The fixture's attestation timestamp, Unix milliseconds.
pub const fixture_timestamp_ms: u64 = 0x000001937de1c543;

const specs_max = 48;
const sent_max = 128;
const outcomes_max = 16;

pub const Outcome = enum {
    success,
    error_retryable,
    error_permanent,
    apply_then_error,
    apply_then_revert,
};

pub const Spec = struct {
    cert: []const u8,
    hash: Hash,
    parent: Hash,
    revocation_id: Hash,
    kind: types.CertKind,
    verified: CachedCert,
};

const Cached = struct { hash: Hash, parent: Hash, verified: CachedCert };

pub const Sent = struct {
    to: Address,
    selector: [4]u8,
    digest: Hash,
};

pub const FakeL1 = struct {
    specs: [specs_max]Spec = undefined,
    spec_count: u32 = 0,
    cached: [specs_max]Cached = undefined,
    cached_count: u32 = 0,
    revoked: [specs_max]Hash = undefined,
    revoked_count: u32 = 0,
    registered: [32]Address = undefined,
    registered_count: u32 = 0,
    sent: [sent_max]Sent = undefined,
    sent_count: u32 = 0,
    outcomes: [outcomes_max]Outcome = undefined,
    outcome_count: u32 = 0,
    outcome_next: u32 = 0,
    /// The signer a successful `registerSigner` registers.
    final_signer: ?Address = null,
    cert_reads: u32 = 0,
    now_ms: u64,
    slept_ms: u64 = 0,
    /// Requests `cancel_target` once a sleep reaches this time.
    cancel_at_ms: ?u64 = null,
    cancel_target: ?*l1.Cancel = null,
    /// Requests `cancel_target` while `getRegisteredSigners` is in flight.
    cancel_on_registered_signers: bool = false,

    pub fn init(now_ms: u64) FakeL1 {
        assert(now_ms > 0);
        return .{ .now_ms = now_ms };
    }

    pub fn verified_for(fake: *const FakeL1, kind: types.CertKind) CachedCert {
        return .{
            .ca = kind == .ca,
            .not_after = fake.now_ms / std.time.ms_per_s + 10_000,
            .has_public_key = true,
        };
    }

    /// Known certificates of `plan`, with the pinned root cached.
    pub fn add_plan(fake: *FakeL1, plan: *const types.RegistrationPlan) void {
        const root_hash = plan.root_cert_hash;
        if (fake.find_spec(plan.root_cert) == null) {
            fake.add_spec(.{
                .cert = plan.root_cert,
                .hash = root_hash,
                .parent = @splat(0),
                .revocation_id = root_hash,
                .kind = .ca,
                .verified = fake.verified_for(.ca),
            });
            fake.cache(root_hash, @splat(0), fake.verified_for(.ca));
        }
        for (plan.cert_plans()) |*cert| {
            if (fake.find_spec(cert.cert) != null) continue;
            fake.add_spec(.{
                .cert = cert.cert,
                .hash = cert.cert_hash,
                .parent = cert.parent_cert_hash,
                .revocation_id = cert.revocation_id,
                .kind = cert.kind,
                .verified = fake.verified_for(cert.kind),
            });
        }
    }

    fn add_spec(fake: *FakeL1, spec: Spec) void {
        assert(fake.spec_count < specs_max);
        fake.specs[fake.spec_count] = spec;
        fake.spec_count += 1;
    }

    pub fn precache(fake: *FakeL1, plan: *const types.RegistrationPlan, prefix: u32) void {
        assert(prefix <= plan.cert_count);
        for (plan.cert_plans()[0..prefix]) |*cert| {
            const spec = fake.find_spec(cert.cert).?;
            fake.cache(spec.hash, spec.parent, spec.verified);
        }
    }

    fn cache(fake: *FakeL1, hash: Hash, parent: Hash, verified: CachedCert) void {
        if (fake.find_cached(hash)) |entry| {
            entry.* = .{ .hash = hash, .parent = parent, .verified = verified };
            return;
        }
        assert(fake.cached_count < specs_max);
        fake.cached[fake.cached_count] = .{ .hash = hash, .parent = parent, .verified = verified };
        fake.cached_count += 1;
    }

    pub fn find_cached(fake: *FakeL1, hash: Hash) ?*Cached {
        for (fake.cached[0..fake.cached_count]) |*entry| {
            if (std.mem.eql(u8, &entry.hash, &hash)) return entry;
        }
        return null;
    }

    fn find_spec(fake: *FakeL1, cert: []const u8) ?*Spec {
        for (fake.specs[0..fake.spec_count]) |*spec| {
            if (std.mem.eql(u8, spec.cert, cert)) return spec;
        }
        return null;
    }

    pub fn set_outcomes(fake: *FakeL1, outcomes: []const Outcome) void {
        assert(outcomes.len <= outcomes_max);
        @memcpy(fake.outcomes[0..outcomes.len], outcomes);
        fake.outcome_count = @intCast(outcomes.len);
        fake.outcome_next = 0;
    }

    pub fn tx_count_to(fake: *const FakeL1, to: Address) u32 {
        var count: u32 = 0;
        for (fake.sent[0..fake.sent_count]) |*sent| {
            if (std.mem.eql(u8, &sent.to, &to)) count += 1;
        }
        return count;
    }

    pub fn is_registered(fake: *const FakeL1, signer: Address) bool {
        for (fake.registered[0..fake.registered_count]) |*item| {
            if (std.mem.eql(u8, item, &signer)) return true;
        }
        return false;
    }

    pub fn register(fake: *FakeL1, signer: Address) void {
        if (fake.is_registered(signer)) return;
        assert(fake.registered_count < fake.registered.len);
        fake.registered[fake.registered_count] = signer;
        fake.registered_count += 1;
    }

    fn deregister(fake: *FakeL1, signer: Address) void {
        for (fake.registered[0..fake.registered_count], 0..) |*item, index| {
            if (!std.mem.eql(u8, item, &signer)) continue;
            fake.registered[index] = fake.registered[fake.registered_count - 1];
            fake.registered_count -= 1;
            return;
        }
    }

    pub fn is_revoked_id(fake: *const FakeL1, cert_id: Hash) bool {
        for (fake.revoked[0..fake.revoked_count]) |*item| {
            if (std.mem.eql(u8, item, &cert_id)) return true;
        }
        return false;
    }

    pub fn revoke(fake: *FakeL1, cert_id: Hash) void {
        if (fake.is_revoked_id(cert_id)) return;
        assert(fake.revoked_count < specs_max);
        fake.revoked[fake.revoked_count] = cert_id;
        fake.revoked_count += 1;
    }

    /// Applies a transaction's effect as the contracts would.
    fn apply(fake: *FakeL1, calldata: []const u8) void {
        const selector = calldata[0..4];
        if (std.mem.eql(u8, selector, &cert_manager_abi.verify_ca_cert_with_hints) or
            std.mem.eql(u8, selector, &cert_manager_abi.verify_client_cert_with_hints))
        {
            const args = abi.Decoder.call(calldata, selector.*) catch unreachable; // Ours.
            const cert = args.bytes(0) catch unreachable; // Encoded by the manager.
            const parent = (args.word(1) catch unreachable).*; // Encoded by the manager.
            const spec = fake.find_spec(cert).?;
            const ca = std.mem.eql(u8, selector, &cert_manager_abi.verify_ca_cert_with_hints);
            assert(spec.kind == (if (ca) types.CertKind.ca else types.CertKind.leaf));
            assert(std.mem.eql(u8, &spec.parent, &parent));
            fake.cache(spec.hash, spec.parent, spec.verified);
        } else if (std.mem.eql(u8, selector, &cert_manager_abi.revoke_cert)) {
            const args = abi.Decoder.call(calldata, cert_manager_abi.revoke_cert) catch
                unreachable; // Encoded by the manager.
            fake.revoke((args.word(0) catch unreachable).*); // Encoded by the manager.
        } else if (std.mem.eql(u8, selector, &registry_abi.register_signer)) {
            if (fake.final_signer) |signer| fake.register(signer);
        } else if (std.mem.eql(u8, selector, &registry_abi.deregister_signer)) {
            const args = abi.Decoder.call(calldata, registry_abi.deregister_signer) catch
                unreachable; // Encoded by the manager.
            fake.deregister(args.address(0) catch unreachable); // Encoded by the manager.
        } else unreachable; // The registrar sends no other calls.
    }

    fn send(context: *anyopaque, to: Address, calldata: []const u8) l1.TxOutcome {
        const fake: *FakeL1 = @ptrCast(@alignCast(context));
        assert(fake.sent_count < sent_max);
        fake.sent[fake.sent_count] = .{
            .to = to,
            .selector = calldata[0..4].*,
            .digest = keccak256(calldata),
        };
        fake.sent_count += 1;
        const outcome: Outcome = if (fake.outcome_next < fake.outcome_count) next: {
            fake.outcome_next += 1;
            break :next fake.outcomes[fake.outcome_next - 1];
        } else .success;
        switch (outcome) {
            .success, .apply_then_error, .apply_then_revert => fake.apply(calldata),
            .error_retryable, .error_permanent => {},
        }
        return switch (outcome) {
            .success => .succeeded,
            .apply_then_revert => .reverted,
            .error_retryable, .apply_then_error => .{ .failed = .{ .retryable = true } },
            .error_permanent => .{ .failed = .{ .retryable = false } },
        };
    }

    fn of(context: *anyopaque) *FakeL1 {
        const fake: *FakeL1 = @ptrCast(@alignCast(context));
        assert(fake.now_ms > 0);
        return fake;
    }

    fn read_registered_signer(context: *anyopaque, signer: Address) l1.ReadError!bool {
        return of(context).is_registered(signer);
    }

    fn read_registered_signers(context: *anyopaque, out: []Address) l1.ReadError![]Address {
        const fake = of(context);
        if (fake.cancel_on_registered_signers) fake.cancel_target.?.request();
        assert(fake.registered_count <= out.len);
        @memcpy(out[0..fake.registered_count], fake.registered[0..fake.registered_count]);
        return out[0..fake.registered_count];
    }

    fn read_load_verified(context: *anyopaque, hash: Hash) l1.ReadError!CachedCert {
        const fake = of(context);
        const entry = fake.find_cached(hash) orelse
            return .{ .ca = false, .not_after = 0, .has_public_key = false };
        return entry.verified;
    }

    fn read_is_revoked(context: *anyopaque, cert_id: Hash) l1.ReadError!bool {
        return of(context).is_revoked_id(cert_id);
    }

    /// The contract's warm path: the certificate must be cached under the same parent,
    /// of the expected kind, and unrevoked.
    fn warm(
        fake: *FakeL1,
        cert: []const u8,
        parent: Hash,
        kind: types.CertKind,
    ) l1.CallError!Cached {
        fake.cert_reads += 1;
        const spec = fake.find_spec(cert) orelse return error.ContractReverted;
        const entry = fake.find_cached(spec.hash) orelse return error.ContractReverted;
        if (!std.mem.eql(u8, &entry.parent, &parent)) return error.ContractReverted;
        if (spec.kind != kind or entry.verified.ca != (kind == .ca)) return error.ContractReverted;
        if (fake.is_revoked_id(spec.revocation_id)) return error.ContractReverted;
        return entry.*;
    }

    fn call_verify_ca(
        context: *anyopaque,
        cert: []const u8,
        parent: Hash,
        hints: []const u8,
    ) l1.CallError!Hash {
        assert(hints.len == 0);
        return (try of(context).warm(cert, parent, .ca)).hash;
    }

    fn call_verify_client(
        context: *anyopaque,
        cert: []const u8,
        parent: Hash,
        hints: []const u8,
    ) l1.CallError!CachedCert {
        assert(hints.len == 0);
        return (try of(context).warm(cert, parent, .leaf)).verified;
    }

    fn clock_now(context: *anyopaque) u64 {
        return of(context).now_ms;
    }

    fn clock_sleep(context: *anyopaque, ms: u64, cancel: *const l1.Cancel) bool {
        const fake = of(context);
        if (fake.cancel_at_ms) |at_ms| {
            if (at_ms <= fake.now_ms + ms) {
                fake.slept_ms += at_ms -| fake.now_ms;
                fake.now_ms = @max(fake.now_ms, at_ms);
                fake.cancel_target.?.request();
                fake.cancel_at_ms = null;
                return false;
            }
        }
        fake.now_ms += ms;
        fake.slept_ms += ms;
        return !cancel.is_cancelled();
    }

    const chain_vtable: l1.Chain.VTable = .{
        .is_registered_signer = read_registered_signer,
        .registered_signers = read_registered_signers,
        .load_verified = read_load_verified,
        .is_revoked = read_is_revoked,
        .verify_ca_cert = call_verify_ca,
        .verify_client_cert = call_verify_client,
    };
    const clock_vtable: l1.Clock.VTable = .{ .now_unix_ms = clock_now, .sleep_ms = clock_sleep };

    pub fn chain(fake: *FakeL1) l1.Chain {
        return .{ .context = fake, .vtable = &chain_vtable };
    }

    pub fn transactor(fake: *FakeL1) l1.Transactor {
        return .{ .context = fake, .send_fn = send };
    }

    pub fn clock(fake: *FakeL1) l1.Clock {
        return .{ .context = fake, .vtable = &clock_vtable };
    }
};

/// Canned CRL bodies served in order (the last one repeats); null fails the fetch.
pub const FakeCrl = struct {
    responses: []const ?[]const u8,
    calls: u32 = 0,

    pub fn fetcher(fake: *FakeCrl) crl.CrlFetcher {
        assert(fake.responses.len > 0);
        return .{ .context = fake, .fetch_fn = fetch };
    }

    fn fetch(context: *anyopaque, url: []const u8, buffer: []u8) crl.FetchError![]const u8 {
        const fake: *FakeCrl = @ptrCast(@alignCast(context));
        assert(url.len > 0);
        const index = @min(fake.calls, fake.responses.len - 1);
        fake.calls += 1;
        const body = fake.responses[index] orelse return error.CrlFetchFailed;
        if (body.len > buffer.len) return error.CrlResponseTooLarge;
        @memcpy(buffer[0..body.len], body);
        return buffer[0..body.len];
    }
};

/// A DER `CertificateList` revoking `serial` (unsigned magnitude), or none when null.
pub fn build_crl(serial: ?[]const u8, out: *[160]u8) []const u8 {
    // AlgorithmIdentifier ecdsa-with-SHA384.
    const algorithm = [_]u8{ 0x30, 0x0a, 0x06, 0x08 } ++
        [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 };
    const date = [_]u8{ 0x17, 0x0d } ++ "240101000000Z".*;
    var tbs: [112]u8 = undefined;
    var tbs_length: usize = 0;
    for ([_][]const u8{ &algorithm, &.{ 0x30, 0x00 }, &date }) |part| {
        @memcpy(tbs[tbs_length..][0..part.len], part);
        tbs_length += part.len;
    }
    if (serial) |value| {
        assert(value.len > 0 and value.len <= 32);
        const pad: u8 = if (value[0] & 0x80 != 0) 1 else 0;
        const integer_length: u8 = @intCast(value.len + pad);
        const entry_length: u8 = 2 + integer_length + @as(u8, date.len);
        for ([_][]const u8{
            &.{ 0x30, entry_length + 2, 0x30, entry_length, 0x02, integer_length },
            (&[_]u8{0})[0..pad],
            value,
            &date,
        }) |part| {
            @memcpy(tbs[tbs_length..][0..part.len], part);
            tbs_length += part.len;
        }
    }
    assert(tbs_length < 128);
    var length: usize = 0;
    const body_length: u8 = @intCast(2 + tbs_length + algorithm.len + 4);
    assert(body_length < 128);
    for ([_][]const u8{
        &.{ 0x30, body_length, 0x30, @intCast(tbs_length) },
        tbs[0..tbs_length],
        &algorithm,
        &.{ 0x03, 0x02, 0x00, 0x00 },
    }) |part| {
        @memcpy(out[length..][0..part.len], part);
        length += part.len;
    }
    return out[0..length];
}

/// The fixture with its `nonce: null` replaced by a 32-byte `nonce`, re-wrapped with the
/// original (now non-matching) signature: a forged attestation.
pub fn fixture_with_nonce(nonce: *const Hash, out: []u8) []const u8 {
    var tbs: [fixture_attestation.len + 64]u8 = undefined;
    const cose = cbor.NitroCose.parse_sign1(fixture_attestation, &tbs) catch
        unreachable; // The fixture parses.
    const needle = [_]u8{ 0x65, 'n', 'o', 'n', 'c', 'e', 0xf6 };
    const position = std.mem.indexOf(u8, cose.payload, &needle).?;
    var payload: [fixture_attestation.len + 64]u8 = undefined;
    var payload_length: usize = 0;
    for ([_][]const u8{
        cose.payload[0 .. position + 6],
        &.{ 0x58, 0x20 },
        nonce,
        cose.payload[position + 7 ..],
    }) |part| {
        @memcpy(payload[payload_length..][0..part.len], part);
        payload_length += part.len;
    }
    assert(payload_length > 256 and payload_length <= 0xffff);
    var length: usize = 0;
    const length_be: [2]u8 = @bitCast(std.mem.nativeToBig(u16, @intCast(payload_length)));
    for ([_][]const u8{
        &.{ 0x84, 0x44, 0xa1, 0x01, 0x38, 0x22, 0xa0, 0x59 },
        &length_be,
        payload[0..payload_length],
        &.{ 0x58, 96 },
        cose.signature,
    }) |part| {
        @memcpy(out[length..][0..part.len], part);
        length += part.len;
    }
    assert(length <= out.len);
    return out[0..length];
}
