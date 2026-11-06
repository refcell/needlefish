//! Registrar data types (base/base `registrar/src/types.rs`).
//!
//! Plans borrow certificate DER from the attestation bytes and the TBS from a
//! caller buffer; hint streams live in fixed-capacity arrays the caller allocates
//! once at startup.

const std = @import("std");
const assert = std.debug.assert;
const nitro_types = @import("../nitro/types.zig");

/// Root plus up to 31 non-root CAs (`cabundle`) plus the leaf.
pub const chain_length_max: u32 = nitro_types.chain_length_max;
/// Non-root CAs plus the leaf.
pub const cert_plan_count_max: u32 = chain_length_max - 1;
pub const label_size_max: u32 = 24;
pub const instance_id_size_max: u32 = 64;
pub const endpoint_size_max: u32 = 128;

/// Upper bound on recorded inverses for one P-384 verification: two `s⁻¹`, 61
/// precompute additions, and the windowed double-scalar multiplication (one
/// double plus add, 61 triple-doubles plus adds for the high limb; one double
/// plus add, 85 triple-doubles plus adds for the low limb).
pub const hint_inverse_count_max: u32 = 2 + 61 + 2 + 61 * 4 + 2 + 85 * 4;
pub const hint_inverse_size: u32 = 48;
pub const hint_stream_size_max: u32 = hint_inverse_count_max * hint_inverse_size;

comptime {
    assert(hint_inverse_count_max == 651);
    assert(cert_plan_count_max == 32);
}

pub const Address = [20]u8;
pub const Hash = [32]u8;

/// Health status of a discovered prover instance.
pub const InstanceHealthStatus = enum(u8) {
    /// Load balancer health checks are in progress: the instance just started.
    initial,
    /// Reachable and passing readiness checks.
    healthy,
    /// Not responding to `readyz` or failing health checks.
    unhealthy,
    /// Load balancer is draining connections from this instance.
    draining,
};

/// Fixed-capacity string, for identifiers and labels.
pub fn BoundedString(comptime capacity: u32) type {
    return struct {
        const Self = @This();
        bytes: [capacity]u8 = undefined,
        length: u32 = 0,

        pub fn init(text: []const u8) error{StringTooLong}!Self {
            if (text.len > capacity) return error.StringTooLong;
            var result: Self = .{ .length = @intCast(text.len) };
            @memcpy(result.bytes[0..text.len], text);
            assert(result.length <= capacity);
            return result;
        }

        pub fn slice(string: *const Self) []const u8 {
            assert(string.length <= capacity);
            return string.bytes[0..string.length];
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            assert(a.length <= capacity and b.length <= capacity);
            return std.mem.eql(u8, a.slice(), b.slice());
        }
    };
}

pub const InstanceId = BoundedString(instance_id_size_max);
pub const Label = BoundedString(label_size_max);

/// A prover instance discovered from the infrastructure layer.
pub const ProverInstance = struct {
    /// EC2 instance ID (e.g. `i-0abc123def456`).
    instance_id: InstanceId,
    /// HTTP endpoint URL for the prover.
    endpoint: BoundedString(endpoint_size_max),
    health_status: InstanceHealthStatus,
};

/// Which `CertManager` cache helper a certificate requires.
pub const CertKind = enum(u8) {
    /// Intermediate / non-root CA certificate.
    ca,
    /// Attestation document leaf (client) certificate.
    leaf,
};

/// One certificate-cache step in dependency order.
///
/// `cert_hash` is the `CertManager` cache key: full-DER keccak for the pinned root
/// (used only as `parent_cert_hash` of the first CA) and `TBSCertificate` keccak for
/// every non-root certificate. `revocation_id` is `computeCertId` for the cert.
pub const CertPlan = struct {
    kind: CertKind,
    label: Label,
    /// DER certificate bytes, borrowed.
    cert: []const u8,
    cert_hash: Hash,
    parent_cert_hash: Hash,
    revocation_id: Hash,

    pub fn eql(a: *const CertPlan, b: *const CertPlan) bool {
        assert(a.cert.len > 0 and b.cert.len > 0);
        return a.kind == b.kind and a.label.eql(&b.label) and
            std.mem.eql(u8, a.cert, b.cert) and
            std.mem.eql(u8, &a.cert_hash, &b.cert_hash) and
            std.mem.eql(u8, &a.parent_cert_hash, &b.parent_cert_hash) and
            std.mem.eql(u8, &a.revocation_id, &b.revocation_id);
    }
};

/// Complete registration plan for one Nitro attestation (no signature hints).
pub const RegistrationPlan = struct {
    /// Signer address derived from the attestation `public_key`.
    signer: Address,
    pcr0: [48]u8,
    /// Attestation timestamp, Unix milliseconds.
    timestamp_ms: u64,
    nonce: ?[]const u8,
    /// Pinned root certificate cache key (`keccak256(full DER)`).
    root_cert_hash: Hash,
    /// DER pinned root certificate, borrowed.
    root_cert: []const u8,
    /// Leaf certificate cache key (`keccak256(TBSCertificate TLV)`).
    leaf_cert_hash: Hash,
    /// COSE `Sig_structure` bytes (attestation TBS), borrowed from the TBS buffer.
    attestation_tbs: []const u8,
    /// P-384 signature `r || s`.
    signature: [96]u8,
    /// Non-root CAs (parent first) followed by the leaf certificate.
    certs: [cert_plan_count_max]CertPlan,
    cert_count: u8,

    pub fn cert_plans(plan: *const RegistrationPlan) []const CertPlan {
        assert(plan.cert_count <= cert_plan_count_max);
        return plan.certs[0..plan.cert_count];
    }

    /// Field-wise content equality (base/base derives `PartialEq`).
    pub fn eql(a: *const RegistrationPlan, b: *const RegistrationPlan) bool {
        assert(a.cert_count <= cert_plan_count_max and b.cert_count <= cert_plan_count_max);
        if (a.cert_count != b.cert_count) return false;
        for (a.cert_plans(), b.cert_plans()) |*cert_a, *cert_b| {
            if (!cert_a.eql(cert_b)) return false;
        }
        const nonce_equal = if (a.nonce) |nonce_a|
            (if (b.nonce) |nonce_b| std.mem.eql(u8, nonce_a, nonce_b) else false)
        else
            b.nonce == null;
        return nonce_equal and a.timestamp_ms == b.timestamp_ms and
            std.mem.eql(u8, &a.signer, &b.signer) and
            std.mem.eql(u8, &a.pcr0, &b.pcr0) and
            std.mem.eql(u8, &a.root_cert_hash, &b.root_cert_hash) and
            std.mem.eql(u8, a.root_cert, b.root_cert) and
            std.mem.eql(u8, &a.leaf_cert_hash, &b.leaf_cert_hash) and
            std.mem.eql(u8, a.attestation_tbs, b.attestation_tbs) and
            std.mem.eql(u8, &a.signature, &b.signature);
    }
};

/// One packed inverse-hint stream: `inverse_0 ‖ … ‖ inverse_{k-1}`, 48-byte
/// big-endian limbs in the exact order the onchain `P384Verifier` consumes them.
pub const HintStream = struct {
    bytes: [hint_stream_size_max]u8,
    length: u32,

    pub fn slice(stream: *const HintStream) []const u8 {
        assert(stream.length <= hint_stream_size_max);
        assert(stream.length % hint_inverse_size == 0);
        return stream.bytes[0..stream.length];
    }
};

/// Packed P-384 inverse-hint streams for one registration plan. About 1 MiB:
/// allocate once and reuse.
pub const RegistrationHints = struct {
    /// Hint stream for each entry in `RegistrationPlan.certs` (same order).
    cert_signature_hints: [cert_plan_count_max]HintStream,
    cert_count: u8,
    /// Hint stream for the attestation COSE signature.
    attestation_hints: HintStream,

    pub fn cert_streams(hints: *const RegistrationHints) []const HintStream {
        assert(hints.cert_count <= cert_plan_count_max);
        return hints.cert_signature_hints[0..hints.cert_count];
    }

    pub fn eql(a: *const RegistrationHints, b: *const RegistrationHints) bool {
        if (a.cert_count != b.cert_count) return false;
        for (a.cert_streams(), b.cert_streams()) |*stream_a, *stream_b| {
            if (!std.mem.eql(u8, stream_a.slice(), stream_b.slice())) return false;
        }
        return std.mem.eql(u8, a.attestation_hints.slice(), b.attestation_hints.slice());
    }
};

test "registrar types: bounded string rejects overflow" {
    const label = try Label.init("regional CA");
    try std.testing.expectEqualStrings("regional CA", label.slice());
    const long: [label_size_max + 1]u8 = @splat('x');
    try std.testing.expectError(error.StringTooLong, Label.init(&long));
}
