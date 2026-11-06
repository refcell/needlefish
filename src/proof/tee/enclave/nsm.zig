//! The Nitro Secure Module behind a small interface (base/base
//! `crates/proof/tee/nitro-enclave/src/nsm.rs`): describe PCR0 (the enclave image
//! measurement), produce an attestation document binding the signer's public key, and
//! draw hardware randomness.
//!
//! The real NSM is an ioctl on `/dev/nsm` with CBOR requests; std has no binding for it
//! and the project links no C, so only the interface and a deterministic fake live here.
//! A real device driver plugs in as another `Nsm` implementation. The fake produces a
//! well-formed `COSE_Sign1` attestation document (synthetic P-384 key, `nitro` test
//! fixture), so tests parse what the enclave returns.

const std = @import("std");
const assert = std.debug.assert;

const Prng = @import("../../../testing/prng.zig").Prng;

/// PCR0 is a SHA-384 digest (AWS Nitro Enclaves specification).
pub const pcr0_length = 48;
/// Largest PCR value the interface returns.
pub const pcr_bytes_max = 64;

pub const Error = error{
    /// No NSM device (outside an enclave).
    Unavailable,
    NoPcrData,
    DescribePcr,
    Attestation,
    Random,
    BufferTooSmall,
};

pub const AttestationInput = struct {
    public_key: []const u8,
    user_data: ?[]const u8 = null,
    nonce: ?[]const u8 = null,
};

pub const Nsm = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        describe_pcr0: *const fn (*anyopaque, *[pcr_bytes_max]u8) Error![]const u8,
        get_attestation: *const fn (*anyopaque, *const AttestationInput, []u8) Error![]const u8,
        get_random: *const fn (*anyopaque, []u8) Error!void,
    };

    pub fn describe_pcr0(nsm: Nsm, out: *[pcr_bytes_max]u8) Error![]const u8 {
        const pcr = try nsm.vtable.describe_pcr0(nsm.context, out);
        if (pcr.len == 0) return error.NoPcrData;
        assert(pcr.len <= pcr_bytes_max);
        return pcr;
    }

    /// The raw attestation document (`COSE_Sign1` bytes) in `out`.
    pub fn get_attestation(
        nsm: Nsm,
        input: *const AttestationInput,
        out: []u8,
    ) Error![]const u8 {
        assert(input.public_key.len > 0);
        const document = try nsm.vtable.get_attestation(nsm.context, input, out);
        assert(document.len <= out.len);
        return document;
    }

    /// Fills `out` from the hardware RNG (the `Signer.generate` source).
    pub fn fill(nsm: Nsm, out: []u8) Error!void {
        assert(out.len > 0);
        try nsm.vtable.get_random(nsm.context, out);
    }
};

/// A deterministic NSM for tests and the simulator.
pub const Fake = struct {
    pcr0: [pcr0_length]u8 = @splat(0x01),
    prng: Prng,
    /// Seed byte of the synthetic P-384 signing key.
    key_seed: u8 = 0x42,
    certificate: []const u8 = "synthetic-nitro-certificate",
    timestamp_ms: u64 = 1_700_000_000_000,
    attestations: u32 = 0,
    /// Fail every call, as outside an enclave.
    unavailable: bool = false,

    pub fn init(seed: u64) Fake {
        return .{ .prng = .init(seed) };
    }

    pub fn nsm(fake: *Fake) Nsm {
        return .{ .context = fake, .vtable = &vtable };
    }

    const vtable: Nsm.VTable = .{
        .describe_pcr0 = describe_pcr0,
        .get_attestation = get_attestation,
        .get_random = get_random,
    };

    fn of(context: *anyopaque) *Fake {
        return @ptrCast(@alignCast(context));
    }

    fn describe_pcr0(context: *anyopaque, out: *[pcr_bytes_max]u8) Error![]const u8 {
        const fake = of(context);
        if (fake.unavailable) return error.Unavailable;
        out[0..pcr0_length].* = fake.pcr0;
        return out[0..pcr0_length];
    }

    fn get_random(context: *anyopaque, out: []u8) Error!void {
        const fake = of(context);
        if (fake.unavailable) return error.Unavailable;
        fake.prng.fill(out);
    }

    fn get_attestation(
        context: *anyopaque,
        input: *const AttestationInput,
        out: []u8,
    ) Error![]const u8 {
        const fake = of(context);
        if (fake.unavailable) return error.Unavailable;
        const fixture = @import("../nitro/test_fixture.zig");
        var payload: [4096]u8 = undefined;
        const document = fixture.build_document(&payload, .{
            .timestamp_ms = fake.timestamp_ms,
            .certificate = fake.certificate,
            .cabundle = &.{},
            .nonce = input.nonce,
            .user_data = input.user_data,
            .public_key = input.public_key,
            .pcr_fill = fake.pcr0[0],
        }) catch return error.Attestation;
        const signer = fixture.key_pair(fake.key_seed) catch return error.Attestation;
        const envelope = fixture.build_cose(out, document, &signer, .{}) catch
            return error.BufferTooSmall;
        fake.attestations += 1;
        assert(envelope.len > document.len);
        return envelope;
    }
};

const testing = std.testing;

test "enclave nsm: the fake describes PCR0, draws randomness, and attests a public key" {
    const attestation = @import("../nitro/attestation.zig");
    var fake: Fake = .init(7);
    const device = fake.nsm();
    var pcr: [pcr_bytes_max]u8 = undefined;
    try testing.expectEqual(@as(usize, pcr0_length), (try device.describe_pcr0(&pcr)).len);
    var first: [32]u8 = undefined;
    var second: [32]u8 = undefined;
    try device.fill(&first);
    try device.fill(&second);
    try testing.expect(!std.mem.eql(u8, &first, &second));
    const public_key: [65]u8 = @splat(0x04);
    var out: [8192]u8 = undefined;
    const document = try device.get_attestation(&.{
        .public_key = &public_key,
        .nonce = "nonce",
    }, &out);
    const report = try attestation.AttestationReport.parse(document);
    try testing.expectEqualSlices(u8, &public_key, report.document.public_key.?);
    try testing.expectEqualStrings("nonce", report.document.nonce.?);
    try testing.expect(report.document.user_data == null);
}

test "enclave nsm: an unavailable device fails every call" {
    var fake: Fake = .init(1);
    fake.unavailable = true;
    const device = fake.nsm();
    var pcr: [pcr_bytes_max]u8 = undefined;
    try testing.expectError(error.Unavailable, device.describe_pcr0(&pcr));
    var random: [4]u8 = undefined;
    try testing.expectError(error.Unavailable, device.fill(&random));
}
