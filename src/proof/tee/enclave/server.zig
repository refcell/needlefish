//! The enclave server (base/base `crates/proof/tee/nitro-enclave/src/server.rs`): holds
//! the signer key, attests it, and proves.
//!
//! In an enclave the server reads PCR0 from the NSM (`tee_image_hash` = keccak256 of it)
//! and draws its key from the NSM's RNG. Local mode (development) takes a key from the
//! caller and commits a zero image hash. A prove request runs the fault-proof client in
//! process over the request's witness, checks the claim (the derived block and output
//! root must be the claimed ones), samples the intermediate roots at the boot interval,
//! and signs one aggregate proposal over the proof journal for the whole range.

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../../preimage/root.zig");
const program = @import("../../program/root.zig");
const proof_client = @import("../../client/root.zig");
const host_store = @import("../../host/store.zig");
const primitives = @import("../../primitives/root.zig");
const keccak = @import("../../../common/crypto/keccak.zig");
const crypto = @import("crypto.zig");
const nsm_module = @import("nsm.zig");
const oracle = @import("oracle.zig");
const protocol = @import("protocol.zig");

const Hash = [32]u8;
const Allocator = std.mem.Allocator;

pub const intermediate_roots_max = protocol.TeeProofResult.intermediate_roots_max;

pub const ProveError = proof_client.client.Error || oracle.Error || error{
    UnsupportedChain,
    /// The range has no intermediate roots to commit (empty or not interval-aligned).
    NoIntermediateRoots,
    TooManyIntermediateRoots,
    /// The derived safe head is not the claimed block (base/base `InvalidClaimBlock`).
    InvalidClaimBlock,
    /// The computed output root is not the claimed one (base/base `InvalidClaim`).
    InvalidClaim,
    RangeBeforeGenesis,
    OracleFailed,
};

pub const InitError = nsm_module.Error || crypto.Error || error{InvalidPcr0Length};

pub const Limits = struct {
    store: host_store.Limits = .{},
    /// Preimage channel between the in-process host and client.
    channel_bytes: u32 = 1 << 20,
};

/// One signed aggregate proof. Holds the bytes `result` points into.
pub const Proof = struct {
    signature: crypto.Signature,
    roots: [intermediate_roots_max]Hash,
    root_count: u32,
    proposal: protocol.Proposal,
    tee_signer: crypto.Address,

    /// base/base `ProofResult::Tee`.
    pub fn result(proof: *const Proof) protocol.TeeProofResult {
        assert(proof.root_count <= intermediate_roots_max);
        assert(proof.proposal.signature.ptr == &proof.signature);
        return .{
            .aggregate_proposal = proof.proposal,
            .intermediate_roots = proof.roots[0..proof.root_count],
            .tee_kind = .aws_nitro,
            .tee_signer = proof.tee_signer,
        };
    }
};

pub const Server = struct {
    signer: crypto.Signer,
    /// PCR0, empty in local mode.
    pcr0: [nsm_module.pcr0_length]u8,
    pcr0_length: u8,
    /// keccak256(PCR0) in an enclave, zero in local mode.
    tee_image_hash: Hash,
    nsm: ?nsm_module.Nsm,
    limits: Limits = .{},

    /// Enclave mode: PCR0 must be a 48-byte SHA-384 measurement.
    pub fn init_enclave(nsm: nsm_module.Nsm) InitError!Server {
        var pcr_buffer: [nsm_module.pcr_bytes_max]u8 = undefined;
        const pcr0 = try nsm.describe_pcr0(&pcr_buffer);
        if (pcr0.len != nsm_module.pcr0_length) return error.InvalidPcr0Length;
        const signer = try crypto.Signer.generate(nsm);
        const server: Server = .{
            .signer = signer,
            .pcr0 = pcr0[0..nsm_module.pcr0_length].*,
            .pcr0_length = nsm_module.pcr0_length,
            .tee_image_hash = keccak.keccak256(pcr0),
            .nsm = nsm,
        };
        assert(!server.is_local_mode());
        assert(!std.mem.allEqual(u8, &server.tee_image_hash, 0));
        return server;
    }

    /// Local (development) mode with the caller's signer (base/base reads
    /// `BASE_ENCLAVE_SIGNER_KEY` or generates one; the binary owns that choice here).
    pub fn init_local(signer: crypto.Signer) Server {
        const server: Server = .{
            .signer = signer,
            .pcr0 = @splat(0),
            .pcr0_length = 0,
            .tee_image_hash = @splat(0),
            .nsm = null,
        };
        assert(server.is_local_mode());
        assert(std.mem.allEqual(u8, &server.tee_image_hash, 0));
        return server;
    }

    pub fn is_local_mode(server: *const Server) bool {
        assert(server.pcr0_length == 0 or server.pcr0_length == nsm_module.pcr0_length);
        return server.pcr0_length == 0;
    }

    pub fn signer_public_key(server: *const Server) *const crypto.PublicKey {
        assert(server.signer.public_key[0] == 0x04);
        return &server.signer.public_key;
    }

    pub fn signer_address(server: *const Server) crypto.Address {
        return server.signer.address;
    }

    /// An attestation document over the signer's public key; fails without an NSM.
    pub fn signer_attestation(
        server: *const Server,
        request: protocol.AttestationRequest,
        out: []u8,
    ) nsm_module.Error![]const u8 {
        const nsm = server.nsm orelse return error.Unavailable;
        assert(!server.is_local_mode());
        return nsm.get_attestation(&.{
            .public_key = server.signer_public_key(),
            .user_data = request.user_data,
            .nonce = request.nonce,
        }, out);
    }

    /// Proves the claim of `preimages` and signs it into `proof`.
    pub fn prove(
        server: *const Server,
        allocator: Allocator,
        preimages: []const protocol.Preimage,
        options: proof_client.client.Options,
        proof: *Proof,
    ) ProveError!void {
        assert(options.intermediate == null);
        var store: host_store.Store = .init(allocator, server.limits.store);
        defer store.deinit();
        try oracle.load(&store, preimages);
        var harness: preimage.InProcess = undefined;
        harness.init(allocator, store.fetcher(), preimage.in_process.ignore_hints, .{
            .channel_bytes = server.limits.channel_bytes,
        }) catch return error.OracleFailed;
        defer harness.deinit(allocator);
        var scratch: [program.boot.rollup_config_bytes_max]u8 = undefined;
        const boot = try program.BootInfo.load(harness.oracle_reader(), &scratch);
        const config_hash = primitives.config_hash_for_chain(boot.chain_id) orelse
            return error.UnsupportedChain;
        const sampler = try allocator.create(program.IntermediateRootSampler);
        defer allocator.destroy(sampler);
        var run_options = options;
        run_options.intermediate = sampler;
        const io: proof_client.Client.Io = .{
            .oracle = harness.oracle_reader(),
            .hints = harness.hint_writer(),
        };
        const outcome = try proof_client.run(allocator, io, run_options);
        const roots = sampler.finish() catch return error.NoIntermediateRoots;
        if (roots.len > intermediate_roots_max) return error.TooManyIntermediateRoots;
        // Trust-critical: the claim must hold before anything is signed.
        if (outcome.block_number != boot.claimed_l2_block_number) return error.InvalidClaimBlock;
        if (!proof_client.claim_holds(&boot, &outcome)) return error.InvalidClaim;
        const starting = std.math.sub(u64, outcome.block_number, sampler.blocks) catch
            return error.RangeBeforeGenesis;
        server.sign(&boot, &outcome, starting, roots, config_hash, proof);
    }

    fn sign(
        server: *const Server,
        boot: *const program.BootInfo,
        outcome: *const proof_client.Outcome,
        starting_l2_block: u64,
        roots: []const Hash,
        config_hash: Hash,
        proof: *Proof,
    ) void {
        assert(roots.len <= intermediate_roots_max);
        assert(starting_l2_block <= outcome.block_number);
        @memcpy(proof.roots[0..roots.len], roots);
        proof.root_count = @intCast(roots.len);
        const journal: primitives.ProofJournal = .{
            .proposer = boot.proposer,
            .l1_origin_hash = boot.l1_head,
            .prev_output_root = boot.agreed_l2_output_root,
            .starting_l2_block = starting_l2_block,
            .output_root = outcome.output_root,
            .ending_l2_block = outcome.block_number,
            .intermediate_roots = proof.roots[0..proof.root_count],
            .config_hash = config_hash,
            .tee_image_hash = server.tee_image_hash,
            .schedule_id = boot.schedule_id,
        };
        var buffer: [primitives.proposal.proof_journal_length_max]u8 = undefined;
        proof.signature = server.signer.sign(journal.encode(&buffer));
        proof.tee_signer = server.signer.address;
        proof.proposal = .{
            .output_root = outcome.output_root,
            .signature = &proof.signature,
            .l1_origin_hash = boot.l1_head,
            .l1_origin_number = boot.l1_head_number,
            .l2_block_number = outcome.block_number,
            .prev_output_root = boot.agreed_l2_output_root,
            .config_hash = config_hash,
            .schedule_id = boot.schedule_id,
        };
    }
};

const testing = std.testing;

test "enclave server: local mode" {
    const signer = try crypto.Signer.from_bytes(&@as([32]u8, @splat(0x11)));
    const server: Server = .init_local(signer);
    try testing.expect(server.is_local_mode());
    try testing.expectEqual(@as(u8, 0x04), server.signer_public_key()[0]);
    try testing.expectEqual(signer.address, server.signer_address());
    var out: [64]u8 = undefined;
    try testing.expectError(error.Unavailable, server.signer_attestation(.{}, &out));
}

test "enclave server: enclave mode hashes PCR0 and draws its key from the NSM" {
    var fake: nsm_module.Fake = .init(5);
    const server: Server = try .init_enclave(fake.nsm());
    try testing.expect(!server.is_local_mode());
    try testing.expectEqual(keccak.keccak256(&fake.pcr0), server.tee_image_hash);
    var other_fake: nsm_module.Fake = .init(6);
    const other: Server = try .init_enclave(other_fake.nsm());
    try testing.expect(!std.mem.eql(u8, &server.signer.address, &other.signer.address));
    var out: [8192]u8 = undefined;
    const document = try server.signer_attestation(.{ .nonce = "n" }, &out);
    try testing.expect(document.len > 0);
    try testing.expectEqual(@as(u32, 1), fake.attestations);
}

test "enclave server: an unavailable NSM cannot start an enclave server" {
    var fake: nsm_module.Fake = .init(5);
    fake.unavailable = true;
    try testing.expectError(error.Unavailable, Server.init_enclave(fake.nsm()));
}

test "enclave server: a prove request with an invalid preimage fails before running" {
    const signer = try crypto.Signer.from_bytes(&@as([32]u8, @splat(0x11)));
    const server: Server = .init_local(signer);
    const bad: protocol.Preimage = .{ .key = .keccak256(@splat(0xaa)), .value = "x" };
    var proof: Proof = undefined;
    const options: proof_client.client.Options = .{
        .builder = proof_client.client.default_builder_config,
        .kzg_settings = undefined,
        .kzg_workspace = undefined,
    };
    const result = server.prove(testing.allocator, &.{bad}, options, &proof);
    try testing.expectError(error.InvalidPreimage, result);
}
