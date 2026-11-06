//! The host side of a TEE proof (base/base `crates/proof/tee/nitro-host/src/backend.rs`
//! with the witness step of `base_proof_host::ProverService::prove_block`): build the
//! witness of a primitive proof request on the host, then hand it to an enclave.
//!
//! The host boots the fault-proof program from the request (the agreed output root
//! preimage comes from the agreed L2 head's header and must hash to the agreed root), runs
//! it natively against the proof host's `Source` (`host/native.zig`, the same hint handler
//! and store as `base proof run`), and records every preimage it read. The recorded witness
//! alone replays to the same verdict, so it is exactly what the enclave needs: the enclave
//! re-runs the program over it, checks the claim, and signs. A claim that does not hold on
//! the host is refused before the enclave is asked (the enclave would refuse it too).

const std = @import("std");
const assert = std.debug.assert;

const host = @import("../../host/root.zig");
const preimage = @import("../../preimage/root.zig");
const proof_client = @import("../../client/root.zig");
const service_protocol = @import("../../prover_service/protocol.zig");
const keccak = @import("../../../common/crypto/keccak.zig");
const kzg = @import("../../../common/crypto/kzg/root.zig");
const enclave = @import("../enclave/root.zig");

const Allocator = std.mem.Allocator;
const Preimage = enclave.protocol.Preimage;
pub const Request = service_protocol.PrimitiveProofRequest;

pub const Config = struct {
    rollup_config_json: []const u8,
    /// Custom L1 chains only: a geth chain config JSON object.
    l1_config_json: []const u8 = "",
    chain_id: u64,
    client_options: proof_client.client.Options,
    roots_brp: ?*const [kzg.field_elements_per_blob][32]u8 = null,
    store_limits: host.store.Limits = .{},
    /// Most preimages one witness may hold.
    preimages_max: u32 = 1 << 20,
};

pub const Error = host.native.Error || host.handler.SourceError || error{
    /// The interval is zero or the claim is not after the agreed block's successor rules.
    InvalidRequest,
    /// The agreed L2 head's output root is not the request's agreed output root.
    AgreedOutputMismatch,
    /// The host's run of the program does not reach the claimed output root.
    ClaimDoesNotHold,
    TooManyPreimages,
};

/// Boot values and the agreed output root preimage for `request` (base/base
/// `HostConfig::boot_info` over `ProofRequest`).
pub fn boot(
    store: *host.Store,
    source: host.Source,
    config: *const Config,
    request: *const Request,
) Error!void {
    request.validate() catch return error.InvalidRequest;
    assert(config.rollup_config_json.len > 0);
    const agreed_hash = request.agreed_l2_head_hash;
    const raw_header = try source.vtable.raw_header(source.context, .l2, agreed_hash);
    if (!std.mem.eql(u8, &keccak.keccak256(raw_header), &request.agreed_l2_head_hash)) {
        return error.InvalidHeader;
    }
    const output = try host.native.output_of(raw_header);
    const encoded = output.encode();
    if (!std.mem.eql(u8, &keccak.keccak256(&encoded), &request.agreed_l2_output_root)) {
        return error.AgreedOutputMismatch;
    }
    const agreed_root = try store.put_keccak(&encoded);
    assert(std.mem.eql(u8, &agreed_root, &request.agreed_l2_output_root));
    try store.put_boot(&.{
        .l1_head = request.l1_head,
        .agreed_l2_output_root = agreed_root,
        .claimed_l2_output_root = request.claimed_l2_output_root,
        .claimed_l2_block_number = request.claimed_l2_block_number,
        .chain_id = config.chain_id,
        .rollup_config_json = config.rollup_config_json,
        .l1_config_json = config.l1_config_json,
        .proposer = request.proposer,
        .intermediate_block_interval = request.intermediate_block_interval,
        .l1_head_number = request.l1_head_number,
        .schedule_block_number = request.schedule_l2_block_number,
    });
}

/// Runs the program for `request` on the host and records its witness into `witness`.
pub fn record_witness(
    allocator: Allocator,
    source: host.Source,
    config: *const Config,
    request: *const Request,
    witness: *host.Store,
) Error!void {
    assert(witness.count() == 0);
    var store: host.Store = .init(allocator, config.store_limits);
    defer store.deinit();
    try boot(&store, source, config, request);
    const verdict = try host.native.run(
        allocator,
        &store,
        source,
        config.roots_brp,
        config.client_options,
        witness,
    );
    if (!verdict.holds) return error.ClaimDoesNotHold;
    assert(witness.count() > 0);
}

/// The witness as prove request preimages; values point into `witness`. Caller frees.
pub fn preimages_of(
    allocator: Allocator,
    witness: *const host.Store,
    preimages_max: u32,
) Error![]Preimage {
    if (witness.count() > preimages_max) return error.TooManyPreimages;
    const preimages = try allocator.alloc(Preimage, witness.count());
    errdefer allocator.free(preimages);
    var entries = witness.map.iterator();
    var index: usize = 0;
    while (entries.next()) |entry| : (index += 1) {
        // The store only holds keys it rendered itself, so the type byte is valid.
        const key = preimage.Key.from_bytes(entry.key_ptr.*) catch return error.InvalidHeader;
        preimages[index] = .{ .key = key, .value = entry.value_ptr.* };
    }
    assert(index == preimages.len);
    return preimages;
}

/// An upper bound on the encoded prove request for `preimages` (bincode: an 8-byte count,
/// then per entry a 4-byte variant, 32-byte key, 8-byte length and the value).
pub fn request_bytes_bound(preimages: []const Preimage) u64 {
    var total: u64 = 64;
    for (preimages) |entry| total += 48 + entry.value.len;
    assert(total >= 64);
    return total;
}

const testing = std.testing;
const rlp = @import("../../../common/rlp/root.zig");
const consensus = @import("../../../common/consensus/root.zig");
const SourceError = host.handler.SourceError;
const Chain = host.handler.Chain;

/// A source with one L2 header; every other call is not found.
const OneHeader = struct {
    raw: []const u8,

    fn source(one: *OneHeader) host.Source {
        return .{ .context = one, .vtable = &.{
            .raw_header = raw_header,
            .transactions = transactions,
            .receipts = receipts,
            .blob = blob,
            .preimage = preimage_of,
            .payload_witness = payload_witness,
        } };
    }

    fn raw_header(
        context: *anyopaque,
        chain: host.handler.Chain,
        hash: [32]u8,
    ) SourceError![]const u8 {
        const one: *OneHeader = @ptrCast(@alignCast(context));
        if (chain != .l2 or !std.mem.eql(u8, &hash, &keccak.keccak256(one.raw))) {
            return error.NotFound;
        }
        return one.raw;
    }
    fn transactions(_: *anyopaque, _: Chain, _: [32]u8) SourceError![]const []const u8 {
        return error.NotFound;
    }
    fn receipts(_: *anyopaque, _: [32]u8) SourceError![]const []const u8 {
        return error.NotFound;
    }
    fn blob(_: *anyopaque, _: [32]u8, _: u64) SourceError!host.handler.Blob {
        return error.NotFound;
    }
    fn preimage_of(_: *anyopaque, _: [32]u8) SourceError![]const u8 {
        return error.NotFound;
    }
    fn payload_witness(_: *anyopaque, _: [32]u8, _: []const u8) SourceError![]const []const u8 {
        return error.NotFound;
    }
};

test "tee host backend: boot checks the agreed head and output root" {
    var buffer: [1024]u8 = undefined;
    const header: consensus.Header = .{
        .number = 3,
        .state_root = .{ .bytes = @splat(1) },
        .withdrawals_root = .{ .bytes = @splat(2) },
        .base_fee_per_gas = 1,
    };
    var one: OneHeader = .{ .raw = rlp.encode_to(&buffer, header) };
    const agreed_root = try host.native.output_root_of(one.raw);
    const config: Config = .{
        .rollup_config_json = "{}",
        .chain_id = 8453,
        .client_options = undefined,
    };
    var request: Request = .{
        .l1_head = @splat(0x10),
        .agreed_l2_head_hash = keccak.keccak256(one.raw),
        .agreed_l2_output_root = agreed_root,
        .claimed_l2_output_root = @splat(0x20),
        .claimed_l2_block_number = 5,
        .proposer = @splat(0x77),
        .l1_head_number = 9,
        .intermediate_block_interval = 1,
    };
    var store: host.Store = .init(testing.allocator, .{});
    defer store.deinit();
    try boot(&store, one.source(), &config, &request);
    try testing.expect(store.get(.keccak256(agreed_root)) != null);
    request.agreed_l2_output_root = @splat(0x33);
    const mismatch = boot(&store, one.source(), &config, &request);
    try testing.expectError(error.AgreedOutputMismatch, mismatch);
    request.agreed_l2_head_hash = @splat(0x44);
    try testing.expectError(error.NotFound, boot(&store, one.source(), &config, &request));
    request.intermediate_block_interval = 0;
    try testing.expectError(error.InvalidRequest, boot(&store, one.source(), &config, &request));
}

test "tee host backend: witness preimages are bounded and sized" {
    var witness: host.Store = .init(testing.allocator, .{});
    defer witness.deinit();
    _ = try witness.put_keccak("one");
    _ = try witness.put_keccak("three");
    try testing.expectError(error.TooManyPreimages, preimages_of(testing.allocator, &witness, 1));
    const preimages = try preimages_of(testing.allocator, &witness, 2);
    defer testing.allocator.free(preimages);
    try testing.expectEqual(@as(usize, 2), preimages.len);
    for (preimages) |entry| try enclave.oracle.check_preimage(entry.key, entry.value);
    try testing.expectEqual(@as(u64, 64 + 48 * 2 + 8), request_bytes_bound(preimages));
}
