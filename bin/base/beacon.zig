//! L1 beacon blob reads for the native prover (`base proof run`, `base proposer`): a beacon
//! API blob provider with its own KZG verifier workspace, exposed as a host `BlobFetcher`.

const std = @import("std");
const base = @import("base");
const consensus_cli = @import("consensus.zig");

const io = base.utilities.io;
const http = base.utilities.http;
const host = base.proof.host;
const kzg = base.common.crypto.kzg;
const BlobProvider = base.consensus.sources.blob_provider;
const Pump = base.proof.rpc.endpoint.Pump;

const Beacon = host.beacon_blobs.BeaconBlobs(io.IO, BlobProvider.KzgVerifier);

/// The `config` object of an L1 genesis file; empty without one (a built-in L1 chain).
pub fn l1_chain_config(l1_genesis: []const u8) ![]const u8 {
    if (l1_genesis.len == 0) return "";
    return try base.utilities.json.find_path(l1_genesis, &.{"config"}) orelse "";
}

/// Heap-allocated once: the provider's buffers are large.
pub const Blobs = struct {
    provider: Beacon.Provider,
    /// The verifier's own workspace: the handler uses the client's after a fetch.
    workspace: kzg.blob.Workspace,
    beacon: Beacon,

    pub fn create(
        allocator: std.mem.Allocator,
        os_io: *io.IO,
        url: []const u8,
        settings: *const kzg.blob.Settings,
        options: http.client.Options,
        pump: Pump,
    ) !*Blobs {
        const blobs = try allocator.create(Blobs);
        errdefer allocator.destroy(blobs);
        const verifier: BlobProvider.KzgVerifier = .{
            .settings = settings,
            .workspace = &blobs.workspace,
        };
        const address = try consensus_cli.parse_url(url);
        try blobs.provider.init(allocator, os_io, address, options, verifier, .{});
        blobs.beacon = .{
            .provider = &blobs.provider,
            .verifier = verifier,
            .pump = pump,
            .steps_max = 300_000,
        };
        return blobs;
    }

    pub fn destroy(blobs: *Blobs, allocator: std.mem.Allocator) void {
        blobs.provider.deinit();
        allocator.destroy(blobs);
    }

    pub fn fetcher(blobs: *Blobs) host.handler.BlobFetcher {
        return blobs.beacon.fetcher();
    }
};
