//! Beacon blobs for the host: a blocking adapter over the consensus `BlobProvider`
//! (slot math, `/eth/v1/beacon/blobs`, versioned-hash checks). Each fetch pumps IO until
//! the provider answers, for at most `steps_max` steps, then derives the blob's KZG
//! commitment, which the host serves under the blob's sha256 key (base/base `l1-blob`).

const std = @import("std");
const assert = std.debug.assert;

const blob_provider = @import("../../consensus/sources/blob_provider.zig");
const BlockInfo = @import("../../consensus/protocol/root.zig").BlockInfo;
const primitives = @import("../../common/primitives/root.zig");
const kzg = @import("../../common/crypto/kzg/root.zig");
const handler = @import("handler.zig");
const endpoint_module = @import("../rpc/endpoint.zig");

const Hash = [32]u8;
const SourceError = handler.SourceError;

pub fn BeaconBlobs(comptime IO: type, comptime Verifier: type) type {
    return struct {
        const Self = @This();
        pub const Provider = blob_provider.BlobProvider(IO, Verifier);

        provider: *Provider,
        verifier: Verifier,
        pump: endpoint_module.Pump,
        steps_max: u32,
        fetches: u64 = 0,

        pub fn fetcher(self: *Self) handler.BlobFetcher {
            assert(self.steps_max > 0);
            return .{ .context = self, .fetch = fetch };
        }

        fn fetch(context: *anyopaque, hash: Hash, timestamp: u64) SourceError!handler.Blob {
            const self: *Self = @ptrCast(@alignCast(context));
            assert(self.steps_max > 0);
            // The provider caches by block hash; the versioned hash names one blob uniquely.
            const block: BlockInfo = .{ .hash = .init(hash), .timestamp = timestamp };
            const wanted = [_]primitives.B256{.init(hash)};
            self.fetches += 1;
            // The provider drops a failed fetch and retries on the next call; the host fails
            // the hint instead (transport errors, bad JSON, or a blob the slot lacks).
            const failures = self.provider.stats.failures;
            var steps: u32 = 0;
            const blobs = while (true) : (steps += 1) {
                break self.provider.blobs(block, &wanted) catch |err| switch (err) {
                    error.NotAvailable => {
                        if (steps == self.steps_max) return error.SourceFailed;
                        self.pump.step(self.pump.context) catch return error.SourceFailed;
                        self.provider.tick();
                        // Checked before the next call, which would enqueue the fetch again.
                        if (self.provider.stats.failures != failures) return error.SourceFailed;
                        continue;
                    },
                    // A missed or orphaned slot: the blob does not exist on this chain.
                    error.BlobsUnavailable => return error.NotFound,
                    else => return error.SourceFailed,
                };
            };
            assert(blobs.len == 1);
            const commitment = self.verifier.blob_commitment(blobs[0]) orelse
                return error.SourceFailed;
            // The provider matched the hash already; re-check what the host will serve.
            if (!std.mem.eql(u8, &kzg.versioned_hash(&commitment), &hash)) {
                return error.SourceFailed;
            }
            return .{ .blob = blobs[0], .commitment = commitment };
        }
    };
}
