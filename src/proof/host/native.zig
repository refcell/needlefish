//! Native mode: the host and the fault-proof client in one process (base/base
//! `base-proof-host --native`). The hint handler fills a store from a chain `Source` while
//! the client runs, so after a run the store holds exactly the preimages the proof read
//! and can be written as an archive for offline replay.

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../preimage/root.zig");
const client = @import("../client/root.zig");
const program = @import("../program/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const crypto = @import("../../common/crypto/root.zig");
const handler_module = @import("handler.zig");
const offline = @import("offline.zig");
const store_module = @import("store.zig");
const recording_module = @import("recording.zig");

pub const Error = client.client.Error || store_module.Error || error{
    InvalidHeader,
    NativeFailed,
};

/// The output root preimage of an L2 block from its raw header (see `output_root_of`).
pub fn output_of(raw_header: []const u8) error{InvalidHeader}!program.sync.OutputRoot {
    const header = rlp.decode_exact(consensus.Header, raw_header) catch
        return error.InvalidHeader;
    const passer_root = header.withdrawals_root orelse return error.InvalidHeader;
    assert(raw_header.len > 0);
    return .{
        .state_root = header.state_root.bytes,
        .message_passer_storage_root = passer_root.bytes,
        .block_hash = crypto.keccak256(raw_header),
    };
}

/// The output root of an L2 block from its raw header. Since Isthmus the header's
/// withdrawals root is the L2ToL1MessagePasser storage root.
pub fn output_root_of(raw_header: []const u8) error{InvalidHeader}![32]u8 {
    const output = try output_of(raw_header);
    const encoded = output.encode();
    const root = crypto.keccak256(&encoded);
    assert(!std.mem.eql(u8, &root, &output.block_hash));
    return root;
}

/// Runs the client over `store` (pre-filled with the boot values and the agreed output
/// root preimage), serving hints from `source`. With `witness`, every preimage the client
/// reads is also recorded there: a replay of the witness alone reaches the same verdict.
pub fn run(
    allocator: std.mem.Allocator,
    store: *store_module.Store,
    source: handler_module.Source,
    roots_brp: ?*const [@import("../../common/crypto/kzg/root.zig").field_elements_per_blob][32]u8,
    options: client.client.Options,
    witness: ?*store_module.Store,
) Error!offline.Verdict {
    assert(store.count() > 0);
    assert(witness != store);
    var recording: recording_module.Recording = .{
        .inner = store.fetcher(),
        .witness = witness orelse store,
    };
    const fetcher = if (witness != null) recording.fetcher() else store.fetcher();
    var handler: handler_module.Handler = .{
        .store = store,
        .source = source,
        .roots_brp = roots_brp,
    };
    var harness: preimage.InProcess = undefined;
    harness.init(allocator, fetcher, handler.router(), .{ .channel_bytes = 1 << 20 }) catch
        return error.NativeFailed;
    defer harness.deinit(allocator);
    const io: client.Client.Io = .{
        .oracle = harness.oracle_reader(),
        .hints = harness.hint_writer(),
    };
    const outcome = client.run(allocator, io, options) catch |err| {
        if (handler.last_error) |cause| std.log.warn("proof: host failed: {t}", .{cause});
        return err;
    };
    var scratch: [program.boot.rollup_config_bytes_max]u8 = undefined;
    const boot = try program.BootInfo.load(harness.oracle_reader(), &scratch);
    const holds = client.claim_holds(&boot, &outcome);
    if (recording.dropped > 0) return error.NativeFailed;
    const claimed = boot.claimed_l2_output_root;
    return .{ .outcome = outcome, .claimed_output_root = claimed, .holds = holds };
}

const testing = std.testing;

test "native: output root of a raw header" {
    var buffer: [1024]u8 = undefined;
    const header: consensus.Header = .{
        .number = 7,
        .state_root = .{ .bytes = @splat(1) },
        .withdrawals_root = .{ .bytes = @splat(2) },
        .base_fee_per_gas = 1,
    };
    const raw = rlp.encode_to(&buffer, header);
    const output: program.sync.OutputRoot = .{
        .state_root = @splat(1),
        .message_passer_storage_root = @splat(2),
        .block_hash = crypto.keccak256(raw),
    };
    try testing.expectEqual(crypto.keccak256(&output.encode()), try output_root_of(raw));
    const pre_shanghai = rlp.encode_to(&buffer, consensus.Header{ .number = 7 });
    try testing.expectError(error.InvalidHeader, output_root_of(pre_shanghai));
    try testing.expectError(error.InvalidHeader, output_root_of("junk"));
}
