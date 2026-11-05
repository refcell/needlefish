//! A submitter that sends nothing (base/base `DryRunProposer`): each creation is logged
//! and reported mined, so the pipeline runs end to end without an L1 key. The game is then
//! not found by its lookup, and the pipeline restarts as base/base's does.

const std = @import("std");
const assert = std.debug.assert;

const factory = @import("../contracts/dispute_game_factory.zig");
const interfaces = @import("interfaces.zig");

const log = std.log.scoped(.proposer);

pub const DryRun = struct {
    sent: u64 = 0,
    /// The last creation's game type and root claim (the extra data is not kept).
    last: ?struct { game_type: u32, root_claim: [32]u8 } = null,

    pub fn submitter(dry_run: *DryRun) interfaces.Submitter {
        return .{ .context = dry_run, .vtable = &vtable };
    }

    const vtable: interfaces.Submitter.VTable = .{ .send = send, .status = status };

    fn send(context: *anyopaque, calldata: []const u8) interfaces.SendResult {
        const dry_run: *DryRun = @ptrCast(@alignCast(context));
        const create = factory.decode_create(calldata) catch return .{ .failed = .reverted };
        dry_run.sent += 1;
        dry_run.last = .{ .game_type = create.game_type, .root_claim = create.root_claim };
        log.info("dry run: would create game type {d} root 0x{x}", .{
            create.game_type,
            &create.root_claim,
        });
        assert(dry_run.sent > 0);
        return .{ .pending = dry_run.sent };
    }

    fn status(context: *anyopaque, tx: interfaces.TxId) interfaces.TxStatus {
        const dry_run: *DryRun = @ptrCast(@alignCast(context));
        assert(tx > 0);
        if (tx > dry_run.sent) return .{ .failed = .dropped };
        return .mined;
    }
};

test "dry run: decodes, logs and reports mined" {
    var dry_run: DryRun = .{};
    const submitter = dry_run.submitter();
    var buffer: [512]u8 = undefined;
    const extra: [factory.extra_data_prefix_bytes]u8 = @splat(1);
    const calldata = try factory.encode_create(&buffer, 621, @splat(4), &extra, "proof");
    const sent = submitter.send(calldata);
    try std.testing.expectEqual(interfaces.TxId, @TypeOf(sent.pending));
    try std.testing.expect(submitter.status(sent.pending) == .mined);
    try std.testing.expectEqual(@as(u32, 621), dry_run.last.?.game_type);
    const junk: [4 + 32 * 4]u8 = @splat(0xff);
    try std.testing.expect(submitter.send(&junk) == .failed);
}
