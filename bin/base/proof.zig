//! `base proof`: fault-proof tooling. `replay` runs the fault-proof client offline over a
//! recorded preimage archive and reports whether the claimed output root holds
//! (base/base `base-proof-host --offline`).

const std = @import("std");
const Io = std.Io;
const base = @import("base");

const proof = base.proof;
const kzg = base.common.crypto.kzg;

const usage =
    \\usage: base proof replay <archive>
    \\
    \\  replay   run the fault-proof client over a recorded preimage archive;
    \\           exit 0 if the claimed output root holds, 1 if it does not
    \\
;

/// Largest archive the CLI loads.
const archive_bytes_max = 4 << 30;

pub const Command = union(enum) {
    replay: []const u8,
};

pub fn parse(args: []const []const u8) error{InvalidArguments}!Command {
    if (args.len != 2) return error.InvalidArguments;
    if (std.mem.eql(u8, args[0], "replay")) return .{ .replay = args[1] };
    return error.InvalidArguments;
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    const command = parse(args) catch {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    const path = command.replay;
    const allocator = init.gpa;
    const bytes = try Io.Dir.cwd().readFileAlloc(
        init.io,
        path,
        allocator,
        .limited(archive_bytes_max),
    );
    defer allocator.free(bytes);
    const storage = try allocator.create(kzg.blob.Settings.Storage);
    defer allocator.destroy(storage);
    const workspace = try allocator.create(kzg.blob.Workspace);
    defer allocator.destroy(workspace);
    const settings = try kzg.blob.Settings.init(storage);
    const verdict = proof.host.offline.replay(allocator, bytes, .{
        .builder = proof.client.client.default_builder_config,
        .kzg_settings = &settings,
        .kzg_workspace = workspace,
    }) catch |err| {
        std.debug.print("proof: replay failed: {t}\n", .{err});
        return 2;
    };
    std.debug.print("proof: block {d} output root 0x{x} claimed 0x{x}: {s}\n", .{
        verdict.outcome.block_number,
        verdict.outcome.output_root,
        verdict.claimed_output_root,
        if (verdict.holds) "holds" else "does not hold",
    });
    return if (verdict.holds) 0 else 1;
}

test "proof: argument parsing" {
    const replay = try parse(&.{ "replay", "run.nfpa" });
    try std.testing.expectEqualStrings("run.nfpa", replay.replay);
    try std.testing.expectError(error.InvalidArguments, parse(&.{"replay"}));
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "record", "x" }));
}
