//! `base proof`: fault-proof tooling. `replay` runs the fault-proof client offline over a
//! recorded preimage archive and reports whether the claimed output root holds
//! (base/base `base-proof-host --offline`).

const std = @import("std");
const Io = std.Io;
const base = @import("base");

const proof = base.proof;
const proof_run = @import("proof_run.zig");
const proof_verify_tee = @import("proof_verify_tee.zig");
const kzg = base.common.crypto.kzg;

const usage =
    \\usage: base proof replay <archive>
    \\       base proof run --l1 <url> --l2 <url> --rollup-config <file>
    \\                      --agreed <n> --claimed <n> [--l1-head <n>]
    \\                      [--claim-root <hex>] [--out <archive>]
    \\                      [--l1-genesis <file>]  (L1 chains that are not built in)
    \\
++ proof_verify_tee.usage ++
    \\       base proof config-hash <rollup.json>
    \\
    \\  replay   run the fault-proof client over a recorded preimage archive
    \\  run      prove a claim against L1/L2 execution RPCs (native mode) and
    \\           optionally record the preimages into an archive
    \\  both exit 0 if the claimed output root holds, 1 if it does not
    \\  verify-tee  check a prover-service TEE receipt offline: rebuild the signed journal
    \\              and recover its signer (exit 0 when it verifies)
    \\  config-hash  print the chain's per-chain config hash (AggregateVerifier CONFIG_HASH),
    \\               as a local-mode enclave derives it for a chain without a pinned hash
    \\
;

/// Largest archive the CLI loads.
const archive_bytes_max = 4 << 30;

pub const Command = union(enum) {
    replay: []const u8,
    config_hash: []const u8,
};

pub fn parse(args: []const []const u8) error{InvalidArguments}!Command {
    if (args.len != 2) return error.InvalidArguments;
    if (std.mem.eql(u8, args[0], "replay")) return .{ .replay = args[1] };
    if (std.mem.eql(u8, args[0], "config-hash")) return .{ .config_hash = args[1] };
    return error.InvalidArguments;
}

/// The canonical config hash of a rollup config file (`PerChainConfig` with forced defaults).
fn config_hash(init: std.process.Init, path: []const u8) !u8 {
    const text = try Io.Dir.cwd().readFileAlloc(init.io, path, init.gpa, .limited(1 << 20));
    defer init.gpa.free(text);
    const rollup = base.consensus.protocol.rollup_json.parse(text) catch |err| {
        std.debug.print("proof: {s}: {t}\n", .{ path, err });
        return 2;
    };
    var config = base.proof.primitives.PerChainConfig.from_rollup_config(&rollup) orelse {
        std.debug.print("proof: {s} has no genesis system config\n", .{path});
        return 2;
    };
    config.force_defaults();
    std.debug.assert(config.chain_id == rollup.l2_chain_id);
    var buffer: [80]u8 = undefined;
    var stdout = Io.File.stdout().writer(init.io, &buffer);
    try stdout.interface.print("0x{x}\n", .{&config.hash()});
    try stdout.interface.flush();
    return 0;
}

pub fn main(init: std.process.Init, args: []const []const u8) !u8 {
    if (args.len > 0 and std.mem.eql(u8, args[0], "run")) {
        const flags = proof_run.parse(args[1..]) catch |err| {
            std.debug.print("proof: {t}\n{s}", .{ err, usage });
            return 2;
        };
        return proof_run.main(init, flags) catch |err| {
            std.debug.print("proof: run failed: {t}\n", .{err});
            return 2;
        };
    }
    if (args.len > 0 and std.mem.eql(u8, args[0], "verify-tee")) {
        const flags = proof_verify_tee.parse(args[1..]) catch |err| {
            std.debug.print("proof: {t}\n{s}", .{ err, usage });
            return 2;
        };
        return proof_verify_tee.main(init, &flags);
    }
    const command = parse(args) catch {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    const path = switch (command) {
        .replay => |replay| replay,
        .config_hash => |rollup| return config_hash(init, rollup),
    };
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
    const hash = try parse(&.{ "config-hash", "rollup.json" });
    try std.testing.expectEqualStrings("rollup.json", hash.config_hash);
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "record", "x" }));
}

test {
    _ = proof_verify_tee;
    _ = proof_run;
}
