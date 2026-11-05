//! `base proof run`: native mode. Proves an L2 claim against live L1/L2 execution RPC
//! endpoints (the needlefish node's `debug_*` methods), reports the verdict, and records
//! every preimage read into an archive that `base proof replay` checks offline.

const std = @import("std");
const Io = std.Io;
const base = @import("base");
const consensus_cli = @import("consensus.zig");

const io = base.utilities.io;
const http = base.utilities.http;
const proof = base.proof;
const host = proof.host;
const kzg = base.common.crypto.kzg;
const crypto = base.common.crypto;
const protocol = base.consensus.protocol;

const Source = host.rpc_source.RpcSource(io.IO);

pub const Flags = struct {
    l1: ?[]const u8 = null,
    l2: ?[]const u8 = null,
    rollup_config: ?[]const u8 = null,
    agreed: ?u64 = null,
    claimed: ?u64 = null,
    /// L1 head block number (default: latest).
    l1_head: ?u64 = null,
    /// Claimed output root (default: the L2 endpoint's own root for `claimed`).
    claim_root: ?[32]u8 = null,
    out: ?[]const u8 = null,
    /// L1 genesis JSON, for an L1 chain that is not built in (its `config` object).
    l1_genesis: ?[]const u8 = null,
};

pub fn parse(args: []const []const u8) !Flags {
    var flags: Flags = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 2) {
        if (index + 1 == args.len) return error.InvalidArguments;
        const name = args[index];
        const value = args[index + 1];
        if (std.mem.eql(u8, name, "--l1")) {
            flags.l1 = value;
        } else if (std.mem.eql(u8, name, "--l2")) {
            flags.l2 = value;
        } else if (std.mem.eql(u8, name, "--rollup-config")) {
            flags.rollup_config = value;
        } else if (std.mem.eql(u8, name, "--agreed")) {
            flags.agreed = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, name, "--claimed")) {
            flags.claimed = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, name, "--l1-head")) {
            flags.l1_head = try std.fmt.parseInt(u64, value, 10);
        } else if (std.mem.eql(u8, name, "--claim-root")) {
            flags.claim_root = try base.utilities.json.parse_fixed(32, value);
        } else if (std.mem.eql(u8, name, "--out")) {
            flags.out = value;
        } else if (std.mem.eql(u8, name, "--l1-genesis")) {
            flags.l1_genesis = value;
        } else return error.InvalidArguments;
    }
    const required = [_]bool{
        flags.l1 != null,
        flags.l2 != null,
        flags.rollup_config != null,
        flags.agreed != null,
        flags.claimed != null,
    };
    for (required) |present| if (!present) return error.MissingFlag;
    if (flags.claimed.? <= flags.agreed.?) return error.InvalidArguments;
    return flags;
}

const Endpoints = struct {
    os_io: io.IO,
    l1: Source.Client,
    l2: Source.Client,

    fn step(context: *anyopaque) anyerror!void {
        const os_io: *io.IO = @ptrCast(@alignCast(context));
        try os_io.run_for_ns(std.time.ns_per_ms);
    }
};

const response_bytes_max = 256 << 20;

fn connect(endpoints: *Endpoints, allocator: std.mem.Allocator, flags: Flags) !void {
    const builtin = @import("builtin");
    endpoints.os_io = if (builtin.os.tag == .linux) try io.IO.init(.{}) else try io.IO.init();
    errdefer endpoints.os_io.deinit();
    const options: http.client.Options = .{
        .recv_buffer_size = response_bytes_max + 64 * 1024,
        .limits = .{ .head_size_max = 8 * 1024, .body_size_max = response_bytes_max },
        .request_timeout_ns = 120 * std.time.ns_per_s,
    };
    const l1_address = try consensus_cli.parse_url(flags.l1.?);
    const l2_address = try consensus_cli.parse_url(flags.l2.?);
    endpoints.l1 = try .init(allocator, &endpoints.os_io, l1_address, options, 4096);
    errdefer endpoints.l1.deinit();
    endpoints.l2 = try .init(allocator, &endpoints.os_io, l2_address, options, 4096);
}

/// Fills the boot values and the agreed output root preimage into `store`.
fn boot(
    source: *Source,
    store: *host.Store,
    flags: Flags,
    rollup_json: []const u8,
    l1_config_json: []const u8,
) !void {
    const rollup = try protocol.rollup_json.parse(rollup_json);
    const agreed = try host.native.output_of(try source.header_by_number(.l2, flags.agreed.?));
    const agreed_root = try store.put_keccak(&agreed.encode());
    const claim_root = flags.claim_root orelse
        try host.native.output_root_of(try source.header_by_number(.l2, flags.claimed.?));
    const l1_head = crypto.keccak256(try source.header_by_number(.l1, flags.l1_head));
    try store.put_boot(&.{
        .l1_head = l1_head,
        .agreed_l2_output_root = agreed_root,
        .claimed_l2_output_root = claim_root,
        .claimed_l2_block_number = flags.claimed.?,
        .chain_id = rollup.l2_chain_id,
        .rollup_config_json = rollup_json,
        .l1_config_json = l1_config_json,
    });
}

fn read_optional(init: std.process.Init, path: ?[]const u8) ![]u8 {
    const file = path orelse return init.gpa.alloc(u8, 0);
    const limit: Io.Limit = .limited(256 << 20);
    return Io.Dir.cwd().readFileAlloc(init.io, file, init.gpa, limit);
}

fn write_archive(init: std.process.Init, store: *const host.Store, path: []const u8) !void {
    const allocator = init.gpa;
    const keys = try allocator.alloc([32]u8, store.count());
    defer allocator.free(keys);
    const bytes = try allocator.alloc(u8, @intCast(host.archive.encoded_bytes(store)));
    defer allocator.free(bytes);
    var writer: Io.Writer = .fixed(bytes);
    try host.archive.encode(store, keys, &writer);
    try Io.Dir.cwd().writeFile(init.io, .{ .sub_path = path, .data = bytes });
}

pub fn main(init: std.process.Init, flags: Flags) !u8 {
    const allocator = init.gpa;
    const rollup_json = try Io.Dir.cwd().readFileAlloc(
        init.io,
        flags.rollup_config.?,
        allocator,
        .limited(proof.program.boot.rollup_config_bytes_max),
    );
    defer allocator.free(rollup_json);
    const endpoints = try allocator.create(Endpoints);
    defer allocator.destroy(endpoints);
    try connect(endpoints, allocator, flags);
    defer endpoints.os_io.deinit();
    defer endpoints.l1.deinit();
    defer endpoints.l2.deinit();
    var source: Source = .init(allocator, &endpoints.l1, &endpoints.l2, .{
        .context = &endpoints.os_io,
        .step = Endpoints.step,
    }, .{ .steps_max = 300_000 });
    defer source.deinit();
    var store: host.Store = .init(allocator, .{});
    defer store.deinit();
    const l1_genesis = try read_optional(init, flags.l1_genesis);
    defer allocator.free(l1_genesis);
    const l1_config = try base.utilities.json.find_path(l1_genesis, &.{"config"}) orelse "";
    try boot(&source, &store, flags, rollup_json, l1_config);
    const verdict = try prove(allocator, &store, &source);
    if (flags.out) |path| try write_archive(init, &store, path);
    std.debug.print("proof: block {d} output root 0x{x} claimed 0x{x}: {s} ({d} preimages)\n", .{
        verdict.outcome.block_number,
        verdict.outcome.output_root,
        verdict.claimed_output_root,
        if (verdict.holds) "holds" else "does not hold",
        store.count(),
    });
    return if (verdict.holds) 0 else 1;
}

fn prove(
    allocator: std.mem.Allocator,
    store: *host.Store,
    source: *Source,
) !host.offline.Verdict {
    const storage = try allocator.create(kzg.blob.Settings.Storage);
    defer allocator.destroy(storage);
    const workspace = try allocator.create(kzg.blob.Workspace);
    defer allocator.destroy(workspace);
    const roots = try allocator.create([kzg.field_elements_per_blob][32]u8);
    defer allocator.destroy(roots);
    host.handler.fill_roots(roots);
    const settings = try kzg.blob.Settings.init(storage);
    return host.native.run(allocator, store, source.as_source(), roots, .{
        .builder = proof.client.client.default_builder_config,
        .kzg_settings = &settings,
        .kzg_workspace = workspace,
    });
}

test "proof run: flags" {
    const flags = try parse(&.{
        "--l1",            "http://127.0.0.1:8545", "--l2",     "http://127.0.0.1:9545",
        "--rollup-config", "rollup.json",           "--agreed", "4",
        "--claimed",       "9",                     "--out",    "run.nfpa",
    });
    try std.testing.expectEqual(@as(u64, 9), flags.claimed.?);
    try std.testing.expectEqualStrings("run.nfpa", flags.out.?);
    try std.testing.expectError(error.MissingFlag, parse(&.{ "--l1", "http://1.2.3.4:5" }));
    try std.testing.expectError(error.InvalidArguments, parse(&.{"--l1"}));
}
