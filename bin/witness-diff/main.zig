//! `witness-diff`: compare two execution witnesses (`debug_executionWitness` results) and
//! report the trie nodes, codes, keys, accounts, and storage slots where they diverge.
//! Port of base/base `etc/tools/witness-diff`; the analysis is `execution.db.witness_diff`.
//!
//!   witness-diff --local FILE --remote FILE
//!   witness-diff --local FILE --rpc-url URL --block N
//!
//! A file holds the witness object (`.result` of the RPC response) or the whole response.
//! `--block` is decimal; the remote witness is fetched with `debug_executionWitness`.
//! Exit codes (as the reference): 0 when the diff ran (identical or not), 1 on an error,
//! 2 on bad usage.

const std = @import("std");
const base = @import("base");
const Io = std.Io;

const witness_diff = base.execution.db.witness_diff;
const lazy = base.utilities.lazy_alloc;
const Witness = witness_diff.Witness;

const assert = std.debug.assert;

const usage =
    \\usage: witness-diff --local FILE (--remote FILE | --rpc-url URL --block N)
    \\
    \\  --local FILE     local witness JSON (the `result` object or a whole RPC response)
    \\  --remote FILE    reference witness JSON file
    \\  --rpc-url URL    reference node (http:// or https://) to fetch the witness from
    \\  --block N        decimal block number for debug_executionWitness
    \\
;

/// Upper bounds for one witness. Buffers are committed only when written.
const witness_config: Witness.Config = .{
    .state_nodes_max = 1 << 19,
    .state_bytes_max = 256 << 20,
    .codes_max = 1 << 14,
    .code_bytes_max = 256 << 20,
    .keys_max = 1 << 19,
    .headers_max = 256,
    .header_bytes_max = 1 << 20,
};
const input_bytes_max = 1 << 30;
const item_bytes_max = 1 << 20;

const Flags = struct {
    local: ?[]const u8 = null,
    remote: ?[]const u8 = null,
    rpc_url: ?[]const u8 = null,
    block: ?u64 = null,
};

const UsageError = error{ MissingFlagValue, UnknownFlag, InvalidBlock, Help };

fn parse_flags(args: []const []const u8) UsageError!Flags {
    var flags: Flags = .{};
    var index: usize = 0;
    while (index < args.len) : (index += 1) {
        const arg = args[index];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) return error.Help;
        if (index + 1 >= args.len) return error.MissingFlagValue;
        index += 1;
        const value = args[index];
        if (std.mem.eql(u8, arg, "--local")) {
            flags.local = value;
        } else if (std.mem.eql(u8, arg, "--remote")) {
            flags.remote = value;
        } else if (std.mem.eql(u8, arg, "--rpc-url")) {
            flags.rpc_url = value;
        } else if (std.mem.eql(u8, arg, "--block")) {
            flags.block = std.fmt.parseInt(u64, value, 10) catch return error.InvalidBlock;
        } else return error.UnknownFlag;
    }
    return flags;
}

/// Exactly one source for the remote witness: a file, or a URL with a block.
fn valid(flags: *const Flags) bool {
    if (flags.local == null) return false;
    if (flags.remote != null) return flags.rpc_url == null and flags.block == null;
    if (flags.rpc_url) |url| {
        const scheme = std.mem.startsWith(u8, url, "http://") or
            std.mem.startsWith(u8, url, "https://");
        return scheme and flags.block != null;
    }
    return false;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const flags = parse_flags(args[1..]) catch |err| {
        if (err != error.Help) std.debug.print("witness-diff: {t}\n", .{err});
        std.debug.print("{s}", .{usage});
        std.process.exit(if (err == error.Help) 0 else 2);
    };
    if (!valid(&flags)) {
        std.debug.print("{s}", .{usage});
        std.process.exit(2);
    }
    run(init, &flags) catch |err| {
        std.debug.print("witness-diff: {t}\n", .{err});
        std.process.exit(1);
    };
}

fn run(init: std.process.Init, flags: *const Flags) !void {
    assert(valid(flags));
    const gpa = init.gpa;
    var buffer: [64 * 1024]u8 = undefined;
    var stdout = Io.File.stdout().writer(init.io, &buffer);
    const out = &stdout.interface;

    var parser = try witness_diff.Parser.init(gpa, item_bytes_max);
    defer parser.deinit(gpa);
    var local = try Witness.init(gpa, witness_config);
    defer local.deinit(gpa);
    var remote = try Witness.init(gpa, witness_config);
    defer remote.deinit(gpa);
    const input = try lazy.alloc(gpa, u8, input_bytes_max);
    defer lazy.free(gpa, input);

    try out.print("Reading local witness from: {s}\n", .{flags.local.?});
    try out.flush();
    try load_file(init.io, flags.local.?, input, &parser, &local);
    try print_counts(out, "Local: ", &local);
    if (flags.remote) |path| {
        try out.print("Reading remote witness from: {s}\n", .{path});
        try out.flush();
        try load_file(init.io, path, input, &parser, &remote);
    } else {
        try out.print("Fetching remote witness for block #{d} from {s}\n", .{
            flags.block.?, flags.rpc_url.?,
        });
        try out.flush();
        const body = try fetch(gpa, init.io, flags.rpc_url.?, flags.block.?, input);
        try parse_reporting(&parser, body, &remote);
    }
    try print_counts(out, "Remote:", &remote);

    var differ = try witness_diff.Differ.init(gpa, .from_witness(witness_config));
    defer differ.deinit();
    const report = try differ.diff(&local, &remote);
    try out.writeAll("\n");
    try witness_diff.render(out, &differ, &report, &local, &remote);
    try out.flush();
}

fn print_counts(out: *Io.Writer, label: []const u8, w: *const Witness) !void {
    try out.print("  {s} {d} state nodes, {d} codes, {d} keys\n", .{
        label, w.state.count, w.codes.count, w.keys.count,
    });
}

fn load_file(
    io: Io,
    path: []const u8,
    input: []u8,
    parser: *witness_diff.Parser,
    out: *Witness,
) !void {
    assert(input.len == input_bytes_max);
    const text = Io.Dir.cwd().readFile(io, path, input) catch |err| {
        std.debug.print("witness-diff: cannot read {s}: {t}\n", .{ path, err });
        return err;
    };
    if (text.len == input.len) return error.InputTooLarge;
    try parse_reporting(parser, text, out);
}

fn parse_reporting(parser: *witness_diff.Parser, text: []const u8, out: *Witness) !void {
    parser.parse(text, out) catch |err| {
        if (err == error.RpcError) {
            const message = base.utilities.json.find_path(text, &.{"error"}) catch null;
            std.debug.print("witness-diff: rpc error: {s}\n", .{message orelse "?"});
        }
        return err;
    };
}

/// POSTs `debug_executionWitness(block)` to `url`; returns the response body in `response`.
fn fetch(
    gpa: std.mem.Allocator,
    io: Io,
    url: []const u8,
    block: u64,
    response: []u8,
) ![]const u8 {
    var request: [128]u8 = undefined;
    const body = try std.fmt.bufPrint(&request,
        \\{{"jsonrpc":"2.0","id":1,"method":"debug_executionWitness","params":["0x{x}"]}}
    , .{block});
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    var writer: Io.Writer = .fixed(response);
    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .payload = body,
        .headers = .{ .content_type = .{ .override = "application/json" } },
        .response_writer = &writer,
    }) catch |err| switch (err) {
        error.WriteFailed => return error.InputTooLarge,
        else => return err,
    };
    if (result.status != .ok) {
        std.debug.print("witness-diff: http status {d}\n", .{@backingInt(result.status)});
        return error.HttpStatus;
    }
    return writer.buffered();
}

test "witness-diff: flags" {
    const both = try parse_flags(&.{ "--local", "a.json", "--remote", "b.json" });
    try std.testing.expect(valid(&both));
    const rpc = try parse_flags(&.{ "--local", "a", "--rpc-url", "http://x:8545", "--block", "7" });
    try std.testing.expect(valid(&rpc));
    try std.testing.expectEqual(@as(u64, 7), rpc.block.?);
    const mixed = try parse_flags(&.{ "--local", "a", "--remote", "b", "--block", "7" });
    try std.testing.expect(!valid(&mixed));
    const no_block = try parse_flags(&.{ "--local", "a", "--rpc-url", "http://x" });
    try std.testing.expect(!valid(&no_block));
    try std.testing.expectError(error.UnknownFlag, parse_flags(&.{ "--x", "1" }));
    try std.testing.expectError(error.MissingFlagValue, parse_flags(&.{"--local"}));
    try std.testing.expectError(error.InvalidBlock, parse_flags(&.{ "--block", "0x1" }));
}
