//! `base proof verify-tee`: checks a TEE proof receipt offline. Reads a `prover_getProof`
//! JSON-RPC response (or its bare `result`), rebuilds the journal `AggregateVerifier` signs
//! over, and prints the recovered signer (base/base `snark-e2e`'s receipt check, for TEE).

const std = @import("std");
const Io = std.Io;
const base = @import("base");

const json = base.utilities.json;
const proof = base.proof;
const protocol = proof.prover_service.protocol;
const codec = proof.prover_service.codec;
const verify = proof.tee.verify;

pub const usage =
    \\       base proof verify-tee --response <file> --proposer <addr> --starting-block <n>
    \\                      --prev-output-root <hex> --claimed-output-root <hex>
    \\                      --claimed-block <n> [--tee-image-hash <hex>] [--signer <addr>]
    \\
;

const response_bytes_max = 1 << 20;

pub const Flags = struct {
    response: []const u8 = "",
    expected: verify.Expected = .{
        .proposer = @splat(0),
        .starting_l2_block = 0,
        .prev_output_root = @splat(0),
        .claimed_output_root = @splat(0),
        .claimed_l2_block_number = 0,
        .tee_image_hash = @splat(0),
    },
    signer: ?[20]u8 = null,
};

pub fn parse(args: []const []const u8) error{InvalidArguments}!Flags {
    var flags: Flags = .{};
    var seen: u8 = 0;
    var index: usize = 0;
    while (index + 1 < args.len) : (index += 2) {
        const name = args[index];
        const value = args[index + 1];
        const expected = &flags.expected;
        if (std.mem.eql(u8, name, "--response")) {
            flags.response = value;
            seen |= 1;
        } else if (std.mem.eql(u8, name, "--proposer")) {
            expected.proposer = try fixed(20, value);
        } else if (std.mem.eql(u8, name, "--starting-block")) {
            expected.starting_l2_block = try number(value);
            seen |= 2;
        } else if (std.mem.eql(u8, name, "--prev-output-root")) {
            expected.prev_output_root = try fixed(32, value);
            seen |= 4;
        } else if (std.mem.eql(u8, name, "--claimed-output-root")) {
            expected.claimed_output_root = try fixed(32, value);
            seen |= 8;
        } else if (std.mem.eql(u8, name, "--claimed-block")) {
            expected.claimed_l2_block_number = try number(value);
            seen |= 16;
        } else if (std.mem.eql(u8, name, "--tee-image-hash")) {
            expected.tee_image_hash = try fixed(32, value);
        } else if (std.mem.eql(u8, name, "--signer")) {
            flags.signer = try fixed(20, value);
        } else return error.InvalidArguments;
    }
    if (index != args.len or seen != 31) return error.InvalidArguments;
    std.debug.assert(flags.response.len > 0);
    return flags;
}

fn fixed(comptime size: usize, value: []const u8) error{InvalidArguments}![size]u8 {
    return json.parse_fixed(size, value) catch error.InvalidArguments;
}

fn number(value: []const u8) error{InvalidArguments}!u64 {
    return std.fmt.parseUnsigned(u64, value, 10) catch error.InvalidArguments;
}

/// The TEE result inside a `prover_getProof` response or its bare result object.
pub fn decode_result(
    arena: std.mem.Allocator,
    bytes: []const u8,
) error{ InvalidResponse, NotSucceeded, NotTee }!protocol.TeeProofResult {
    const enveloped = json.find_path(bytes, &.{"result"}) catch return error.InvalidResponse;
    const raw = enveloped orelse bytes;
    const response = codec.decode(protocol.GetProofResponse, arena, raw) catch
        return error.InvalidResponse;
    if (response.status != .succeeded) return error.NotSucceeded;
    const result = response.result orelse return error.NotSucceeded;
    return switch (result) {
        .tee => |tee| tee,
        .compressed, .snark_plonk => error.NotTee,
    };
}

pub fn main(init: std.process.Init, flags: *const Flags) !u8 {
    var arena_state: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const bytes = try Io.Dir.cwd().readFileAlloc(init.io, flags.response, arena, .limited(
        response_bytes_max,
    ));
    const result = decode_result(arena, bytes) catch |err| {
        std.debug.print("proof: verify-tee: {t}\n", .{err});
        return 1;
    };
    const signer = verify.recover_signer(&result, &flags.expected) catch |err| {
        std.debug.print("proof: verify-tee: {t}\n", .{err});
        return 1;
    };
    if (flags.signer) |wanted| {
        if (!std.mem.eql(u8, &wanted, &signer)) {
            const line = "proof: verify-tee: signed by 0x{x}, not 0x{x}\n";
            std.debug.print(line, .{ &signer, &wanted });
            return 1;
        }
    }
    std.debug.print("proof: verify-tee: block {d} signed by 0x{x}\n", .{
        result.aggregate_proposal.l2_block_number,
        &signer,
    });
    return 0;
}

test "proof verify-tee: flags and response decoding" {
    const root = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const zero = "0x0000000000000000000000000000000000000000";
    const args = [_][]const u8{
        "--response",       "r.json", "--proposer",            zero,
        "--starting-block", "10",     "--prev-output-root",    root,
        "--claimed-block",  "14",     "--claimed-output-root", root,
    };
    const flags = try parse(&args);
    try std.testing.expectEqual(@as(u64, 14), flags.expected.claimed_l2_block_number);
    try std.testing.expectError(error.InvalidArguments, parse(args[0..8]));
    try std.testing.expectError(error.InvalidArguments, parse(args[0..9]));
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const queued = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"status\":\"queued\"}}";
    try std.testing.expectError(error.NotSucceeded, decode_result(arena, queued));
    try std.testing.expectError(error.InvalidResponse, decode_result(arena, "{\"result\":7}"));
}
