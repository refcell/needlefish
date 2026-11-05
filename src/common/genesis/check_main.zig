//! `zig build genesischeck -- <genesis.json>...`: parity check of base/base genesis files
//! (fetched by `just vectors` into `.cache/vectors/base-genesis/`) against the canonical
//! chain data in `common.chains`. For each file: parse, compute the state root and the
//! genesis header, and require the header hash to equal the chain's `genesis_l2_hash`
//! (when the chain id is known and the hash is pinned).

const std = @import("std");
const base = @import("base");
const genesis_module = base.common.genesis;
const chains = base.common.chains;
const Io = std.Io;

const Outcome = enum { match, mismatch, unpinned };

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const gpa = std.heap.smp_allocator;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2) {
        std.debug.print("usage: genesischeck <genesis.json>...\n", .{});
        return 2;
    }
    var failed: u32 = 0;
    for (args[1..]) |path| {
        const outcome = check(io, gpa, path) catch |err| {
            std.debug.print("ERROR {s}: {t}\n", .{ path, err });
            failed += 1;
            continue;
        };
        failed += @intFromBool(outcome == .mismatch);
    }
    std.debug.print("genesischeck: files={d} failed={d}\n", .{ args.len - 1, failed });
    return if (failed == 0) 0 else 1;
}

fn check(io: Io, gpa: std.mem.Allocator, path: []const u8) !Outcome {
    const bytes = try Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 << 20));
    defer gpa.free(bytes);
    const parsed = try genesis_module.json.parse(gpa, bytes);
    defer parsed.deinit();
    const genesis = &parsed.value;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    const state_root = try genesis_module.state.state_root(allocator, genesis.accounts);
    const header = try genesis.header(allocator, state_root);
    const hash = header.hash();
    const chain_id = genesis.config.chain_id;
    const chain = chains.by_chain_id(chain_id) orelse {
        std.debug.print("UNPINNED {s}: chain {d} hash {f}\n", .{ path, chain_id, hash });
        return .unpinned;
    };
    if (chain.genesis_l2_hash.eql(.zero)) {
        std.debug.print("UNPINNED {s}: chain {d} hash {f}\n", .{ path, chain_id, hash });
        return .unpinned;
    }
    if (!chain.genesis_l2_hash.eql(hash)) {
        std.debug.print("MISMATCH {s}: chain {d} computed {f} expected {f}\n", .{
            path, chain_id, hash, chain.genesis_l2_hash,
        });
        return .mismatch;
    }
    std.debug.print("OK {s}: chain {d} accounts {d} hash {f}\n", .{
        path, chain_id, genesis.accounts.len, hash,
    });
    return .match;
}
