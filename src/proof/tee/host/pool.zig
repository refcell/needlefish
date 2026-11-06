//! A bounded pool of enclave links (base/base `crates/proof/tee/nitro-host/src/pool.rs`).
//!
//! Each enclave proves at most one request at a time (base/base
//! `MAX_CONCURRENT_PROOF_REQUESTS_PER_ENCLAVE = 1`): proving is CPU and memory bound and the
//! enclave would only queue a second request, so the host refuses it (`Busy`) and the
//! caller retries. With a registration checker only enclaves whose signer is valid onchain
//! now are candidates. Candidates are tried round robin from the enclave after the last one
//! used (base/base takes the first free one), so dual-enclave hosts spread their load.

const std = @import("std");
const assert = std.debug.assert;

const enclave = @import("../enclave/root.zig");
const link_module = @import("link.zig");
const registration = @import("registration.zig");

const Link = link_module.Link;
const protocol = enclave.protocol;

pub const enclaves_max = registration.enclaves_max;
pub const concurrent_proofs_per_enclave_max = 1;

pub const Error = link_module.LinkError || registration.Error || error{
    /// Every candidate enclave is already proving.
    Busy,
};

pub const SetupError = error{
    InvalidSetup,
    /// The checker was built over other links, or in another order: its valid-signer
    /// indices would route proofs to enclaves it never validated.
    CheckerMismatch,
};

pub const Pool = struct {
    links: []const *Link,
    busy: [enclaves_max]bool = @splat(false),
    checker: ?*registration.Checker = null,
    /// The enclave to try first next time.
    next: u32 = 0,
    /// Requests refused because every candidate was busy.
    rejected_busy: u64 = 0,
    proved: u64 = 0,
    /// The enclave of the last `prove`, for its failure message.
    last_index: ?u32 = null,

    pub fn init(links: []const *Link) SetupError!Pool {
        if (links.len == 0 or links.len > enclaves_max) return error.InvalidSetup;
        const pool: Pool = .{ .links = links };
        assert(pool.links.len > 0);
        assert(pool.next < pool.links.len);
        return pool;
    }

    /// Routes proofs only to enclaves `checker` finds valid. Same links, same order.
    pub fn set_checker(pool: *Pool, checker: *registration.Checker) SetupError!void {
        if (checker.links.len != pool.links.len) return error.CheckerMismatch;
        for (pool.links, checker.links) |ours, theirs| {
            if (ours != theirs) return error.CheckerMismatch;
        }
        pool.checker = checker;
        assert(pool.checker.?.links.len == pool.links.len);
    }

    /// Takes the next free candidate enclave; release it with `release`.
    pub fn acquire(pool: *Pool) Error!u32 {
        var candidates: [enclaves_max]bool = @splat(false);
        if (pool.checker) |checker| {
            var valid_buffer: [enclaves_max]registration.ValidSigner = undefined;
            const valid = try checker.select_all_valid(&valid_buffer);
            for (valid) |signer| candidates[signer.index] = true;
        } else {
            @memset(candidates[0..pool.links.len], true);
        }
        const count: u32 = @intCast(pool.links.len);
        var offset: u32 = 0;
        while (offset < count) : (offset += 1) {
            const index = (pool.next + offset) % count;
            if (!candidates[index] or pool.busy[index]) continue;
            pool.busy[index] = true;
            pool.next = (index + 1) % count;
            assert(pool.busy[index]);
            return index;
        }
        pool.rejected_busy += 1;
        return error.Busy;
    }

    pub fn release(pool: *Pool, index: u32) void {
        assert(index < pool.links.len);
        assert(pool.busy[index]);
        pool.busy[index] = false;
    }

    /// Proves `preimages` on a free valid enclave. The result points into that enclave's
    /// link and stays valid until its next call.
    pub fn prove(pool: *Pool, preimages: []const protocol.Preimage) Error!Proved {
        const index = try pool.acquire();
        defer pool.release(index);
        pool.last_index = index;
        const result = try pool.links[index].prove(preimages);
        pool.proved += 1;
        assert(result.intermediate_roots.len > 0);
        return .{ .index = index, .result = result };
    }

    /// base/base `ProofGenerator::ready_to_claim`: false while no signer is valid.
    pub fn ready_to_claim(pool: *Pool) bool {
        const checker = pool.checker orelse return true;
        var valid_buffer: [enclaves_max]registration.ValidSigner = undefined;
        const valid = checker.select_all_valid(&valid_buffer) catch return false;
        assert(valid.len > 0);
        return true;
    }

    /// The enclave's message for the last failed `prove`, or an empty string.
    pub fn last_failure_message(pool: *const Pool) []const u8 {
        const index = pool.last_index orelse return "";
        assert(index < pool.links.len);
        return pool.links[index].last_failure_message();
    }
};

pub const Proved = struct {
    /// The enclave that signed.
    index: u32,
    result: protocol.TeeProofResult,
};

const testing = std.testing;

const Trio = struct {
    locals: [3]*link_module.LocalEnclave,
    links: [3]*Link,

    fn init(trio: *Trio) !void {
        var created: u32 = 0;
        errdefer for (trio.locals[0..created]) |local| local.destroy();
        while (created < 3) : (created += 1) {
            trio.locals[created] = try link_module.test_local_enclave(@intCast(0x51 + created));
            trio.links[created] = &trio.locals[created].link;
        }
    }

    fn deinit(trio: *Trio) void {
        for (trio.locals) |local| local.destroy();
    }
};

test "tee pool: round robin over free enclaves, busy when all are proving" {
    var trio: Trio = undefined;
    try trio.init();
    defer trio.deinit();
    var pool: Pool = try .init(&trio.links);
    try testing.expectEqual(@as(u32, 0), try pool.acquire());
    try testing.expectEqual(@as(u32, 1), try pool.acquire());
    pool.release(0);
    try testing.expectEqual(@as(u32, 2), try pool.acquire());
    try testing.expectEqual(@as(u32, 0), try pool.acquire());
    try testing.expectError(error.Busy, pool.acquire());
    try testing.expectEqual(@as(u64, 1), pool.rejected_busy);
    pool.release(1);
    try testing.expectEqual(@as(u32, 1), try pool.acquire());
}

test "tee pool: a checker routes only to valid signers and gates claims" {
    var trio: Trio = undefined;
    try trio.init();
    defer trio.deinit();
    var fake: registration.FakeRegistry = .{};
    var checker: registration.Checker = try .init(&trio.links, fake.registry());
    var pool: Pool = try .init(&trio.links);
    try pool.set_checker(&checker);
    try testing.expect(!pool.ready_to_claim());
    try testing.expectError(error.NoValidSigner, pool.acquire());
    fake.allow(trio.locals[2].server.signer_address());
    try testing.expect(pool.ready_to_claim());
    try testing.expectEqual(@as(u32, 2), try pool.acquire());
    try testing.expectError(error.Busy, pool.acquire());
}

test "tee pool: a checker over other links is refused" {
    var trio: Trio = undefined;
    try trio.init();
    defer trio.deinit();
    var fake: registration.FakeRegistry = .{};
    var pool: Pool = try .init(&trio.links);
    var short: registration.Checker = try .init(trio.links[0..2], fake.registry());
    try testing.expectError(error.CheckerMismatch, pool.set_checker(&short));
    const swapped = [_]*Link{ trio.links[1], trio.links[0], trio.links[2] };
    var reordered: registration.Checker = try .init(&swapped, fake.registry());
    try testing.expectError(error.CheckerMismatch, pool.set_checker(&reordered));
    try testing.expectError(error.InvalidSetup, Pool.init(&.{}));
}

test "tee pool: a failed proof frees its enclave" {
    var trio: Trio = undefined;
    try trio.init();
    defer trio.deinit();
    var pool: Pool = try .init(trio.links[0..1]);
    try testing.expectError(error.EnclaveProofFailed, pool.prove(&.{}));
    try testing.expect(!pool.busy[0]);
    try testing.expectEqual(@as(u64, 0), pool.proved);
    try testing.expect(pool.last_failure_message().len > 0);
}
