//! Enclave signers against the onchain `TEEProverRegistry` (base/base
//! `crates/proof/tee/nitro-host/src/registration.rs`).
//!
//! Health accepts a currently valid signer, or a signer whose registered image hash is the
//! configured nonzero pending hash (so the next image can deploy before onchain
//! activation). Once healthy it stays healthy, so a transient L1 failure does not replace
//! the instance. Proving and enclave routing always check current validity and never
//! accept the pending hash.
//!
//! The registry is an interface: its L1 `eth_call`s (`isValidSigner`, `signerImageHash`)
//! and their timeout (ten seconds in base/base) belong to the implementation's
//! `utilities/io` client. Every check here is a bounded loop over at most `enclaves_max`
//! links.

const std = @import("std");
const assert = std.debug.assert;

const link_module = @import("link.zig");

const Link = link_module.Link;
pub const Address = [20]u8;
pub const Hash = [32]u8;

/// Most enclaves one host fronts (base/base deploys one or two per instance).
pub const enclaves_max = 8;

pub const RegistryError = error{
    /// The L1 call failed or timed out.
    RegistryUnavailable,
};

/// base/base `TEEProverRegistryClient`.
pub const Registry = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        is_valid_signer: *const fn (context: *anyopaque, signer: Address) RegistryError!bool,
        signer_image_hash: *const fn (context: *anyopaque, signer: Address) RegistryError!Hash,
    };

    pub fn is_valid_signer(registry: Registry, signer: Address) RegistryError!bool {
        return registry.vtable.is_valid_signer(registry.context, signer);
    }

    pub fn signer_image_hash(registry: Registry, signer: Address) RegistryError!Hash {
        return registry.vtable.signer_image_hash(registry.context, signer);
    }
};

pub const Error = RegistryError || error{
    /// No enclave links, too many, or a zero pending image hash.
    InvalidSetup,
    /// The enclave signer key could not be fetched or parsed.
    SignerUnavailable,
    /// The first enclave's signer is not valid in `TEEProverRegistry`.
    NotValid,
    /// Every reachable signer is invalid.
    NoValidSigner,
};

/// A signer confirmed valid onchain (base/base `ValidSigner`).
pub const ValidSigner = struct {
    /// Index into the checker's links.
    index: u32,
    signer: Address,
};

pub const Checker = struct {
    links: []const *Link,
    registry: Registry,
    pending_image_hash: ?Hash = null,
    /// Latched once health succeeded.
    healthy: bool = false,
    /// The signer of the last failed check, for diagnostics.
    last_signer: Address = @splat(0),
    /// Registry calls made (validity and image hash).
    registry_calls: u64 = 0,

    pub fn init(links: []const *Link, registry: Registry) Error!Checker {
        if (links.len == 0 or links.len > enclaves_max) return error.InvalidSetup;
        const checker: Checker = .{ .links = links, .registry = registry };
        assert(!checker.healthy);
        assert(checker.links.len <= enclaves_max);
        return checker;
    }

    /// Sets the image hash health accepts before onchain activation; zero is refused.
    pub fn with_pending_image_hash(checker: *Checker, pending: ?Hash) Error!void {
        if (pending) |hash| {
            if (std.mem.allEqual(u8, &hash, 0)) return error.InvalidSetup;
        }
        checker.pending_image_hash = pending;
        assert(checker.pending_image_hash == null or pending != null);
    }

    fn is_valid(checker: *Checker, signer: Address) RegistryError!bool {
        checker.registry_calls += 1;
        return checker.registry.is_valid_signer(signer) catch |err| {
            checker.last_signer = signer;
            return err;
        };
    }

    /// True when `signer` is registered with the pending image hash.
    fn has_pending_image(checker: *Checker, signer: Address) RegistryError!bool {
        const pending = checker.pending_image_hash orelse return false;
        assert(!std.mem.allEqual(u8, &pending, 0));
        checker.registry_calls += 1;
        const image_hash = try checker.registry.signer_image_hash(signer);
        return std.mem.eql(u8, &image_hash, &pending);
    }

    fn fetch_health(checker: *Checker) Error!bool {
        var first_error: ?RegistryError = null;
        for (checker.links) |link| {
            const signer = link.signer_address() catch continue;
            const valid = checker.is_valid(signer) catch |err| {
                if (first_error == null) first_error = err;
                continue;
            };
            if (valid) return true;
            const pending = checker.has_pending_image(signer) catch |err| {
                checker.last_signer = signer;
                if (first_error == null) first_error = err;
                continue;
            };
            if (pending) return true;
            checker.last_signer = signer;
        }
        if (first_error) |err| return err;
        return false;
    }

    /// True once any signer is valid or has the pending image; success latches.
    pub fn check_health(checker: *Checker) Error!bool {
        if (checker.healthy) return true;
        const healthy = try checker.fetch_health();
        checker.healthy = healthy;
        assert(!healthy or checker.healthy);
        return healthy;
    }

    /// Fails unless the first enclave's signer is valid now (fail closed).
    pub fn require_valid_signer(checker: *Checker) Error!void {
        assert(checker.links.len > 0);
        const signer = checker.links[0].signer_address() catch return error.SignerUnavailable;
        if (!try checker.is_valid(signer)) {
            checker.last_signer = signer;
            return error.NotValid;
        }
    }

    /// Every enclave whose signer is valid now, in link order. Registry failures for one
    /// signer are skipped; with no valid signer the first failure (L1 reachability) wins
    /// over `NoValidSigner`.
    pub fn select_all_valid(
        checker: *Checker,
        out: *[enclaves_max]ValidSigner,
    ) Error![]ValidSigner {
        assert(checker.links.len <= enclaves_max);
        var count: u32 = 0;
        var first_error: ?RegistryError = null;
        for (checker.links, 0..) |link, index| {
            const signer = link.signer_address() catch continue;
            const valid = checker.is_valid(signer) catch |err| {
                if (first_error == null) first_error = err;
                continue;
            };
            if (!valid) {
                checker.last_signer = signer;
                continue;
            }
            out[count] = .{ .index = @intCast(index), .signer = signer };
            count += 1;
        }
        assert(count <= checker.links.len);
        if (count > 0) return out[0..count];
        if (first_error) |err| return err;
        return error.NoValidSigner;
    }
};

/// A registry with fixed answers, for tests and local development.
pub const FakeRegistry = struct {
    /// Valid signers.
    valid: [enclaves_max]Address = @splat(@splat(0)),
    valid_count: u32 = 0,
    image_hash: Hash = @splat(0),
    unavailable: bool = false,
    /// Fail only calls about this signer.
    unavailable_signer: ?Address = null,
    calls: u32 = 0,

    pub fn registry(fake: *FakeRegistry) Registry {
        return .{ .context = fake, .vtable = &.{
            .is_valid_signer = is_valid_signer,
            .signer_image_hash = signer_image_hash,
        } };
    }

    pub fn allow(fake: *FakeRegistry, signer: Address) void {
        assert(fake.valid_count < enclaves_max);
        fake.valid[fake.valid_count] = signer;
        fake.valid_count += 1;
    }

    fn of(context: *anyopaque) *FakeRegistry {
        return @ptrCast(@alignCast(context));
    }

    fn fails(fake: *FakeRegistry, signer: Address) bool {
        if (fake.unavailable) return true;
        const target = fake.unavailable_signer orelse return false;
        return std.mem.eql(u8, &target, &signer);
    }

    fn is_valid_signer(context: *anyopaque, signer: Address) RegistryError!bool {
        const fake = of(context);
        fake.calls += 1;
        if (fake.fails(signer)) return error.RegistryUnavailable;
        for (fake.valid[0..fake.valid_count]) |valid| {
            if (std.mem.eql(u8, &valid, &signer)) return true;
        }
        return false;
    }

    fn signer_image_hash(context: *anyopaque, signer: Address) RegistryError!Hash {
        const fake = of(context);
        fake.calls += 1;
        if (fake.fails(signer)) return error.RegistryUnavailable;
        return fake.image_hash;
    }
};

const testing = std.testing;

const Pair = struct {
    first: *link_module.LocalEnclave,
    second: *link_module.LocalEnclave,
    links: [2]*Link,

    fn init(pair: *Pair) !void {
        pair.first = try link_module.test_local_enclave(0x41);
        errdefer pair.first.destroy();
        pair.second = try link_module.test_local_enclave(0x42);
        pair.links = .{ &pair.first.link, &pair.second.link };
    }

    fn deinit(pair: *Pair) void {
        pair.second.destroy();
        pair.first.destroy();
    }
};

test "tee registration: health latches after the first valid signer" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();
    var fake: FakeRegistry = .{};
    var checker: Checker = try .init(pair.links[0..1], fake.registry());
    try testing.expect(!try checker.check_health());
    fake.allow(pair.first.server.signer_address());
    try testing.expect(try checker.check_health());
    fake.unavailable = true;
    const calls = fake.calls;
    try testing.expect(try checker.check_health());
    try testing.expectEqual(calls, fake.calls);
}

test "tee registration: a registry failure before the latch is an error" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();
    var fake: FakeRegistry = .{ .unavailable = true };
    var checker: Checker = try .init(&pair.links, fake.registry());
    try testing.expectError(error.RegistryUnavailable, checker.check_health());
    try testing.expectError(error.RegistryUnavailable, checker.require_valid_signer());
    try testing.expect(!checker.healthy);
}

test "tee registration: a pending image passes health but never proving" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();
    const pending: Hash = @splat(0x01);
    var fake: FakeRegistry = .{ .image_hash = pending };
    var checker: Checker = try .init(&pair.links, fake.registry());
    try testing.expectError(error.InvalidSetup, checker.with_pending_image_hash(@splat(0)));
    try testing.expect(!try checker.check_health());
    try checker.with_pending_image_hash(pending);
    try testing.expect(try checker.check_health());
    try testing.expectError(error.NotValid, checker.require_valid_signer());
    var out: [enclaves_max]ValidSigner = undefined;
    try testing.expectError(error.NoValidSigner, checker.select_all_valid(&out));
}

test "tee registration: select all skips invalid and unreachable signers" {
    var pair: Pair = undefined;
    try pair.init();
    defer pair.deinit();
    const first = pair.first.server.signer_address();
    const second = pair.second.server.signer_address();
    var fake: FakeRegistry = .{ .unavailable_signer = first };
    fake.allow(second);
    var checker: Checker = try .init(&pair.links, fake.registry());
    var out: [enclaves_max]ValidSigner = undefined;
    const valid = try checker.select_all_valid(&out);
    try testing.expectEqual(@as(usize, 1), valid.len);
    try testing.expectEqual(@as(u32, 1), valid[0].index);
    try testing.expectEqual(second, valid[0].signer);
    fake.valid_count = 0;
    try testing.expectError(error.RegistryUnavailable, checker.select_all_valid(&out));
    fake.unavailable_signer = null;
    try testing.expectError(error.NoValidSigner, checker.select_all_valid(&out));
    fake.allow(first);
    fake.allow(second);
    try testing.expectEqual(@as(usize, 2), (try checker.select_all_valid(&out)).len);
}

test "tee registration: setup bounds" {
    var fake: FakeRegistry = .{};
    try testing.expectError(error.InvalidSetup, Checker.init(&.{}, fake.registry()));
}
