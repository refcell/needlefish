//! Unsafe block signer watcher: reads the signer address from the L1 SystemConfig contract
//! storage (base/base `P2PArgs::unsafe_block_signer`, slot
//! `keccak256("systemconfig.unsafeblocksigner") - 1`) and re-reads it periodically so a
//! signer rotation reaches gossip validation. base/base reads it once at startup with
//! retries; polling also covers a node started before L1 had the contract.
//!
//! Tick-driven and non-blocking like `L1Watcher`: at most one `eth_getStorageAt` in flight,
//! retried after `retry_interval_ns` on failure. A zero word (contract not deployed yet or
//! L1 still syncing) leaves the signer unknown, so callers keep their fallback signer.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const http_client = @import("../../utilities/http/client.zig");
const primitives = @import("../../common/primitives/root.zig");

const Address = primitives.Address;

/// `bytes32(uint256(keccak256("systemconfig.unsafeblocksigner")) - 1)`.
pub const storage_slot = "0x65a7ed542fb37fe237fdfbdd70b31598523fe5b32879e307bae27a0bd9581c08";

pub const Options = struct {
    poll_interval_ns: u64 = 60 * std.time.ns_per_s,
    retry_interval_ns: u64 = 2 * std.time.ns_per_s,
};

pub const Stats = struct { requests: u64 = 0, failures: u64 = 0, zero_words: u64 = 0 };

const request_size_max = 512;

/// Parses a JSON storage word (`"0x" ++ up to 64 hex digits`) into 32 big-endian bytes.
pub fn parse_storage_word(raw: []const u8) error{InvalidWord}![32]u8 {
    if (raw.len < 4 or raw[0] != '"' or raw[raw.len - 1] != '"') return error.InvalidWord;
    const text = raw[1 .. raw.len - 1];
    if (!std.mem.startsWith(u8, text, "0x")) return error.InvalidWord;
    const digits = text[2..];
    if (digits.len == 0 or digits.len > 64) return error.InvalidWord;
    var word: [32]u8 = @splat(0);
    // Right-align: digit i (from the end) lands in nibble i of the word.
    for (digits, 0..) |digit, index| {
        const value = std.fmt.charToDigit(digit, 16) catch return error.InvalidWord;
        const nibble = digits.len - 1 - index;
        const byte = 31 - nibble / 2;
        word[byte] |= if (nibble % 2 == 0) value else value << 4;
    }
    assert(word.len == 32);
    return word;
}

/// The address held in the low 20 bytes of `word`, or null for the zero word.
pub fn signer_of(word: [32]u8) ?Address {
    if (std.mem.allEqual(u8, &word, 0)) return null;
    const address: Address = .{ .bytes = word[12..32].* };
    if (std.mem.allEqual(u8, &address.bytes, 0)) return null;
    return address;
}

pub fn SignerWatcher(comptime IO: type) type {
    return struct {
        const Self = @This();
        pub const Rpc = rpc.Client(IO);

        io: *IO,
        client: Rpc,
        options: Options,
        system_config: Address,
        /// The newest non-zero signer read from L1.
        signer: ?Address = null,
        /// Bumped whenever `signer` changes.
        version: u64 = 0,
        due_ns: u64 = 0,
        in_flight: bool = false,
        stats: Stats = .{},

        /// `watcher` must not move afterwards while a request is in flight.
        pub fn init(
            watcher: *Self,
            allocator: Allocator,
            io: *IO,
            address: rpc.client.Address,
            http_options: http_client.Options,
            system_config: Address,
            options: Options,
        ) !void {
            assert(options.poll_interval_ns > 0);
            assert(!std.mem.allEqual(u8, &system_config.bytes, 0));
            const client = try Rpc.init(allocator, io, address, http_options, request_size_max);
            watcher.* = .{
                .io = io,
                .client = client,
                .options = options,
                .system_config = system_config,
            };
        }

        pub fn deinit(watcher: *Self) void {
            assert(!watcher.in_flight);
            watcher.client.deinit();
            watcher.* = undefined;
        }

        pub fn busy(watcher: *const Self) bool {
            return watcher.in_flight;
        }

        pub fn tick(watcher: *Self) void {
            watcher.client.http.tick();
            if (watcher.in_flight or watcher.client.http.busy()) return;
            const now_ns = watcher.io.now_monotonic_ns();
            if (now_ns < watcher.due_ns) return;
            watcher.due_ns = now_ns + watcher.options.poll_interval_ns;
            watcher.in_flight = true;
            watcher.stats.requests += 1;
            const method = "eth_getStorageAt";
            watcher.client.call(*Self, watcher, on_result, method, watcher, write_params) catch {
                watcher.in_flight = false;
                watcher.fail(now_ns);
            };
        }

        fn write_params(self: *Self, writer: *json.Writer) json.Writer.WriteError!void {
            try writer.data(&self.system_config.bytes);
            try writer.string(storage_slot);
            try writer.string("latest");
        }

        fn on_result(
            watcher: *Self,
            client: *Rpc,
            result: rpc.client.Error!rpc.client.Result,
        ) void {
            assert(client == &watcher.client);
            assert(watcher.in_flight);
            watcher.in_flight = false;
            const now_ns = watcher.io.now_monotonic_ns();
            const raw = switch (result catch return watcher.fail(now_ns)) {
                .ok => |raw| raw,
                .rpc_error => return watcher.fail(now_ns),
            };
            const word = parse_storage_word(raw) catch return watcher.fail(now_ns);
            const signer = signer_of(word) orelse {
                watcher.stats.zero_words += 1;
                watcher.due_ns = now_ns + watcher.options.retry_interval_ns;
                return;
            };
            if (watcher.signer == null or !watcher.signer.?.eql(signer)) watcher.version += 1;
            watcher.signer = signer;
        }

        fn fail(watcher: *Self, now_ns: u64) void {
            watcher.stats.failures += 1;
            watcher.due_ns = now_ns + watcher.options.retry_interval_ns;
            assert(!watcher.in_flight);
        }
    };
}

// ------------------------------------------------------------------------ tests

const testing = std.testing;
const sim = @import("../../utilities/io/root.zig");
const harness_module = @import("../sources/sim_harness.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const FakeRpc = harness_module.FakeRpc;
const Harness = harness_module.Harness(*FakeRpc, FakeRpc.handle);
const Watcher = SignerWatcher(sim.SimIo);

test "signer watcher: storage word parsing" {
    const word = try parse_storage_word(
        "\"0x000000000000000000000000af6e19be0f9ce7f8afd49a1824851023a8249e8a\"",
    );
    try testing.expectEqual(@as(u8, 0xaf), word[12]);
    try testing.expectEqual(@as(u8, 0x8a), word[31]);
    const short = try parse_storage_word("\"0xabc\"");
    try testing.expectEqual(@as(u8, 0x0a), short[30]);
    try testing.expectEqual(@as(u8, 0xbc), short[31]);
    try testing.expect(signer_of(try parse_storage_word("\"0x0\"")) == null);
    try testing.expectError(error.InvalidWord, parse_storage_word("\"0x\""));
    try testing.expectError(error.InvalidWord, parse_storage_word("0x12"));
    try testing.expectError(error.InvalidWord, parse_storage_word("\"0xzz\""));
    const ones: [65]u8 = @splat('1');
    var long_text: [70]u8 = undefined;
    const long = try std.fmt.bufPrint(&long_text, "\"0x{s}\"", .{&ones});
    try testing.expectError(error.InvalidWord, parse_storage_word(long));
}

test "signer watcher: seeded fuzz round-trips addresses through the storage word" {
    var prng = Prng.init(0x5167);
    for (0..512) |_| {
        var address: Address = undefined;
        prng.fill(&address.bytes);
        var text: [70]u8 = undefined;
        const hex = std.fmt.bytesToHex(address.bytes, .lower);
        const raw = try std.fmt.bufPrint(&text, "\"0x{s}\"", .{&hex});
        const parsed = signer_of(try parse_storage_word(raw));
        if (std.mem.allEqual(u8, &address.bytes, 0)) {
            try testing.expect(parsed == null);
        } else try testing.expect(parsed.?.eql(address));
    }
}

fn fuzz_word(_: void, smith: *std.testing.Smith) anyerror!void {
    var bytes: [80]u8 = undefined;
    const len = smith.slice(&bytes);
    const word = parse_storage_word(bytes[0..len]) catch return;
    _ = signer_of(word);
}

test "signer watcher: fuzz storage words" {
    try testing.fuzz({}, fuzz_word, .{});
}

test "signer watcher: reads the signer from SystemConfig storage" {
    var fake: FakeRpc = .{};
    fake.add(.{
        .method = "eth_getStorageAt",
        .params_contain = storage_slot,
        .result = "\"0x000000000000000000000000af6e19be0f9ce7f8afd49a1824851023a8249e8a\"",
    });
    var harness: Harness = undefined;
    try harness.init(&fake, 0x51);
    defer harness.deinit();
    var watcher: Watcher = undefined;
    const system_config: Address = .{ .bytes = @splat(0x5c) };
    try watcher.init(
        testing.allocator,
        &harness.client_io,
        harness.address,
        harness_module.client_options,
        system_config,
        .{},
    );
    defer watcher.deinit();
    for (0..8) |_| {
        watcher.tick();
        harness.world.run_for_ns(std.time.ns_per_s / 4);
    }
    try testing.expectEqual(@as(u8, 0xaf), watcher.signer.?.bytes[0]);
    try testing.expectEqual(@as(u64, 1), watcher.version);
    try testing.expectEqual(@as(u64, 1), watcher.stats.requests); // Next poll in 60 s.
    while (watcher.busy()) harness.world.run_for_ns(std.time.ns_per_s / 4);
}
