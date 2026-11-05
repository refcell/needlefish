//! Shared fuzz helpers.
//!
//! One fuzz body serves two drivers:
//!   - `std.testing.fuzz` (coverage guided, `zig build test --fuzz`), and
//!   - a seeded deterministic driver that runs on every `zig build test`, feeding
//!     `std.testing.Smith` from `Prng` bytes so a failure reproduces from
//!     `(seed, iteration)` alone.
//!
//! Usage:
//!   test "rlp: fuzz decode" {
//!       try fuzz.run({}, fuzz_decode, .{});
//!   }
//!   fn fuzz_decode(_: void, smith: *std.testing.Smith) !void { ... }
//!
//! Byte-oriented decoders can use `run_bytes` with a `fn (ctx, []const u8) !void`.

const std = @import("std");
const assert = std.debug.assert;
const Smith = std.testing.Smith;
const Prng = @import("prng.zig").Prng;

/// Largest input the seeded driver generates. Inputs live on the stack.
pub const input_size_limit: u32 = 16 * 1024;

pub const Options = struct {
    /// Base seed. Each iteration derives its own seed from `(seed, iteration)`.
    seed: u64 = 0x6e65_6564_6c65_6669,
    /// Seeded iterations per `zig build test` run. Keep cheap: the suite runs often.
    iterations: u32 = 256,
    /// Maximum generated input size in bytes, at most `input_size_limit`.
    input_size_max: u32 = 1024,
    /// Extra inputs fed to both drivers first (regressions, interesting cases).
    corpus: []const []const u8 = &.{},
    /// Also register the body with `std.testing.fuzz` (coverage guided).
    coverage: bool = true,
};

/// Seed for one iteration. Exposed so a failure report can be replayed exactly.
pub fn iteration_seed(seed: u64, iteration: u32) u64 {
    var hasher = std.hash.Wyhash.init(seed);
    hasher.update(std.mem.asBytes(&iteration));
    return hasher.final();
}

/// Run `test_one` under the seeded driver, then under `std.testing.fuzz`.
pub fn run(
    context: anytype,
    comptime test_one: fn (@TypeOf(context), *Smith) anyerror!void,
    options: Options,
) !void {
    try run_seeded(context, test_one, options);
    if (options.coverage) {
        try std.testing.fuzz(context, test_one, .{ .corpus = options.corpus });
    }
}

/// Deterministic driver only. Runs the corpus, then `options.iterations` random inputs.
pub fn run_seeded(
    context: anytype,
    comptime test_one: fn (@TypeOf(context), *Smith) anyerror!void,
    options: Options,
) !void {
    assert(options.input_size_max <= input_size_limit);
    assert(options.iterations > 0 or options.corpus.len > 0);

    for (options.corpus) |input| {
        var smith: Smith = .{ .in = input };
        try test_one(context, &smith);
    }

    var buffer: [input_size_limit]u8 = undefined;
    var iteration: u32 = 0;
    while (iteration < options.iterations) : (iteration += 1) {
        const seed = iteration_seed(options.seed, iteration);
        const input = generate(&buffer, seed, options.input_size_max);
        assert(input.len <= options.input_size_max);
        var smith: Smith = .{ .in = input };
        test_one(context, &smith) catch |err| {
            std.debug.print(
                "fuzz: failure seed=0x{x} iteration={d} input_len={d} error={s}\n",
                .{ options.seed, iteration, input.len, @errorName(err) },
            );
            return err;
        };
    }
}

/// Byte-oriented convenience: `test_bytes` receives the raw fuzz input.
pub fn run_bytes(
    context: anytype,
    comptime test_bytes: fn (@TypeOf(context), []const u8) anyerror!void,
    options: Options,
) !void {
    const Context = @TypeOf(context);
    const Adapter = struct {
        fn test_one(inner: Context, smith: *Smith) anyerror!void {
            var buffer: [input_size_limit]u8 = undefined;
            const len = smith.slice(&buffer);
            assert(len <= buffer.len);
            try test_bytes(inner, buffer[0..len]);
        }
    };
    try run(context, Adapter.test_one, options);
}

/// Fill a prefix of `buffer` with seeded bytes. Lengths skew small: most decoder
/// bugs live in short inputs, and short inputs keep the suite fast.
///
/// `Smith` replays `.in` bytes literally: a value reads 8 little-endian bytes and
/// falls back to its minimum when they miss the range, `eos` ends on any nonzero
/// byte, and a slice reads a u32 length. Uniform random bytes therefore yield
/// minimums, instant loop ends, and empty slices. Half of the inputs are words
/// instead: little-endian u64s with skewed-small values, which land in typical ranges
/// and read as mostly-zero `eos` bytes.
fn generate(buffer: []u8, seed: u64, input_size_max: u32) []const u8 {
    assert(input_size_max <= buffer.len);
    var prng = Prng.init(seed);
    const len_max: u64 = switch (prng.below(4)) {
        0 => @min(input_size_max, 16),
        1 => @min(input_size_max, 128),
        else => input_size_max,
    };
    const len: usize = @intCast(prng.range(0, len_max));
    const input = buffer[0..len];
    if (prng.chance(1, 2)) {
        generate_words(&prng, input);
        return input;
    }
    // Mix fully random bytes with structured fills that decoders find interesting.
    switch (prng.below(4)) {
        0 => @memset(input, 0),
        1 => @memset(input, 0xff),
        else => prng.fill(input),
    }
    if (len > 0 and prng.chance(1, 2)) {
        const flips = prng.range(1, 8);
        var flip: u64 = 0;
        while (flip < flips) : (flip += 1) {
            input[@intCast(prng.below(len))] = prng.int(u8);
        }
    }
    return input;
}

fn generate_words(prng: *Prng, input: []u8) void {
    var offset: usize = 0;
    while (offset < input.len) : (offset += 8) {
        const word: u64 = switch (prng.below(8)) {
            // Booleans and `u1`s accept only 0 or 1.
            0, 1 => prng.below(2),
            2, 3 => prng.below(16),
            4, 5 => prng.below(256),
            6 => prng.below(1 << 16),
            else => prng.int(u64),
        };
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, word, .little);
        const length = @min(8, input.len - offset);
        @memcpy(input[offset..][0..length], bytes[0..length]);
    }
    assert(offset >= input.len);
}

const Spread = struct {
    seen: [21]bool = @splat(false),
    true_count: u32 = 0,
    loop_max: u32 = 0,
    slice_max: u32 = 0,
};

fn spread_values(spread: *Spread, smith: *Smith) anyerror!void {
    spread.seen[smith.valueRangeAtMost(u32, 0, 20)] = true;
    spread.true_count += @intFromBool(smith.value(bool));
    var loop: u32 = 0;
    while (loop < 64 and !smith.eosWeightedSimple(7, 1)) loop += 1;
    spread.loop_max = @max(spread.loop_max, loop);
    var buffer: [32]u8 = undefined;
    spread.slice_max = @max(spread.slice_max, smith.slice(&buffer));
}

test "fuzz: seeded inputs drive Smith past its minimums" {
    var spread: Spread = .{};
    try run_seeded(&spread, spread_values, .{ .iterations = 512 });
    var distinct: u32 = 0;
    for (spread.seen) |seen| distinct += @intFromBool(seen);
    try std.testing.expect(distinct >= 15);
    try std.testing.expect(spread.true_count >= 16);
    try std.testing.expect(spread.loop_max >= 4);
    try std.testing.expect(spread.slice_max >= 4);
}

test "fuzz: iteration seeds are distinct and stable" {
    try std.testing.expectEqual(iteration_seed(1, 0), iteration_seed(1, 0));
    try std.testing.expect(iteration_seed(1, 0) != iteration_seed(1, 1));
    try std.testing.expect(iteration_seed(1, 0) != iteration_seed(2, 0));
}

test "fuzz: generate respects bounds" {
    var buffer: [256]u8 = undefined;
    var iteration: u32 = 0;
    while (iteration < 1000) : (iteration += 1) {
        const input = generate(&buffer, iteration, 200);
        try std.testing.expect(input.len <= 200);
    }
}

const Counter = struct { calls: u32 = 0, bytes: u64 = 0 };

fn count_bytes(counter: *Counter, input: []const u8) anyerror!void {
    counter.calls += 1;
    counter.bytes += input.len;
}

test "fuzz: seeded driver is deterministic" {
    var a: Counter = .{};
    var b: Counter = .{};
    const options: Options = .{ .iterations = 64, .coverage = false, .corpus = &.{"abc"} };
    try run_bytes(&a, count_bytes, options);
    try run_bytes(&b, count_bytes, options);
    try std.testing.expectEqual(@as(u32, 65), a.calls);
    try std.testing.expectEqual(a.bytes, b.bytes);
}

fn smith_values(_: void, smith: *Smith) anyerror!void {
    const x = smith.valueRangeAtMost(u16, 3, 9);
    try std.testing.expect(x >= 3 and x <= 9);
}

test "fuzz: run with coverage target" {
    try run({}, smith_values, .{ .iterations = 32 });
}
