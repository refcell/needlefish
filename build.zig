//! needlefish build graph.
//!
//! Layout mirrors base/base: `src/` holds every library (one `base` module,
//! grouped like base/base's `crates/`), `bin/<name>/main.zig` holds binaries.
//!
//! Steps:
//!   zig build              install every binary into zig-out/bin
//!   zig build test         run all unit tests (-Dtest-filter=... to narrow)
//!   zig build fuzz         build fuzz smoke tests (use `zig build test --fuzz`)
//!   zig build sim -- SEED  run the deterministic simulator (DST) for SEED
//!   zig build bench        run micro benchmarks (ReleaseFast recommended)

const std = @import("std");

/// Every binary lives at `bin/<name>/main.zig`. Add new ones here.
const binaries = [_][]const u8{
    "base",
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_filter = b.option([]const u8, "test-filter", "Only run tests matching");

    const options = b.addOptions();
    options.addOption([]const u8, "version", "0.0.0");
    const git_rev = b.option([]const u8, "git-rev", "Git revision baked into binaries");
    options.addOption([]const u8, "git_rev", git_rev orelse "unknown");
    const slow_tests = b.option(bool, "slow-tests", "Also run large simulation tests") orelse false;
    options.addOption(bool, "slow_tests", slow_tests);
    const require_io_uring = b.option(
        bool,
        "require-io-uring",
        "Fail (instead of skip) OS IO tests when io_uring is unavailable",
    ) orelse false;
    options.addOption(bool, "require_io_uring", require_io_uring);

    const base = b.addModule("base", .{
        .root_source_file = b.path("src/base.zig"),
        .target = target,
        .optimize = optimize,
    });
    base.addOptions("build_options", options);

    // Unit tests: one test binary over the whole `base` module tree.
    const filters: []const []const u8 = if (test_filter) |f| &.{f} else &.{};
    const unit_tests = b.addTest(.{ .root_module = base, .filters = filters });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    add_binaries(b, base, target, optimize, test_step, filters);

    // Deterministic simulation testing and micro benchmarks.
    const sim = add_tool(b, base, target, optimize, .{
        .name = "simulator",
        .path = "src/testing/simulator_main.zig",
        .step = "sim",
        .description = "Run the deterministic simulator: zig build sim -- [seed]",
    });
    b.installArtifact(sim);
    const bench = add_tool(b, base, target, optimize, .{
        .name = "bench",
        .path = "src/testing/bench_main.zig",
        .step = "bench",
        .description = "Run micro benchmarks",
    });

    add_vector_tools(b, base, target, optimize);

    // Compile-only check for editors and CI speed.
    const check_step = b.step("check", "Compile everything without running");
    check_step.dependOn(&unit_tests.step);
    check_step.dependOn(&sim.step);
    check_step.dependOn(&bench.step);
}

/// Runners over public vectors fetched by `just vectors`.
fn add_vector_tools(
    b: *std.Build,
    base: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    // ethereum/tests GeneralStateTests runner (vectors from `just vectors`).
    _ = add_tool(b, base, target, optimize, .{
        .name = "statetest",
        .path = "src/execution/evm/state_test_main.zig",
        .step = "statetest",
        .description = "Run state tests: zig build statetest -- <file-or-dir>",
    });

    // ethereum/tests TransactionTests through the strict tx decoder.
    _ = add_tool(b, base, target, optimize, .{
        .name = "txtest",
        .path = "src/common/consensus/tx_test_main.zig",
        .step = "txtest",
        .description = "Run transaction tests: zig build txtest -- <file-or-dir>",
    });

    // ethereum/tests BlockchainTests block RLP through the strict block decoder.
    _ = add_tool(b, base, target, optimize, .{
        .name = "blockrlp",
        .path = "src/common/consensus/block_test_main.zig",
        .step = "blockrlp",
        .description = "Check block RLP: zig build blockrlp -- <file-or-dir>",
    });

    // base/base genesis parity (files from `just vectors`).
    _ = add_tool(b, base, target, optimize, .{
        .name = "genesischeck",
        .path = "src/common/genesis/check_main.zig",
        .step = "genesischeck",
        .description = "Check genesis files: zig build genesischeck -- <genesis.json>...",
    });
}

const Tool = struct {
    name: []const u8,
    path: []const u8,
    step: []const u8,
    description: []const u8,
};

/// An executable over the `base` module with a run step that forwards `-- args`.
fn add_tool(
    b: *std.Build,
    base: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    tool: Tool,
) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{
        .name = tool.name,
        .root_module = b.createModule(.{
            .root_source_file = b.path(tool.path),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "base", .module = base }},
        }),
    });
    const run = b.addRunArtifact(exe);
    run.addPassthruArgs();
    b.step(tool.step, tool.description).dependOn(&run.step);
    return exe;
}

/// Each binary gets an install, a `run-<name>` step, and its own test binary.
fn add_binaries(
    b: *std.Build,
    base: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    test_step: *std.Build.Step,
    filters: []const []const u8,
) void {
    for (binaries) |name| {
        const exe = b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("bin/{s}/main.zig", .{name})),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "base", .module = base }},
            }),
        });
        b.installArtifact(exe);

        const run = b.addRunArtifact(exe);
        run.addPassthruArgs();
        const run_step = b.step(b.fmt("run-{s}", .{name}), b.fmt("Run {s}", .{name}));
        run_step.dependOn(&run.step);
    }

    // Binary tests (each main.zig may hold integration tests).
    for (binaries) |name| {
        const bin_tests = b.addTest(.{
            .name = b.fmt("test-{s}", .{name}),
            .root_module = b.createModule(.{
                .root_source_file = b.path(b.fmt("bin/{s}/main.zig", .{name})),
                .target = target,
                .optimize = optimize,
                .imports = &.{.{ .name = "base", .module = base }},
            }),
            .filters = filters,
        });
        test_step.dependOn(&b.addRunArtifact(bin_tests).step);
    }
}
