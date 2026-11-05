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

    const base = b.addModule("base", .{
        .root_source_file = b.path("src/base.zig"),
        .target = target,
        .optimize = optimize,
    });
    base.addOptions("build_options", options);

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

    // Unit tests: one test binary over the whole `base` module tree.
    const filters: []const []const u8 = if (test_filter) |f| &.{f} else &.{};
    const unit_tests = b.addTest(.{ .root_module = base, .filters = filters });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

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

    // Deterministic simulation testing.
    const sim = b.addExecutable(.{
        .name = "simulator",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/testing/simulator_main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "base", .module = base }},
        }),
    });
    const run_sim = b.addRunArtifact(sim);
    run_sim.addPassthruArgs();
    const sim_step = b.step("sim", "Run the deterministic simulator: zig build sim -- [seed]");
    sim_step.dependOn(&run_sim.step);

    // Micro benchmarks.
    const bench = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/testing/bench_main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "base", .module = base }},
        }),
    });
    const run_bench = b.addRunArtifact(bench);
    run_bench.addPassthruArgs();
    const bench_step = b.step("bench", "Run micro benchmarks");
    bench_step.dependOn(&run_bench.step);

    // Compile-only check for editors and CI speed.
    const check_step = b.step("check", "Compile everything without running");
    check_step.dependOn(&unit_tests.step);
    check_step.dependOn(&sim.step);
    check_step.dependOn(&bench.step);
}
