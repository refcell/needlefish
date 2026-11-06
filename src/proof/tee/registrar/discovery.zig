//! Prover instance discovery (base/base `registrar/src/{traits,discovery}.rs`).
//!
//! base/base discovers provers through an AWS ALB target group (`describe_target_health`
//! plus EC2 private IPs). needlefish has no AWS SDK and no cloud dependency, so the one
//! implementation is a static list from `--prover-endpoints url1,url2`, behind the same
//! `Discovery` interface base/base's `InstanceDiscovery` trait describes. Each URL is one
//! instance whose id is the URL without its scheme; instances start `initial`, and the
//! driver's `readyz` probe decides health every cycle, as it does for ALB targets.

const std = @import("std");
const assert = std.debug.assert;

const types = @import("types.zig");
const reconciler = @import("reconciler.zig");

pub const instances_max: u32 = reconciler.instance_count_max;

pub const Error = error{DiscoveryFailed};

pub const ParseError = error{
    EmptyEndpointList,
    InvalidEndpoint,
    DuplicateEndpoint,
    TooManyEndpoints,
};

pub const Discovery = struct {
    context: *anyopaque,
    discover_fn: *const fn (*anyopaque, []types.ProverInstance) Error![]types.ProverInstance,

    /// The current prover instances with their health status, written into `out`.
    pub fn discover(
        discovery: Discovery,
        out: []types.ProverInstance,
    ) Error![]types.ProverInstance {
        assert(out.len > 0);
        const instances = try discovery.discover_fn(discovery.context, out);
        assert(instances.len <= out.len);
        return instances;
    }
};

pub const StaticDiscovery = struct {
    instances: [instances_max]types.ProverInstance = undefined,
    count: u32 = 0,

    /// Parses a comma-separated list of `http://` or `https://` endpoint URLs.
    pub fn parse(list: []const u8) ParseError!StaticDiscovery {
        var result: StaticDiscovery = .{};
        var parts = std.mem.splitScalar(u8, list, ',');
        while (parts.next()) |part| {
            const url = std.mem.trim(u8, part, " \t");
            if (url.len == 0) continue;
            if (result.count == instances_max) return error.TooManyEndpoints;
            const instance = try parse_instance(url);
            for (result.slice()) |*existing| {
                if (existing.instance_id.eql(&instance.instance_id)) {
                    return error.DuplicateEndpoint;
                }
            }
            result.instances[result.count] = instance;
            result.count += 1;
        }
        if (result.count == 0) return error.EmptyEndpointList;
        assert(result.count <= instances_max);
        return result;
    }

    fn parse_instance(url: []const u8) ParseError!types.ProverInstance {
        assert(url.len > 0);
        const schemes = [_][]const u8{ "http://", "https://" };
        const rest = for (schemes) |scheme| {
            if (std.mem.startsWith(u8, url, scheme)) break url[scheme.len..];
        } else return error.InvalidEndpoint;
        const host_end = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
        if (host_end == 0) return error.InvalidEndpoint;
        for (rest) |char| {
            if (char <= ' ' or char >= 0x7f) return error.InvalidEndpoint;
        }
        const id = std.mem.trimEnd(u8, rest, "/");
        return .{
            .instance_id = types.InstanceId.init(id) catch return error.InvalidEndpoint,
            .endpoint = types.BoundedString(types.endpoint_size_max).init(url) catch
                return error.InvalidEndpoint,
            .health_status = .initial,
        };
    }

    pub fn slice(static: *const StaticDiscovery) []const types.ProverInstance {
        assert(static.count <= instances_max);
        return static.instances[0..static.count];
    }

    pub fn discovery(static: *StaticDiscovery) Discovery {
        return .{ .context = static, .discover_fn = discover };
    }

    fn discover(context: *anyopaque, out: []types.ProverInstance) Error![]types.ProverInstance {
        const static: *StaticDiscovery = @ptrCast(@alignCast(context));
        const instances = static.slice();
        if (instances.len > out.len) return error.DiscoveryFailed;
        @memcpy(out[0..instances.len], instances);
        return out[0..instances.len];
    }
};

const testing = std.testing;

test "registrar discovery: static endpoint list" {
    var static = try StaticDiscovery.parse(" http://10.0.1.5:8000/ ,https://prover-b:8000,");
    var out: [4]types.ProverInstance = undefined;
    const instances = try static.discovery().discover(&out);
    try testing.expectEqual(@as(usize, 2), instances.len);
    try testing.expectEqualStrings("10.0.1.5:8000", instances[0].instance_id.slice());
    try testing.expectEqualStrings("http://10.0.1.5:8000/", instances[0].endpoint.slice());
    try testing.expectEqualStrings("prover-b:8000", instances[1].instance_id.slice());
    try testing.expectEqual(types.InstanceHealthStatus.initial, instances[1].health_status);
    try testing.expectError(error.DiscoveryFailed, static.discovery().discover(out[0..1]));
}

test "registrar discovery: rejects malformed lists" {
    try testing.expectError(error.EmptyEndpointList, StaticDiscovery.parse(" , "));
    try testing.expectError(error.InvalidEndpoint, StaticDiscovery.parse("ftp://a"));
    try testing.expectError(error.InvalidEndpoint, StaticDiscovery.parse("http:///path"));
    try testing.expectError(error.InvalidEndpoint, StaticDiscovery.parse("http://a b"));
    try testing.expectError(
        error.DuplicateEndpoint,
        StaticDiscovery.parse("http://a:1,http://a:1/"),
    );
    var many: [instances_max * 12]u8 = undefined;
    var length: usize = 0;
    for (0..instances_max + 1) |index| {
        const written = try std.fmt.bufPrint(many[length..], "http://h{d},", .{index});
        length += written.len;
    }
    try testing.expectError(error.TooManyEndpoints, StaticDiscovery.parse(many[0..length]));
}

fn fuzz_parse(_: void, smith: *testing.Smith) anyerror!void {
    var input: [512]u8 = undefined;
    const length = smith.index(input.len);
    smith.bytes(input[0..length]);
    const static = StaticDiscovery.parse(input[0..length]) catch return;
    try testing.expect(static.count >= 1 and static.count <= instances_max);
    for (static.slice()) |*instance| {
        try testing.expect(instance.instance_id.length > 0);
        try testing.expect(std.mem.startsWith(u8, instance.endpoint.slice(), "http"));
    }
}

test "registrar discovery: fuzz parse" {
    const fuzz = @import("../../../testing/fuzz.zig");
    try fuzz.run({}, fuzz_parse, .{ .iterations = 2000 });
}
