//! Client and host in one process over in-memory channels: the client's oracle and hint
//! reads pump one host server step when they would block. Used by tests, the cluster
//! simulator, and native mode (`bin/base proof`) once the host lands.

const std = @import("std");
const assert = std.debug.assert;

const channel = @import("channel.zig");
const oracle = @import("oracle.zig");
const hint = @import("hint.zig");

pub const Options = struct {
    /// Bytes per direction per channel; must hold the largest preimage frame.
    channel_bytes: u32 = 1 << 20,
    hint_bytes: u32 = 4096,
};

pub const InProcess = struct {
    preimage_duplex: channel.Duplex,
    hint_duplex: channel.Duplex,
    hint_buffer: []u8,
    fetcher: oracle.Fetcher,
    router: hint.Router,
    oracle_error: ?oracle.ServeError = null,
    hint_error: ?hint.ServeError = null,
    hints_served: u64 = 0,
    preimages_served: u64 = 0,

    /// The struct must not move after `init`.
    pub fn init(
        self: *InProcess,
        allocator: std.mem.Allocator,
        fetcher: oracle.Fetcher,
        router: hint.Router,
        options: Options,
    ) !void {
        assert(options.hint_bytes > 0 and options.hint_bytes <= hint.hint_size_max);
        self.* = .{
            .preimage_duplex = undefined,
            .hint_duplex = undefined,
            .hint_buffer = try allocator.alloc(u8, options.hint_bytes),
            .fetcher = fetcher,
            .router = router,
        };
        errdefer allocator.free(self.hint_buffer);
        try self.preimage_duplex.init(allocator, options.channel_bytes);
        errdefer self.preimage_duplex.deinit(allocator);
        try self.hint_duplex.init(allocator, options.hint_bytes + 8);
        self.preimage_duplex.client_endpoint.pump = .{ .context = self, .step = step_oracle };
        self.hint_duplex.client_endpoint.pump = .{ .context = self, .step = step_hint };
    }

    pub fn deinit(self: *InProcess, allocator: std.mem.Allocator) void {
        self.hint_duplex.deinit(allocator);
        self.preimage_duplex.deinit(allocator);
        allocator.free(self.hint_buffer);
        self.* = undefined;
    }

    fn step_oracle(context: *anyopaque) bool {
        const self: *InProcess = @ptrCast(@alignCast(context));
        const server = oracle.OracleServer.init(self.preimage_duplex.host());
        server.next_preimage_request(self.fetcher) catch |err| {
            self.oracle_error = err;
            return false;
        };
        self.preimages_served += 1;
        return true;
    }

    fn step_hint(context: *anyopaque) bool {
        const self: *InProcess = @ptrCast(@alignCast(context));
        const reader = hint.HintReader.init(self.hint_duplex.host(), self.hint_buffer);
        reader.next_hint(self.router) catch |err| {
            self.hint_error = err;
            // The host acknowledged unless the channel itself failed.
            return err != error.WouldBlock and err != error.ChannelClosed;
        };
        self.hints_served += 1;
        return true;
    }

    pub fn oracle_reader(self: *InProcess) oracle.OracleReader {
        return .init(self.preimage_duplex.client());
    }

    pub fn hint_writer(self: *InProcess) hint.HintWriter {
        return .init(self.hint_duplex.client());
    }
};

/// A router that accepts and ignores every hint.
pub const ignore_hints: hint.Router = .{
    .context = @constCast(&ignore_context),
    .route_hint = ignore_route,
};
const ignore_context: u8 = 0;

fn ignore_route(context: *anyopaque, text: []const u8) hint.RouteError!void {
    _ = context;
    _ = text;
}

const testing = std.testing;

test "in_process: oracle and hints through one harness" {
    var store: oracle.MemoryStore(4, 64) = .{};
    try store.put(.local(7), "seven");
    var harness: InProcess = undefined;
    try harness.init(testing.allocator, store.fetcher(), ignore_hints, .{ .channel_bytes = 256 });
    defer harness.deinit(testing.allocator);
    try harness.hint_writer().write("anything 0x00");
    var buffer: [16]u8 = undefined;
    const value = try harness.oracle_reader().get(.local(7), &buffer);
    try testing.expectEqualStrings("seven", value);
    try testing.expectEqual(@as(u64, 1), harness.hints_served);
    try testing.expectEqual(@as(u64, 1), harness.preimages_served);
    try testing.expectError(error.WouldBlock, harness.oracle_reader().get(.local(8), &buffer));
    try testing.expectEqual(@as(?oracle.ServeError, error.KeyNotFound), harness.oracle_error);
}
