//! Differential execution adapter (`base diff-adapter`): runs a fuzz harness's blocks on
//! needlefish's block execution path over stateless witnesses and reports every header
//! field, receipt and state change it computes, for comparison against base/base and other
//! clients. The protocol is newline-delimited JSON: one request line in, one response line
//! out (`request.zig`, `response.zig`); `adapter.zig` executes a case.

const std = @import("std");
const assert = std.debug.assert;

pub const request = @import("request.zig");
pub const adapter = @import("adapter.zig");
pub const response = @import("response.zig");
pub const coverage = @import("coverage.zig");
pub const system_config = @import("system_config.zig");
pub const trie = @import("trie.zig");
pub const trie_request = @import("trie_request.zig");
pub const Adapter = adapter.Adapter;
pub const Coverage = coverage.Coverage;

/// Answers one request line into `out` (no newline). Every line gets a response: requests
/// that cannot be processed get `ok: false`. With `features`, the response carries the
/// request's coverage.
pub fn handle_line(
    self: *Adapter,
    arena: std.mem.Allocator,
    line: []const u8,
    out: *std.Io.Writer,
    features: ?*const Coverage,
) std.Io.Writer.Error!void {
    if (features) |collected| collected.begin();
    const raw = request.parse(arena, line) catch |err| {
        const id = request.salvage_id(arena, line);
        const text = error_text(arena, "invalid request", err);
        return response.write_error(out, id, text, features);
    };
    if (std.mem.eql(u8, raw.mode, "systemConfig") and
        std.mem.eql(u8, raw.chain, "base-mainnet"))
    {
        return system_config.handle(arena, raw.id, raw.systemConfig, out);
    }
    if (std.mem.eql(u8, raw.mode, "trie")) return handle_trie(self, arena, &raw, out, features);
    const case = request.decode(arena, &raw) catch |err| {
        const text = error_text(arena, "invalid request", err);
        return response.write_error(out, raw.id, text, features);
    };
    const outcome = self.run(arena, &case) catch |err| {
        const text = if (err == error.WitnessIncomplete)
            missing_text(arena, &self.missing)
        else
            error_text(arena, "cannot execute", err);
        std.log.info("diff adapter: {s}: {s}", .{ raw.id orelse "(no id)", text });
        return response.write_error(out, raw.id, text, features);
    };
    return response.write_outcome(out, raw.id, &outcome, features);
}

/// `trie` mode (`trie.zig`): every request starts from an empty state in its own databases.
fn handle_trie(
    self: *Adapter,
    arena: std.mem.Allocator,
    raw: *const request.RawRequest,
    out: *std.Io.Writer,
    features: ?*const Coverage,
) std.Io.Writer.Error!void {
    const raw_trie = raw.trie orelse {
        return response.write_error(out, raw.id, "invalid request: MissingField trie", features);
    };
    const case = trie_request.decode(arena, &raw_trie) catch |err| {
        const text = error_text(arena, "invalid request", err);
        return response.write_error(out, raw.id, text, features);
    };
    const io = self.io orelse {
        return response.write_error(out, raw.id, "trie mode needs file IO", features);
    };
    const outcome = trie.run(arena, self.allocator, io, &case) catch |err| {
        const text = error_text(arena, "cannot run", err);
        std.log.info("diff adapter: {s}: {s}", .{ raw.id orelse "(no id)", text });
        return response.write_error(out, raw.id, text, features);
    };
    return trie.write(out, raw.id, &outcome, features);
}

/// `WitnessIncomplete: witness lacks trie node 0x.., reading account 0x.., executing
/// transaction 7`.
fn missing_text(arena: std.mem.Allocator, missing: *const adapter.Missing) []const u8 {
    var text: std.Io.Writer.Allocating = .init(arena);
    text.writer.writeAll("WitnessIncomplete: ") catch return "WitnessIncomplete";
    missing.describe(&text.writer) catch return "WitnessIncomplete";
    return text.written();
}

fn error_text(arena: std.mem.Allocator, what: []const u8, err: anyerror) []const u8 {
    assert(what.len > 0);
    return std.fmt.allocPrint(arena, "{s}: {t}", .{ what, err }) catch what;
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("adapter_test.zig");
    _ = @import("coverage.zig");
    _ = @import("system_config.zig");
    _ = @import("trie_test.zig");
    _ = @import("trie_hooks_test.zig");
}
