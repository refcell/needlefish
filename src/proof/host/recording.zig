//! A recording fetcher (base/base `crates/proof/host/src/recording.rs`): it serves every
//! preimage from an inner fetcher and copies it into a witness store, so the witness
//! holds exactly what the client read. Hints are not recorded; the data they make the
//! host fetch is recorded when the client reads it. A replay of the witness alone, with
//! hints ignored, reaches the same verdict.

const std = @import("std");
const assert = std.debug.assert;

const preimage = @import("../preimage/root.zig");
const store_module = @import("store.zig");

pub const Recording = struct {
    inner: preimage.Fetcher,
    witness: *store_module.Store,
    /// Reads served, including repeats.
    reads: u64 = 0,
    /// Reads the witness could not hold (it is then incomplete).
    dropped: u64 = 0,

    pub fn fetcher(recording: *Recording) preimage.Fetcher {
        assert(recording.inner.context != @as(*anyopaque, @ptrCast(recording)));
        return .{ .context = recording, .get_preimage = get_preimage };
    }

    fn get_preimage(
        context: *anyopaque,
        key: preimage.Key,
    ) preimage.oracle.FetchError![]const u8 {
        const recording: *Recording = @ptrCast(@alignCast(context));
        const value = try recording.inner.get_preimage(recording.inner.context, key);
        recording.reads += 1;
        recording.witness.put(key, value) catch {
            recording.dropped += 1;
        };
        assert(recording.dropped <= recording.reads);
        return value;
    }
};

const testing = std.testing;

test "recording: copies what was read, once" {
    var store: store_module.Store = .init(testing.allocator, .{});
    defer store.deinit();
    var witness: store_module.Store = .init(testing.allocator, .{});
    defer witness.deinit();
    const read_key = preimage.Key.keccak256(@splat(1));
    const unread_key = preimage.Key.keccak256(@splat(2));
    try store.put(read_key, "read");
    try store.put(unread_key, "unread");
    var recording: Recording = .{ .inner = store.fetcher(), .witness = &witness };
    const fetcher = recording.fetcher();
    try testing.expectEqualStrings("read", try fetcher.get_preimage(fetcher.context, read_key));
    try testing.expectEqualStrings("read", try fetcher.get_preimage(fetcher.context, read_key));
    const missing = preimage.Key.keccak256(@splat(3));
    try testing.expectError(error.KeyNotFound, fetcher.get_preimage(fetcher.context, missing));
    try testing.expectEqual(@as(u64, 2), recording.reads);
    try testing.expectEqual(@as(u32, 1), witness.count());
    try testing.expect(witness.get(unread_key) == null);
    try testing.expectEqualStrings("read", witness.get(read_key).?);
}
