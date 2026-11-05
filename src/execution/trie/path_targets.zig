//! Sorted 32-byte key paths for multi-key trie walks (`TrieType.visit_paths_in`,
//! `history.Store` witness walks).
//!
//! A multi-key walk visits, once each, the union of the `eth_getProof` nodes of every target
//! (the root, then each node on the path referenced by hash) plus, for targets with
//! `siblings`, the hashed children off the path of each branch on it. Targets are sorted by
//! path and unique, so the targets whose paths enter a node are one contiguous range and the
//! targets taking one child of a branch are a contiguous sub-range.

const std = @import("std");
const assert = std.debug.assert;

/// Nibbles in a target path (keys are 32-byte hashes).
pub const path_nibbles = 64;

pub const PathTarget = struct {
    /// The hashed key: the path walked.
    path: [32]u8,
    /// Also visit the hashed children off this path of every branch on it: deleting the key
    /// can collapse such a branch into one of them.
    siblings: bool = false,
    /// Report the nodes on this path as marked (the witness builder: read keys).
    mark: bool = false,
};

/// Upper bound on pending frames of a depth-first multi-key walk: each of at most
/// `path_nibbles` branch levels leaves at most 15 child ranges pending, plus the current one.
pub const stack_frames_max = 16 * (path_nibbles + 1);

pub fn nibble(target: *const PathTarget, at: u32) u8 {
    assert(at < path_nibbles);
    const byte = target.path[at >> 1];
    return if (at & 1 == 0) byte >> 4 else byte & 0x0f;
}

pub fn order(a: *const PathTarget, b: *const PathTarget) std.math.Order {
    return std.mem.order(u8, &a.path, &b.path);
}

fn less_than(_: void, a: PathTarget, b: PathTarget) bool {
    return order(&a, &b) == .lt;
}

/// Sorts `targets` by path and merges equal paths (their flags are OR-ed). Returns the
/// number of unique targets, now at the front.
pub fn sort_unique(targets: []PathTarget) u32 {
    assert(targets.len < std.math.maxInt(u32));
    if (targets.len == 0) return 0;
    std.sort.pdq(PathTarget, targets, {}, less_than);
    var unique: u32 = 1;
    for (targets[1..]) |target| {
        const last = &targets[unique - 1];
        if (std.mem.eql(u8, &last.path, &target.path)) {
            last.siblings = last.siblings or target.siblings;
            last.mark = last.mark or target.mark;
        } else {
            targets[unique] = target;
            unique += 1;
        }
    }
    assert(sorted(targets[0..unique]));
    return unique;
}

/// Strictly increasing paths.
pub fn sorted(targets: []const PathTarget) bool {
    if (targets.len < 2) return true;
    for (targets[0 .. targets.len - 1], targets[1..]) |*a, *b| {
        if (order(a, b) != .lt) return false;
    }
    return true;
}

pub fn any_mark(range: []const PathTarget) bool {
    for (range) |*target| if (target.mark) return true;
    return false;
}

pub fn any_siblings(range: []const PathTarget) bool {
    for (range) |*target| if (target.siblings) return true;
    return false;
}

/// Bit `n` is set when some target of `range` takes nibble `n` at depth `at`.
pub fn taken_mask(range: []const PathTarget, at: u32) u16 {
    assert(range.len > 0);
    var mask: u16 = 0;
    for (range) |*target| mask |= @as(u16, 1) << @intCast(nibble(target, at));
    assert(mask != 0);
    return mask;
}

/// The start of the run of targets ending at `end` (exclusive) that share the nibble at
/// depth `at` with `range[end - 1]`. Range indices are relative to `range`.
pub fn group_start(range: []const PathTarget, end: u32, at: u32) u32 {
    assert(end > 0 and end <= range.len);
    const value = nibble(&range[end - 1], at);
    var start = end - 1;
    while (start > 0 and nibble(&range[start - 1], at) == value) start -= 1;
    assert(nibble(&range[start], at) == value);
    return start;
}

test "path targets: sort_unique merges flags and keeps order" {
    var targets = [_]PathTarget{
        .{ .path = @splat(3), .mark = true },
        .{ .path = @splat(1) },
        .{ .path = @splat(3), .siblings = true },
        .{ .path = @splat(2) },
    };
    const unique = sort_unique(&targets);
    try std.testing.expectEqual(@as(u32, 3), unique);
    try std.testing.expect(sorted(targets[0..unique]));
    try std.testing.expect(targets[2].mark and targets[2].siblings);
    try std.testing.expect(!targets[0].mark and !targets[0].siblings);
    try std.testing.expectEqual(@as(u16, 1 << 0), taken_mask(targets[0..unique], 0));
    try std.testing.expectEqual(@as(u32, 0), group_start(targets[0..unique], 3, 0));
    try std.testing.expectEqual(@as(u32, 2), group_start(targets[0..unique], 3, 1));
}
