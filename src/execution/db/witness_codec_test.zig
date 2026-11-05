//! Witness codec tests: builder witnesses round-trip through the canonical encoding (and
//! re-encode byte for byte), a `SparseState` loaded from the decoded witness reaches the same
//! post-state root, every preimage is found by digest, and the strict decoder rejects every
//! non-canonical input (seeded and coverage-guided fuzz: no crash, accepted input re-encodes
//! to itself).

const std = @import("std");
const testing = std.testing;

const codec = @import("witness_codec.zig");
const witness = @import("witness.zig");
const state_module = @import("state.zig");
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const evm_backend = @import("evm_backend.zig");
const trie = @import("../trie/root.zig");
const Prng = @import("../../testing/prng.zig").Prng;

const State = state_module.State;
const Overlay = overlay_module.Overlay;
const Changeset = changeset_module.Changeset;
const Address = state_module.Address;
const AccountInfo = state_module.AccountInfo;
const Hash = state_module.Hash;
const Witness = witness.Witness;
const keccak256 = trie.node.keccak256;

const addresses_total = 48;
const genesis_accounts = 32;
const slot_ids = 10;
const headers_total = 4;

const state_config: state_module.Config = .{
    .accounts_max = 128,
    .storage_slots_max = 1024,
    .codes_max = 64,
    .code_bytes_max = 64 * 32,
    .account_nodes_max = 1024,
    .storage_nodes_max = 8192,
};

const changeset_config: changeset_module.Config = .{
    .accounts_max = 128,
    .storage_max = 1024,
    .codes_max = 64,
    .code_bytes_max = 64 * 32,
};

const overlay_config: overlay_module.Config = .{
    .accounts_max = 128,
    .slots_max = 1024,
    .codes_max = 64,
};

const keys_config: witness.KeySet.Config = .{
    .accounts_max = 128,
    .slots_max = 1024,
    .codes_max = 64,
    .block_numbers_max = 16,
};

const sparse_config: witness.SparseState.Config = .{
    .nodes_max = 4096,
    .node_bytes_max = 1 << 21,
    .codes_max = 64,
    .code_bytes_max = 64 * 32,
    .headers_max = 16,
    .trie_nodes_max = 16384,
    .storage_tries_max = 128,
};

const witness_config: Witness.Config = .{
    .state_nodes_max = 4096,
    .state_bytes_max = 1 << 21,
    .codes_max = 64,
    .code_bytes_max = 64 * 32,
    .keys_max = 128 + 1024,
    .headers_max = 16,
    .header_bytes_max = 1024,
};

/// Small witnesses for the decoder fuzz and the hand-built cases.
const small_config: Witness.Config = .{
    .state_nodes_max = 8,
    .state_bytes_max = 256,
    .codes_max = 4,
    .code_bytes_max = 128,
    .keys_max = 4,
    .headers_max = 4,
    .header_bytes_max = 64,
};

fn address_of(index: u64) Address {
    var address: Address = @splat(0);
    address[0] = 0xa0;
    address[19] = @intCast(index);
    return address;
}

/// `rlp([1, 1, 1, 1, 1, 1, 1, 1, number])`, a minimal header-shaped list (number < 128).
fn header_of(number: u8) [10]u8 {
    std.debug.assert(number > 0 and number < 0x80);
    return .{ 0xc9, 1, 1, 1, 1, 1, 1, 1, 1, number };
}

fn random_info(prng: *Prng, overlay: *Overlay) !AccountInfo {
    var info: AccountInfo = .{ .nonce = prng.below(4), .balance = prng.below(1 << 40) };
    if (prng.chance(1, 3)) {
        var code: [24]u8 = undefined;
        prng.fill(&code);
        info.code_hash = try overlay.insert_code(code[0..prng.range(1, code.len)]);
    }
    return info;
}

fn genesis(prng: *Prng, state: *State, overlay: *Overlay, changeset: *Changeset) !void {
    for (0..genesis_accounts) |index| {
        const address = address_of(index);
        try overlay.set_account(address, try random_info(prng, overlay));
        for (0..prng.below(6)) |_| {
            try overlay.set_storage(address, prng.below(slot_ids), prng.range(1, 1 << 20));
        }
    }
    _ = try overlay.commit(changeset);
    for (1..headers_total + 1) |number| {
        const header = header_of(@intCast(number));
        state.set_block_hash(number, keccak256(&header));
    }
}

fn random_reads(prng: *Prng, state: *State, recorder: *witness.Recorder) !void {
    const database = recorder.database();
    for (0..16) |_| {
        const address = address_of(prng.below(addresses_total));
        switch (prng.below(4)) {
            0 => _ = try database.basic(address),
            1 => _ = try database.storage(address, prng.below(slot_ids)),
            2 => if (state.basic(address)) |info| {
                _ = try database.code_by_hash(info.code_hash);
            },
            else => _ = try database.block_hash(prng.range(1, headers_total)),
        }
    }
}

fn random_writes(prng: *Prng, overlay: *Overlay) !void {
    for (0..16) |_| {
        const address = address_of(prng.below(addresses_total));
        const exists = overlay.basic(address) != null;
        switch (prng.below(10)) {
            0...2 => try overlay.set_account(address, try random_info(prng, overlay)),
            3...6 => if (exists) {
                const value = if (prng.chance(1, 2)) 0 else prng.range(1, 1 << 20);
                try overlay.set_storage(address, prng.below(slot_ids), value);
            },
            7, 8 => if (exists) try overlay.set_account(address, null),
            else => if (exists) try overlay.wipe_storage(address),
        }
    }
}

const Fixture = struct {
    state: State,
    overlay: Overlay,
    changeset: Changeset,
    recorder: witness.Recorder,
    builder: witness.Builder,
    built: Witness,
    decoded: Witness,
    sparse: witness.SparseState,
    encoder: codec.Encoder,
    buffer: []u8,
    again: []u8,

    fn init(fixture: *Fixture) !void {
        const allocator = testing.allocator;
        fixture.state = try State.init(allocator, state_config);
        fixture.overlay = try Overlay.init(allocator, &fixture.state, overlay_config);
        fixture.changeset = try Changeset.init(allocator, changeset_config);
        const inner = evm_backend.database(&fixture.state);
        fixture.recorder = try witness.Recorder.init(allocator, inner, keys_config);
        fixture.builder = try witness.Builder.init(allocator, .{
            .sparse = sparse_config,
            .keys = keys_config,
        });
        fixture.built = try Witness.init(allocator, witness_config);
        fixture.decoded = try Witness.init(allocator, witness_config);
        fixture.sparse = try witness.SparseState.init(allocator, sparse_config);
        fixture.encoder = try codec.Encoder.init(allocator, witness_config);
        fixture.buffer = try allocator.alloc(u8, 1 << 22);
        fixture.again = try allocator.alloc(u8, 1 << 22);
    }

    fn deinit(fixture: *Fixture) void {
        const allocator = testing.allocator;
        allocator.free(fixture.again);
        allocator.free(fixture.buffer);
        fixture.encoder.deinit(allocator);
        fixture.sparse.deinit(allocator);
        fixture.decoded.deinit(allocator);
        fixture.built.deinit(allocator);
        fixture.builder.deinit(allocator);
        fixture.recorder.deinit(allocator);
        fixture.changeset.deinit(allocator);
        fixture.overlay.deinit(allocator);
        fixture.state.deinit(allocator);
    }
};

/// Builds one block's witness; returns the witness-only post-state root.
fn build_block(prng: *Prng, fixture: *Fixture) !Hash {
    const keys = &fixture.recorder.keys;
    keys.clear();
    try random_reads(prng, &fixture.state, &fixture.recorder);
    try random_writes(prng, &fixture.overlay);
    try fixture.overlay.build_changeset(&fixture.changeset);
    var headers_buffer: [headers_total][10]u8 = undefined;
    var headers: [headers_total][]const u8 = undefined;
    for (keys.block_numbers.slice(), 0..) |number, index| {
        headers_buffer[index] = header_of(@intCast(number));
        headers[index] = &headers_buffer[index];
    }
    return fixture.builder.build(
        &fixture.state,
        keys,
        &fixture.changeset,
        headers[0..keys.block_numbers.len],
        &fixture.built,
    );
}

/// Every built state node and code is found by digest in the decoded witness; keys too.
fn check_lookup(prng: *Prng, built: *const Witness, decoded: *const Witness) !void {
    const lists = [_]*const witness.ByteList{ &built.state, &built.codes, &built.keys };
    for (lists) |list| {
        for (0..list.count) |index| {
            const item = list.get(@intCast(index));
            const found = codec.lookup(decoded, &keccak256(item)) orelse return error.Missing;
            try testing.expectEqualSlices(u8, item, found);
        }
    }
    for (0..32) |_| {
        var absent: Hash = undefined;
        prng.fill(&absent);
        try testing.expectEqual(null, codec.lookup(decoded, &absent));
    }
    var preimages = codec.PreimageIterator.init(decoded);
    var count: u32 = 0;
    while (preimages.next()) |preimage| : (count += 1) {
        try testing.expectEqual(keccak256(preimage.bytes), preimage.digest);
        const found = codec.lookup(decoded, &preimage.digest) orelse return error.Missing;
        try testing.expectEqualSlices(u8, preimage.bytes, found);
        const key = codec.preimage_key(preimage.digest);
        try testing.expectEqual(codec.keccak256_key_type, key[0]);
        try testing.expectEqualSlices(u8, preimage.digest[1..], key[1..]);
    }
    try testing.expectEqual(decoded.state.count + decoded.codes.count + decoded.keys.count, count);
}

fn round_trip_block(prng: *Prng, fixture: *Fixture) !void {
    const pre_root = try fixture.state.state_root();
    const sparse_root = try build_block(prng, fixture);
    const built = &fixture.built;
    const decoded = &fixture.decoded;
    const size = try fixture.encoder.encoded_size(built);
    const written = try fixture.encoder.encode(built, fixture.buffer);
    try testing.expectEqual(@as(usize, size), written);
    try codec.decode(fixture.buffer[0..written], decoded);
    // Nodes and codes are unique in the builder output; slot keys repeat across accounts
    // (the key is the slot, not the account), so only those collapse.
    try testing.expectEqual(built.state.count, decoded.state.count);
    try testing.expectEqual(built.codes.count, decoded.codes.count);
    try testing.expect(decoded.keys.count <= built.keys.count);
    try testing.expectEqual(built.headers.count, decoded.headers.count);
    const again = try fixture.encoder.encode(decoded, fixture.again);
    try testing.expectEqualSlices(u8, fixture.buffer[0..written], fixture.again[0..again]);
    try check_lookup(prng, built, decoded);
    const sparse = &fixture.sparse;
    sparse.reset(pre_root);
    try sparse.load(decoded);
    try witness.replay(sparse, &fixture.recorder.keys, &fixture.changeset);
    try testing.expectEqual(sparse_root, sparse.state_root());
    const post_root = try fixture.overlay.commit(&fixture.changeset);
    try testing.expectEqual(post_root, sparse.state_root());
}

test "witness codec: builder witnesses round-trip and replay to the same root" {
    var seed: u64 = 0;
    while (seed < 4) : (seed += 1) {
        var prng = Prng.init(0xc0dec + seed);
        var fixture: Fixture = undefined;
        try fixture.init();
        defer fixture.deinit();
        try genesis(&prng, &fixture.state, &fixture.overlay, &fixture.changeset);
        for (0..3) |_| try round_trip_block(&prng, &fixture);
    }
}

/// Writes sections verbatim (no sorting), for building non-canonical inputs.
const RawWriter = struct {
    buffer: []u8,
    offset: usize = 0,

    fn int(self: *RawWriter, value: u32) void {
        std.mem.writeInt(u32, self.buffer[self.offset..][0..4], value, .little);
        self.offset += 4;
    }

    fn header(self: *RawWriter) void {
        @memcpy(self.buffer[0..4], &codec.magic);
        self.offset = 4;
        self.int(codec.version);
    }

    fn section(self: *RawWriter, items: []const []const u8) void {
        var payload: u32 = 0;
        for (items) |item| payload += 4 + @as(u32, @intCast(item.len));
        self.int(@intCast(items.len));
        self.int(payload);
        for (items) |item| {
            self.int(@intCast(item.len));
            @memcpy(self.buffer[self.offset..][0..item.len], item);
            self.offset += item.len;
        }
    }

    fn written(self: *const RawWriter) []const u8 {
        return self.buffer[0..self.offset];
    }
};

fn raw(buffer: []u8, sections: [4][]const []const u8) []const u8 {
    var writer: RawWriter = .{ .buffer = buffer };
    writer.header();
    for (sections) |items| writer.section(items);
    return writer.written();
}

/// `items` ordered by keccak256 ascending.
fn sorted_by_hash(items: *[3][]const u8) void {
    const Order = struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, &keccak256(a), &keccak256(b)) == .lt;
        }
    };
    std.sort.insertion([]const u8, items, {}, Order.less);
}

test "witness codec: decoder rejects non-canonical input" {
    var out = try Witness.init(testing.allocator, small_config);
    defer out.deinit(testing.allocator);
    var buffer: [512]u8 = undefined;
    var nodes: [3][]const u8 = .{ "node-a", "node-b", "node-c" };
    sorted_by_hash(&nodes);
    const key_a: [20]u8 = @splat(1);
    const key_b: [32]u8 = @splat(1);
    const h1 = header_of(1);
    const h2 = header_of(2);
    const keys: []const []const u8 = &.{ &key_a, &key_b };
    const headers: []const []const u8 = &.{ &h1, &h2 };
    try codec.decode(raw(&buffer, .{ &nodes, &.{"code"}, keys, headers }), &out);
    try testing.expectEqual(@as(u32, 3), out.state.count);
    const reversed: []const []const u8 = &.{ nodes[2], nodes[1], nodes[0] };
    const duplicated: []const []const u8 = &.{ nodes[0], nodes[0] };
    const too_many: [small_config.state_nodes_max + 1][]const u8 = @splat("x");
    const cases = [_]struct { sections: [4][]const []const u8, err: codec.DecodeError }{
        .{ .sections = .{ reversed, &.{}, &.{}, &.{} }, .err = error.NonCanonical },
        .{ .sections = .{ duplicated, &.{}, &.{}, &.{} }, .err = error.NonCanonical },
        .{ .sections = .{ &.{}, duplicated, &.{}, &.{} }, .err = error.NonCanonical },
        .{ .sections = .{ &.{}, &.{}, &.{ &key_b, &key_a }, &.{} }, .err = error.NonCanonical },
        .{ .sections = .{ &.{}, &.{}, &.{ &key_a, &key_a }, &.{} }, .err = error.NonCanonical },
        .{ .sections = .{ &.{}, &.{}, &.{"short"}, &.{} }, .err = error.NonCanonical },
        .{ .sections = .{ &.{}, &.{}, &.{}, &.{ &h2, &h1 } }, .err = error.NonCanonical },
        .{ .sections = .{ &.{}, &.{}, &.{}, &.{ &h1, &h1 } }, .err = error.NonCanonical },
        .{ .sections = .{ &.{}, &.{}, &.{}, &.{"not a header"} }, .err = error.InvalidHeader },
        .{ .sections = .{ &too_many, &.{}, &.{}, &.{} }, .err = error.WitnessFull },
    };
    for (cases) |case| {
        try testing.expectError(case.err, codec.decode(raw(&buffer, case.sections), &out));
        try testing.expectEqual(@as(u32, 0), out.state.count);
    }
}

test "witness codec: decoder rejects framing errors" {
    var out = try Witness.init(testing.allocator, small_config);
    defer out.deinit(testing.allocator);
    var buffer: [256]u8 = undefined;
    const valid = raw(&buffer, .{ &.{"node"}, &.{}, &.{}, &.{} });
    try codec.decode(valid, &out);
    var copy: [256]u8 = undefined;
    @memcpy(copy[0..valid.len], valid);
    for (0..valid.len) |length| {
        try testing.expectError(error.Truncated, codec.decode(copy[0..length], &out));
    }
    copy[valid.len] = 0;
    try testing.expectError(error.TrailingBytes, codec.decode(copy[0 .. valid.len + 1], &out));
    copy[0] ^= 1;
    try testing.expectError(error.BadMagic, codec.decode(copy[0..valid.len], &out));
    copy[0] ^= 1;
    copy[4] = 2;
    try testing.expectError(error.UnsupportedVersion, codec.decode(copy[0..valid.len], &out));
    copy[4] = 1;
    // State payload_bytes one larger than its items: the item ends early.
    copy[12] += 1;
    copy[valid.len] = 0;
    try testing.expectError(error.LengthMismatch, codec.decode(copy[0 .. valid.len + 1], &out));
    copy[12] -= 2;
    try testing.expectError(error.LengthMismatch, codec.decode(copy[0..valid.len], &out));
}

test "witness codec: encoder sorts, deduplicates, and checks keys and headers" {
    const allocator = testing.allocator;
    var encoder = try codec.Encoder.init(allocator, small_config);
    defer encoder.deinit(allocator);
    var input = try Witness.init(allocator, small_config);
    defer input.deinit(allocator);
    var out = try Witness.init(allocator, small_config);
    defer out.deinit(allocator);
    const key: [20]u8 = @splat(9);
    for ([_][]const u8{ "c", "a", "b", "a" }) |item| try input.state.append(item);
    for ([_][]const u8{ "code", "code" }) |item| try input.codes.append(item);
    try input.keys.append(&key);
    try input.keys.append(&key);
    try input.headers.append(&header_of(3));
    try input.headers.append(&header_of(2));
    try input.headers.append(&header_of(3));
    var buffer: [256]u8 = undefined;
    const written = try encoder.encode(&input, &buffer);
    try testing.expectError(error.BufferTooSmall, encoder.encode(&input, buffer[0 .. written - 1]));
    try codec.decode(buffer[0..written], &out);
    try testing.expectEqual(@as(u32, 3), out.state.count);
    try testing.expectEqual(@as(u32, 1), out.codes.count);
    try testing.expectEqual(@as(u32, 1), out.keys.count);
    try testing.expectEqual(@as(u32, 2), out.headers.count);
    try testing.expectEqual(@as(u64, 2), try witness.header_number(out.headers.get(0)));
    try testing.expectEqualSlices(u8, "code", codec.lookup(&out, &keccak256("code")).?);
    try testing.expectEqual(null, codec.lookup(&out, &keccak256("d")));
    var header_bad = header_of(3);
    header_bad[1] = 2;
    try input.headers.append(&header_bad);
    try testing.expectError(error.InvalidWitness, encoder.encode(&input, &buffer));
    input.headers.clear();
    try input.keys.append("short");
    try testing.expectError(error.InvalidWitness, encoder.encoded_size(&input));
}

const FuzzContext = struct {
    out: *Witness,
    encoder: *codec.Encoder,
    buffer: []u8,
};

/// Accepted input is canonical: it re-encodes to exactly the same bytes.
fn check_decode(context: *const FuzzContext, bytes: []const u8) !void {
    codec.decode(bytes, context.out) catch return;
    const written = try context.encoder.encode(context.out, context.buffer);
    try testing.expectEqualSlices(u8, bytes, context.buffer[0..written]);
}

fn fuzz_decode(context: *const FuzzContext, smith: *testing.Smith) anyerror!void {
    var input: [1024]u8 = undefined;
    const length = smith.slice(&input);
    try check_decode(context, input[0..length]);
}

test "witness codec: fuzz decode" {
    const allocator = testing.allocator;
    var out = try Witness.init(allocator, small_config);
    defer out.deinit(allocator);
    var encoder = try codec.Encoder.init(allocator, small_config);
    defer encoder.deinit(allocator);
    var buffer: [2048]u8 = undefined;
    const context: FuzzContext = .{ .out = &out, .encoder = &encoder, .buffer = &buffer };
    try testing.fuzz(&context, fuzz_decode, .{});
}

/// Fills `input` with random (possibly duplicated, unsorted) items within `small_config`.
fn random_witness(prng: *Prng, input: *Witness) !void {
    input.clear();
    var item: [32]u8 = undefined;
    for (0..prng.below(6)) |_| {
        prng.fill(&item);
        try input.state.append(item[0..prng.range(0, 24)]);
    }
    for (0..prng.below(3)) |_| try input.codes.append(&.{@intCast(prng.below(4))});
    for (0..prng.below(4)) |_| {
        @memset(&item, @intCast(prng.below(3)));
        try input.keys.append(item[0..if (prng.chance(1, 2)) 20 else 32]);
    }
    for (0..prng.below(4)) |_| try input.headers.append(&header_of(@intCast(prng.range(1, 5))));
}

test "witness codec: seeded decode fuzz" {
    const allocator = testing.allocator;
    var input = try Witness.init(allocator, small_config);
    defer input.deinit(allocator);
    var out = try Witness.init(allocator, small_config);
    defer out.deinit(allocator);
    var encoder = try codec.Encoder.init(allocator, small_config);
    defer encoder.deinit(allocator);
    var buffer: [2048]u8 = undefined;
    var valid: [1024]u8 = undefined;
    const context: FuzzContext = .{ .out = &out, .encoder = &encoder, .buffer = &buffer };
    var prng = Prng.init(0xf022c0de);
    for (0..3000) |_| {
        try random_witness(&prng, &input);
        const length = try encoder.encode(&input, &valid);
        try codec.decode(valid[0..length], &out);
        try check_decode(&context, valid[0..length]);
        // Random corruption: flips, truncation, extension.
        var mutated = valid;
        var mutated_length = length;
        for (0..prng.range(1, 4)) |_| {
            switch (prng.below(3)) {
                0 => mutated[prng.below(mutated_length)] ^= @intCast(prng.range(1, 255)),
                1 => mutated_length = prng.range(1, mutated_length),
                else => if (mutated_length < mutated.len) {
                    mutated[mutated_length] = @intCast(prng.below(256));
                    mutated_length += 1;
                },
            }
        }
        try check_decode(&context, mutated[0..mutated_length]);
    }
}
