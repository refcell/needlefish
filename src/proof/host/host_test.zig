//! Host tests: the program's providers read through an initially empty store that the
//! hint handler fills from a map-backed chain source, so every preimage the program
//! reads exists only because its hint was served.

const std = @import("std");
const testing = std.testing;

const preimage = @import("../preimage/root.zig");
const mpt = @import("../mpt/root.zig");
const program = @import("../program/root.zig");
const consensus = @import("../../common/consensus/root.zig");
const primitives = @import("../../common/primitives/root.zig");
const rlp = @import("../../common/rlp/root.zig");
const kzg = @import("../../common/crypto/kzg/root.zig");
const handler_module = @import("handler.zig");
const trie = @import("../../execution/trie/root.zig");
const protocol = @import("../../consensus/protocol/root.zig");
const store_module = @import("store.zig");

const Hash = [32]u8;
const B256 = primitives.B256;
const Chain = handler_module.Chain;
const SourceError = handler_module.SourceError;

const MapSource = struct {
    arena: std.heap.ArenaAllocator,
    headers: std.AutoHashMapUnmanaged(Hash, []const u8) = .empty,
    bodies: std.AutoHashMapUnmanaged(Hash, []const []const u8) = .empty,
    blob_bytes: *const [kzg.bytes_per_blob]u8 = undefined,
    commitment: [kzg.bytes_per_commitment]u8 = @splat(0xa7),

    fn deinit(source: *MapSource) void {
        source.headers.deinit(testing.allocator);
        source.bodies.deinit(testing.allocator);
        source.arena.deinit();
    }

    /// Adds a header whose transactions root commits to `transactions`.
    fn add_block(source: *MapSource, header: *consensus.Header, items: []const []const u8) !Hash {
        const arena = source.arena.allocator();
        header.transactions_root = .{ .bytes = trie.ordered_trie_root(items) };
        var buffer: [1024]u8 = undefined;
        const encoded = try arena.dupe(u8, rlp.encode_to(&buffer, header.*));
        const hash = header.hash().bytes;
        try source.headers.put(testing.allocator, hash, encoded);
        const copies = try arena.alloc([]const u8, items.len);
        for (copies, items) |*copy, item| copy.* = try arena.dupe(u8, item);
        try source.bodies.put(testing.allocator, hash, copies);
        return hash;
    }

    fn get(context: *anyopaque) *MapSource {
        return @ptrCast(@alignCast(context));
    }

    fn raw_header(context: *anyopaque, chain: Chain, hash: Hash) SourceError![]const u8 {
        _ = chain;
        return get(context).headers.get(hash) orelse error.NotFound;
    }

    fn transactions(context: *anyopaque, chain: Chain, hash: Hash) SourceError![]const []const u8 {
        _ = chain;
        return get(context).bodies.get(hash) orelse error.NotFound;
    }

    fn receipts(context: *anyopaque, hash: Hash) SourceError![]const []const u8 {
        _ = get(context).headers.get(hash) orelse return error.NotFound;
        return &.{};
    }

    fn blob_of(context: *anyopaque, hash: Hash, timestamp: u64) SourceError!handler_module.Blob {
        _ = hash;
        _ = timestamp;
        const source = get(context);
        return .{ .blob = source.blob_bytes, .commitment = source.commitment };
    }

    fn preimage_of(context: *anyopaque, hash: Hash) SourceError![]const u8 {
        return get(context).headers.get(hash) orelse error.NotFound;
    }

    fn payload_witness(
        context: *anyopaque,
        parent: Hash,
        json: []const u8,
    ) SourceError![]const []const u8 {
        _ = context;
        _ = parent;
        _ = json;
        return error.NotFound;
    }

    const vtable: handler_module.Source.VTable = .{
        .raw_header = raw_header,
        .transactions = transactions,
        .receipts = receipts,
        .blob = blob_of,
        .preimage = preimage_of,
        .payload_witness = payload_witness,
    };

    fn as_source(map: *MapSource) handler_module.Source {
        return .{ .context = map, .vtable = &vtable };
    }
};

fn transfer(nonce: u64, buffer: []u8) ![]const u8 {
    var key: [32]u8 = @splat(0);
    key[31] = 1;
    const tx: consensus.Eip1559 = .{
        .chain_id = 1,
        .nonce = nonce,
        .max_priority_fee_per_gas = 1,
        .max_fee_per_gas = 100,
        .gas_limit = 21_000,
        .to = .{ .call = .{ .bytes = @splat(0xff) } },
        .value = nonce,
        .input = "batch",
        .access_list = .empty,
    };
    return (try consensus.tx.sign(tx, key)).encode_to(buffer);
}

var roots: [kzg.field_elements_per_blob][32]u8 = undefined;
var test_blob: [kzg.bytes_per_blob]u8 = undefined;
var kzg_storage: kzg.blob.Settings.Storage = undefined;
var kzg_workspace: kzg.blob.Workspace = undefined;

test "host: hints fill an empty store for the L1 providers" {
    var source: MapSource = .{ .arena = .init(testing.allocator) };
    defer source.deinit();
    var buffers: [2][256]u8 = undefined;
    var genesis: consensus.Header = .{ .number = 0 };
    const genesis_hash = try source.add_block(&genesis, &.{});
    var child: consensus.Header = .{
        .number = 1,
        .parent_hash = .{ .bytes = genesis_hash },
        .timestamp = 12,
    };
    const items = [_][]const u8{ try transfer(0, &buffers[0]), try transfer(1, &buffers[1]) };
    const child_hash = try source.add_block(&child, &items);

    var store: store_module.Store = .init(testing.allocator, .{});
    defer store.deinit();
    handler_module.fill_roots(&roots);
    var handler: handler_module.Handler = .{
        .store = &store,
        .source = source.as_source(),
        .roots_brp = &roots,
    };
    var harness: preimage.InProcess = undefined;
    const options: preimage.in_process.Options = .{ .channel_bytes = 1 << 12 };
    try harness.init(testing.allocator, store.fetcher(), handler.router(), options);
    defer harness.deinit(testing.allocator);
    var resolver: mpt.OracleResolver = try .init(testing.allocator, harness.oracle_reader(), .{
        .bytes_max = 1 << 16,
        .entries_max = 256,
    });
    defer resolver.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 0), store.count());
    const hints = harness.hint_writer();
    var l1: program.L1ChainProvider = try .init(testing.allocator, &resolver, hints, child_hash, .{
        .items_max = 8,
        .logs_max = 8,
        .topics_max = 8,
        .blob_hashes_max = 8,
    });
    defer l1.deinit(testing.allocator);
    const found = try l1.l1_transactions_by_hash(.{ .bytes = child_hash });
    try testing.expectEqual(@as(usize, 2), found.len);
    try testing.expectEqualStrings("batch", found[1].input);
    try testing.expect((try l1.l1_block_info_by_number(0)).hash.eql(.{ .bytes = genesis_hash }));
    const receipts = try l1.l1_receipts_by_hash(.{ .bytes = genesis_hash });
    try testing.expectEqual(@as(usize, 0), receipts.len);
    try testing.expect(store.count() > 2);

    // Blobs: the handler's field-element keys match the program's.
    for (0..kzg.field_elements_per_blob) |index| {
        test_blob[index * 32 ..][0..32].* = @splat(@truncate(index));
        test_blob[index * 32] = 0;
    }
    source.blob_bytes = &test_blob;
    kzg.blob.fill_roots_brp(&kzg_storage.roots_brp);
    const settings: kzg.blob.Settings = .{
        .g1_lagrange = &kzg_storage.g1_lagrange,
        .roots_brp = &kzg_storage.roots_brp,
    };
    var blobs: program.L1BlobProvider = try .init(
        testing.allocator,
        harness.oracle_reader(),
        harness.hint_writer(),
        &settings,
        &kzg_workspace,
        .{ .blobs_max = 1, .verify = false },
    );
    defer blobs.deinit(testing.allocator);
    const versioned: B256 = .{ .bytes = kzg.versioned_hash(&source.commitment) };
    const block: protocol.BlockInfo = .{ .number = 1, .timestamp = 12 };
    const served = try blobs.blobs(block, &.{versioned});
    try testing.expectEqualSlices(u8, &test_blob, served[0]);
}

test "host: a source header that does not match its hash is refused" {
    var source: MapSource = .{ .arena = .init(testing.allocator) };
    defer source.deinit();
    var header: consensus.Header = .{ .number = 3 };
    const hash = try source.add_block(&header, &.{});
    try source.headers.put(testing.allocator, hash, "forged");
    var store: store_module.Store = .init(testing.allocator, .{});
    defer store.deinit();
    var handler: handler_module.Handler = .{ .store = &store, .source = source.as_source() };
    try testing.expectError(error.HashMismatch, handler.handle(.l1_block_header, &hash));
    try testing.expectError(error.InvalidHintData, handler.handle(.l2_block_header, "short"));
    try testing.expectError(error.UnsupportedHint, handler.handle(.l1_precompile, &hash));
    const blob_data = hash ++ @as([8]u8, @splat(0));
    try testing.expectError(error.MissingRoots, handler.handle(.l1_blob, &blob_data));
    try testing.expectEqual(@as(u32, 0), store.count());
}

const fuzz = @import("../../testing/fuzz.zig");

fn fuzz_route(handler: *handler_module.Handler, smith: *std.testing.Smith) anyerror!void {
    var text: [200]u8 = undefined;
    const names = [_][]const u8{ "l1-block-header 0x", "l1-blob 0x", "l2-payload-witness 0x", "" };
    const prefix = names[smith.index(names.len)];
    @memcpy(text[0..prefix.len], prefix);
    const length = prefix.len + smith.slice(text[prefix.len..]);
    // Arbitrary hints are accepted or refused, never crash, and never store bad data.
    const router = handler.router();
    router.route_hint(router.context, text[0..length]) catch {};
    try testing.expectEqual(@as(u32, 0), handler.store.count());
}

test "host: fuzz hint routing" {
    var source: MapSource = .{ .arena = .init(testing.allocator) };
    defer source.deinit();
    var store: store_module.Store = .init(testing.allocator, .{});
    defer store.deinit();
    var handler: handler_module.Handler = .{ .store = &store, .source = source.as_source() };
    try fuzz.run(&handler, fuzz_route, .{ .iterations = 512 });
}
