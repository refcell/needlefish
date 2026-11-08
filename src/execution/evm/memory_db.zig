//! In-memory `Database` for tests, the state-test runner, and fuzzing. It allocates
//! while being populated (setup time); lookups during execution never allocate.

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("primitives.zig");
const state_module = @import("state.zig");
const Address = primitives.Address;
const B256 = primitives.B256;
const AccountInfo = state_module.AccountInfo;
const Database = state_module.Database;
const Error = state_module.Error;
const StorageKey = state_module.StorageKey;

pub const MemoryDatabase = struct {
    allocator: std.mem.Allocator,
    accounts: state_module.AddressMap(AccountInfo) = .empty,
    storage: state_module.StorageKeyMap(u256) = .empty,
    codes: std.AutoHashMapUnmanaged(B256, []const u8) = .empty,
    block_hashes: std.AutoHashMapUnmanaged(u64, B256) = .empty,

    pub fn init(allocator: std.mem.Allocator) MemoryDatabase {
        return .{ .allocator = allocator };
    }

    pub fn deinit(database: *MemoryDatabase) void {
        var codes = database.codes.valueIterator();
        while (codes.next()) |bytes| database.allocator.free(bytes.*);
        database.accounts.deinit(database.allocator);
        database.storage.deinit(database.allocator);
        database.codes.deinit(database.allocator);
        database.block_hashes.deinit(database.allocator);
        database.* = undefined;
    }

    /// Insert or replace an account; `code` is copied and indexed by its hash.
    pub fn put_account(
        database: *MemoryDatabase,
        address: Address,
        balance: u256,
        nonce: u64,
        code: []const u8,
    ) !void {
        const code_hash = if (code.len == 0)
            primitives.keccak_empty
        else
            primitives.keccak256(code);
        if (code.len > 0 and !database.codes.contains(code_hash)) {
            const copy = try database.allocator.dupe(u8, code);
            errdefer database.allocator.free(copy);
            try database.codes.put(database.allocator, code_hash, copy);
        }
        try database.accounts.put(database.allocator, address, .{
            .balance = balance,
            .nonce = nonce,
            .code_hash = code_hash,
        });
    }

    pub fn put_storage(database: *MemoryDatabase, address: Address, slot: u256, value: u256) !void {
        assert(database.accounts.contains(address));
        try database.storage.put(database.allocator, .{ .address = address, .slot = slot }, value);
        if (value != 0) database.accounts.getPtr(address).?.has_storage = true;
    }

    pub fn put_block_hash(database: *MemoryDatabase, number: u64, hash: B256) !void {
        try database.block_hashes.put(database.allocator, number, hash);
    }

    pub fn interface(database: *MemoryDatabase) Database {
        return .{ .context = database, .vtable = &vtable };
    }

    const vtable = Database.VTable{
        .basic = basic,
        .code_by_hash = code_by_hash,
        .storage = storage_at,
        .block_hash = block_hash,
    };

    fn cast(context: *anyopaque) *MemoryDatabase {
        return @ptrCast(@alignCast(context));
    }

    fn basic(context: *anyopaque, address: Address) Error!?AccountInfo {
        return cast(context).accounts.get(address);
    }

    fn code_by_hash(context: *anyopaque, code_hash: B256) Error![]const u8 {
        return cast(context).codes.get(code_hash) orelse error.DatabaseFailure;
    }

    fn storage_at(context: *anyopaque, address: Address, slot: u256) Error!u256 {
        return cast(context).storage.get(.{ .address = address, .slot = slot }) orelse 0;
    }

    /// Unknown block hashes default to keccak256(number as decimal string), the
    /// convention ethereum/tests uses for BLOCKHASH fixtures.
    fn block_hash(context: *anyopaque, number: u64) Error!B256 {
        if (cast(context).block_hashes.get(number)) |hash| return hash;
        var buffer: [20]u8 = undefined;
        const text = std.fmt.bufPrint(&buffer, "{d}", .{number}) catch unreachable; // Fits.
        return primitives.keccak256(text);
    }
};

test "memory_db: accounts, code, storage" {
    var database = MemoryDatabase.init(std.testing.allocator);
    defer database.deinit();
    const address = primitives.address_from_int(0xaa);
    try database.put_account(address, 7, 1, &.{ 0x60, 0x01 });
    try database.put_storage(address, 3, 4);
    const db = database.interface();
    const info = (try db.basic(address)).?;
    try std.testing.expectEqual(@as(u256, 7), info.balance);
    try std.testing.expectEqual(@as(usize, 2), (try db.code_by_hash(info.code_hash)).len);
    try std.testing.expectEqual(@as(u256, 4), try db.storage(address, 3));
    try std.testing.expectEqual(@as(u256, 0), try db.storage(address, 5));
    try std.testing.expect((try db.basic(primitives.address_from_int(1))) == null);
}
