//! A read-only evm `Database` over the state of an older canonical block, read from the
//! chain's history window (`Chain.proof_at`). Each account and slot read walks a proof,
//! so it suits RPC simulation (eth_call, eth_estimateGas at older blocks), not block
//! execution. Code is read from the head's code store (content addressed, never deleted)
//! and BLOCKHASH from the head's canonical ring, which agrees with every canonical block
//! up to the one simulated.
//!
//! The first history failure is kept in `failure` (the evm only sees `DatabaseFailure`),
//! so the caller can report "historical state unavailable" precisely.

const std = @import("std");
const assert = std.debug.assert;
const evm = @import("../evm/root.zig");
const trie_node = @import("../trie/node.zig");
const state_trie = @import("../trie/state_trie.zig");
const db_database = @import("../db/database.zig");
const chain_module = @import("chain.zig");

const Hash = [32]u8;
const Address = [20]u8;
const Chain = chain_module.Chain;
const Database = evm.state.Database;
const AccountInfo = evm.state.AccountInfo;

pub const HistoryDatabase = struct {
    chain: *Chain,
    hash: Hash,
    number: u64,
    account_proof: *state_trie.StateTrie.AccountProof,
    storage_proof: *state_trie.StateTrie.StorageProof,
    failure: ?db_database.ProofError = null,

    const vtable: Database.VTable = .{
        .basic = basic,
        .code_by_hash = code_by_hash,
        .storage = storage,
        .block_hash = block_hash,
    };

    pub fn database(self: *HistoryDatabase) Database {
        assert(self.number < std.math.maxInt(u64));
        return .{ .context = self, .vtable = &vtable };
    }

    fn from(context: *anyopaque) *HistoryDatabase {
        return @ptrCast(@alignCast(context));
    }

    fn fail(self: *HistoryDatabase, err: db_database.ProofError) evm.state.Error {
        if (self.failure == null) self.failure = err;
        return error.DatabaseFailure;
    }

    fn basic(context: *anyopaque, address: Address) evm.state.Error!?AccountInfo {
        const self = from(context);
        const found = self.chain.proof_at(
            self.hash,
            self.number,
            address,
            &.{},
            self.account_proof,
            &.{},
            &.{},
        ) catch |err| return self.fail(err);
        const account = found orelse return null;
        const empty_storage = std.mem.eql(u8, &account.storage_root, &trie_node.empty_root);
        return .{
            .balance = account.balance,
            .nonce = account.nonce,
            .code_hash = account.code_hash,
            .has_storage = !empty_storage,
        };
    }

    fn code_by_hash(context: *anyopaque, code_hash: Hash) evm.state.Error![]const u8 {
        const self = from(context);
        if (std.mem.eql(u8, &code_hash, &trie_node.empty_code_hash)) return &.{};
        return self.chain.db.code(code_hash) orelse error.DatabaseFailure;
    }

    fn storage(context: *anyopaque, address: Address, slot: u256) evm.state.Error!u256 {
        const self = from(context);
        const slots = [1]u256{slot};
        var values: [1]u256 = .{0};
        const proofs: *[1]state_trie.StateTrie.StorageProof = self.storage_proof;
        _ = self.chain.proof_at(
            self.hash,
            self.number,
            address,
            &slots,
            self.account_proof,
            proofs,
            &values,
        ) catch |err| return self.fail(err);
        return values[0];
    }

    fn block_hash(context: *anyopaque, number: u64) evm.state.Error!Hash {
        const self = from(context);
        if (number > self.number) return @splat(0);
        return self.chain.db.database().block_hash(number);
    }
};
