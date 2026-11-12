//! The read-only JSON-RPC server of `base el-run` (`--rpc`, `--rpc.addr <ip:port>`): answers
//! the common eth/net/web3 read methods from what el-run itself executed, never from another
//! node.
//!
//! - State (`eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt`,
//!   `eth_call`, `eth_getProof`) is read from the database's head state, or with el-run's
//!   archive (`--archive`, `History`) at any block of its window: the archive opens a view
//!   of that block's state for the request (`view_begin_fn`), and the same reads answer from
//!   it. A block outside the window is an error (-32000 "historical state unavailable"),
//!   never an answer from the wrong state.
//! - Blocks, transactions and receipts (`eth_getBlockByNumber`/`ByHash`,
//!   `eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getBlockReceipts`) come
//!   from the RPC ring (`Store`): every block el-run commits, with its receipts as executed,
//!   kept in memory up to `--rpc.ring-blocks` / `--rpc.ring-mb`, plus a transaction hash
//!   index over it; then from the archive, which keeps the same records on disk. A block
//!   that el-run executed but holds in neither is an error (-32000); a block above the head
//!   or an unknown hash is `null`. The ring starts empty at startup.
//! - Transactions (`eth_sendRawTransaction`): decoded, checked (chain, signature, intrinsic
//!   gas, fees) and added to el-run's pool (`txpool.Pool`: by sender and nonce, against the
//!   head state; `txpool_status`, pending transactions by hash, the `pending` nonce). With
//!   `--rollup.sequencer-http` (`el_sequencer.zig`) the transaction is also forwarded to the
//!   sequencer, whose answer is the call's answer (as base/base); without it the pool's
//!   verdict is. After each block the pool drops what the block included and re-reads the
//!   accounts of those senders (and of every sender each `pool_sweep_blocks`).
//! - `safe` and `finalized` are the labels of the Engine API's last valid forkchoice update
//!   (`--engine.addr`); without one they are an error.
//!
//! Single-threaded on el-run's thread: the server runs on its own completion IO that el-run
//! drives only between blocks (`poll`, a few non-blocking ticks) and during the idle wait at
//! the tip (`wait`), so a request never runs while the runner executes or commits a block.
//! The database is not shared with another thread: its reads fill the disk state's read memo
//! and pin codes. Requests are bounded: `eth_call` gas is capped at `call_gas_max`, request
//! bodies at `request_bytes_max`, batches at `rpc.batch_size_max`. Binds to 127.0.0.1 by
//! default. Only `eth_sendRawTransaction` changes anything, and only the pool.

const std = @import("std");
const base = @import("base");
const el_ring = @import("el_ring.zig");
const el_engine = @import("el_engine.zig");
const el_sequencer = @import("el_sequencer.zig");

const json = base.utilities.json;
const rpc = base.utilities.rpc;
const http = base.utilities.http;
const io_module = base.utilities.io;
const lazy_alloc = base.utilities.lazy_alloc;
const rlp = base.common.rlp;
const consensus = base.common.consensus;
const primitives = base.common.primitives;
const format = base.execution.rpc.format;
const eth = base.execution.rpc.eth;
const eth_proof = base.execution.rpc.eth_proof;
const node_chain = base.execution.node.chain;
const state_trie = base.execution.trie.state_trie;
const txpool = base.execution.txpool;
const send_sync = base.execution.rpc.eth.send_sync;
const ChainSpec = base.execution.chainspec.ChainSpec;
const Executor = base.execution.node.executor.Executor;
const BlockEnv = base.execution.node.executor.BlockEnv;
const ExecutorError = base.execution.node.executor.Error;
pub const AccountState = base.execution.db.history.AccountState;
const Io = std.Io;
const assert = std.debug.assert;

const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Hash = [32]u8;
const Address = [20]u8;
pub const Label = el_engine.Label;
pub const AccountProof = state_trie.StateTrie.AccountProof;
pub const StorageProof = state_trie.StateTrie.StorageProof;

pub const default_addr = "127.0.0.1:8545";
/// The most gas an `eth_call` may name (geth's RPC gas cap).
pub const call_gas_max: u64 = 50_000_000;
/// Largest request body (call data of an `eth_call` is at most half of it, in hex).
pub const request_bytes_max = 1 << 20;
/// Largest record (header, transactions, receipts) of one block the ring stores.
pub const record_bytes_max = 64 << 20;
/// Blocks between re-reads of every pool sender's account.
pub const pool_sweep_blocks = 64;
const pool_config: txpool.Config = .{
    .tx_capacity = 4096,
    // The sequencer judges the block gas limit; the pool only bounds a transaction by it.
    .block_gas_limit = 1 << 30,
};

pub const Flags = struct {
    addr: ?[]const u8 = null,
    ring_blocks: u32 = 16_384,
    ring_mib: u32 = 1024,
    /// Transaction index entries (a power of two); about four per retained transaction.
    index_entries: u32 = 1 << 21,
    /// `--rollup.sequencer-http`: where `eth_sendRawTransaction` forwards to.
    sequencer_url: ?[]const u8 = null,

    /// Parses one `--rpc.*` flag; false when `name` is not one.
    pub fn parse(flags: *Flags, name: []const u8, value: []const u8) error{InvalidArguments}!bool {
        const eql = std.mem.eql;
        const parse_int = std.fmt.parseInt;
        if (eql(u8, name, "--rpc.addr")) {
            flags.addr = value;
        } else if (eql(u8, name, "--rpc.ring-blocks")) {
            flags.ring_blocks = parse_int(u32, value, 10) catch return error.InvalidArguments;
            if (flags.ring_blocks < 2) return error.InvalidArguments;
        } else if (eql(u8, name, "--rpc.ring-mb")) {
            flags.ring_mib = parse_int(u32, value, 10) catch return error.InvalidArguments;
            if (flags.ring_mib == 0 or flags.ring_mib > 64 * 1024) return error.InvalidArguments;
        } else if (eql(u8, name, "--rpc.tx-index")) {
            flags.index_entries = parse_int(u32, value, 10) catch return error.InvalidArguments;
            const entries = flags.index_entries;
            if (entries < TxIndex.ways or !std.math.isPowerOfTwo(entries)) {
                return error.InvalidArguments;
            }
        } else return false;
        assert(std.mem.startsWith(u8, name, "--rpc."));
        return true;
    }

    /// `--rpc` (no value): serve on `default_addr` unless `--rpc.addr` names another.
    pub fn enable(flags: *Flags) void {
        if (flags.addr == null) flags.addr = default_addr;
        assert(flags.addr != null);
    }

    fn ring_options(flags: *const Flags) el_ring.Options {
        assert(flags.ring_blocks >= 2);
        // One record per block: the whole record is the ring's "header" bytes.
        return .{
            .blocks_max = flags.ring_blocks,
            .bytes_max = @as(u64, flags.ring_mib) << 20,
            .transactions_max = 1,
        };
    }
};

// ---- The node: el-run's head state and executor -----------------------------------------

pub const Account = struct { nonce: u64, balance: u256, code_hash: Hash };

/// Reads of el-run's database and calls on its executor, at the database head. Only called
/// between blocks.
pub const Node = struct {
    context: *anyopaque,
    recoverer: consensus.Recoverer,
    head_fn: *const fn (context: *anyopaque) Label,
    /// The header RLP of a block the database keeps (its recent blocks), else null.
    header_fn: *const fn (context: *anyopaque, hash: Hash) ?[]const u8,
    canonical_hash_fn: *const fn (context: *anyopaque, number: u64) ?Hash,
    account_fn: *const fn (context: *anyopaque, address: Address) ?Account,
    storage_fn: *const fn (context: *anyopaque, address: Address, slot: u256) u256,
    code_fn: *const fn (context: *anyopaque, code_hash: Hash) ?[]const u8,
    /// `Database.proof_at` at the head for at most one slot.
    proof_fn: *const fn (
        context: *anyopaque,
        address: Address,
        slots: []const u256,
        account_proof: *AccountProof,
        storage_proofs: []StorageProof,
        values: []u256,
    ) anyerror!?AccountState,
    simulate_fn: *const fn (
        context: *anyopaque,
        env: *const BlockEnv,
        call: Executor.Call,
    ) ExecutorError!Executor.Simulated,
    /// The request ended: release what its reads pinned (`Database.codes_release`).
    release_fn: *const fn (context: *anyopaque) void,

    fn head(n: *const Node) Label {
        return n.head_fn(n.context);
    }
};

/// The `Node` of el-run's import runner (`execution.import.run.RunnerType`): its database's
/// head state and its executor.
pub fn runner_node(comptime Runner: type, runner: *Runner) Node {
    const adapter = struct {
        fn of(context: *anyopaque) *Runner {
            return @ptrCast(@alignCast(context));
        }
        fn head(context: *anyopaque) Label {
            const info = of(context).db.head_info;
            assert(info.present);
            return .{ .number = info.number, .hash = info.hash };
        }
        fn header(context: *anyopaque, hash: Hash) ?[]const u8 {
            const view = of(context).db.chain.block(hash) orelse return null;
            return view.header;
        }
        fn canonical_hash(context: *anyopaque, number: u64) ?Hash {
            return of(context).db.chain.canonical_hash(number);
        }
        fn account(context: *anyopaque, address: Address) ?Account {
            const info = of(context).db.state.basic(address) orelse return null;
            return .{ .nonce = info.nonce, .balance = info.balance, .code_hash = info.code_hash };
        }
        fn storage(context: *anyopaque, address: Address, slot: u256) u256 {
            return of(context).db.state.storage(address, slot);
        }
        fn code(context: *anyopaque, code_hash: Hash) ?[]const u8 {
            return of(context).db.state.code_by_hash(code_hash);
        }
        fn proof(
            context: *anyopaque,
            address: Address,
            slots: []const u256,
            account_proof: *AccountProof,
            storage_proofs: []StorageProof,
            values: []u256,
        ) anyerror!?AccountState {
            const db = of(context).db;
            const number = db.head_info.number;
            return db.proof_at(number, address, slots, account_proof, storage_proofs, values);
        }
        fn simulate(
            context: *anyopaque,
            env: *const BlockEnv,
            call: Executor.Call,
        ) ExecutorError!Executor.Simulated {
            return of(context).executor.simulate(env, call);
        }
        fn release(context: *anyopaque) void {
            of(context).db.codes_release();
        }
    };
    return .{
        .context = runner,
        .recoverer = runner.executor.recoverer,
        .head_fn = adapter.head,
        .header_fn = adapter.header,
        .canonical_hash_fn = adapter.canonical_hash,
        .account_fn = adapter.account,
        .storage_fn = adapter.storage,
        .code_fn = adapter.code,
        .proof_fn = adapter.proof,
        .simulate_fn = adapter.simulate,
        .release_fn = adapter.release,
    };
}

// ---- History: el-run's archive -----------------------------------------------------------

/// Blocks and state older than the ring and the head (`el_archive.zig`). Records of blocks
/// `oldest..head`, state after blocks `oldest - 1..head`. Errors are a damaged archive.
pub const History = struct {
    context: *anyopaque,
    window_fn: *const fn (context: *anyopaque) ?Window,
    /// Block `number`'s hash and record (`node.chain.Record` bytes), valid until the next
    /// history call; null when not archived.
    block_fn: *const fn (context: *anyopaque, number: u64) anyerror!?Archived,
    find_block_fn: *const fn (context: *anyopaque, hash: Hash) anyerror!?u64,
    find_transaction_fn: *const fn (context: *anyopaque, hash: Hash) anyerror!?Location,
    /// The node's state reads (account, storage, proof, simulate) see the state after
    /// block `number` (its state root `state_root`, in the window) until `view_end_fn`.
    view_begin_fn: *const fn (context: *anyopaque, number: u64, state_root: Hash) void,
    view_end_fn: *const fn (context: *anyopaque) void,

    fn window(history: *const History) ?Window {
        return history.window_fn(history.context);
    }
};

pub const Window = struct { oldest: u64, head: u64 };
pub const Archived = struct { hash: Hash, bytes: []const u8 };

// ---- The store: executed blocks with their receipts ------------------------------------

/// Transaction hash -> (block number, index), set-associative and lossy: each hash maps to a
/// bucket of `ways` entries; a full bucket overwrites its oldest entry. Entries are hints,
/// checked against the ring's transaction bytes, so a stale or colliding entry is never an
/// answer. Number 0 marks a free entry (block 0 is never executed by el-run).
pub const TxIndex = struct {
    pub const ways = 4;

    const Entry = struct { tag: u64 = 0, number: u64 = 0, index: u32 = 0 };

    entries: []Entry,

    fn init(allocator: std.mem.Allocator, count: u32) !TxIndex {
        assert(count >= ways and std.math.isPowerOfTwo(count));
        const entries = try lazy_alloc.alloc(allocator, Entry, count);
        @memset(entries, .{});
        return .{ .entries = entries };
    }

    fn deinit(index: *TxIndex, allocator: std.mem.Allocator) void {
        lazy_alloc.free(allocator, index.entries);
        index.* = undefined;
    }

    fn tag_of(hash: *const Hash) u64 {
        return std.mem.readInt(u64, hash[0..8], .little);
    }

    pub fn bucket(index: *const TxIndex, hash: *const Hash) []Entry {
        const buckets = index.entries.len / ways;
        const position = std.mem.readInt(u64, hash[8..16], .little) & (buckets - 1);
        return index.entries[@intCast(position * ways)..][0..ways];
    }

    fn insert(index: *TxIndex, hash: *const Hash, number: u64, position: u32) void {
        assert(number > 0);
        const entries = index.bucket(hash);
        var oldest: *Entry = &entries[0];
        for (entries) |*entry| {
            if (entry.number < oldest.number) oldest = entry;
        }
        oldest.* = .{ .tag = tag_of(hash), .number = number, .index = position };
        assert(oldest.number == number);
    }
};

pub const Location = struct { number: u64, index: u32 };

/// The RPC ring: one record per executed block (`node.chain.Record`: header, transactions,
/// the empty withdrawals list when the header has a withdrawals root, receipts, requests).
pub const Store = struct {
    ring: el_ring.Ring,
    index: TxIndex,
    /// Encoding space of one record.
    staging: []u8,
    /// Blocks whose record exceeded `staging` or the ring (the ring restarted after them).
    dropped: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, flags: *const Flags) !Store {
        var ring = try el_ring.Ring.init(allocator, flags.ring_options());
        errdefer ring.deinit(allocator);
        var index = try TxIndex.init(allocator, flags.index_entries);
        errdefer index.deinit(allocator);
        const staging = try lazy_alloc.alloc(allocator, u8, record_bytes_max);
        return .{ .ring = ring, .index = index, .staging = staging };
    }

    pub fn deinit(store: *Store, allocator: std.mem.Allocator) void {
        lazy_alloc.free(allocator, store.staging);
        store.index.deinit(allocator);
        store.ring.deinit(allocator);
        store.* = undefined;
    }

    /// The per-block hook: `block` was executed (`receipts`, one per transaction) and
    /// committed as the database head. Returns the block's record (valid until the next
    /// call), null when it is too large to encode.
    pub fn on_block(
        store: *Store,
        block: *const el_ring.Block,
        receipts: []const consensus.Receipt,
    ) ?[]const u8 {
        assert(receipts.len == block.transactions.len);
        const encoded = encode_record(store.staging, block, receipts) orelse {
            store.drop(block.number);
            return null;
        };
        store.ring.push(&.{
            .number = block.number,
            .hash = block.hash,
            .header_rlp = encoded,
            .transactions = &.{},
        }) catch |err| switch (err) {
            error.BlockTooLarge => {
                store.drop(block.number);
                return encoded;
            },
        };
        for (block.transactions, 0..) |transaction, position| {
            const hash = primitives.keccak256(transaction).bytes;
            store.index.insert(&hash, block.number, @intCast(position));
        }
        assert(store.ring.newest_number().? == block.number);
        return encoded;
    }

    fn drop(store: *Store, number: u64) void {
        store.dropped += 1;
        store.ring.clear();
        report("el-run rpc: block {d} is too large for the RPC ring; ring restarted\n", .{
            number,
        });
    }

    /// The record of retained block `number` and its hash, borrowed until the next push.
    pub fn record(store: *const Store, number: u64) ?Stored {
        var scratch: [1][]const u8 = undefined;
        const block = store.ring.get(number, &scratch) orelse return null;
        assert(block.transactions.len == 0);
        // Proof: `on_block` encoded it.
        const decoded = node_chain.Record.decode(block.header_rlp) catch unreachable;
        assert(decoded.header.number == number);
        return .{ .hash = block.hash, .bytes = block.header_rlp, .record = decoded };
    }

    /// Where retained transaction `hash` is, checked against the stored bytes.
    pub fn find(store: *const Store, hash: *const Hash) ?Location {
        for (store.index.bucket(hash)) |entry| {
            if (entry.number == 0 or entry.tag != TxIndex.tag_of(hash)) continue;
            const stored = store.record(entry.number) orelse continue;
            const raw = nth_transaction(stored.record, entry.index) orelse continue;
            if (!std.mem.eql(u8, &primitives.keccak256(raw).bytes, hash)) continue;
            return .{ .number = entry.number, .index = entry.index };
        }
        return null;
    }
};

pub const Stored = struct { hash: Hash, bytes: []const u8, record: node_chain.Record };

fn nth_transaction(record: node_chain.Record, index: u32) ?[]const u8 {
    var transactions = record.transactions;
    var position: u32 = 0;
    while (!transactions.is_empty()) : (position += 1) {
        const raw = transactions.bytes() catch unreachable; // Stored by `on_block`.
        if (position == index) return raw;
    }
    return null;
}

/// Encodes `block`'s record into `out`; null when it does not fit.
fn encode_record(
    out: []u8,
    block: *const el_ring.Block,
    receipts: []const consensus.Receipt,
) ?[]const u8 {
    // Proof: the runner decoded this header before executing the block.
    const header = consensus.Header.decode(block.header_rlp) catch unreachable;
    var transactions_length: usize = 0;
    for (block.transactions) |raw| transactions_length += rlp.bytes_length(raw);
    var receipts_length: usize = 0;
    for (receipts) |receipt| {
        const length = receipt.encoded_length();
        receipts_length += rlp.header_length(length) + length;
    }
    const withdrawals_length: usize = if (header.withdrawals_root != null)
        rlp.list_length(0)
    else
        rlp.bytes_length(&.{});
    const payload_length = block.header_rlp.len + rlp.list_length(transactions_length) +
        withdrawals_length + rlp.list_length(receipts_length) + rlp.list_length(0);
    const total = rlp.list_length(payload_length);
    if (total > out.len) return null;
    var encoder = rlp.Encoder.init(out[0..total]);
    encoder.list_header(payload_length);
    encoder.raw(block.header_rlp);
    encoder.list_header(transactions_length);
    for (block.transactions) |raw| encoder.bytes(raw);
    if (header.withdrawals_root != null) encoder.list_header(0) else encoder.bytes(&.{});
    encoder.list_header(receipts_length);
    for (receipts) |receipt| {
        encoder.string_header(receipt.encoded_length());
        receipt.encode(&encoder);
    }
    encoder.list_header(0);
    assert(encoder.written().len == total);
    return encoder.written();
}

/// The block's RLP size (`size`): header, transactions, no ommers, and the withdrawals list
/// when the header has a withdrawals root.
fn block_size(stored: *const Stored) u64 {
    var transactions = stored.record.transactions;
    var transactions_length: usize = 0;
    while (!transactions.is_empty()) {
        const raw = transactions.bytes() catch unreachable; // Stored by `on_block`.
        assert(raw.len > 0);
        const legacy = raw[0] >= 0xc0;
        transactions_length += if (legacy) raw.len else rlp.bytes_length(raw);
    }
    var header_items = rlp.Decoder.init(stored.bytes);
    var items = header_items.list() catch unreachable; // Stored by `on_block`.
    const header_length = (items.raw() catch unreachable).len;
    const withdrawals = stored.record.header.withdrawals_root != null;
    const payload = header_length + rlp.list_length(transactions_length) + 1 +
        @as(usize, @intFromBool(withdrawals));
    return rlp.list_length(payload);
}

// ---- The API --------------------------------------------------------------------------

pub const Stats = struct {
    requests: u64 = 0,
    /// Reads of an executed block held in neither the ring nor the archive.
    ring_misses: u64 = 0,
    /// Blocks, transactions, and receipts the archive answered.
    archive_reads: u64 = 0,
    /// State reads that named a block outside the archive's window (or without one).
    historical: u64 = 0,
    /// State reads at an older block the archive answered.
    historical_served: u64 = 0,
    calls: u64 = 0,
    /// `eth_sendRawTransaction` calls the pool took, and the ones it refused.
    pool_added: u64 = 0,
    pool_refused: u64 = 0,
};

pub const Api = struct {
    spec: *const ChainSpec,
    node: Node,
    store: Store,
    /// The Engine API's forkchoice labels (`safe`, `finalized`), when it runs.
    engine: ?*const el_engine.Engine = null,
    /// el-run's archive (`--archive`), when it runs.
    history: ?History = null,
    pool: txpool.Pool,
    /// Pool senders' indexes (`pool_sweep`).
    pool_senders: []u32,
    blocks_since_sweep: u32 = 0,
    /// `--rollup.sequencer-http`, when set.
    sequencer: ?*el_sequencer.Forwarder = null,
    /// The request being routed: its id when it is a single call (null: a batch), and the
    /// sequencer slot its `eth_sendRawTransaction` started (to park its response).
    send_id: ?[]const u8 = null,
    send_slot: ?u32 = null,
    /// Call data decoding space.
    scratch: []u8,
    proofs: *eth_proof.Scratch,
    message_buffer: [256]u8 = undefined,
    stats: Stats = .{},

    /// `api` must not move afterwards (the server keeps a pointer).
    pub fn init(
        api: *Api,
        allocator: std.mem.Allocator,
        spec: *const ChainSpec,
        node: Node,
        flags: *const Flags,
    ) !void {
        var store = try Store.init(allocator, flags);
        errdefer store.deinit(allocator);
        const scratch = try lazy_alloc.alloc(allocator, u8, request_bytes_max);
        errdefer lazy_alloc.free(allocator, scratch);
        const proofs = try allocator.create(eth_proof.Scratch);
        errdefer allocator.destroy(proofs);
        var pool = try txpool.Pool.init(allocator, pool_config);
        errdefer pool.deinit(allocator);
        const pool_senders = try allocator.alloc(u32, pool.sender_capacity());
        api.* = .{
            .spec = spec,
            .node = node,
            .store = store,
            .scratch = scratch,
            .proofs = proofs,
            .pool = pool,
            .pool_senders = pool_senders,
        };
        assert(api.store.ring.count == 0);
    }

    pub fn deinit(api: *Api, allocator: std.mem.Allocator) void {
        allocator.free(api.pool_senders);
        api.pool.deinit(allocator);
        allocator.destroy(api.proofs);
        lazy_alloc.free(allocator, api.scratch);
        api.store.deinit(allocator);
        api.* = undefined;
    }

    /// The HTTP handler: JSON-RPC over POST (`Router`), no authentication (read-only).
    pub fn handle_http(
        api: *Api,
        request: *const http.Request,
        response: *http.ResponseBuilder,
    ) void {
        api.stats.requests += 1;
        if (request.method != .POST) return response.fail(405);
        defer api.node.release_fn(api.node.context);
        api.send_id = send_sync.request_id(request.body);
        api.send_slot = null;
        const outcome = Router.handle(api, request.body, response.writer());
        if (outcome == .empty) response.status = 204;
        const slot = api.send_slot orelse return;
        api.send_slot = null;
        const id = api.send_id.?; // Set only for a single call.
        // A notification (no id) gets no answer: nothing to wait for.
        if (outcome != .response or std.mem.eql(u8, id, "null")) return;
        api.sequencer.?.park(slot, response.defer_response(), id);
    }

    /// The per-block hook: the RPC ring's (`Store.on_block`, whose record it returns), then
    /// the pool's: the block's transactions leave it, their senders' accounts are re-read.
    pub fn on_block(
        api: *Api,
        block: *const el_ring.Block,
        receipts: []const consensus.Receipt,
    ) ?[]const u8 {
        const record = api.store.on_block(block, receipts);
        for (block.transactions) |raw| {
            const hash = primitives.keccak256(raw);
            const tx = api.pool.get(hash) orelse continue;
            const sender = tx.sender;
            _ = api.pool.remove(hash);
            api.pool_refresh(sender);
        }
        api.blocks_since_sweep += 1;
        if (api.blocks_since_sweep >= pool_sweep_blocks) api.pool_sweep();
        return record;
    }

    fn pool_refresh(api: *Api, sender: primitives.Address) void {
        const account = api.node.account_fn(api.node.context, sender.bytes);
        api.pool.update_account(sender, .{
            .nonce = if (account) |found| found.nonce else 0,
            .balance = if (account) |found| found.balance else 0,
        });
    }

    /// Re-reads every pool sender's account: drops what was included without the pool
    /// seeing it (a replacement sent elsewhere), promotes what became payable.
    fn pool_sweep(api: *Api) void {
        api.blocks_since_sweep = 0;
        const count = api.pool.sorted_senders(api.pool_senders);
        for (api.pool_senders[0..count]) |index| {
            api.pool_refresh(api.pool.sender_address(index));
        }
        assert(api.pool.count() <= pool_config.tx_capacity);
    }

    pub fn summary(api: *const Api) void {
        const ring = &api.store.ring;
        std.debug.print("rpc: ring {d} blocks {?d}..{?d} {d} MiB, requests {d}, calls {d}, " ++
            "ring misses {d}, archive reads {d}, historical served {d} refused {d}, " ++
            "dropped {d}, pool {d} (added {d} refused {d})\n", .{
            ring.count,
            ring.oldest_number(),
            ring.newest_number(),
            ring.bytes_used >> 20,
            api.stats.requests,
            api.stats.calls,
            api.stats.ring_misses,
            api.stats.archive_reads,
            api.stats.historical_served,
            api.stats.historical,
            api.store.dropped,
            api.pool.count(),
            api.stats.pool_added,
            api.stats.pool_refused,
        });
        if (api.sequencer) |forwarder| forwarder.summary();
    }
};

/// Operator reports; quiet in unit tests.
fn report(comptime text: []const u8, arguments: anytype) void {
    if (@import("builtin").is_test) return;
    std.debug.print(text, arguments);
}

const methods = [_]rpc.Method(*Api){
    .{ .name = "web3_clientVersion", .handler = client_version },
    .{ .name = "net_version", .handler = net_version },
    .{ .name = "eth_chainId", .handler = chain_id },
    .{ .name = "eth_blockNumber", .handler = block_number },
    .{ .name = "eth_gasPrice", .handler = gas_price },
    .{ .name = "eth_maxPriorityFeePerGas", .handler = max_priority_fee },
    .{ .name = "eth_getBalance", .handler = get_balance },
    .{ .name = "eth_getTransactionCount", .handler = get_transaction_count },
    .{ .name = "eth_getCode", .handler = get_code },
    .{ .name = "eth_getStorageAt", .handler = get_storage_at },
    .{ .name = "eth_getBlockByNumber", .handler = get_block_by_number },
    .{ .name = "eth_getBlockByHash", .handler = get_block_by_hash },
    .{ .name = "eth_getTransactionByHash", .handler = get_transaction_by_hash },
    .{ .name = "eth_getTransactionReceipt", .handler = get_transaction_receipt },
    .{ .name = "eth_getBlockReceipts", .handler = get_block_receipts },
    .{ .name = "eth_call", .handler = eth_call },
    .{ .name = "eth_getProof", .handler = get_proof },
    .{ .name = "eth_sendRawTransaction", .handler = send_raw_transaction },
    .{ .name = "txpool_status", .handler = txpool_status },
};

pub const Router = rpc.Router(*Api, &methods);

fn client_version(_: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    try call.writer.string("needlefish/v" ++ base.build_options.version ++ "/el-run");
}

fn net_version(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    var buffer: [20]u8 = undefined;
    const text = std.fmt.bufPrint(&buffer, "{d}", .{api.spec.chain_id}) catch unreachable;
    try call.writer.string(text);
}

fn chain_id(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    try call.writer.quantity(api.spec.chain_id);
}

fn block_number(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    try call.writer.quantity(api.node.head().number);
}

/// The tip el-run suggests: op-geth's floor for OP Stack chains (`MinSuggestedPriorityFee`,
/// 0.001 gwei). Base blocks rarely fill, so the floor is what the sequencer needs.
const suggested_priority_fee: u64 = 1_000_000;

/// `eth_gasPrice`: the head's base fee plus the suggested tip, as op-geth.
fn gas_price(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    const head = try head_header(api, call);
    const base_fee = head.base_fee_per_gas orelse 0;
    try call.writer.quantity(@as(u128, base_fee) + suggested_priority_fee);
}

fn max_priority_fee(_: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    try call.writer.quantity(suggested_priority_fee);
}

// ---- Block parameters ----------------------------------------------------------------

/// A block parameter: a tag, a number, or (EIP-1898) a hash.
pub const Tag = union(enum) { latest, safe, finalized, number: u64, hash: Hash };

/// Parses a block parameter: `"latest"`, `"pending"`, `"safe"`, `"finalized"`,
/// `"earliest"`, a quantity, or an EIP-1898 object (`blockNumber` or `blockHash`).
pub fn parse_tag(raw: []const u8) HandlerError!Tag {
    if (raw.len > 0 and raw[0] == '{') return parse_tag_object(raw);
    if (raw.len < 2 or raw[0] != '"' or raw[raw.len - 1] != '"') return error.InvalidParams;
    const text = raw[1 .. raw.len - 1];
    const eql = std.mem.eql;
    if (eql(u8, text, "latest") or eql(u8, text, "pending")) return .latest;
    if (eql(u8, text, "safe")) return .safe;
    if (eql(u8, text, "finalized")) return .finalized;
    if (eql(u8, text, "earliest")) return .{ .number = 0 };
    if (text.len == 66) {
        return .{ .hash = json.parse_fixed(32, text) catch return error.InvalidParams };
    }
    return .{ .number = json.parse_quantity(u64, text) catch return error.InvalidParams };
}

fn parse_tag_object(raw: []const u8) HandlerError!Tag {
    var scanner = json.Scanner.init(raw);
    const first = scanner.next() catch return error.InvalidParams;
    if (first.tag != .object_begin) return error.InvalidParams;
    var result: ?Tag = null;
    while (true) {
        const name = scanner.next() catch return error.InvalidParams;
        if (name.tag == .object_end) break;
        const value = scanner.next() catch return error.InvalidParams;
        if (std.mem.eql(u8, name.bytes, "blockHash")) {
            if (value.tag != .string) return error.InvalidParams;
            const hash = json.parse_fixed(32, value.bytes) catch return error.InvalidParams;
            result = .{ .hash = hash };
        } else if (std.mem.eql(u8, name.bytes, "blockNumber")) {
            if (value.tag != .string) return error.InvalidParams;
            var quoted: [80]u8 = undefined;
            if (value.bytes.len + 2 > quoted.len) return error.InvalidParams;
            quoted[0] = '"';
            @memcpy(quoted[1..][0..value.bytes.len], value.bytes);
            quoted[value.bytes.len + 1] = '"';
            result = try parse_tag(quoted[0 .. value.bytes.len + 2]);
        } else {
            scanner.skip(value) catch return error.InvalidParams;
        }
    }
    return result orelse error.InvalidParams;
}

/// The executed block `tag` names; null when it names none (above the head, an unknown
/// hash, a forked-off block).
fn resolve(api: *Api, call: *Call, tag: Tag) HandlerError!?Label {
    const head = api.node.head();
    switch (tag) {
        .latest => return head,
        .safe, .finalized => {
            const engine = api.engine orelse return call.fail(rpc.code.server_error, "safe " ++
                "and finalized need el-run's Engine API (--engine.addr) and a consensus node");
            const label = if (tag == .safe) engine.safe else engine.finalized;
            return label orelse call.fail(rpc.code.server_error, "safe and finalized are " ++
                "unset until the consensus node sends a forkchoice update");
        },
        .number => |number| {
            if (number > head.number) return null;
            if (api.store.ring.hash_at(number)) |hash| return .{ .number = number, .hash = hash };
            if (api.node.canonical_hash_fn(api.node.context, number)) |hash| {
                return .{ .number = number, .hash = hash };
            }
            const archived = try archived_block(api, call, number) orelse
                return fail_missing(api, call, number);
            return .{ .number = number, .hash = archived.hash };
        },
        .hash => |hash| {
            if (api.store.ring.number_of(hash)) |number| return .{ .number = number, .hash = hash };
            const header_rlp = api.node.header_fn(api.node.context, hash) orelse {
                const history = api.history orelse return null;
                const found = history.find_block_fn(history.context, hash) catch |err|
                    return fail_archive(call, err);
                const number = found orelse return null;
                return .{ .number = number, .hash = hash };
            };
            const header = consensus.Header.decode(header_rlp) catch unreachable; // Stored.
            const canonical = api.node.canonical_hash_fn(api.node.context, header.number);
            if (canonical == null or !std.mem.eql(u8, &canonical.?, &hash)) return null;
            return .{ .number = header.number, .hash = hash };
        },
    }
}

/// Block `number`'s archived hash and record, when the archive holds it.
fn archived_block(api: *Api, call: *Call, number: u64) HandlerError!?Archived {
    const history = api.history orelse return null;
    const archived = history.block_fn(history.context, number) catch |err|
        return fail_archive(call, err);
    if (archived != null) api.stats.archive_reads += 1;
    return archived;
}

fn fail_archive(call: *Call, err: anyerror) HandlerError {
    var buffer: [96]u8 = undefined;
    const message = std.fmt.bufPrint(&buffer, "archive read failed: {t}", .{err}) catch
        "archive read failed";
    return call.fail(rpc.code.server_error, message);
}

fn fail_missing(api: *Api, call: *Call, number: u64) HandlerError {
    api.stats.ring_misses += 1;
    if (api.history) |history| if (history.window()) |window| {
        const message = std.fmt.bufPrint(&api.message_buffer, "block {d} is not held: " ++
            "el-run's archive keeps blocks {d}..{d}", .{
            number, window.oldest, window.head,
        }) catch "block not held";
        return call.fail(rpc.code.server_error, message);
    };
    const ring = &api.store.ring;
    if (ring.count == 0) {
        return call.fail(rpc.code.server_error, "block not held: el-run's RPC ring is empty " ++
            "(it fills with the blocks executed since el-run started)");
    }
    const message = std.fmt.bufPrint(&api.message_buffer, "block {d} was executed but is " ++
        "not in el-run's RPC ring (blocks {d}..{d}); raise --rpc.ring-blocks or --rpc.ring-mb", .{
        number, ring.oldest_number().?, ring.newest_number().?,
    }) catch "block was executed but is not in el-run's RPC ring";
    return call.fail(rpc.code.server_error, message);
}

/// The block whose state the optional block parameter `raw` names: null for the head.
/// Otherwise opens the archive's view of it (the caller ends it, `view_end`), or fails.
fn view_state(api: *Api, call: *Call, raw: ?[]const u8) HandlerError!?Label {
    const text = raw orelse return null;
    if (std.mem.eql(u8, text, "null")) return null;
    const tag = try parse_tag(text);
    if (tag == .latest) return null;
    const head = api.node.head();
    const label = try resolve(api, call, tag) orelse
        return call.fail(rpc.code.server_error, "header not found");
    if (std.mem.eql(u8, &label.hash, &head.hash)) return null;
    assert(label.number < head.number);
    const history = api.history orelse return fail_historical(api, call, label.number, null);
    const window = history.window() orelse return fail_historical(api, call, label.number, null);
    // State after block `oldest - 1` is block `oldest`'s pre-state.
    if (label.number + 1 < window.oldest) {
        return fail_historical(api, call, label.number, window);
    }
    const header = try header_at(api, call, label);
    history.view_begin_fn(history.context, label.number, header.state_root.bytes);
    api.stats.historical_served += 1;
    return label;
}

fn view_end(api: *Api, label: ?Label) void {
    if (label == null) return;
    const history = api.history.?;
    history.view_end_fn(history.context);
}

fn fail_historical(api: *Api, call: *Call, number: u64, window: ?Window) HandlerError {
    api.stats.historical += 1;
    const fallback = "historical state unavailable";
    const buffer = &api.message_buffer;
    const message = if (window) |held| std.fmt.bufPrint(buffer, fallback ++ ": el-run's " ++
        "archive keeps the state of blocks {d}..{d}, not block {d}", .{
        held.oldest -| 1, held.head, number,
    }) catch fallback else std.fmt.bufPrint(buffer, fallback ++ ": el-run keeps only the " ++
        "head state (block {d}), not block {d} (run with --archive)", .{
        api.node.head().number, number,
    }) catch fallback;
    return call.fail(rpc.code.server_error, message);
}

// ---- State ---------------------------------------------------------------------------

fn read_account(api: *Api, call: *Call) HandlerError!?Account {
    const address = try call.params.fixed(20);
    const raw = try call.params.optional_raw();
    try call.params.finish();
    const view = try view_state(api, call, raw);
    defer view_end(api, view);
    return api.node.account_fn(api.node.context, address);
}

fn get_balance(api: *Api, call: *Call) HandlerError!void {
    const account = try read_account(api, call);
    try call.writer.quantity(if (account) |found| found.balance else 0);
}

fn get_transaction_count(api: *Api, call: *Call) HandlerError!void {
    const address = try call.params.fixed(20);
    const raw = try call.params.optional_raw();
    try call.params.finish();
    const view = try view_state(api, call, raw);
    const account = api.node.account_fn(api.node.context, address);
    view_end(api, view);
    var nonce = if (account) |found| found.nonce else 0;
    // `pending`: past the sender's pooled transactions with consecutive nonces.
    const pending = raw != null and std.mem.eql(u8, raw.?, "\"pending\"");
    if (pending) nonce = api.pool.next_nonce(.{ .bytes = address }, nonce);
    try call.writer.quantity(nonce);
}

fn get_code(api: *Api, call: *Call) HandlerError!void {
    const account = try read_account(api, call) orelse return call.writer.data(&.{});
    const code = api.node.code_fn(api.node.context, account.code_hash) orelse
        return call.fail(rpc.code.internal_error, "code unavailable");
    try call.writer.out.ensureUnusedCapacity(2 * code.len + 16);
    try call.writer.data(code);
}

fn get_storage_at(api: *Api, call: *Call) HandlerError!void {
    const address = try call.params.fixed(20);
    const slot = try parse_slot(try call.params.string());
    const raw = try call.params.optional_raw();
    try call.params.finish();
    const view = try view_state(api, call, raw);
    const word = api.node.storage_fn(api.node.context, address, slot);
    view_end(api, view);
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, word, .big);
    try call.writer.data(&bytes);
}

/// A storage slot as clients send it: hex of at most 32 bytes, leading zeros allowed.
pub fn parse_slot(text: []const u8) HandlerError!u256 {
    if (text.len < 3 or text.len > 66 or text[0] != '0' or (text[1] != 'x' and text[1] != 'X')) {
        return error.InvalidParams;
    }
    return std.fmt.parseInt(u256, text[2..], 16) catch error.InvalidParams;
}

fn eth_call(api: *Api, call: *Call) HandlerError!void {
    const call_raw = try call.params.raw();
    const raw = try call.params.optional_raw();
    try call.params.finish();
    var message = try eth.parse_call(api.scratch, call_raw);
    // Absent: the executor's default (the block limit, EIP-7825-capped from Osaka on).
    if (message.gas) |gas| message.gas = @min(gas, call_gas_max);
    const view = try view_state(api, call, raw);
    defer view_end(api, view);
    const header = if (view) |label|
        try header_at(api, call, label)
    else
        try head_header(api, call);
    // The call runs in the context of the block whose state it reads (as geth's eth_call).
    const env = node_chain.env_of(&header);
    api.stats.calls += 1;
    const simulated = api.node.simulate_fn(api.node.context, &env, message) catch |err| {
        return call.fail(rpc.code.internal_error, @errorName(err));
    };
    switch (simulated) {
        .invalid => |reason| return call.fail(rpc.code.server_error, @tagName(reason)),
        .executed => |executed| {
            if (!executed.success) return call.fail(3, "execution reverted");
            try call.writer.out.ensureUnusedCapacity(2 * executed.output.len + 16);
            try call.writer.data(executed.output);
        },
    }
}

/// The header of block `label` (ring, database, archive).
fn header_at(api: *Api, call: *Call, label: Label) HandlerError!consensus.Header {
    if (api.node.header_fn(api.node.context, label.hash)) |bytes| {
        return consensus.Header.decode(bytes) catch unreachable; // Stored by the runner.
    }
    const stored = try read_label(api, call, label);
    assert(stored.record.header.number == label.number);
    return stored.record.header;
}

fn head_header(api: *Api, call: *Call) HandlerError!consensus.Header {
    const head = api.node.head();
    const header = if (api.store.record(head.number)) |stored|
        stored.record.header
    else if (api.node.header_fn(api.node.context, head.hash)) |bytes|
        consensus.Header.decode(bytes) catch unreachable // Stored by the runner.
    else
        return call.fail(rpc.code.internal_error, "head header unavailable");
    assert(header.number == head.number);
    return header;
}

fn get_proof(api: *Api, call: *Call) HandlerError!void {
    const address = try call.params.fixed(20);
    var keys: [eth_proof.storage_keys_max]Hash = undefined;
    const keys_count = try eth_proof.parse_keys(try call.params.raw(), &keys);
    const raw = try call.params.optional_raw();
    try call.params.finish();
    const view = try view_state(api, call, raw);
    defer view_end(api, view);
    const proofs = api.proofs;
    const found = try prove(api, call, address, null, &proofs.storage);
    const w = call.writer;
    try w.out.ensureUnusedCapacity(64 * 1024 + keys_count * 16 * 1024);
    try eth_proof.write_account(w, &address, &proofs.account, found.account orelse .{
        .nonce = 0,
        .balance = 0,
        .storage_root = base.execution.trie.node.empty_root,
        .code_hash = base.execution.trie.node.empty_code_hash,
    });
    try w.begin_array();
    for (keys[0..keys_count]) |*key| {
        const slot = std.mem.readInt(u256, key, .big);
        const result = try prove(api, call, address, slot, &proofs.storage);
        try eth_proof.write_slot(w, key, result.value, &proofs.storage);
    }
    try w.end_array();
    try w.end_object();
}

const Proved = struct { account: ?AccountState, value: u256 };

/// The account proof into `api.proofs.account`, and with `slot` its proof into `storage`.
fn prove(
    api: *Api,
    call: *Call,
    address: Address,
    slot: ?u256,
    storage: *StorageProof,
) HandlerError!Proved {
    const slots: []const u256 = if (slot) |*value| value[0..1] else &.{};
    var values: [1]u256 = .{0};
    const proofs: []StorageProof = if (slot != null) storage[0..1] else &.{};
    const account = api.node.proof_fn(
        api.node.context,
        address,
        slots,
        &api.proofs.account,
        proofs,
        values[0..slots.len],
    ) catch |err| return call.fail(rpc.code.server_error, @errorName(err));
    return .{ .account = account, .value = values[0] };
}

// ---- Transactions ---------------------------------------------------------------------

fn send_raw_transaction(api: *Api, call: *Call) HandlerError!void {
    const half = api.scratch.len / 2;
    const raw = try call.params.data(api.scratch[0..half]);
    try call.params.finish();
    const header = try head_header(api, call);
    const validated = txpool.validate.validate_known(
        raw,
        api.scratch[half..],
        api.spec,
        header.timestamp + 1,
        api.node.recoverer,
        null,
    ) catch |err| return call.fail(rpc.code.server_error, @errorName(err));
    const tx = validated.tx;
    const sequencer = api.sequencer orelse {
        if (validated.lane != null) {
            return call.fail(rpc.code.server_error, "EIP-8130 transactions need a sequencer " ++
                "(--rollup.sequencer-http)");
        }
        pool_add(api, &tx) catch |err| return call.fail(rpc.code.server_error, @errorName(err));
        return call.writer.data(&tx.hash.bytes);
    };
    const slot = sequencer.slot_free() orelse return call.fail(rpc.code.server_error, "too " ++
        "many transactions are being forwarded to the sequencer; retry");
    // As base/base: the sequencer's verdict counts; the local pool keeps what it can.
    if (validated.lane == null) pool_add(api, &tx) catch {};
    sequencer.submit(slot, raw);
    if (api.send_id != null) api.send_slot = slot;
    try call.writer.data(&tx.hash.bytes);
}

/// Adds `tx` to the pool against the sender's head account.
fn pool_add(api: *Api, tx: *const txpool.Tx) txpool.AddError!void {
    const account = api.node.account_fn(api.node.context, tx.sender.bytes);
    _ = api.pool.add(tx.*, .{
        .nonce = if (account) |found| found.nonce else 0,
        .balance = if (account) |found| found.balance else 0,
    }) catch |err| {
        api.stats.pool_refused += 1;
        return err;
    };
    api.stats.pool_added += 1;
}

fn txpool_status(api: *Api, call: *Call) HandlerError!void {
    try call.params.finish();
    const w = call.writer;
    try w.begin_object();
    try w.key("pending");
    try w.quantity(api.pool.pending_count);
    try w.key("queued");
    try w.quantity(api.pool.queued_count);
    try w.end_object();
}

// ---- Blocks, transactions, receipts ----------------------------------------------------

/// The record of retained block `number`: the ring's, else the archive's.
fn stored_at(api: *Api, call: *Call, number: u64) HandlerError!?Stored {
    if (api.store.record(number)) |stored| return stored;
    const archived = try archived_block(api, call, number) orelse return null;
    const record = node_chain.Record.decode(archived.bytes) catch
        return fail_archive(call, error.InvalidRecord);
    if (record.header.number != number) return fail_archive(call, error.InvalidRecord);
    return .{ .hash = archived.hash, .bytes = archived.bytes, .record = record };
}

/// The retained record of `label`, an error when neither the ring nor the archive has it.
fn read_label(api: *Api, call: *Call, label: Label) HandlerError!Stored {
    const number = label.number;
    const stored = try stored_at(api, call, number) orelse return fail_missing(api, call, number);
    if (!std.mem.eql(u8, &stored.hash, &label.hash)) {
        return call.fail(rpc.code.server_error, "block is no longer el-run's chain");
    }
    return stored;
}

/// An upper bound of a block's or its receipts' JSON: hex doubles every byte; the fields of
/// a log or a transaction add at most about 20 times their smallest encoding.
fn json_size_bound(stored: *const Stored) usize {
    return 4096 + 24 * stored.bytes.len;
}

fn write_block(api: *Api, call: *Call, tag: Tag, full: bool) HandlerError!void {
    const label = try resolve(api, call, tag) orelse return call.writer.null_value();
    const stored = try read_label(api, call, label);
    try call.writer.out.ensureUnusedCapacity(json_size_bound(&stored));
    const recoverer = api.node.recoverer;
    try format.block(call.writer, stored.record, stored.hash, block_size(&stored), full, recoverer);
}

fn get_block_by_number(api: *Api, call: *Call) HandlerError!void {
    const tag = try parse_tag(try call.params.raw());
    if (tag == .hash) return error.InvalidParams;
    const full = try call.params.optional_boolean() orelse false;
    try call.params.finish();
    try write_block(api, call, tag, full);
}

fn get_block_by_hash(api: *Api, call: *Call) HandlerError!void {
    const hash = try call.params.fixed(32);
    const full = try call.params.optional_boolean() orelse false;
    try call.params.finish();
    try write_block(api, call, .{ .hash = hash }, full);
}

/// Where transaction `hash` is (ring, else archive) and its block's record.
fn find_transaction(api: *Api, call: *Call, hash: *const Hash) HandlerError!?Found {
    if (api.store.find(hash)) |location| {
        // Proof: just found.
        return .{ .location = location, .stored = api.store.record(location.number).? };
    }
    const history = api.history orelse return null;
    const found = history.find_transaction_fn(history.context, hash.*) catch |err|
        return fail_archive(call, err);
    const location = found orelse return null;
    const stored = try stored_at(api, call, location.number) orelse
        return fail_archive(call, error.MissingBlock);
    if (nth_transaction(stored.record, location.index) == null) {
        return fail_archive(call, error.MissingTransaction);
    }
    return .{ .location = location, .stored = stored };
}

const Found = struct { location: Location, stored: Stored };

fn get_transaction_by_hash(api: *Api, call: *Call) HandlerError!void {
    const hash = try call.params.fixed(32);
    try call.params.finish();
    const found = try find_transaction(api, call, &hash) orelse {
        const pending = api.pool.get(.{ .bytes = hash }) orelse return call.writer.null_value();
        try call.writer.out.ensureUnusedCapacity(3 * pending.raw.len + 4096);
        return format.transaction(call.writer, pending.raw, null, api.node.recoverer);
    };
    const location = found.location;
    const stored = found.stored;
    const raw = nth_transaction(stored.record, location.index).?;
    try call.writer.out.ensureUnusedCapacity(3 * raw.len + 4096);
    try format.transaction(call.writer, raw, .{
        .block_hash = stored.hash,
        .block_number = location.number,
        .index = location.index,
        .base_fee = stored.record.header.base_fee_per_gas,
        .timestamp_ms = format.timestamp_ms(stored.record),
        .timestamp = stored.record.header.timestamp,
        .deposit = format.deposit_receipt(stored.record, location.index),
    }, api.node.recoverer);
}

fn get_transaction_receipt(api: *Api, call: *Call) HandlerError!void {
    const hash = try call.params.fixed(32);
    try call.params.finish();
    const found = try find_transaction(api, call, &hash) orelse return call.writer.null_value();
    const location = found.location;
    const stored = found.stored;
    try call.writer.out.ensureUnusedCapacity(json_size_bound(&stored));
    const w = call.writer;
    const recoverer = api.node.recoverer;
    const index = location.index;
    try format.block_receipts(w, api.spec, recoverer, stored.record, stored.hash, index);
}

fn get_block_receipts(api: *Api, call: *Call) HandlerError!void {
    const tag = try parse_tag(try call.params.raw());
    try call.params.finish();
    const label = try resolve(api, call, tag) orelse return call.writer.null_value();
    const stored = try read_label(api, call, label);
    try call.writer.out.ensureUnusedCapacity(json_size_bound(&stored));
    try call.writer.begin_array();
    const recoverer = api.node.recoverer;
    try format.block_receipts(call.writer, api.spec, recoverer, stored.record, stored.hash, null);
    try call.writer.end_array();
}

// ---- Serving --------------------------------------------------------------------------

pub fn Server(comptime IO: type) type {
    return http.Server(IO, *Api, Api.handle_http);
}

pub const server_options: http.server.Options = .{
    .connections_max = 64,
    .recv_buffer_size = 16 * 1024 + request_bytes_max,
    .send_buffer_size = 256 * 1024,
    .limits = .{ .head_size_max = 16 * 1024, .body_size_max = request_bytes_max },
    .large_send_buffers_max = 4,
    .large_send_buffer_size = 64 << 20,
};

/// Non-blocking ticks per `poll`: accept, receive, and send each take one.
const poll_ticks = 4;
const timeout_tick_interval_ns = 250 * std.time.ns_per_ms;

/// The production server: the API, its own completion IO, and the HTTP server.
pub const Service = struct {
    const IO = io_module.IO;

    api: Api,
    io: IO,
    server: Server(IO),
    address: io_module.Address = undefined,
    last_tick_ns: u64 = 0,

    /// Null without `--rpc`/`--rpc.addr`. Listens. `io` runs the sequencer forwards.
    pub fn start(
        allocator: std.mem.Allocator,
        io: Io,
        flags: *const Flags,
        spec: *const ChainSpec,
        node: Node,
    ) !?*Service {
        const addr = flags.addr orelse return null;
        const address = io_module.Address.parse(addr) catch return error.InvalidRpcAddress;
        if (address.port == 0) return error.InvalidRpcAddress;
        const service = try create(allocator, address, spec, node, flags, server_options);
        errdefer service.destroy(allocator);
        if (flags.sequencer_url) |url| {
            service.api.sequencer = try el_sequencer.Forwarder.create(allocator, io, url);
            std.debug.print("el-run: eth_sendRawTransaction forwards to {s}\n", .{url});
        }
        std.debug.print("el-run: JSON-RPC on {f} (read-only), ring {d} blocks / {d} MiB\n", .{
            service.address, flags.ring_blocks, flags.ring_mib,
        });
        return service;
    }

    pub fn create(
        allocator: std.mem.Allocator,
        address: io_module.Address,
        spec: *const ChainSpec,
        node: Node,
        flags: *const Flags,
        options: http.server.Options,
    ) !*Service {
        const service = try allocator.create(Service);
        errdefer allocator.destroy(service);
        try service.api.init(allocator, spec, node, flags);
        errdefer service.api.deinit(allocator);
        service.io = if (@import("builtin").os.tag == .linux) try IO.init(.{}) else try IO.init();
        errdefer service.io.deinit();
        try service.server.init(allocator, &service.io, &service.api, options);
        errdefer service.server.deinit();
        service.address = try service.server.listen(address);
        service.last_tick_ns = 0;
        assert(address.port == 0 or service.address.port == address.port);
        return service;
    }

    pub fn destroy(service: *Service, allocator: std.mem.Allocator) void {
        if (service.api.sequencer) |forwarder| forwarder.destroy(allocator);
        service.server.deinit();
        service.io.deinit();
        service.api.deinit(allocator);
        allocator.destroy(service);
    }

    /// Answers what is ready without blocking (between blocks).
    pub fn poll(service: *Service) void {
        service.prepare();
        for (0..poll_ticks) |_| {
            service.io.tick() catch |err| {
                std.debug.print("el-run rpc: io tick failed: {t}\n", .{err});
                return;
            };
        }
    }

    /// Serves requests for `duration_ms` (the idle wait at the tip).
    pub fn wait(service: *Service, duration_ms: u64) !void {
        assert(duration_ms > 0);
        service.prepare();
        try service.io.run_for_ns(duration_ms * std.time.ns_per_ms);
    }

    fn prepare(service: *Service) void {
        if (service.api.sequencer) |forwarder| forwarder.poll(&service.server);
        const now_ns = service.io.now_monotonic_ns();
        if (now_ns -| service.last_tick_ns < timeout_tick_interval_ns) return;
        service.last_tick_ns = now_ns;
        service.server.tick();
    }
};

test {
    _ = @import("el_rpc_test.zig");
    _ = @import("el_sequencer.zig");
}
