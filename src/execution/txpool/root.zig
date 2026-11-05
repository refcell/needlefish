//! Transaction pool. Holds validated, signed transactions per sender ordered by nonce.
//! A sender's transactions are *pending* while their nonces run contiguously from the
//! account nonce and their cumulative cost fits the balance; the rest are *queued*.
//! The pool is fixed-capacity: every table is allocated in `init` and `add` evicts the
//! worst sender-tail transaction when full. Deposit transactions are never pooled.
//!
//! Decoding, signature recovery and state lookups happen in the caller (the RPC layer),
//! which hands the pool a `Tx` descriptor plus the sender's current `Account`.
//! Mirrors reth's pool as used by base/base `crates/execution/txpool` (price bump 10%,
//! blob price bump 100%, 16 slots per account).

const std = @import("std");
const assert = std.debug.assert;
const primitives = @import("../../common/primitives/root.zig");
pub const slab = @import("slab.zig");
pub const validate = @import("validate.zig");

pub const Address = primitives.Address;
pub const B256 = primitives.B256;

pub const deposit_tx_type: u8 = 0x7e;
pub const blob_tx_type: u8 = 0x03;
pub const gas_per_blob: u64 = 1 << 17;
const none: u32 = std.math.maxInt(u32);

/// Validated transaction metadata. `raw` is the network encoding (copied on add).
pub const Tx = struct {
    hash: B256,
    sender: Address,
    nonce: u64,
    tx_type: u8,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    max_fee_per_blob_gas: u128 = 0,
    blob_count: u8 = 0,
    value: u256 = 0,
    raw: []const u8,

    /// Upper bound of what executing this transaction can debit from the sender.
    pub fn cost(tx: *const Tx) u256 {
        const gas: u256 = @as(u256, tx.gas_limit) * tx.max_fee_per_gas;
        const blob_gas: u256 = @as(u256, tx.blob_count) * gas_per_blob * tx.max_fee_per_blob_gas;
        return gas +| blob_gas +| tx.value;
    }

    /// Miner tip at `base_fee`, or null when the fee cap is below the base fee.
    pub fn effective_tip(tx: *const Tx, base_fee: u64) ?u128 {
        if (tx.max_fee_per_gas < base_fee) return null;
        return @min(tx.max_priority_fee_per_gas, tx.max_fee_per_gas - base_fee);
    }
};

pub const Account = struct {
    nonce: u64,
    balance: u256,
};

pub const Config = struct {
    tx_capacity: u32 = 4096,
    account_slots_max: u32 = 16,
    price_bump_percent: u64 = 10,
    blob_price_bump_percent: u64 = 100,
    block_gas_limit: u64 = 30_000_000,
    slab: slab.Config = .{ .classes = &default_classes },
};

pub const default_classes = [_]slab.Class{
    .{ .size_bytes = 512, .count = 4096 },
    .{ .size_bytes = 4096, .count = 1024 },
    .{ .size_bytes = 32 * 1024, .count = 128 },
    .{ .size_bytes = 128 * 1024, .count = 16 },
    // Network-form blob txs: up to 9 blobs (Prague) plus commitments and proofs.
    .{ .size_bytes = 1280 * 1024, .count = 8 },
};

pub const AddError = error{
    DepositTx,
    AlreadyKnown,
    NonceTooLow,
    TipAboveFeeCap,
    GasLimitExceeded,
    InsufficientFunds,
    ReplacementUnderpriced,
    AccountFull,
    PoolFull,
    TooLarge,
};

pub const AddOutcome = enum { pending, queued, replaced_pending, replaced_queued };

const Entry = struct {
    tx: Tx,
    handle: slab.Handle,
    sender: u32,
    /// Next entry of the same sender, by ascending nonce.
    next: u32,
    pending: bool,
};

const Sender = struct {
    address: Address,
    account: Account,
    head: u32,
    count: u32,
};

pub const Pool = struct {
    config: Config,
    bytes: slab.Slab,
    entries: []Entry,
    entry_live: []bool,
    entry_free: []u32,
    entry_free_len: u32,
    senders: []Sender,
    sender_free: []u32,
    sender_free_len: u32,
    by_hash: std.AutoHashMapUnmanaged(B256, u32),
    by_sender: std.AutoHashMapUnmanaged(Address, u32),
    /// Scratch heap for `select`, sized to the sender capacity.
    heap: []u32,
    pending_count: u32,
    queued_count: u32,

    pub fn init(allocator: std.mem.Allocator, config: Config) !Pool {
        assert(config.tx_capacity > 0);
        assert(config.account_slots_max > 0);
        const capacity = config.tx_capacity;
        var pool: Pool = undefined;
        pool.config = config;
        pool.bytes = try slab.Slab.init(allocator, config.slab);
        errdefer pool.bytes.deinit(allocator);
        pool.entries = try allocator.alloc(Entry, capacity);
        errdefer allocator.free(pool.entries);
        pool.entry_live = try allocator.alloc(bool, capacity);
        errdefer allocator.free(pool.entry_live);
        pool.entry_free = try allocator.alloc(u32, capacity);
        errdefer allocator.free(pool.entry_free);
        pool.senders = try allocator.alloc(Sender, capacity);
        errdefer allocator.free(pool.senders);
        pool.sender_free = try allocator.alloc(u32, capacity);
        errdefer allocator.free(pool.sender_free);
        pool.heap = try allocator.alloc(u32, capacity);
        errdefer allocator.free(pool.heap);
        pool.by_hash = .empty;
        try pool.by_hash.ensureTotalCapacity(allocator, capacity);
        errdefer pool.by_hash.deinit(allocator);
        pool.by_sender = .empty;
        try pool.by_sender.ensureTotalCapacity(allocator, capacity);
        @memset(pool.entry_live, false);
        for (0..capacity) |i| {
            pool.entry_free[i] = capacity - 1 - @as(u32, @intCast(i));
            pool.sender_free[i] = capacity - 1 - @as(u32, @intCast(i));
        }
        pool.entry_free_len = capacity;
        pool.sender_free_len = capacity;
        pool.pending_count = 0;
        pool.queued_count = 0;
        return pool;
    }

    pub fn deinit(pool: *Pool, allocator: std.mem.Allocator) void {
        pool.by_sender.deinit(allocator);
        pool.by_hash.deinit(allocator);
        allocator.free(pool.heap);
        allocator.free(pool.sender_free);
        allocator.free(pool.senders);
        allocator.free(pool.entry_free);
        allocator.free(pool.entry_live);
        allocator.free(pool.entries);
        pool.bytes.deinit(allocator);
        pool.* = undefined;
    }

    pub fn count(pool: *const Pool) u32 {
        assert(pool.pending_count + pool.queued_count == pool.config.tx_capacity -
            pool.entry_free_len);
        return pool.pending_count + pool.queued_count;
    }

    pub fn get(pool: *const Pool, hash: B256) ?*const Tx {
        const index = pool.by_hash.get(hash) orelse return null;
        assert(pool.entry_live[index]);
        return &pool.entries[index].tx;
    }

    pub fn is_pending(pool: *const Pool, hash: B256) bool {
        const index = pool.by_hash.get(hash) orelse return false;
        return pool.entries[index].pending;
    }

    /// Highest pending nonce + 1 for `address`, i.e. the next nonce it should use.
    pub fn next_nonce(pool: *const Pool, address: Address, account_nonce: u64) u64 {
        const sender_index = pool.by_sender.get(address) orelse return account_nonce;
        var nonce = account_nonce;
        var cursor = pool.senders[sender_index].head;
        var steps: u32 = 0;
        while (cursor != none) : (steps += 1) {
            assert(steps < pool.config.account_slots_max);
            const entry = &pool.entries[cursor];
            if (entry.pending) nonce = entry.tx.nonce + 1;
            cursor = entry.next;
        }
        return nonce;
    }

    /// Most senders the pool tracks at once (the size `sorted_senders` needs).
    pub fn sender_capacity(pool: *const Pool) u32 {
        return @intCast(pool.senders.len);
    }

    /// Writes the live senders' indexes into `out`, by ascending address (deterministic
    /// listings for txpool_content/inspect), and returns how many there are.
    pub fn sorted_senders(pool: *const Pool, out: []u32) u32 {
        assert(out.len >= pool.senders.len);
        var live: u32 = 0;
        var iterator = pool.by_sender.valueIterator();
        while (iterator.next()) |index| {
            assert(pool.senders[index.*].count > 0);
            out[live] = index.*;
            live += 1;
        }
        assert(live == pool.by_sender.count());
        std.sort.pdq(u32, out[0..live], pool, sender_less);
        return live;
    }

    fn sender_less(pool: *const Pool, a: u32, b: u32) bool {
        const left = &pool.senders[a].address.bytes;
        const right = &pool.senders[b].address.bytes;
        return std.mem.order(u8, left, right) == .lt;
    }

    pub fn sender_address(pool: *const Pool, sender: u32) Address {
        assert(sender < pool.senders.len);
        assert(pool.senders[sender].count > 0);
        return pool.senders[sender].address;
    }

    /// A sender's transactions by ascending nonce, each with its pending flag.
    pub fn sender_transactions(pool: *const Pool, sender: u32) SenderTransactions {
        assert(sender < pool.senders.len);
        const entry = &pool.senders[sender];
        return .{ .pool = pool, .cursor = entry.head, .remaining = entry.count };
    }

    pub const SenderTransactions = struct {
        pool: *const Pool,
        cursor: u32,
        remaining: u32,

        pub const Item = struct { tx: *const Tx, pending: bool };

        pub fn next(iterator: *SenderTransactions) ?Item {
            if (iterator.cursor == none) {
                assert(iterator.remaining == 0);
                return null;
            }
            assert(iterator.remaining > 0);
            iterator.remaining -= 1;
            const entry = &iterator.pool.entries[iterator.cursor];
            assert(iterator.pool.entry_live[iterator.cursor]);
            iterator.cursor = entry.next;
            return .{ .tx = &entry.tx, .pending = entry.pending };
        }
    };

    pub fn add(pool: *Pool, tx: Tx, account: Account) AddError!AddOutcome {
        try pool.check_stateless(&tx);
        if (tx.nonce < account.nonce) return error.NonceTooLow;
        if (tx.cost() > account.balance) return error.InsufficientFunds;
        if (pool.by_hash.contains(tx.hash)) return error.AlreadyKnown;

        // Fresh account state may have mined some of this sender's transactions.
        pool.update_account(tx.sender, account);
        if (pool.by_sender.get(tx.sender)) |sender_index| {
            if (pool.find_nonce(sender_index, tx.nonce)) |existing| {
                return pool.replace(existing, tx);
            }
            if (pool.senders[sender_index].count >= pool.config.account_slots_max) {
                return error.AccountFull;
            }
        }
        if (pool.entry_free_len == 0) try pool.evict_for(&tx);
        const handle = pool.bytes.alloc(tx.raw) catch |err| switch (err) {
            error.TooLarge => return error.TooLarge,
            error.Full => return error.PoolFull,
        };
        const sender_index = pool.sender_for(tx.sender, account);
        const index = pool.entry_take();
        pool.entries[index] = .{
            .tx = tx,
            .handle = handle,
            .sender = sender_index,
            .next = none,
            .pending = false,
        };
        pool.entries[index].tx.raw = pool.bytes.slice(handle);
        pool.queued_count += 1;
        pool.by_hash.putAssumeCapacityNoClobber(tx.hash, index);
        pool.link(sender_index, index);
        pool.promote(sender_index);
        return if (pool.entries[index].pending) .pending else .queued;
    }

    fn check_stateless(pool: *const Pool, tx: *const Tx) AddError!void {
        if (tx.tx_type == deposit_tx_type) return error.DepositTx;
        if (tx.max_priority_fee_per_gas > tx.max_fee_per_gas) return error.TipAboveFeeCap;
        if (tx.gas_limit > pool.config.block_gas_limit) return error.GasLimitExceeded;
        if (tx.raw.len > pool.bytes.max_size_bytes()) return error.TooLarge;
    }

    fn replace(pool: *Pool, index: u32, tx: Tx) AddError!AddOutcome {
        const old = &pool.entries[index];
        assert(old.tx.nonce == tx.nonce);
        assert(old.tx.sender.eql(tx.sender));
        const bump = if (tx.tx_type == blob_tx_type or old.tx.tx_type == blob_tx_type)
            pool.config.blob_price_bump_percent
        else
            pool.config.price_bump_percent;
        if (!bumped(old.tx.max_fee_per_gas, tx.max_fee_per_gas, bump) or
            !bumped(old.tx.max_priority_fee_per_gas, tx.max_priority_fee_per_gas, bump) or
            !bumped(old.tx.max_fee_per_blob_gas, tx.max_fee_per_blob_gas, bump))
        {
            return error.ReplacementUnderpriced;
        }
        // Allocate before freeing so a failure leaves the old transaction intact.
        const handle = pool.bytes.alloc(tx.raw) catch |err| return switch (err) {
            error.TooLarge => error.TooLarge,
            error.Full => error.PoolFull,
        };
        pool.bytes.free_handle(old.handle);
        assert(pool.by_hash.remove(old.tx.hash));
        old.tx = tx;
        old.tx.raw = pool.bytes.slice(handle);
        old.handle = handle;
        pool.by_hash.putAssumeCapacityNoClobber(tx.hash, index);
        pool.promote(old.sender);
        return if (old.pending) .replaced_pending else .replaced_queued;
    }

    /// Frees one entry for `incoming` by evicting the worst sender-tail transaction:
    /// queued before pending, then lowest fee cap. Fails when the victim pays at least
    /// as much as `incoming`.
    fn evict_for(pool: *Pool, incoming: *const Tx) AddError!void {
        assert(pool.entry_free_len == 0);
        var victim: u32 = none;
        var it = pool.by_sender.valueIterator();
        while (it.next()) |sender_index| {
            const last = pool.tail(sender_index.*);
            if (victim == none or worse(&pool.entries[last], &pool.entries[victim])) victim = last;
        }
        assert(victim != none);
        const v = &pool.entries[victim];
        if (v.pending and v.tx.max_fee_per_gas >= incoming.max_fee_per_gas) {
            return error.PoolFull;
        }
        pool.remove_index(victim);
    }

    /// Removes a transaction (e.g. on inclusion or invalidation). Later nonces of the
    /// same sender become queued.
    pub fn remove(pool: *Pool, hash: B256) bool {
        const index = pool.by_hash.get(hash) orelse return false;
        pool.remove_index(index);
        return true;
    }

    /// Applies a new account state (after a block): drops transactions whose nonce is
    /// now used and re-evaluates which of the rest are pending.
    pub fn update_account(pool: *Pool, address: Address, account: Account) void {
        const sender_index = pool.by_sender.get(address) orelse return;
        pool.senders[sender_index].account = account;
        var steps: u32 = 0;
        while (steps < pool.config.account_slots_max) : (steps += 1) {
            const head = pool.senders[sender_index].head;
            if (head == none or pool.entries[head].tx.nonce >= account.nonce) break;
            pool.remove_index(head); // May free the sender when it was the last entry.
            if (!pool.by_sender.contains(address)) return;
        }
        pool.promote(sender_index);
    }

    /// Fills `out` with pending transactions in block order: highest effective tip first,
    /// nonces ascending per sender. Skips senders whose next tx cannot pay `base_fee`.
    /// Returns the number written.
    pub fn select(pool: *Pool, base_fee: u64, out: []*const Tx) u32 {
        var heap: Heap = .{ .pool = pool, .base_fee = base_fee, .items = pool.heap, .len = 0 };
        var it = pool.by_sender.valueIterator();
        while (it.next()) |sender_index| {
            const head = pool.senders[sender_index.*].head;
            if (head == none or !pool.entries[head].pending) continue;
            if (pool.entries[head].tx.effective_tip(base_fee) == null) continue;
            heap.push(head);
        }
        var written: u32 = 0;
        while (written < out.len) {
            const index = heap.pop() orelse break;
            out[written] = &pool.entries[index].tx;
            written += 1;
            const next = pool.entries[index].next;
            if (next == none or !pool.entries[next].pending) continue;
            if (pool.entries[next].tx.effective_tip(base_fee) == null) continue;
            heap.push(next);
        }
        assert(written <= out.len);
        return written;
    }

    fn remove_index(pool: *Pool, index: u32) void {
        assert(pool.entry_live[index]);
        const entry = &pool.entries[index];
        const sender_index = entry.sender;
        assert(pool.by_hash.remove(entry.tx.hash));
        pool.unlink(sender_index, index);
        if (entry.pending) pool.pending_count -= 1 else pool.queued_count -= 1;
        pool.bytes.free_handle(entry.handle);
        pool.entry_live[index] = false;
        pool.entry_free[pool.entry_free_len] = index;
        pool.entry_free_len += 1;
        if (pool.senders[sender_index].count == 0) {
            assert(pool.by_sender.remove(pool.senders[sender_index].address));
            pool.sender_free[pool.sender_free_len] = sender_index;
            pool.sender_free_len += 1;
        } else {
            pool.promote(sender_index);
        }
    }

    /// Recomputes pending flags: contiguous nonces from the account nonce whose
    /// cumulative cost fits the balance.
    fn promote(pool: *Pool, sender_index: u32) void {
        const sender = &pool.senders[sender_index];
        var expected = sender.account.nonce;
        var spent: u256 = 0;
        var contiguous = true;
        var cursor = sender.head;
        var steps: u32 = 0;
        while (cursor != none) : (steps += 1) {
            assert(steps <= pool.config.account_slots_max);
            const entry = &pool.entries[cursor];
            spent +|= entry.tx.cost();
            const affordable = spent <= sender.account.balance;
            contiguous = contiguous and entry.tx.nonce == expected and affordable;
            expected = entry.tx.nonce +| 1;
            if (entry.pending != contiguous) {
                if (contiguous) {
                    pool.queued_count -= 1;
                    pool.pending_count += 1;
                } else {
                    pool.pending_count -= 1;
                    pool.queued_count += 1;
                }
                entry.pending = contiguous;
            }
            cursor = entry.next;
        }
        assert(steps == sender.count);
    }

    fn find_nonce(pool: *const Pool, sender_index: u32, nonce: u64) ?u32 {
        var cursor = pool.senders[sender_index].head;
        var steps: u32 = 0;
        while (cursor != none) : (steps += 1) {
            assert(steps < pool.config.account_slots_max);
            if (pool.entries[cursor].tx.nonce == nonce) return cursor;
            if (pool.entries[cursor].tx.nonce > nonce) return null;
            cursor = pool.entries[cursor].next;
        }
        return null;
    }

    fn tail(pool: *const Pool, sender_index: u32) u32 {
        var cursor = pool.senders[sender_index].head;
        assert(cursor != none);
        var steps: u32 = 0;
        while (pool.entries[cursor].next != none) : (steps += 1) {
            assert(steps < pool.config.account_slots_max);
            cursor = pool.entries[cursor].next;
        }
        return cursor;
    }

    fn sender_for(pool: *Pool, address: Address, account: Account) u32 {
        if (pool.by_sender.get(address)) |index| return index;
        assert(pool.sender_free_len > 0);
        pool.sender_free_len -= 1;
        const index = pool.sender_free[pool.sender_free_len];
        pool.senders[index] = .{ .address = address, .account = account, .head = none, .count = 0 };
        pool.by_sender.putAssumeCapacityNoClobber(address, index);
        return index;
    }

    fn entry_take(pool: *Pool) u32 {
        assert(pool.entry_free_len > 0);
        pool.entry_free_len -= 1;
        const index = pool.entry_free[pool.entry_free_len];
        assert(!pool.entry_live[index]);
        pool.entry_live[index] = true;
        return index;
    }

    /// Inserts `index` into the sender list keeping nonces ascending.
    fn link(pool: *Pool, sender_index: u32, index: u32) void {
        const sender = &pool.senders[sender_index];
        const nonce = pool.entries[index].tx.nonce;
        var previous: u32 = none;
        var cursor = sender.head;
        var steps: u32 = 0;
        while (cursor != none and pool.entries[cursor].tx.nonce < nonce) : (steps += 1) {
            assert(steps < pool.config.account_slots_max);
            previous = cursor;
            cursor = pool.entries[cursor].next;
        }
        assert(cursor == none or pool.entries[cursor].tx.nonce != nonce);
        pool.entries[index].next = cursor;
        if (previous == none) sender.head = index else pool.entries[previous].next = index;
        sender.count += 1;
    }

    fn unlink(pool: *Pool, sender_index: u32, index: u32) void {
        const sender = &pool.senders[sender_index];
        assert(sender.count > 0);
        var previous: u32 = none;
        var cursor = sender.head;
        var steps: u32 = 0;
        while (cursor != index) : (steps += 1) {
            assert(cursor != none);
            assert(steps < pool.config.account_slots_max);
            previous = cursor;
            cursor = pool.entries[cursor].next;
        }
        const next = pool.entries[index].next;
        if (previous == none) sender.head = next else pool.entries[previous].next = next;
        sender.count -= 1;
    }
};

/// `new >= old * (100 + bump) / 100`, computed without overflow.
fn bumped(old: u128, new: u128, bump_percent: u64) bool {
    const required: u256 = @as(u256, old) * (100 + bump_percent) / 100;
    return new >= required;
}

fn worse(a: *const Entry, b: *const Entry) bool {
    if (a.pending != b.pending) return !a.pending;
    return a.tx.max_fee_per_gas < b.tx.max_fee_per_gas;
}

/// Bounded binary max-heap of entry indices keyed by effective tip.
const Heap = struct {
    pool: *const Pool,
    base_fee: u64,
    items: []u32,
    len: u32,

    fn key(heap: *const Heap, index: u32) u128 {
        return heap.pool.entries[index].tx.effective_tip(heap.base_fee).?;
    }

    fn higher(heap: *const Heap, a: u32, b: u32) bool {
        const ka = heap.key(a);
        const kb = heap.key(b);
        if (ka != kb) return ka > kb;
        return a < b; // Deterministic tie break.
    }

    fn push(heap: *Heap, index: u32) void {
        assert(heap.len < heap.items.len);
        var child = heap.len;
        heap.items[child] = index;
        heap.len += 1;
        while (child > 0) {
            const parent = (child - 1) / 2;
            if (!heap.higher(heap.items[child], heap.items[parent])) break;
            std.mem.swap(u32, &heap.items[child], &heap.items[parent]);
            child = parent;
        }
    }

    fn pop(heap: *Heap) ?u32 {
        if (heap.len == 0) return null;
        const top = heap.items[0];
        heap.len -= 1;
        heap.items[0] = heap.items[heap.len];
        var parent: u32 = 0;
        while (true) {
            const left = parent * 2 + 1;
            if (left >= heap.len) break;
            var best = left;
            if (left + 1 < heap.len and heap.higher(heap.items[left + 1], heap.items[left])) {
                best = left + 1;
            }
            if (!heap.higher(heap.items[best], heap.items[parent])) break;
            std.mem.swap(u32, &heap.items[best], &heap.items[parent]);
            parent = best;
        }
        return top;
    }
};

test {
    std.testing.refAllDecls(@This());
    _ = @import("tests.zig");
}
