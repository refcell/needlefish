//! Withdrawals sent through the L2ToL1MessagePasser predeploy (base/base
//! `crates/infra/withdrawer/src/withdrawal.rs`): `MessagePassed` log decoding, the withdrawal
//! hash and its `sentMessages` storage slot, the version-zero output root, and verification of
//! an `eth_getProof` response against a block state root and an onchain output claim.
//!
//! Proofs come in two shapes. Geth omits trie nodes shorter than 32 bytes (they are inlined in
//! their parent); reth returns them as separate elements. The portal's `MerkleTrie` needs the
//! reth shape, the verifier the geth one, so a proof is first stripped of an authenticated
//! inline tail, verified, then expanded again. Embedded nodes are subslices of their parent's
//! encoding, so expansion copies nothing. All walks are iterative and bounded.

const std = @import("std");
const assert = std.debug.assert;

const abi = @import("../../proof/contracts/abi.zig");
const trie_rlp = @import("../../execution/trie/rlp.zig");
const trie_proof = @import("../../execution/trie/proof.zig");
const nibbles_module = @import("../../execution/trie/nibbles.zig");
const state_trie = @import("../../execution/trie/state_trie.zig");
const predeploys = @import("../../common/consensus/predeploys.zig");

const Keccak256 = std.crypto.hash.sha3.Keccak256;

pub const Address = [20]u8;
pub const Hash = [32]u8;

pub const message_passer: Address = predeploys.l2_to_l1_message_passer.bytes;
/// `MessagePassed(uint256,address,address,uint256,uint256,bytes,bytes32)`.
pub const message_passed_topic: Hash = keccak256(
    "MessagePassed(uint256,address,address,uint256,uint256,bytes,bytes32)",
);
/// Largest withdrawal calldata accepted (the portal itself has no hard cap; this bounds memory).
pub const data_bytes_max: u32 = 32 * 1024;
/// Withdrawals kept from one receipt.
pub const withdrawals_max: u32 = 16;
/// Nodes on one 32-byte key's path: a branch or extension per nibble, plus the leaf.
pub const proof_nodes_max: u32 = nibbles_module.nibbles_max + 2;

comptime {
    assert(proof_nodes_max >= 64 * 2);
    assert(data_bytes_max % 32 == 0);
}

pub const Error = error{
    NoWithdrawals,
    TooManyWithdrawals,
    MissingBlockNumber,
    DecodeEvent,
    DataTooLarge,
    WithdrawalHashMismatch,
    ProofAddressMismatch,
    StorageProofCount,
    StorageKeyMismatch,
    StorageValueMismatch,
    AccountProof,
    StorageProof,
    ProofTooLong,
    OutputRootMismatch,
};

pub fn keccak256(bytes: []const u8) Hash {
    @setEvalBranchQuota(100_000);
    var digest: Hash = undefined;
    Keccak256.hash(bytes, &digest, .{});
    return digest;
}

/// Arguments of the portal's `WithdrawalTransaction` struct. `data` is borrowed.
pub const Transaction = struct {
    nonce: u256,
    sender: Address,
    target: Address,
    value: u256,
    gas_limit: u256,
    data: []const u8,

    /// keccak256(abi.encode(nonce, sender, target, value, gasLimit, data)), streamed.
    pub fn hash(transaction: *const Transaction) Hash {
        assert(transaction.data.len <= std.math.maxInt(u32));
        var head: [7 * 32]u8 = @splat(0);
        std.mem.writeInt(u256, head[0..32], transaction.nonce, .big);
        head[32 + 12 .. 64].* = transaction.sender;
        head[64 + 12 .. 96].* = transaction.target;
        std.mem.writeInt(u256, head[96..128], transaction.value, .big);
        std.mem.writeInt(u256, head[128..160], transaction.gas_limit, .big);
        std.mem.writeInt(u256, head[160..192], 6 * 32, .big);
        std.mem.writeInt(u256, head[192..224], transaction.data.len, .big);
        var hasher = Keccak256.init(.{});
        hasher.update(&head);
        hasher.update(transaction.data);
        const padding = (32 - transaction.data.len % 32) % 32;
        const zeros: [32]u8 = @splat(0);
        hasher.update(zeros[0..padding]);
        var digest: Hash = undefined;
        hasher.final(&digest);
        return digest;
    }
};

/// A withdrawal and the L2 block whose receipt emitted it.
pub const Withdrawal = struct {
    transaction: Transaction,
    block_number: u64,

    pub fn hash(withdrawal: *const Withdrawal) Hash {
        return withdrawal.transaction.hash();
    }

    /// The `sentMessages[hash]` slot: keccak256(hash ++ uint256(0)).
    pub fn slot(withdrawal: *const Withdrawal) Hash {
        return storage_slot(withdrawal.hash());
    }
};

pub fn storage_slot(withdrawal_hash: Hash) Hash {
    var preimage: [64]u8 = @splat(0);
    preimage[0..32].* = withdrawal_hash;
    const result = keccak256(&preimage);
    assert(!std.mem.eql(u8, &result, &withdrawal_hash));
    return result;
}

/// One receipt log. `topics` and `data` are borrowed.
pub const Log = struct {
    address: Address,
    topics: []const Hash,
    data: []const u8,
};

/// Decodes a `MessagePassed` log of the message passer. Returns null for other emitters and
/// events; errors when the event is malformed or does not commit to its own fields.
pub fn decode_message_passed(log: Log, block_number: u64) Error!?Withdrawal {
    if (!std.mem.eql(u8, &log.address, &message_passer)) return null;
    if (log.topics.len == 0) return null;
    if (!std.mem.eql(u8, &log.topics[0], &message_passed_topic)) return null;
    if (log.topics.len != 4) return error.DecodeEvent;
    const sender = topic_address(log.topics[2]) orelse return error.DecodeEvent;
    const target = topic_address(log.topics[3]) orelse return error.DecodeEvent;
    const decoder: abi.Decoder = .{ .data = log.data };
    // Strict like alloy's validating decoder: canonical offset and exact length.
    const offset = decoder.uint(u32, 2) catch return error.DecodeEvent;
    if (offset != 4 * 32) return error.DecodeEvent;
    const data = decoder.bytes(2) catch return error.DecodeEvent;
    const padded = (data.len + 31) / 32 * 32;
    if (log.data.len != 5 * 32 + padded) return error.DecodeEvent;
    if (data.len > data_bytes_max) return error.DataTooLarge;
    const withdrawal: Withdrawal = .{
        .transaction = .{
            .nonce = std.mem.readInt(u256, &log.topics[1], .big),
            .sender = sender,
            .target = target,
            .value = decoder.uint(u256, 0) catch unreachable, // Length checked above.
            .gas_limit = decoder.uint(u256, 1) catch unreachable, // Length checked above.
            .data = data,
        },
        .block_number = block_number,
    };
    const emitted = (decoder.word(3) catch unreachable).*; // Length checked above.
    if (!std.mem.eql(u8, &withdrawal.hash(), &emitted)) return error.WithdrawalHashMismatch;
    return withdrawal;
}

fn topic_address(topic: Hash) ?Address {
    if (!std.mem.allEqual(u8, topic[0..12], 0)) return null;
    return topic[12..32].*;
}

/// Every message passer withdrawal of a receipt in log order, into `out`.
pub fn from_logs(logs: []const Log, block_number: ?u64, out: []Withdrawal) Error![]Withdrawal {
    assert(out.len > 0);
    var count: usize = 0;
    for (logs) |log| {
        const number = block_number orelse {
            if (try decode_message_passed(log, 0) == null) continue;
            return error.MissingBlockNumber;
        };
        const withdrawal = try decode_message_passed(log, number) orelse continue;
        if (count == out.len) return error.TooManyWithdrawals;
        out[count] = withdrawal;
        count += 1;
    }
    if (count == 0) return error.NoWithdrawals;
    assert(count <= out.len);
    return out[0..count];
}

/// The version-zero output root preimage, as the portal's `OutputRootProof`.
pub const OutputRootProof = struct {
    version: Hash = @splat(0),
    state_root: Hash,
    message_passer_storage_root: Hash,
    latest_blockhash: Hash,

    pub fn root(proof: *const OutputRootProof) Hash {
        var preimage: [128]u8 = undefined;
        preimage[0..32].* = proof.version;
        preimage[32..64].* = proof.state_root;
        preimage[64..96].* = proof.message_passer_storage_root;
        preimage[96..128].* = proof.latest_blockhash;
        assert(std.mem.allEqual(u8, &proof.version, 0));
        return keccak256(&preimage);
    }
};

pub const StorageProof = struct {
    key: Hash,
    value: u256,
    proof: []const []const u8,
};

/// An `eth_getProof` response. Slices are borrowed.
pub const AccountProof = struct {
    address: Address,
    nonce: u64,
    balance: u256,
    storage_hash: Hash,
    code_hash: Hash,
    account_proof: []const []const u8,
    storage_proof: []const StorageProof,
};

/// An authenticated block header: the caller checked that `block_hash` is the header's hash.
pub const BlockCommitment = struct {
    state_root: Hash,
    block_hash: Hash,
};

/// Storage proof nodes in the portal's (reth) shape. Slices point into the input proof.
pub const ProofNodes = struct {
    nodes: [proof_nodes_max][]const u8 = undefined,
    count: u32 = 0,

    pub fn slice(nodes: *const ProofNodes) []const []const u8 {
        assert(nodes.count <= proof_nodes_max);
        return nodes.nodes[0..nodes.count];
    }

    fn push(nodes: *ProofNodes, node: []const u8) error{ ProofTooLong, InvalidNode }!void {
        if (node.len == 0) return error.InvalidNode;
        if (nodes.count == proof_nodes_max) return error.ProofTooLong;
        nodes.nodes[nodes.count] = node;
        nodes.count += 1;
        assert(nodes.count <= proof_nodes_max);
    }
};

/// Authenticates the withdrawal's inclusion against `expected_output_root` and returns the
/// portal's output root preimage; `storage_out` receives the storage proof to submit.
///
/// Does not establish that the claim is valid: callers check that its game is proper,
/// respected, and not resolved for the challenger.
pub fn verify_proof(
    withdrawal: *const Withdrawal,
    block: BlockCommitment,
    proof: *const AccountProof,
    expected_output_root: Hash,
    storage_out: *ProofNodes,
) Error!OutputRootProof {
    if (!std.mem.eql(u8, &proof.address, &message_passer)) return error.ProofAddressMismatch;
    if (proof.storage_proof.len != 1) return error.StorageProofCount;
    const storage = &proof.storage_proof[0];
    const slot = withdrawal.slot();
    if (!std.mem.eql(u8, &storage.key, &slot)) return error.StorageKeyMismatch;
    if (storage.value != 1) return error.StorageValueMismatch;
    // Binding both roots to the claim first keeps a self-consistent fake proof from reaching
    // the node walks at all; the walks are bounded and total either way.
    const output: OutputRootProof = .{
        .state_root = block.state_root,
        .message_passer_storage_root = proof.storage_hash,
        .latest_blockhash = block.block_hash,
    };
    if (!std.mem.eql(u8, &output.root(), &expected_output_root)) return error.OutputRootMismatch;
    try verify_account(proof, block.state_root);
    const storage_key = keccak256(&slot);
    const expected_value = [_]u8{0x01}; // rlp(uint256(1)).
    const stripped = strip_inline_nodes(
        storage.proof,
        proof.storage_hash,
        &storage_key,
        &expected_value,
    ) catch return error.StorageProof;
    storage_out.count = 0;
    expand_inline_nodes(stripped, &storage_key, storage_out) catch |err| switch (err) {
        error.ProofTooLong => return error.ProofTooLong,
        else => return error.StorageProof,
    };
    assert(storage_out.count >= stripped.len);
    return output;
}

fn verify_account(proof: *const AccountProof, state_root: Hash) Error!void {
    var encoded: [state_trie.account_rlp_bytes_max]u8 = undefined;
    const account: state_trie.Account = .{
        .nonce = proof.nonce,
        .balance = proof.balance,
        .code_hash = proof.code_hash,
    };
    const expected = state_trie.encode_account(&account, &proof.storage_hash, &encoded);
    const key = keccak256(&proof.address);
    const value = trie_proof.verify(state_root, &key, proof.account_proof) catch
        return error.AccountProof;
    const found = value orelse return error.AccountProof;
    if (!std.mem.eql(u8, found, expected)) return error.AccountProof;
    assert(expected.len > 0);
}

pub const StripError = trie_proof.VerifyError || error{ValueMismatch};

/// Verifies `proof` and drops a trailing run that exactly duplicates authenticated inline
/// nodes (the reth shape). A candidate prefix must verify before its nodes are expanded;
/// otherwise the full proof must verify, and its error is returned.
pub fn strip_inline_nodes(
    proof: []const []const u8,
    root: Hash,
    key: []const u8,
    expected_value: []const u8,
) StripError![]const []const u8 {
    assert(key.len <= nibbles_module.key_bytes_max);
    var length: usize = 1;
    while (length < proof.len) : (length += 1) {
        const prefix = proof[0..length];
        if (!value_matches(root, key, prefix, expected_value)) continue;
        var expanded: ProofNodes = .{};
        expand_inline_nodes(prefix, key, &expanded) catch continue;
        if (nodes_equal(expanded.slice(), proof)) return prefix;
    }
    const value = try trie_proof.verify(root, key, proof);
    const found = value orelse return error.ValueMismatch;
    if (!std.mem.eql(u8, found, expected_value)) return error.ValueMismatch;
    return proof;
}

fn value_matches(
    root: Hash,
    key: []const u8,
    proof: []const []const u8,
    expected: []const u8,
) bool {
    const value = trie_proof.verify(root, key, proof) catch return false;
    const found = value orelse return false;
    return std.mem.eql(u8, found, expected);
}

fn nodes_equal(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| if (!std.mem.eql(u8, left, right)) return false;
    return true;
}

pub const ExpandError = trie_rlp.DecodeError || error{ InvalidNode, ProofTooLong };

const Decoded = union(enum) {
    branch: [17]trie_rlp.Item,
    extension: struct { path_length: u32, child: trie_rlp.Item },
    leaf,
};

fn decode_node(encoded: []const u8) ExpandError!Decoded {
    const outer = try trie_rlp.decode_item(encoded);
    if (outer.kind != .list or outer.encoded_length != encoded.len) return error.InvalidNode;
    var items: [17]trie_rlp.Item = undefined;
    const count = trie_rlp.decode_list(outer.payload, &items) catch return error.InvalidNode;
    if (count == 17) return .{ .branch = items };
    if (count != 2 or items[0].kind != .string) return error.InvalidNode;
    const decoded = nibbles_module.hex_prefix_decode(items[0].payload) catch
        return error.InvalidNode;
    if (decoded.leaf) return .leaf;
    return .{ .extension = .{ .path_length = decoded.path.len, .child = items[1] } };
}

/// Appends the nodes embedded along `key` in the proof's last node as separate elements
/// (geth shape to reth shape). Inline nodes can only sit at the tail of a path.
pub fn expand_inline_nodes(
    proof: []const []const u8,
    key: []const u8,
    out: *ProofNodes,
) ExpandError!void {
    assert(out.count == 0);
    assert(key.len <= nibbles_module.key_bytes_max);
    for (proof) |node| try out.push(node);
    if (proof.len == 0) return;
    const path = nibbles_module.Nibbles.from_bytes(key);
    const nibbles = path.slice();
    var depth: usize = 0;
    for (proof[0 .. proof.len - 1]) |node| switch (try decode_node(node)) {
        .branch => depth += 1,
        .extension => |extension| depth += extension.path_length,
        .leaf => return,
    };
    var node = proof[proof.len - 1];
    var steps: u32 = 0;
    while (steps < proof_nodes_max) : (steps += 1) {
        const child: trie_rlp.Item = switch (try decode_node(node)) {
            .branch => |items| blk: {
                if (depth >= nibbles.len) return;
                const nibble = nibbles[depth];
                depth += 1;
                break :blk items[nibble];
            },
            .extension => |extension| blk: {
                depth += extension.path_length;
                break :blk extension.child;
            },
            .leaf => return,
        };
        if (child.kind != .list) return; // A hash reference or an empty slot.
        node = child.raw;
        try out.push(node);
    }
    return error.InvalidNode;
}

const testing = std.testing;
const fuzz = @import("../../testing/fuzz.zig");
const Prng = @import("../../testing/prng.zig").Prng;

test "withdrawal: event topic and selector constants" {
    const expected = "02a52367d10742d8032712c1bb8e0144ff1ec5ffda1ed7d70bb05a2744955054";
    var hex: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{&message_passed_topic}) catch unreachable;
    try testing.expectEqualStrings(expected, &hex);
    try testing.expectEqual(@as(u8, 0x16), message_passer[19]);
}

test "withdrawal: trie node expansion ignores hash references" {
    var out: ProofNodes = .{};
    try expand_inline_nodes(&.{}, &@as(Hash, @splat(0)), &out);
    try testing.expectEqual(@as(u32, 0), out.count);
    out = .{};
    try testing.expectError(error.InvalidNode, expand_inline_nodes(&.{"\xc0"}, "", &out));
}

fn fuzz_log(_: void, smith: *std.testing.Smith) anyerror!void {
    var topics: [5]Hash = undefined;
    const topic_count = smith.valueRangeAtMost(u8, 0, 5);
    for (topics[0..topic_count]) |*topic| smith.bytes(topic);
    if (topic_count > 0 and smith.value(bool)) topics[0] = message_passed_topic;
    var data: [512]u8 = undefined;
    const length = smith.slice(&data);
    const log: Log = .{
        .address = message_passer,
        .topics = topics[0..topic_count],
        .data = data[0..length],
    };
    const withdrawal = decode_message_passed(log, 7) catch return;
    const decoded = withdrawal orelse return;
    // A decoded event always commits to its own fields and borrows the log data.
    try testing.expectEqualSlices(u8, &decoded.hash(), data[length - 32 .. length]);
    try testing.expect(@intFromPtr(decoded.transaction.data.ptr) >= @intFromPtr(&data));
}

test "withdrawal: fuzz MessagePassed decode" {
    try fuzz.run({}, fuzz_log, .{ .iterations = 1024 });
}

fn fuzz_proof(_: void, smith: *std.testing.Smith) anyerror!void {
    var storage: [4][96]u8 = undefined;
    var nodes: [4][]const u8 = undefined;
    const count = smith.valueRangeAtMost(u8, 0, 4);
    for (0..count) |index| nodes[index] = storage[index][0..smith.slice(&storage[index])];
    var key: Hash = undefined;
    smith.bytes(&key);
    const root = keccak256(if (count > 0) nodes[0] else "");
    // Arbitrary nodes verify or fail cleanly; expansions keep the input as a prefix.
    _ = strip_inline_nodes(nodes[0..count], root, &key, "\x01") catch {};
    var out: ProofNodes = .{};
    expand_inline_nodes(nodes[0..count], &key, &out) catch return;
    try testing.expect(out.count >= count);
    for (nodes[0..count], 0..) |node, index| {
        try testing.expectEqual(node.ptr, out.nodes[index].ptr);
    }
}

test "withdrawal: fuzz proof strip and expand" {
    try fuzz.run({}, fuzz_proof, .{ .iterations = 1024 });
}
