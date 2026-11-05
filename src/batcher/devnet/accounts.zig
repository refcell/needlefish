//! Devnet accounts derived from the public dev mnemonic.
//!
//! `test test test test test test test test test test test junk` is the mnemonic every
//! Ethereum dev tool (anvil, hardhat, op devnets) prefunds. Its keys are public by
//! design; deriving them here (BIP39 seed, BIP32 path m/44'/60'/0'/0/i) avoids
//! committing key material and lets `--key-index N` pick a role.

const std = @import("std");
const assert = std.debug.assert;
const Secp256k1 = std.crypto.ecc.Secp256k1;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
const primitives = @import("../../common/primitives/root.zig");

pub const dev_mnemonic = "test test test test test test test test test test test junk";

/// Accounts `0..funded_count` are prefunded on L1 and L2.
pub const funded_count = 10;

/// Roles, by index into the dev mnemonic (docs/DEVNET.md).
pub const Role = enum(u32) {
    deployer = 0,
    user = 1,
    sequencer = 5,
    batcher = 6,
    proposer = 7,
};

pub const Account = struct {
    private_key: [32]u8,
    address: primitives.Address,
};

const hardened: u32 = 0x8000_0000;

/// Derives account `index` of `mnemonic` along m/44'/60'/0'/0/index.
pub fn derive(mnemonic: []const u8, index: u32) Account {
    assert(mnemonic.len > 0);
    assert(index < hardened);
    var seed: [64]u8 = undefined;
    // BIP39: PBKDF2-HMAC-SHA512, salt "mnemonic" ++ passphrase (empty), 2048 rounds.
    std.crypto.pwhash.pbkdf2(&seed, mnemonic, "mnemonic", 2048, HmacSha512) catch
        unreachable; // Fixed, valid parameters.
    var node = master_node(&seed);
    const path = [_]u32{ 44 | hardened, 60 | hardened, hardened, 0, index };
    for (path) |child| node = child_node(node, child);
    const account: Account = .{ .private_key = node.key, .address = address_of(node.key) };
    assert(!std.mem.allEqual(u8, &account.private_key, 0));
    return account;
}

pub fn derive_dev(index: u32) Account {
    return derive(dev_mnemonic, index);
}

/// Ethereum address of a secp256k1 private key: keccak(pubkey x ++ y)[12..].
pub fn address_of(private_key: [32]u8) primitives.Address {
    const point = Secp256k1.basePoint.mul(private_key, .big) catch
        unreachable; // Derived keys are valid non-zero scalars.
    const uncompressed = point.toUncompressedSec1();
    assert(uncompressed[0] == 0x04);
    const hash = primitives.keccak256(uncompressed[1..]);
    return .{ .bytes = hash.bytes[12..32].* };
}

const Node = struct {
    key: [32]u8,
    chain_code: [32]u8,
};

fn master_node(seed: *const [64]u8) Node {
    var out: [64]u8 = undefined;
    HmacSha512.create(&out, seed, "Bitcoin seed");
    Secp256k1.scalar.rejectNonCanonical(out[0..32].*, .big) catch
        unreachable; // Probability below 2^-127; the dev mnemonic is known-good.
    return .{ .key = out[0..32].*, .chain_code = out[32..64].* };
}

fn child_node(parent: Node, index: u32) Node {
    var data: [37]u8 = undefined;
    if (index >= hardened) {
        data[0] = 0;
        @memcpy(data[1..33], &parent.key);
    } else {
        const point = Secp256k1.basePoint.mul(parent.key, .big) catch unreachable; // Valid key.
        @memcpy(data[0..33], &point.toCompressedSec1());
    }
    std.mem.writeInt(u32, data[33..37], index, .big);
    var out: [64]u8 = undefined;
    HmacSha512.create(&out, &data, &parent.chain_code);
    // IL >= n or a zero child key happens with probability ~2^-127; BIP32 says skip
    // to the next index. The fixed dev paths are known not to hit it.
    const key = Secp256k1.scalar.add(out[0..32].*, parent.key, .big) catch unreachable;
    assert(!std.mem.allEqual(u8, &key, 0));
    return .{ .key = key, .chain_code = out[32..64].* };
}

const testing = std.testing;

test "accounts: dev mnemonic matches the well-known addresses" {
    const expected = [_]struct { index: u32, address: []const u8 }{
        .{ .index = 0, .address = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266" },
        .{ .index = 1, .address = "70997970c51812dc3a010c7d01b50e0d17dc79c8" },
        .{ .index = 5, .address = "9965507d1a55bcc2695c58ba16fb37d819b0a4dc" },
        .{ .index = 6, .address = "976ea74026e726554db657fa54763abd0c3a0aa9" },
    };
    for (expected) |entry| {
        const account = derive_dev(entry.index);
        var want: [20]u8 = undefined;
        _ = try std.fmt.hexToBytes(&want, entry.address);
        try testing.expectEqualSlices(u8, &want, &account.address.bytes);
    }
}

test "accounts: index 0 key is the well-known dev key" {
    const account = derive_dev(@backingInt(Role.deployer));
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &want,
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    );
    try testing.expectEqualSlices(u8, &want, &account.private_key);
    try testing.expectEqualSlices(u8, &account.address.bytes, &address_of(want).bytes);
}
