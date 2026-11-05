//! Network upgrade transactions: the deposits a hardfork's activation block executes right
//! after the L1 info deposit (and user deposits) to deploy and wire new predeploy
//! implementations. Each is a non-system deposit whose source hash is derived from an
//! intent string in the upgrade domain.
//!
//! Deployment bytecode is public base/base content, embedded as hex from
//! `upgrade_bytecode/` (copied verbatim from `crates/consensus/upgrades/src/bytecode`).
//! Mirrors base/base `crates/consensus/upgrades/src/{ecotone,fjord,isthmus,jovian}.rs`.

const std = @import("std");
const assert = std.debug.assert;

const primitives = @import("../../common/primitives/root.zig");
const protocol = @import("../protocol/root.zig");
const deposits = protocol.deposits;
const Address = primitives.Address;
const B256 = primitives.B256;

/// Forks that emit upgrade transactions, in the order the builder appends them.
pub const Fork = enum { ecotone, fjord, isthmus, jovian };

/// `upgradeTo(address)` selector.
pub const upgrade_to_selector: [4]u8 = .{ 0x36, 0x59, 0xcf, 0xe6 };
pub const upgrade_to_calldata_length: u32 = 4 + 32;

pub const predeploy_gas_price_oracle = Address.comptime_hex(
    "0x420000000000000000000000000000000000000F",
);
pub const predeploy_l1_block = deposits.l1_block_info_address;
pub const predeploy_operator_fee_vault = Address.comptime_hex(
    "0x420000000000000000000000000000000000001B",
);

/// System deployer accounts (base/base `Deployers`).
pub const deployer_ecotone_l1_block = deployer(0);
pub const deployer_ecotone_gas_price_oracle = deployer(1);
pub const deployer_fjord_gas_price_oracle = deployer(2);
pub const deployer_isthmus_l1_block = deployer(3);
pub const deployer_isthmus_gas_price_oracle = deployer(4);
pub const deployer_isthmus_operator_fee_vault = deployer(5);
pub const deployer_jovian_l1_block = deployer(6);
pub const deployer_jovian_gas_price_oracle = deployer(7);

fn deployer(comptime index: u8) Address {
    var bytes: [20]u8 = @splat(0);
    bytes[0] = 0x42;
    bytes[1] = 0x10;
    bytes[19] = index;
    comptime assert(index < 8);
    comptime assert(bytes[0] == 0x42 and bytes[1] == 0x10);
    return .init(bytes);
}

/// Implementation addresses: `CREATE(deployer, nonce 0)`, checked by tests.
pub const ecotone_l1_block = Address.comptime_hex("0x07dbe8500fc591d1852b76fee44d5a05e13097ff");
pub const ecotone_gas_price_oracle =
    Address.comptime_hex("0xb528d11cc114e026f138fe568744c6d45ce6da7a");
pub const fjord_gas_price_oracle =
    Address.comptime_hex("0xa919894851548179a0750865e7974da599c0fac7");
pub const isthmus_l1_block = Address.comptime_hex("0xff256497d61dcd71a9e9ff43967c13fde1f72d12");
pub const isthmus_gas_price_oracle =
    Address.comptime_hex("0x93e57a196454cb919193fa9946f14943cf733845");
pub const isthmus_operator_fee_vault =
    Address.comptime_hex("0x4fa2be8cd41504037f1838bce3bcc93bc68ff537");
pub const jovian_l1_block = Address.comptime_hex("0x3ba4007f5c922fbb33c454b41ea7a1f11e83df2c");
pub const jovian_gas_price_oracle =
    Address.comptime_hex("0x4f1db3c6abd250ba86e0928471a8f7db3afd88f1");

/// Senders of the EIP-4788 / EIP-2935 presigned-style deployments.
pub const eip4788_from = Address.comptime_hex("0x0B799C86a49DEeb90402691F1041aa3AF2d3C875");
pub const eip2935_from = Address.comptime_hex("0x3462413Af4609098e1E27A490f554f260213D685");

/// `setEcotone()`, `setFjord()`, `setIsthmus()`, `setJovian()` selectors.
pub const set_ecotone_selector: [4]u8 = .{ 0x22, 0xb9, 0x0a, 0xb3 };
pub const set_fjord_selector: [4]u8 = .{ 0x8e, 0x98, 0xb1, 0x06 };
pub const set_isthmus_selector: [4]u8 = .{ 0x29, 0x1b, 0x03, 0x83 };
pub const set_jovian_selector: [4]u8 = .{ 0xb3, 0xd7, 0x20, 0x79 };

pub const Input = union(enum) {
    /// Embedded hex (optional `0x`, surrounding whitespace already trimmed).
    bytecode_hex: []const u8,
    /// `upgradeTo(address)` calldata for a proxy.
    upgrade_to: Address,
    /// A bare 4-byte selector call.
    selector: [4]u8,

    pub fn length(input: Input) u32 {
        const result: u32 = switch (input) {
            .bytecode_hex => |text| @intCast(primitives.hex.decoded_length(text) catch
                unreachable), // Proof: embedded hex is decoded in tests.
            .upgrade_to => upgrade_to_calldata_length,
            .selector => 4,
        };
        assert(result > 0);
        return result;
    }

    pub fn write(input: Input, out: []u8) void {
        assert(out.len == input.length());
        switch (input) {
            // Proof: embedded hex is decoded in tests.
            .bytecode_hex => |text| primitives.hex.decode(out, text) catch unreachable,
            .upgrade_to => |address| {
                @memset(out, 0);
                out[0..4].* = upgrade_to_selector;
                out[16..36].* = address.bytes;
            },
            .selector => |selector| out[0..4].* = selector,
        }
        assert(out.len < 4 or out[0] != 0 or input == .bytecode_hex);
    }
};

/// One upgrade deposit (mint and value are always zero, never a system tx).
pub const UpgradeDeposit = struct {
    intent: []const u8,
    from: Address,
    /// Null means contract creation.
    to: ?Address,
    gas_limit: u64,
    input: Input,

    pub fn source_hash(deposit: *const UpgradeDeposit) B256 {
        assert(deposit.intent.len > 0);
        return deposits.upgrade_source_hash(deposit.intent);
    }

    /// Returns the EIP-2718 encoding, owned by the caller (free with `allocator`).
    pub fn encode(deposit: *const UpgradeDeposit, allocator: std.mem.Allocator) error{
        OutOfMemory,
    }![]u8 {
        const input = try allocator.alloc(u8, deposit.input.length());
        defer allocator.free(input);
        deposit.input.write(input);
        const tx: deposits.DepositTx = .{
            .source_hash = deposit.source_hash(),
            .from = deposit.from,
            .to = deposit.to,
            .gas_limit = deposit.gas_limit,
            .is_system_transaction = false,
            .input = input,
        };
        const out = try allocator.alloc(u8, tx.encoded_length());
        const written = tx.encode(out);
        assert(written.len == out.len);
        assert(out[0] == deposits.deposit_tx_type);
        return out;
    }
};

fn bytecode(comptime name: []const u8) Input {
    const text = comptime std.mem.trim(u8, @embedFile("upgrade_bytecode/" ++ name), " \t\r\n");
    comptime assert(text.len > 0);
    comptime assert(text.len % 2 == 0);
    return .{ .bytecode_hex = text };
}

fn create(
    comptime intent: []const u8,
    comptime from: Address,
    comptime gas_limit: u64,
    comptime input: Input,
) UpgradeDeposit {
    comptime assert(gas_limit > 0 and intent.len > 0);
    comptime assert(input == .bytecode_hex);
    return .{ .intent = intent, .from = from, .to = null, .gas_limit = gas_limit, .input = input };
}

fn call(
    comptime intent: []const u8,
    comptime from: Address,
    comptime to: Address,
    comptime gas_limit: u64,
    comptime input: Input,
) UpgradeDeposit {
    comptime assert(gas_limit > 0 and intent.len > 0);
    comptime assert(input != .bytecode_hex);
    return .{ .intent = intent, .from = from, .to = to, .gas_limit = gas_limit, .input = input };
}

const zero = Address.zero;
const depositor = deposits.depositor_account;
const gpo = predeploy_gas_price_oracle;

pub const ecotone = [_]UpgradeDeposit{
    create(
        "Ecotone: L1 Block Deployment",
        deployer_ecotone_l1_block,
        375_000,
        bytecode("l1_block_ecotone.hex"),
    ),
    create(
        "Ecotone: Gas Price Oracle Deployment",
        deployer_ecotone_gas_price_oracle,
        1_000_000,
        bytecode("gpo_ecotone.hex"),
    ),
    call("Ecotone: L1 Block Proxy Update", zero, predeploy_l1_block, 50_000, .{
        .upgrade_to = ecotone_l1_block,
    }),
    call("Ecotone: Gas Price Oracle Proxy Update", zero, gpo, 50_000, .{
        .upgrade_to = ecotone_gas_price_oracle,
    }),
    call("Ecotone: Gas Price Oracle Set Ecotone", depositor, gpo, 80_000, .{
        .selector = set_ecotone_selector,
    }),
    create(
        "Ecotone: beacon block roots contract deployment",
        eip4788_from,
        250_000,
        bytecode("eip4788_ecotone.hex"),
    ),
};

pub const fjord = [_]UpgradeDeposit{
    create(
        "Fjord: Gas Price Oracle Deployment",
        deployer_fjord_gas_price_oracle,
        1_450_000,
        bytecode("gpo_fjord.hex"),
    ),
    call("Fjord: Gas Price Oracle Proxy Update", zero, gpo, 50_000, .{
        .upgrade_to = fjord_gas_price_oracle,
    }),
    call("Fjord: Gas Price Oracle Set Fjord", depositor, gpo, 90_000, .{
        .selector = set_fjord_selector,
    }),
};

pub const isthmus = [_]UpgradeDeposit{
    create(
        "Isthmus: L1 Block Deployment",
        deployer_isthmus_l1_block,
        425_000,
        bytecode("l1_block_isthmus.hex"),
    ),
    create(
        "Isthmus: Gas Price Oracle Deployment",
        deployer_isthmus_gas_price_oracle,
        1_625_000,
        bytecode("gpo_isthmus.hex"),
    ),
    create(
        "Isthmus: Operator Fee Vault Deployment",
        deployer_isthmus_operator_fee_vault,
        500_000,
        bytecode("ofv_isthmus.hex"),
    ),
    call("Isthmus: L1 Block Proxy Update", zero, predeploy_l1_block, 50_000, .{
        .upgrade_to = isthmus_l1_block,
    }),
    call("Isthmus: Gas Price Oracle Proxy Update", zero, gpo, 50_000, .{
        .upgrade_to = isthmus_gas_price_oracle,
    }),
    call("Isthmus: Operator Fee Vault Proxy Update", zero, predeploy_operator_fee_vault, 50_000, .{
        .upgrade_to = isthmus_operator_fee_vault,
    }),
    call("Isthmus: Gas Price Oracle Set Isthmus", depositor, gpo, 90_000, .{
        .selector = set_isthmus_selector,
    }),
    create(
        "Isthmus: EIP-2935 Contract Deployment",
        eip2935_from,
        250_000,
        bytecode("eip2935_isthmus.hex"),
    ),
};

pub const jovian = [_]UpgradeDeposit{
    create(
        "Jovian: L1 Block Deployment",
        deployer_jovian_l1_block,
        447_315,
        bytecode("jovian_l1_block_deployment.hex"),
    ),
    call("Jovian: L1 Block Proxy Update", zero, predeploy_l1_block, 50_000, .{
        .upgrade_to = jovian_l1_block,
    }),
    create(
        "Jovian: Gas Price Oracle Deployment",
        deployer_jovian_gas_price_oracle,
        1_750_714,
        bytecode("jovian_gas_price_oracle_deployment.hex"),
    ),
    call("Jovian: Gas Price Oracle Proxy Update", zero, gpo, 50_000, .{
        .upgrade_to = jovian_gas_price_oracle,
    }),
    call("Jovian: Gas Price Oracle Set Jovian", depositor, gpo, 90_000, .{
        .selector = set_jovian_selector,
    }),
};

/// The most upgrade transactions any single fork emits.
pub const transactions_per_fork_max: u32 = 8;
/// Upper bound on upgrade transactions in one block (every fork activating at once).
pub const transactions_max: u32 = ecotone.len + fjord.len + isthmus.len + jovian.len;

comptime {
    assert(ecotone.len == 6 and fjord.len == 3 and isthmus.len == 8 and jovian.len == 5);
    assert(@max(@max(ecotone.len, fjord.len), @max(isthmus.len, jovian.len)) ==
        transactions_per_fork_max);
}

pub fn deposits_for(fork: Fork) []const UpgradeDeposit {
    const result: []const UpgradeDeposit = switch (fork) {
        .ecotone => &ecotone,
        .fjord => &fjord,
        .isthmus => &isthmus,
        .jovian => &jovian,
    };
    assert(result.len > 0 and result.len <= transactions_per_fork_max);
    return result;
}

/// Appends the encoded upgrade transactions of `fork` to `list`. Each element is owned by
/// the list's owner and freed with `allocator`. On error, nothing new remains in `list`.
pub fn append_transactions(
    allocator: std.mem.Allocator,
    list: *std.ArrayList([]u8),
    fork: Fork,
) error{OutOfMemory}!void {
    const fork_deposits = deposits_for(fork);
    const length_before = list.items.len;
    try list.ensureUnusedCapacity(allocator, fork_deposits.len);
    errdefer {
        for (list.items[length_before..]) |tx| allocator.free(tx);
        list.shrinkRetainingCapacity(length_before);
    }
    for (fork_deposits) |*deposit| {
        list.appendAssumeCapacity(try deposit.encode(allocator));
    }
    assert(list.items.len == length_before + fork_deposits.len);
}

const testing = std.testing;

fn hex_bytes(comptime text: []const u8) [text.len / 2]u8 {
    return primitives.hex.decode_array(text.len / 2, text) catch unreachable;
}

/// `CREATE` address: `keccak256(rlp([sender, nonce 0]))[12..]`.
fn create_address(sender: Address) Address {
    var input: [23]u8 = undefined;
    input[0] = 0xd6;
    input[1] = 0x94;
    input[2..22].* = sender.bytes;
    input[22] = 0x80;
    return .init(primitives.keccak256(&input).bytes[12..32].*);
}

test "upgrades: selectors match signatures" {
    const cases = [_]struct { []const u8, [4]u8 }{
        .{ "upgradeTo(address)", upgrade_to_selector },
        .{ "setEcotone()", set_ecotone_selector },
        .{ "setFjord()", set_fjord_selector },
        .{ "setIsthmus()", set_isthmus_selector },
        .{ "setJovian()", set_jovian_selector },
    };
    for (cases) |case| {
        try testing.expectEqualSlices(u8, &case[1], primitives.keccak256(case[0]).bytes[0..4]);
    }
}

test "upgrades: implementation addresses are CREATE(deployer, 0)" {
    const cases = [_]struct { Address, Address }{
        .{ deployer_ecotone_l1_block, ecotone_l1_block },
        .{ deployer_ecotone_gas_price_oracle, ecotone_gas_price_oracle },
        .{ deployer_fjord_gas_price_oracle, fjord_gas_price_oracle },
        .{ deployer_isthmus_l1_block, isthmus_l1_block },
        .{ deployer_isthmus_gas_price_oracle, isthmus_gas_price_oracle },
        .{ deployer_isthmus_operator_fee_vault, isthmus_operator_fee_vault },
        .{ deployer_jovian_l1_block, jovian_l1_block },
        .{ deployer_jovian_gas_price_oracle, jovian_gas_price_oracle },
    };
    for (cases) |case| try testing.expect(create_address(case[0]).eql(case[1]));
    try testing.expect(deployer_jovian_gas_price_oracle.eql(
        Address.comptime_hex("0x4210000000000000000000000000000000000007"),
    ));
}

test "upgrades: source hashes (base/base vectors)" {
    const expected = [_][]const u8{
        // Ecotone.
        "877a6077205782ea15a6dc8699fa5ebcec5e0f4389f09cb8eda09488231346f8",
        "a312b4510adf943510f05fcc8f15f86995a5066bd83ce11384688ae20e6ecf42",
        "18acb38c5ff1c238a7460ebc1b421fa49ec4874bdf1e0a530d234104e5e67dbc",
        "ee4f9385eceef498af0be7ec5862229f426dec41c8d42397c7257a5117d9230a",
        "0c1cb38e99dbc9cbfab3bb80863380b0905290b37eb3d6ab18dc01c1f3e75f93",
        "69b763c48478b9dc2f65ada09b3d92133ec592ea715ec65ad6e7f3dc519dc00c",
        // Fjord.
        "86122c533fdcb89b16d8713174625e44578a89751d96c098ec19ab40a51a8ea3",
        "1e6bb0c28bfab3dc9b36ffb0f721f00d6937f33577606325692db0965a7d58c6",
        "bac7bb0d5961cad209a345408b0280a0d4686b1b20665e1b0f9cdafd73b19b6b",
        // Isthmus.
        "3b2d0821ca2411ad5cd3595804d1213d15737188ae4cbd58aa19c821a6c211bf",
        "fc70b48424763fa3fab9844253b4f8d508f91eb1f7cb11a247c9baec0afb8035",
        "107a570d3db75e6110817eb024f09f3172657e920634111ce9875d08a16daa96",
        "ebe8b5cb10ca47e0d8bda8f5355f2d66711a54ddeb0ef1d30e29418c9bf17a0e",
        "ecf2d9161d26c54eda6b7bfdd9142719b1e1199a6e5641468d1bf705bc531ab0",
        "ad74e1adb877ccbe176b8fa1cc559388a16e090ddbe8b512f5b37d07d887a927",
        "3ddf4b1302548dd92939826e970f260ba36167f4c25f18390a5e8b194b295319",
        // Jovian.
        "bb1a656f65401240fac3db12e7a79ebb954b11e62f7626eb11691539b798d3bf",
        "f3275f829340521028f9ad5bce4ecb1c64a45d448794effa2a77674627338e76",
        "239b7021a6c2cf3a918481242bbb5a9499057f24501539467536c691bb133962",
        "a70c60aa53b8c1c0d52b39b1e901e7d7c09f7819595cb24048a6bb1983b401ff",
        "e836db6a959371756f8941be3e962d000f7e12a32e49e2c9ca42ba177a92716c",
    };
    // base/base has no vector for the Isthmus EIP-2935 deployment source hash.
    const all = ecotone ++ fjord ++ isthmus[0..7].* ++ jovian;
    try testing.expectEqual(expected.len, all.len);
    for (all, expected) |deposit, hash_hex| {
        const hash = try B256.from_hex(hash_hex);
        try testing.expect(deposit.source_hash().eql(hash));
    }
}

test "upgrades: jovian upgradeTo calldata (base/base vectors)" {
    var out: [upgrade_to_calldata_length]u8 = undefined;
    const input: Input = .{ .upgrade_to = jovian_gas_price_oracle };
    input.write(&out);
    const expected_gpo = hex_bytes("3659cfe6" ++ "000000000000000000000000" ++
        "4f1db3c6abd250ba86e0928471a8f7db3afd88f1");
    try testing.expectEqualSlices(u8, &expected_gpo, &out);
    const l1_block: Input = .{ .upgrade_to = jovian_l1_block };
    l1_block.write(&out);
    const expected_l1 = hex_bytes("3659cfe6" ++ "000000000000000000000000" ++
        "3ba4007f5c922fbb33c454b41ea7a1f11e83df2c");
    try testing.expectEqualSlices(u8, &expected_l1, &out);
}

fn expect_encoded(fork: Fork, comptime vectors: []const []const u8) !void {
    const allocator = testing.allocator;
    var list: std.ArrayList([]u8) = .empty;
    defer {
        for (list.items) |tx| allocator.free(tx);
        list.deinit(allocator);
    }
    try append_transactions(allocator, &list, fork);
    try testing.expectEqual(vectors.len, list.items.len);
    inline for (vectors, 0..) |name, index| {
        const text = comptime std.mem.trim(
            u8,
            @embedFile("testdata/upgrades/" ++ name),
            " \t\r\n",
        );
        const expected = try allocator.alloc(u8, try primitives.hex.decoded_length(text));
        defer allocator.free(expected);
        try primitives.hex.decode(expected, text);
        try testing.expectEqualSlices(u8, expected, list.items[index]);
    }
}

test "upgrades: ecotone txs encoded (base/base vectors)" {
    try expect_encoded(.ecotone, &.{
        "ecotone_tx_0.hex", "ecotone_tx_1.hex", "ecotone_tx_2.hex",
        "ecotone_tx_3.hex", "ecotone_tx_4.hex", "ecotone_tx_5.hex",
    });
}

test "upgrades: fjord txs encoded (base/base vectors)" {
    try expect_encoded(.fjord, &.{ "fjord_tx_0.hex", "fjord_tx_1.hex", "fjord_tx_2.hex" });
}

test "upgrades: isthmus txs encoded (base/base vectors)" {
    try expect_encoded(.isthmus, &.{
        "isthmus_tx_0.hex", "isthmus_tx_1.hex", "isthmus_tx_2.hex", "isthmus_tx_3.hex",
        "isthmus_tx_4.hex", "isthmus_tx_5.hex", "isthmus_tx_6.hex", "isthmus_tx_7.hex",
    });
}

test "upgrades: jovian txs are well-formed deposits" {
    const allocator = testing.allocator;
    var list: std.ArrayList([]u8) = .empty;
    defer {
        for (list.items) |tx| allocator.free(tx);
        list.deinit(allocator);
    }
    try append_transactions(allocator, &list, .jovian);
    try testing.expectEqual(@as(usize, 5), list.items.len);
    for (list.items, jovian) |tx, deposit| {
        try testing.expectEqual(deposits.deposit_tx_type, tx[0]);
        const hash = deposit.source_hash();
        // The RLP list header is 1-4 bytes; the source hash string follows it.
        try testing.expect(std.mem.indexOf(u8, tx[0..40], &hash.bytes) != null);
    }
}

test "upgrades: append failure leaves the list unchanged" {
    var failing = testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 3 });
    const allocator = failing.allocator();
    var list: std.ArrayList([]u8) = .empty;
    defer {
        for (list.items) |tx| allocator.free(tx);
        list.deinit(allocator);
    }
    try testing.expectError(error.OutOfMemory, append_transactions(allocator, &list, .fjord));
    try testing.expectEqual(@as(usize, 0), list.items.len);
}
