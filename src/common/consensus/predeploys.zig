//! Base L2 predeploy, system and upgrade-deployer addresses.
//! Mirrors base/base `crates/common/consensus/src/predeploys.rs`.

const std = @import("std");
const primitives = @import("../primitives/root.zig");
const Address = primitives.Address;

fn address(comptime text: []const u8) Address {
    return Address.comptime_hex(text);
}

pub const legacy_message_passer = address("4200000000000000000000000000000000000000");
pub const deployer_whitelist = address("4200000000000000000000000000000000000002");
pub const legacy_erc20_eth = address("DeadDeAddeAddEAddeadDEaDDEAdDeaDDeAD0000");
pub const weth9 = address("4200000000000000000000000000000000000006");
pub const l2_cross_domain_messenger = address("4200000000000000000000000000000000000007");
pub const l2_standard_bridge = address("4200000000000000000000000000000000000010");
pub const sequencer_fee_vault = address("4200000000000000000000000000000000000011");
pub const base_mintable_erc20_factory = address("4200000000000000000000000000000000000012");
pub const l1_block_number = address("4200000000000000000000000000000000000013");
pub const gas_price_oracle = address("420000000000000000000000000000000000000F");
pub const governance_token = address("4200000000000000000000000000000000000042");
pub const l1_block_info = address("4200000000000000000000000000000000000015");
pub const l2_to_l1_message_passer = address("4200000000000000000000000000000000000016");
pub const l2_erc721_bridge = address("4200000000000000000000000000000000000014");
pub const base_mintable_erc721_factory = address("4200000000000000000000000000000000000017");
pub const proxy_admin = address("4200000000000000000000000000000000000018");
pub const base_fee_vault = address("4200000000000000000000000000000000000019");
pub const l1_fee_vault = address("420000000000000000000000000000000000001a");
pub const schema_registry = address("4200000000000000000000000000000000000020");
pub const eas = address("4200000000000000000000000000000000000021");
/// EIP-4788 beacon roots contract (same address as on L1).
pub const beacon_block_root = address("000F3df6D732807Ef1319fB7B8bB8522d0Beac02");
pub const operator_fee_vault = address("420000000000000000000000000000000000001B");
pub const cross_l2_inbox = address("4200000000000000000000000000000000000022");
pub const l2_to_l2_xdm = address("4200000000000000000000000000000000000023");
/// Receives the Denim BaseTime metadata deposit.
pub const base_time = address("4200000000000000000000000000000000000030");

pub const all = [_]Address{
    legacy_message_passer,   deployer_whitelist,          legacy_erc20_eth,
    weth9,                   l2_cross_domain_messenger,   l2_standard_bridge,
    sequencer_fee_vault,     base_mintable_erc20_factory, l1_block_number,
    gas_price_oracle,        governance_token,            l1_block_info,
    l2_to_l1_message_passer, l2_erc721_bridge,            base_mintable_erc721_factory,
    proxy_admin,             base_fee_vault,              l1_fee_vault,
    schema_registry,         eas,                         beacon_block_root,
    operator_fee_vault,      cross_l2_inbox,              l2_to_l2_xdm,
    base_time,
};

pub fn is_predeploy(candidate: Address) bool {
    for (all) |predeploy| {
        if (predeploy.eql(candidate)) return true;
    }
    return false;
}

/// Sender of every L1-attributes and system deposit.
pub const depositor_account = address("DeaDDEaDDeAdDeAdDEAdDEaddeAddEAdDEAd0001");

/// Deployers of the network-upgrade transactions.
pub const deployers = struct {
    pub const ecotone_l1_block = address("4210000000000000000000000000000000000000");
    pub const ecotone_gas_price_oracle = address("4210000000000000000000000000000000000001");
    pub const fjord_gas_price_oracle = address("4210000000000000000000000000000000000002");
    pub const isthmus_l1_block = address("4210000000000000000000000000000000000003");
    pub const isthmus_gas_price_oracle = address("4210000000000000000000000000000000000004");
    pub const isthmus_operator_fee_vault = address("4210000000000000000000000000000000000005");
    pub const jovian_l1_block = address("4210000000000000000000000000000000000006");
    pub const jovian_gas_price_oracle = address("4210000000000000000000000000000000000007");
};

test "predeploys: table" {
    try std.testing.expectEqual(@as(usize, 25), all.len);
    for (all, 0..) |a, i| {
        for (all[i + 1 ..]) |b| try std.testing.expect(!a.eql(b));
    }
    try std.testing.expect(is_predeploy(base_time));
    try std.testing.expect(!is_predeploy(depositor_account));
    try std.testing.expectEqual(@as(u8, 0x30), base_time.bytes[19]);
}
