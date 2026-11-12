// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { Script } from "lib/forge-std/src/Script.sol";
import { L2Genesis } from "scripts/L2Genesis.s.sol";
import { Fork } from "scripts/libraries/Config.sol";

/// Runs L2Genesis for the needlefish public test chain and dumps the allocs to $NF_ALLOCS_OUT.
contract NfL2Genesis is Script {
    function run() public {
        address owner = vm.envAddress("NF_OWNER");
        L2Genesis genesis = new L2Genesis();
        genesis.run(
            L2Genesis.Input({
                l1ChainID: vm.envUint("NF_L1_CHAIN_ID"),
                l2ChainID: vm.envUint("NF_L2_CHAIN_ID"),
                l1CrossDomainMessengerProxy: payable(vm.envAddress("NF_L1_CDM")),
                l1StandardBridgeProxy: payable(vm.envAddress("NF_L1_BRIDGE")),
                l1ERC721BridgeProxy: payable(vm.envAddress("NF_L1_ERC721_BRIDGE")),
                opChainProxyAdminOwner: owner,
                sequencerFeeVaultRecipient: owner,
                sequencerFeeVaultMinimumWithdrawalAmount: 1 ether,
                sequencerFeeVaultWithdrawalNetwork: 1,
                baseFeeVaultRecipient: owner,
                baseFeeVaultMinimumWithdrawalAmount: 1 ether,
                baseFeeVaultWithdrawalNetwork: 1,
                l1FeeVaultRecipient: owner,
                l1FeeVaultMinimumWithdrawalAmount: 1 ether,
                l1FeeVaultWithdrawalNetwork: 1,
                operatorFeeVaultRecipient: owner,
                operatorFeeVaultMinimumWithdrawalAmount: 1 ether,
                operatorFeeVaultWithdrawalNetwork: 1,
                fork: uint256(Fork.JOVIAN),
                fundDevAccounts: false
            })
        );
        // Drop the script's own accounts so only the chain state is dumped.
        vm.etch(address(genesis), "");
        vm.resetNonce(address(genesis));
        vm.dumpState(vm.envString("NF_ALLOCS_OUT"));
    }
}
