// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import { Script } from "lib/forge-std/src/Script.sol";
import { console2 as console } from "lib/forge-std/src/console2.sol";

import { AggregateVerifier } from "src/L1/proofs/AggregateVerifier.sol";
import { DevTEEProverRegistry } from "test/mocks/MockDevTEEProverRegistry.sol";
import { TEEProverRegistry } from "src/L1/proofs/tee/TEEProverRegistry.sol";
import { IDisputeGame } from "interfaces/L1/proofs/IDisputeGame.sol";
import { IDisputeGameFactory } from "interfaces/L1/proofs/IDisputeGameFactory.sol";
import { IProxyAdmin } from "interfaces/universal/IProxyAdmin.sol";
import { GameType } from "src/libraries/bridge/Types.sol";

/// After `SystemDeploy`, makes the multiproof system provable by a local-mode enclave (no AWS
/// Nitro attestation), the same dev setup as base/base's anvil Nitro devnet:
///  - the TEE prover registry proxy is upgraded to base/contracts' `DevTEEProverRegistry` and
///    the given signers are registered with image hash 0 (what a local-mode enclave signs);
///  - a new `AggregateVerifier` with TEE image hash 0 and the chain's real config hash
///    replaces the game implementation (SystemDeploy refuses a zero image hash).
/// Every other immutable is copied from the implementation SystemDeploy registered.
contract NfPostDeploy is Script {
    function run() public {
        IDisputeGameFactory factory = IDisputeGameFactory(vm.envAddress("NF_FACTORY"));
        IProxyAdmin proxyAdmin = IProxyAdmin(vm.envAddress("NF_PROXY_ADMIN"));
        address payable registry = payable(vm.envAddress("NF_TEE_REGISTRY"));
        GameType gameType = GameType.wrap(uint32(vm.envUint("NF_GAME_TYPE")));
        AggregateVerifier old = AggregateVerifier(address(factory.gameImpls(gameType)));
        address[] memory signers = vm.envAddress("NF_SIGNERS", ",");

        vm.startBroadcast();
        DevTEEProverRegistry devImpl =
            new DevTEEProverRegistry(TEEProverRegistry(registry).NITRO_VALIDATOR(), factory);
        proxyAdmin.upgrade(registry, address(devImpl));
        for (uint256 i = 0; i < signers.length; i++) {
            DevTEEProverRegistry(registry).addDevSigner(signers[i], bytes32(0));
        }
        AggregateVerifier verifier = new AggregateVerifier(
            gameType,
            old.anchorStateRegistry(),
            old.DELAYED_WETH(),
            old.TEE_VERIFIER(),
            old.ZK_VERIFIER(),
            bytes32(0),
            AggregateVerifier.ZkHashes(old.ZK_RANGE_HASH(), old.ZK_AGGREGATE_HASH()),
            vm.envBytes32("NF_CONFIG_HASH"),
            old.L2_CHAIN_ID(),
            AggregateVerifier.IntervalConfig({
                slowBlockInterval: old.SLOW_BLOCK_INTERVAL(),
                slowIntermediateBlockInterval: old.SLOW_INTERMEDIATE_BLOCK_INTERVAL(),
                fastBlockInterval: old.FAST_BLOCK_INTERVAL(),
                fastIntermediateBlockInterval: old.FAST_INTERMEDIATE_BLOCK_INTERVAL()
            }),
            AggregateVerifier.ScheduleConfig({
                protocolVersions: old.PROTOCOL_VERSIONS(),
                genesisBlockNumber: old.L2_GENESIS_BLOCK_NUMBER(),
                genesisTimestamp: old.L2_GENESIS_TIMESTAMP(),
                blockTime: old.L2_BLOCK_TIME()
            })
        );
        factory.setImplementation(gameType, IDisputeGame(address(verifier)));
        vm.stopBroadcast();

        console.log("DevTEEProverRegistryImpl:", address(devImpl));
        console.log("AggregateVerifier:", address(verifier));
    }
}
