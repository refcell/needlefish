# A public L2 sequenced by needlefish

Base's own chains are sequenced by Base, so needlefish's sequencer, batcher, proposer, and
challenger are exercised on an OP Stack L2 of their own: chain id 20261112, sequenced by
needlefish, with its L1 contracts on Ethereum Sepolia. `etc/public-l2/public-l2.sh` deploys
and runs it. Never point it at mainnet: it signs with throwaway keys that live on the
machine that runs it.

## What runs

| Unit (`nfl2-*`) | Command | Role |
| --- | --- | --- |
| `bridge` | `base https-bridge` | plain-HTTP view of a public HTTPS Sepolia RPC and beacon API |
| `seq-el`, `seq-cl` | `base node --builder.enabled`, `base consensus --sequencer` | builds 200 ms blocks and gossips them |
| `ver-el`, `ver-cl` | `base node --proofs-history`, `base consensus` | an independent verifier that derives the chain from L1 |
| `batcher` | `base batcher` | posts the sequencer's blocks to Sepolia as blob (or calldata) batches |
| `prover-service`, `prover-worker` | `base prover-service`, `base prover-worker --backend tee` | proves output roots for the proposer and challenger |
| `proposer` | `base proposer` | creates a dispute game for each proven output root |
| `challenger` | `base challenger` | finds games with a wrong root and nullifies them with a proof |

The verifier, not the sequencer, serves the proposer, prover, and challenger, so every
output root on L1 comes from a chain re-derived from Sepolia.

## Contracts

`deploy` uses the base/contracts `SystemDeploy` script as is. Two parts of the production
setup cannot exist on a private chain and are replaced:

- **TEE attestation**: the AWS Nitro attestation validator and the SP1 verifier become empty
  mock contracts, and the TEE prover registry is upgraded to `DevTEEProverRegistry`. The
  enclave key is a local key registered as a dev signer (image hash 0).
- **The multiproof verifier**: a new `AggregateVerifier` is deployed with image hash 0 and
  the chain's real config hash (`base proof config-hash rollup.json`).

Everything else is the production code path: OptimismPortal2, the dispute game factory,
the anchor state registry, the delayed WETH, and game type 621 (TEE proofs, with the
challenger's counter-proof). Dispute and finality delays are shortened to 600 s. A game
claims `GAME_INTERVAL` L2 blocks (default 1800, six minutes of 200 ms blocks, with an
intermediate root every tenth), so the proposer sends about 240 Sepolia transactions a day.
Because the subsecond-block upgrade is active from genesis, the contracts apply their
"fast" interval pair to every game; the deploy sets that pair to `GAME_INTERVAL`.
The factory's initial bond for game type 621 is 0, so proposing costs gas only.

The L2 genesis is the `base devnet init` template with L2Genesis predeploy allocs for the
simulated bridge proxy addresses (the deploy checks they match after broadcasting). Every
fork up to Denim is active from genesis, so the chain runs Base's 200 ms blocks.

## Run it

Needs Foundry, jq, a base/contracts checkout with `just deps` run (`NF_CONTRACTS`), and a
ReleaseSafe build (`zig build -Doptimize=ReleaseSafe`).

```sh
etc/public-l2/public-l2.sh keys      # once: role keys under $NF_L2_DIR/keys (mode 700)
# fund deployer, batcher, proposer, challenger, and user with Sepolia ETH
etc/public-l2/public-l2.sh deploy    # about 10 minutes; SystemDeploy is 45 txs, 39M gas
etc/public-l2/public-l2.sh up
etc/public-l2/public-l2.sh status
etc/public-l2/public-l2.sh deposit 0.01        # L1 -> L2 through OptimismPortal2
etc/public-l2/public-l2.sh withdraw initiate 0.001
etc/public-l2/public-l2.sh withdraw run        # prove against a game, then finalize
etc/public-l2/public-l2.sh bad-claim           # a wrong root the challenger must nullify
```

Ports 313xx to 319xx; none collide with the nf-* Base nodes or the local devnet. Logs are
in `$NF_L2_DIR/logs`. `L1_RPC`, `L1_UPSTREAM`, and `L1_BEACON` point it at another L1; a
local anvil with chain id 11155111 rehearses the whole flow without spending Sepolia ETH.

## Found while bringing it up

- Public RPCs answer `debug_getRaw*` with "method not found". The proof clients rebuild
  headers, transactions, and receipts from `eth_getBlockBy*` and `eth_getBlockReceipts`
  and check them against the block hash and the header's roots.
- A verifier lost a derived block whenever its EL answered the safe forkchoice update with
  SYNCING (the durable store briefly Busy) and stalled for good. The consolidate task now
  retries it.
- A sequencer retried a failed seal forever with a payload id the EL had dropped. It now
  drops the block and builds the next one, as base/base does.
- `base node` does not forward transactions to a sequencer, so `withdraw initiate` sends
  through the sequencer's EL; proving reads the verifier's historical state proofs.
- The proposer never proposed: the consensus node answers `optimism_outputAtBlock` from an
  L2 block cache whose by-number entries expire after 2 s, so a proposer polling every 12 s
  always started a fetch and missed. The node now keeps fetching the finalized outputs it
  was asked for and caches them.
- The prover could not prove a finalized game: a durable `base node` served execution
  witnesses only for its last 1024 retained blocks (3.4 min of 200 ms blocks) whatever
  `--proofs-history.window` said, and L1 finality alone takes about 13 min. The retention
  now grows to the window; the verifier keeps `WITNESS_WINDOW` (16384 blocks, 55 min; a
  game whose blocks leave it can never be proven, and every later game waits on it).
- No proof held: the proof host fed the client the execution witness of each block, which
  lacks the L2ToL1MessagePasser account when the block does not touch it, but the client
  reads that account's storage root to seal every Isthmus block (base/base's
  `debug_executePayload` witness force-loads it). The host now adds the passer's account
  proof at the parent (`eth_getProof`) to the payload witness.
- Open: unsafe gossip reaches the verifier in bursts, so its unsafe head trails the
  sequencer by about 10 to 30 s and catches up when derivation fills the gap. The safe
  chain is unaffected.
