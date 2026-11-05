# Devnet

`just devnet up` starts a local, all-Zig Base devnet as native processes (no Docker).
`just devnet smoke` proves it works end to end. A cold `up` (nothing running) wipes chain
state and writes a fresh genesis; `DEVNET_KEEP=1 just devnet up` keeps it. Everything the devnet writes lives in
`.devnet/` (git-ignored): generated configs, the JWT secret, data dirs, pids, logs.

This file is the **process contract** between the batcher-devnet lane (which owns the
scripts) and the lanes that own each binary. If you change a flag or port here, change
`etc/devnet/devnet.sh` in the same commit.

## Topology

```
            deposits (portal logs)          batches (calldata / blobs)
  L1 dev chain  ◄──────────────────────────── batcher ◄──── L2 sequencer EL
  node --dev-l1                                  │ eth_getBlockByNumber
  :8545 http                                     │ optimism_syncStatus
  :5052 beacon (blobs)                           ▼
       │                              consensus --sequencer :7545 ──engine──► :9551
       │ L1 blocks, receipts, blobs                                          node :9545
       ├─────────────────────────────►
       └─────────────────────────────► consensus (verifier) :8547 ──engine──► :10551
                                                                           node :10545
```

| Process | Binary | Ports | Data dir |
| --- | --- | --- | --- |
| L1 dev chain | `base node --dev-l1` | http 8545, beacon 5052 | `.devnet/l1` |
| L2 sequencer EL | `base node` | http 9545, engine 9551 | `.devnet/seq-el` |
| L2 sequencer CL | `base consensus --sequencer` | rpc 7545 | `.devnet/seq-cl` |
| Batcher | `base batcher` | metrics 7300 | `.devnet/batcher` |
| L2 verifier EL | `base node` | http 10545, engine 10551 | `.devnet/ver-el` |
| L2 verifier CL | `base consensus` | rpc 8547 | `.devnet/ver-cl` |

L1 contracts are placed in the L1 genesis alloc (no deployment step): a minimal
deposit portal at `0x000000000000000000000000000000000000de90` (any call deposits
`msg.value` to `msg.sender` on L2, see `src/batcher/devnet/portal.zig`) and the system
config address `0x0000000000000000000000000000000000005cf9` (no code yet; the genesis
system config in `rollup.json` applies until the contract lands).

Each process runs as `zig-out/bin/base <subcommand>` until a lane ships its own binary,
then the script switches to that binary. Logs go to `.devnet/logs/<process>.log`,
pids to `.devnet/pids/<process>.pid`.

## Chain parameters

| Parameter | Value | Why |
| --- | --- | --- |
| L1 chain id | 900 | OP Stack devnet convention |
| L2 chain id | 901 | OP Stack devnet convention |
| L1 block time | 2 s | fast feedback, still exercises epochs |
| L2 block time | 1 s | Base mainnet block time |
| Batch inbox | `0xff00000000000000000000000000000000000385` | `0xff` ++ zeros ++ L2 chain id (901 = 0x385) |
| Sequencer window | 3600 L1 blocks | rollup default |
| Channel timeout | 300 L1 blocks | Granite value |
| Max sequencer drift | 1800 s | Fjord constant |
| Hardforks | all active at genesis (through Isthmus) | simplest; tests the current rules |

### Accounts

All keys derive from the publicly known dev mnemonic
`test test test test test test test test test test test junk` (the accounts every
Ethereum devnet tool prefunds). They are never secret and never used outside devnets.

| Role | Index | Address |
| --- | --- | --- |
| Deployer / funded user | 0 | `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` |
| Smoke-test user | 1 | `0x70997970C51812dc3A010C7d01b50e0d17dc79C8` |
| Sequencer (P2P signer) | 5 | `0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc` |
| Batcher | 6 | `0x976EA74026E726554dB657fA54763abd0C3a0aa9` |
| Proposer | 7 | `0x14dC79964da2C08b23698B3D3cc7Ca32193d9955` |

Accounts 0..9 get 10,000 ETH on both L1 and L2.

## Generated files (`base devnet init`)

`base devnet init --out .devnet` writes:

| File | Consumer | Contents |
| --- | --- | --- |
| `l1-genesis.json` | `node --dev-l1` | geth-style genesis: alloc (funded accounts, portal, system config) |
| `l2-genesis.json` | L2 `node` | geth-style genesis with OP predeploys and funded accounts |
| `rollup.json` | `consensus`, `batcher` | rollup config (op-node JSON schema) with the L1/L2 genesis hashes |
| `jwt.hex` | EL engine API, `consensus` | 32 random bytes, hex; generated at runtime, never committed |
| `devnet.env` | scripts, smoke test | ports, addresses, chain ids for shell use |

Re-running `init` with existing files is a no-op unless `--force` is passed.

## Process flags

Each binary must accept at least the flags below. Lanes may add more.

- `node --dev-l1 --chain .devnet/l1-genesis.json --datadir D --http.port 8545
  --beacon.port 5052 --block-time 2`
- `node --chain .devnet/l2-genesis.json --datadir D --http.port P --authrpc.port E
  --authrpc.jwtsecret .devnet/jwt.hex`
- `consensus --rollup-config .devnet/rollup.json --l1 http://127.0.0.1:8545
  --l1-beacon http://127.0.0.1:5052 --l2 http://127.0.0.1:E --l2-jwt .devnet/jwt.hex
  --rpc.port R [--sequencer --sequencer.key-index 5]`
- `batcher --rollup-config .devnet/rollup.json --l1 http://127.0.0.1:8545
  --l2 http://127.0.0.1:9545 --rollup-rpc http://127.0.0.1:7545 --key-index 6
  --metrics.port 7300 [--data-availability calldata|blobs] [--compression brotli|zlib]`
  Blob mode packs up to 6 frames per transaction. `GET :7300/metrics` serves Prometheus
  text (`base_batcher_*` heads, pending txs, DA backlog, and activity counters).
  DA throttling (base/base defaults, quadratic; `--throttle-strategy`, `--no-throttle`) pushes
  `miner_setMaxDASize` to the L2 EL; a builder without that method disables it.
  `--admin-port P [--admin-addr IP]` serves base/base's admin JSON-RPC (`admin_startBatcher`,
  `admin_stopBatcher`, `admin_flushBatcher`, `admin_getBatcherStatus`,
  `admin_getThrottleController`, `admin_setThrottleController`); `--stopped` starts with ingestion stopped.
  `--sequencer-urls URL|L2_URL=ROLLUP_URL,...` replaces `--l2`/`--rollup-rpc`; the leader is
  the first endpoint whose rollup node answers `admin_sequencerActive` with true.
  txmgr: `--num-confirmations N --min-tip-cap GWEI --min-basefee GWEI
  --max-pending-transactions N` (base/base semantics).

## Smoke test

`just devnet smoke` passes when, within 120 s of `up`:

0. **Liveness.** The sequencer EL head advances within 10 L2 block times; otherwise the
   smoke fails at once and names the sequencer CL.

1. **Sequencing.** The smoke user sends an L2 transfer to the sequencer EL; it is in
   an L2 block (receipt status 1).
2. **Batching.** `base devnet batches` decodes, from batcher transactions to the batch
   inbox, a singular batch with that L2 block's timestamp.
3. **Derivation.** The verifier's `optimism_syncStatus.safe_l2` reaches the L2 block
   from step 1, and its hash equals the sequencer's hash for that number.
4. **Deposits.** A deposit sent to the L1 portal shows up on L2 (the recipient balance
   rises) on both sequencer and verifier.

Each step prints `ok` or the reason it failed; the script exits non-zero on failure.
