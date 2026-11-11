# Running a Base mainnet node

`base up` runs all of this in one command; `base up --help` lists its options. This guide is
what happens underneath, step by step. These are the steps the first needlefish Base mainnet
node ran, from November 7, 2026, before `base up` existed. They take verified state from
Base's public reth snapshot, execute every block after it from execution-layer peers over
devp2p, and derive the safe and finalized heads from Ethereum L1. Every step is a `base`
subcommand.

## Requirements

- About 3.5 TB free on one NVMe filesystem. The snapshot's state component is 761 GB
  compressed and 1.14 TB extracted. The needlefish database it is imported into is about
  2 TB. The extracted snapshot can be deleted after the import.
- An Ethereum L1 JSON-RPC and beacon API. Keyless public endpoints work:
  `https://ethereum-rpc.publicnode.com` and `https://ethereum-beacon-api.publicnode.com`.
- Outbound TCP to execution-layer peers. Inbound ports are not needed.

## 1. Build

```sh
just release            # writes zig-out/bin/base
B=$PWD/zig-out/bin/base
D=/path/to/nvme/needlefish && mkdir -p $D
```

## 2. Download the snapshot's state

`https://chain.base.org/api/snapshots` lists Base's current snapshots. Its mainnet entry
names the manifest, `https://mainnet-v2-snapshots.base.org/<id>/manifest.json`. Only the
`state` component is needed: the others are chain history that needlefish does not use.

```sh
M=https://mainnet-v2-snapshots.base.org/<id>/manifest.json
curl -fsS -o $D/manifest.json $M
FILE=$(jq -r .components.state.file $D/manifest.json)          # <id>/state.tar.zst
BLAKE3=$(jq -r '.components.state.output_files[]
    | select(.path == "db/mdbx.dat") | .blake3' $D/manifest.json)
curl -fL -C - -o $D/state.tar.zst "$(jq -r .base_url $D/manifest.json)/$FILE"
mkdir -p $D/extracted && zstd -d -T0 < $D/state.tar.zst | tar -x -C $D/extracted
```

The download is resumable (`-C -`). On a home link it takes most of a day.

## 3. Import and verify

```sh
$B snapshot-import --db $D/extracted/db/mdbx.dat --chain base-mainnet --blake3 $BLAKE3 \
    --out $D/mainnet.nf
```

The import checks `mdbx.dat` against the manifest's blake3. It then reads the reth database
with needlefish's own MDBX reader and recomputes the state root from every account and
storage slot. It writes `mainnet.nf` only if that root equals the snapshot block's header,
fetched from mainnet.base.org and bound to the block hash. It exits non-zero on any
mismatch. On the first node this took about 14 hours, with a peak RSS of 3.6 GB.

## 4. Find execution-layer peers

```sh
$B el-peers --chain base-mainnet --fork-hash 169d85a3 --duration 600 > $D/peers.txt
```

`el-peers` crawls discv4 from Base's boot nodes. It keeps only nodes that advertise Base
mainnet's fork id. `169d85a3` is the EIP-2124 fork hash of the current upgrade schedule;
without `--fork-hash`, it prints every node's hash. To grow the file later, run it again
with `--peers $D/peers.txt`. el-run re-reads the file every minute.

## 5. Follow the chain: `base el-run`

```sh
openssl rand -hex 32 > $D/jwt.hex
$B el-run --db $D/mainnet.nf --chain base-mainnet --peers $D/peers.txt \
    --rpc --rpc.addr 127.0.0.1:8546 \
    --engine.addr 127.0.0.1:8552 --engine.jwt $D/jwt.hex \
    --engine.ring-blocks 65536 --engine.ring-mb 2048 >> $D/follow.log 2>&1
```

el-run downloads blocks from every peer until it reaches the tip, then follows the tip
from one peer. The first block must name the imported head's hash as its parent, so the
peers' chain is bound to the verified state. For every block it checks the transactions
root, gas used, logs bloom, receipts root, state root, withdrawals root and the resealed
block hash, and commits the block only when every check passes. The first mismatch exits 1
with the database on the parent block. It logs one line per block:

```text
block 56001552 hash 3c5039da…0dcfd417 12 txs 1010330 gas 8 ms lag_ms 370 checks ok
```

`--rpc` serves the common read methods from the executed state (`eth_getBalance`,
`eth_call`, `eth_getProof`, blocks and receipts, and more; see `bin/base/el_rpc.zig`).
`--engine.*` serves the Engine API for step 6. A `kill -9` is safe: the database recovers
from its journal. Opening it again took about 8 minutes on the first node.

## 6. Safe and finalized heads: `base consensus`

The consensus node derives L2 blocks from L1 and checks them against el-run's chain through
the Engine API. It speaks plain HTTP, so `https-bridge` forwards loopback ports to the
HTTPS L1 endpoints:

```sh
$B https-bridge --routes \
    28545=https://ethereum-rpc.publicnode.com,25052=https://ethereum-beacon-api.publicnode.com &
$B rollup-config --chain base-mainnet --out $D/rollup.json
$B consensus --rollup-config $D/rollup.json \
    --l1 http://127.0.0.1:28545 --l1-beacon http://127.0.0.1:25052 \
    --l2 http://127.0.0.1:8552 --l2-jwt $D/jwt.hex --p2p.disabled --rpc.port 7546 \
    --safedb.path $D/safedb.bin --checkpoint.path $D/checkpoint.bin >> $D/consensus.log 2>&1
```

Start it once el-run is at the tip (it logs `el-run: at the tip`) and its engine ring holds
at least 16,384 blocks (the `engine:` summary line's `ring`), about 55 minutes after el-run
starts. `optimism_syncStatus` on port 7546 reports the safe and finalized heads.

## Limits

- **Unsafe head.** It comes from devp2p peers (a median of about 180 ms behind the tip on
  the first node), not from the consensus gossip network.
- **State history.** The database keeps only the head state. RPC calls for older state
  return "historical state unavailable", and blocks and receipts are served only for the
  blocks el-run executed since it started.
- **RPC.** Reads only: there is no transaction pool and no `eth_sendRawTransaction`.
- **Restarts.**
  - Restarting el-run empties its engine ring, so consensus has to wait for it to warm up
    again.
  - Run by hand, nothing restarts the processes on their own. `base up` supervises them
    and restarts them with backoff.
- **Snapshots.** Base rotates its snapshots. The import has been verified on reth
  2.5.2-dev snapshots (block 54528124).
