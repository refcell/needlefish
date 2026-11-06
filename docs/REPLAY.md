# Replaying Base mainnet

`base replay` re-executes real Base mainnet blocks offline and checks that needlefish
reproduces every field the block header commits to. If needlefish computed one wrong
balance, nonce, storage slot, receipt, log or gas charge, the block's state root, receipts
root or block hash would differ.

```sh
just replay                # fetch the latest 10 blocks from public RPC, replay offline
just replay 100            # the latest 100 blocks (about 15 minutes from a cold cache)
just replay 100 53750445   # a pinned window: the same blocks every run
just replay-run            # replay the committed 10-block archive (no network)
```

`just replay` needs only Zig and the network: `base replay fetch` downloads the blocks and
the witness from public keyless endpoints (about 80 s for 10 blocks), caching every
response under `.cache/replay/`, and writes `.cache/replay/latest.nfrp`; `base replay run`
then replays that archive with no network access.

```
needlefish replay  Base mainnet (chain 8453)  10 blocks 53715983..53715992  archive 8.8 MB, offline

  block       txs       gas     exec  state root          tx  gas bloom blob rcpt state wdr hash
  53715983     15    1.55M    4.1ms  aa2c756a..1214      ✓   ✓   ✓     ✓    ✓    ✓     ✓   ✓
  ...
  10/10 blocks reproduced  253 txs  46.5 Mgas
```

## What is checked

For every block, needlefish executes the transactions with its own executor and Base
mainnet rules (the fork schedule from `ChainSpec.presets.base_mainnet`, the L1 info and
BaseTime deposits, the pre-block system calls, L1/operator fees), then rebuilds the header
from its own results and compares, field by field, against the canonical header:

| Column | Header field | What it covers |
| --- | --- | --- |
| tx | `transactionsRoot` | the transactions were decoded and re-encoded exactly |
| gas | `gasUsed` | gas accounting of every transaction |
| bloom | `logsBloom` | every log address and topic |
| blob | `blobGasUsed` | the DA footprint accounting |
| rcpt | `receiptsRoot` | status, cumulative gas, logs, and deposit receipt fields |
| state | `stateRoot` | every account and storage slot after the block |
| wdr | `withdrawalsRoot` | the L2ToL1MessagePasser storage root (Isthmus) |
| hash | block hash | the resealed header equals the canonical one |

Replay is chained: block N+1 runs on needlefish's own post-state of block N, never on
fetched state, so an error in one block also breaks the next.

On a mismatch the run stops and prints the first failed check, the first receipt that
differs, and the first account or slot whose post-block value differs from the canonical
chain, plus the state root expected and computed.

## How it works offline

needlefish has no Base state database to replay against, so the archive carries a
stateless witness: the Merkle-Patricia trie nodes and contract code the blocks touch.
`SparseState` (`src/execution/db/witness.zig`) serves account and storage reads from those
nodes and recomputes the state root after each block over the partial trie. A read outside
the witness is an error, never a silent zero.

The archive (`src/infra/replay/archive.zig`) is one file:

- an `NFRP` frame: version, body size, keccak256 of the body, raw-deflate body;
- the witness (`NFWT`, canonical: nodes and codes sorted by hash, no duplicates);
- the parent's state root and the 256 ancestor block hashes (`BLOCKHASH`);
- the replayed blocks: RLP header, EIP-2718 transactions, and for diagnostics the
  canonical receipts and post-block values of the accounts and slots each block changed.

The decoder is strict (one valid encoding per archive) and fuzzed.

## Building an archive

No public Base endpoint serves `debug_executionWitness`, so the witness is assembled from
standard archive-node calls (all public, keyless):

| Call | Endpoint | Gives |
| --- | --- | --- |
| `eth_getBlockByNumber(n, true)` | `base.drpc.org` | header and transactions |
| `eth_getBlockReceipts(n)` | `base.drpc.org` | canonical receipts |
| `debug_traceBlockByNumber(n, prestateTracer)` | `base.drpc.org` | touched accounts, slots, code |
| same, `diffMode` | `base.drpc.org` | which accounts and slots each block changed |
| `eth_getProof(account, slots, n - 1)` | `base-mainnet.public.blastapi.io` | pre-state trie nodes |
| `eth_getProof(account, slots, n)` | `base-mainnet.public.blastapi.io` | post-state values and nodes |

`base replay fetch [--count n] [--from block]` makes these calls (headers and proofs in
paced batches of 16, retries with backoff on rate limits), saves each result under
`.cache/replay/<first>-<count>/`, and builds the archive. `base replay import <raw dir>
--out <archive>` builds an archive from such a directory alone.
Every byte is bound to the chain before it is used:

- the header is re-encoded from JSON and must hash to the block hash;
- the transactions are re-encoded and must hash to `transactionsRoot`;
- every account and storage proof must verify against the parent's (or the block's) state
  root;
- ancestor hashes must form a `parentHash` chain ending at the first block's parent.

Raw directory layout (each file is the exact JSON-RPC `result`):

```
<raw dir>/window.json                  {"first": n, "count": k}
<raw dir>/headers.json                 [{number, hash, parentHash, stateRoot}, ...]
<raw dir>/<n>/block.json               eth_getBlockByNumber(n, true)
<raw dir>/<n>/receipts.json            eth_getBlockReceipts(n)
<raw dir>/<n>/prestate.json            prestateTracer
<raw dir>/<n>/prestate_diff.json       prestateTracer, diffMode
<raw dir>/<n>/proofs_pre.json          eth_getProof at n - 1, every touched key
<raw dir>/<n>/proofs_post.json         eth_getProof at n, same keys
<raw dir>/<n>/proofs_extra.json        optional: eth_getProof at n - 1, extra keys
<raw dir>/<n>/codes_extra.json         optional: eth_getCode of those accounts
```

### State no transaction trace shows

Transaction traces miss state that needlefish still reads:

- the pre-block system calls: the EIP-4788 beacon roots contract and the EIP-2935 block
  hash history contract;
- precompile and system accounts the executor loads;
- the L2ToL1MessagePasser, whose storage root is the Isthmus `withdrawalsRoot`.

`base replay fetch` seeds every block with the system contracts (and the ring-buffer slots
they write) and the message passer, and the first block with the precompiles. It then
replays the archive in-process in probe mode, where a missing account reads as absent and a
missing slot as zero, so one pass collects every key a block lacks. Those keys are fetched
at the parent into `proofs_extra.json` and `codes_extra.json` and the archive is rebuilt,
until the replay has no gaps (about one round per block with gaps; 256 rounds at most). `base replay run` prints
the same gaps on a machine-readable line
(`GAPS {"block":n,"accounts":[...],"slots":[...],"nodes":[...]}`).

### Deleted keys and branch collapse

When a block deletes a storage slot (or an account) and its trie branch is left with one
child, the branch collapses into that child. Recomputing the root then needs the child's
node, which no proof contains: a proof only holds the nodes on its own key's path, and the
sibling appears in it only as a hash.

After the collapse the sibling is merged into a node on the deleted key's post-state path:
a leaf or extension whose path is the collapsed nibbles followed by the sibling's own
path. So the importer takes every suffix of every post-state leaf or extension path as a
candidate sibling and keeps the ones whose hash a witness node references but no proof
supplies. When the sibling is itself a branch, the post-state node is an extension that
points at the branch's hash; its preimage is not derivable, but the collapse only needs to
know it is a branch, so the archive records the hash as opaque and the replay resolves it
to a stand-in branch while keeping the real hash as its reference.

## What it found

The first run over blocks 53715983..53715992 diverged in block 53715983, transaction 3: an
MEV transaction that succeeded on mainnet reverted in needlefish. It called a pool through
an EIP-1167 minimal proxy, which uses `RETURNDATASIZE` as a cheap zero for the offset of
`CALLDATACOPY`. needlefish's EVM shared one return-data buffer across frames and did not
clear it when a frame started, so the proxy saw the previous call's return size, copied
the calldata to the wrong offset and forwarded zeros. The fix is one line in
`src/execution/evm/evm.zig` (`push_frame`), with a regression test. After it, all 10 blocks
reproduce every checked field.

## Tests

`zig build test` replays the committed archive
(`src/infra/replay/testdata/base-mainnet-53715983-10.nfrp`, 8.7 MB) in
`src/infra/replay/mainnet_test.zig` and requires all 10 blocks to pass. The archive codec
has round-trip, strictness and seeded fuzz tests in `archive_test.zig`.
