# Benchmarks: needlefish vs base/base

needlefish and the Rust [base/base](https://github.com/base/base) implementation execute the
same real Base mainnet blocks from the same pre-state, on the same machine, and both must
reproduce every block's canonical header (state root, receipts root, gas used, block hash).
A block that does not reproduce stops the run and the numbers do not count.

## Results

Apple M4 Pro (10 performance + 4 efficiency cores), 48 GB, macOS, 2026-11-06. One cold run,
then 10 warm runs, per implementation and block range. Every block matched its canonical
header in all 11 runs on both sides.

| Blocks | Phase | needlefish Mgas/s | base/base Mgas/s | needlefish ms/block (median / p90) | base/base ms/block (median / p90) |
| --- | --- | ---: | ---: | ---: | ---: |
| 53775088..53775187 (100) | execution | 1717 | 626 | 1.23 / 3.29 | 3.83 / 7.41 |
| 53775088..53775187 (100) | execution + roots | 1182 | 202 | 1.84 / 4.65 | 14.25 / 20.56 |
| 53715983..53715992 (10) | execution | 1537 | 616 | 2.77 / 5.48 | 6.57 / 13.64 |
| 53715983..53715992 (10) | execution + roots | 1153 | 430 | 3.50 / 7.15 | 8.51 / 17.96 |

Mgas/s is the median over the warm runs of (total gas / total time). Per-block statistics use
every (block, warm run) sample. Full output, including cold runs:

| Implementation | Phase | Blocks | Mgas | Warm runs | Mgas/s warm median | Mgas/s cold | ms/block warm median | ms/block warm p90 | ms/block cold median |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| needlefish, 100 blocks | execution | 100 | 271.9 | 10 | 1717 | 1669 | 1.23 | 3.29 | 1.27 |
| needlefish, 100 blocks | execution + roots | 100 | 271.9 | 10 | 1182 | 1168 | 1.84 | 4.65 | 1.90 |
| base/base, 100 blocks | execution | 100 | 271.9 | 10 | 626 | 642 | 3.83 | 7.41 | 3.81 |
| base/base, 100 blocks | execution + roots | 100 | 271.9 | 10 | 202 | 209 | 14.25 | 20.56 | 13.97 |
| needlefish, 10 blocks | execution | 10 | 46.5 | 10 | 1537 | 1451 | 2.77 | 5.48 | 2.68 |
| needlefish, 10 blocks | execution + roots | 10 | 46.5 | 10 | 1153 | 1098 | 3.50 | 7.15 | 3.41 |
| base/base, 10 blocks | execution | 10 | 46.5 | 10 | 616 | 609 | 6.57 | 13.64 | 6.50 |
| base/base, 10 blocks | execution + roots | 10 | 46.5 | 10 | 430 | 428 | 8.51 | 17.96 | 8.52 |

| | needlefish | base/base |
| --- | ---: | ---: |
| Peak RSS, 100 blocks x 11 runs | 289 MiB | 253 MiB |
| Peak RSS, 10 blocks x 11 runs | 96 MiB | 76 MiB |
| Binary size | 9.5 MB (`base`, the whole multi-tool: node, consensus, batcher, proof, tools) | 31.6 MB (harness: executor only) |

Where base/base wins: peak memory. base/base uses 12-21% less RSS. needlefish allocates its
pools and buffers up front from configured limits (TigerStyle static allocation), which is
the likely reason; we have not profiled it.

Where the gap comes from:

- **State root.** base/base's state root work grows across the 100-block window: root and
  seal take 1.71 ms/block over the first 10 blocks and 14.55 ms/block over the last 10.
  `TrieDB` keeps the account trie in memory across blocks and re-hashes every node it holds
  on each `state_root`; it caches no hashes. needlefish caches node hashes and re-hashes only
  dirty nodes, deepest level first, spread over worker threads: 0.54 ms/block over the first 10 blocks, 0.91 ms/block over the last 10. The
  10-block range shows the smaller, early-window gap (2.7x on execution + roots).
- **Sender recovery.** needlefish recovers senders on worker threads and recovers the next
  block's senders while the current block commits. base/base's builder recovers them
  serially inside `build_block`, using the C libsecp256k1 (base/base's default `secp256k1`
  feature). Both count recovery as execution.
- **Execution.** Both execute every transaction against a witness-backed state that reads
  trie nodes on demand. needlefish's EVM, trie, and crypto are pure Zig. base/base uses revm
  43.0.3, alloy 2.5.0, and the C libraries behind its default features (`secp256k1`,
  `blst`, `c-kzg`).

## What these numbers are not

Known biases in these numbers (laptop, thread count, build settings, few runs) and the plan
to remove them are in [BENCHMARK_PLAN.md](BENCHMARK_PLAN.md).

They compare **stateless** executors: both read state from a witness of trie nodes, not from
a database. base/base's executor over a witness is `base-proof-executor`
(`StatelessL2Builder`), the block builder of its fault-proof program. base/base's node
(reth, an MDBX database, and a parallel sparse-trie state root) is a different code path.
It needs a full Base state database, so it is not measured here. Its state root performance
in particular is not what this harness shows.

## Methodology

### Workload

- The pinned 100-block window 53775088..53775187 (1571 transactions, 271.9 Mgas), also used
  by `just replay-check`.
- The committed 10-block fixture
  `src/infra/replay/testdata/base-mainnet-53715983-10.nfrp` (253 transactions, 46.5 Mgas).

Both inputs are needlefish replay archives ([REPLAY.md](REPLAY.md)): the blocks' raw
transactions and headers, the pre-state trie nodes and bytecodes they touch (every byte bound
to the chain by hash or proof), and 256 ancestor block hashes. Both implementations read the
**same archive file**. base/base also gets the first block's parent header, fetched from
public RPC (`eth_getBlockByNumber`); the harness checks that it hashes to the archive's
parent hash and carries the archive's parent state root.

### What each side runs

- **needlefish**: `base replay bench <archive> <warm runs>`
  ([bin/base/replay_bench.zig](../bin/base/replay_bench.zig)), the replayer behind
  `base replay run`: `execution/node/executor.zig` over `SparseState`, chained so block N+1
  runs on needlefish's own post-state of block N.
- **base/base**: `nf-replay-bench`, a small binary added to a base/base checkout at commit
  `a8b34b69ee43d12fd9f4b4f9335521315f6953ff` by
  [etc/bench/base-harness.patch](../etc/bench/base-harness.patch). It builds
  `StatelessL2Builder` with `BaseEvmFactory` and the Base mainnet `RollupConfig` from
  `base-common-chains`, and calls `build_block` once per block, chaining the sealed header
  as the next parent. That is how base/base's proof program drives it. Payload attributes
  come from the canonical header: timestamp, prev randao, fee recipient, gas limit, parent
  beacon root, and the EIP-1559 and minimum base fee parameters from `extraData`, plus
  empty withdrawals and the raw transactions.

The patch adds the harness crate, one workspace member line, and 41 lines in two base/base
crates (`base-proof-mpt`, `base-proof-executor`). None of the changes
alter execution or the root computations:

1. `TrieProvider::is_opaque_branch` (default `false`) and its use in
   `TrieNode::collapse_if_possible`. When a branch collapses onto a child that the witness
   holds only as a hash, the parent becomes an extension over that hash. That is the same
   result as unblinding a branch child. needlefish archives list such branches (no public
   endpoint serves their preimage). The harness also treats any other sibling that the
   witness lacks as such a reference: `TrieDB` collapses a branch on every delete, and a
   later insert in the same block can re-expand it. If a sibling was really merged, the
   state root would differ and the block would fail. No block failed.
2. `TrieDBProvider::block_hash_by_number` (default `None`), checked first in
   `TrieDB::block_hash`. BLOCKHASH reads come from the archive's 256 ancestor hashes, as in
   a node with a block index. Without it, the archive would need the 256 ancestor headers.
3. A `clock` and `last_execute_ns` field on `StatelessL2Builder`, and a `trie_db()`
   accessor. They time the execution phase and read the computed storage tries (point 4).

4. Between blocks, outside the timed region, the harness gives the provider the
   storage-trie nodes `TrieDB` computed in earlier blocks. `TrieDB` reopens each account's
   storage trie from its root hash in every block, and in the proof program the host serves
   those post-state nodes. needlefish keeps its post-state trie in memory and pays nothing
   for this, so this step favours base/base.

### Phases

- **execution**: from the start of the block to the end of its last transaction. That
  covers the pre-block system calls (L1 info deposit, EIP-4788, EIP-2935), sender recovery,
  and every transaction, with state reads from the witness.
  - needlefish: start of `execute_block` to the end of `apply_list` (`Executor.phase_clock`).
  - base/base: start of `build_block` to the return of `execute_block` (patch item 3).
- **execution + roots**: the whole block, until the resealed header is compared with the
  canonical one. That adds post-block changes, the receipts root, logs bloom, state commit,
  the state root, the transactions root, and the header hash.
  - needlefish: `Replayer.replay_next`.
  - base/base: `build_block`.

The clock is the monotonic clock: `std.Io.Clock.awake` for needlefish, `std::time::Instant`
for base/base. Loading and decoding the archive and building the node index are not timed.

### Runs

Each process replays the archive once cold (run 0, the first execution in a fresh process),
then N warm runs (here N = 10). Every run starts from a fresh replayer or `TrieDB` over the
same decoded archive, so every run executes the same blocks from the same pre-state. Peak RSS
is `/usr/bin/time -l` over the whole process (all 11 runs).

### Versions and flags

| | needlefish | base/base |
| --- | --- | --- |
| Source | this repository (the commit that adds this file) | `a8b34b69ee43d12fd9f4b4f9335521315f6953ff` |
| Toolchain | Zig 0.17.1 | rustc 1.96.0 (pinned by base/base's `rust-toolchain.toml`) |
| Build | `zig build -Doptimize=ReleaseFast` | `cargo build --release --locked` (base/base's `release` profile: opt-level 3, thin LTO, 16 codegen units) |
| Recovery threads | 7 (one per spare core, at most 7) | 1 (inline) |

### Machine state

The machine ran no other build or benchmark: every other needlefish workstream was paused,
and no compiler or test process was running. Endpoint security agents kept running at about
3 cores of background load, and the 1-minute load average was 5.8 on 14 cores. `pmset -g
therm` recorded no thermal or performance warning. Both implementations ran back to back
under the same conditions.

## Reproduce

```sh
etc/bench/reproduce.sh 10
```

[etc/bench/reproduce.sh](../etc/bench/reproduce.sh) builds needlefish, fetches the 100-block
archive from public keyless RPC (cached under `.cache/`), clones base/base at the pinned
commit, applies the harness patch, builds it, runs all four combinations, and prints the
tables above ([etc/bench/summarize.sh](../etc/bench/summarize.sh)). Everything it writes
stays under the git-ignored `.cache/`. The Rust harness never enters this repository's build,
and needlefish keeps zero dependencies.

The harness takes `nf-replay-bench <archive> <parent-block.json> [warm runs]`. needlefish
takes `base replay bench <archive> [warm runs]`. Both print one line per block, in the same
format:

```
BENCH run=<r> block=<n> txs=<k> gas=<g> exec_ns=<e> total_ns=<t> ok=<0|1>
```
