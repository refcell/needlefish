# Lane: replay

Owns `src/infra/replay/*`, the `base replay`
subcommand, `etc/replay/`, the `just replay` recipes, `docs/REPLAY.md`, and the README demo
(`docs/assets/demo.*`).

Goal: **prove needlefish executes real Base mainnet blocks correctly.** Fetch 10 recent
Base mainnet blocks plus a stateless witness of the state they touch, then replay
them offline through needlefish's executor and check every block's state root, receipts
root, gas used, and block hash against the canonical headers. Show it in a TUI, record a
raw Ghostty demo with subtitles, and put it near the top of the README.

## Data sources (verified 2026-11-05, public, no API keys)

| Endpoint | Works | Does not |
| --- | --- | --- |
| `https://base.drpc.org` | `eth_getBlockByNumber`, archive `eth_getProof`, `debug_traceBlockByNumber` with `prestateTracer` | `debug_executionWitness` |
| `https://base-mainnet.public.blastapi.io` | archive `eth_getProof` | `debug_*` |
| `https://mainnet.base.org` | blocks, receipts | `eth_getProof` (no state), `debug_*` |

Never commit or require API keys. Be polite to public endpoints: batch, cache every
response under `.cache/replay/`, retry with backoff on 429, cap concurrency.

## Design

1. `base replay fetch --rpc <url> --from <n> --count <k> --out <archive>`: for each block,
   get the full block + receipts, the `prestateTracer` pre-state (touched accounts, slots,
   code), `eth_getProof` at the parent for every touched account/slot (pre-state trie
   nodes), and `eth_getProof` at the block itself for the same keys (post-state nodes, so
   branch collapses on deletion can be resolved). Write one self-contained, checksummed,
   compressed witness archive (reuse `src/execution/db/witness*` and the proof lane's
   archive format where it fits). This is the "snapshot".
2. `base replay run <archive>`: offline and deterministic. Build a partial state from the
   witness, execute each block with the real executor (OP/Base rules, the correct
   hardforks for Base mainnet at those heights, L1 info deposit, fees), recompute the
   state root over the partial trie, and compare against the canonical header. Any
   mismatch prints the first differing account/slot/receipt and exits non-zero.
3. TUI (zero deps, ANSI): live per-block rows (number, txs, gas, exec ms, state root
   expected vs computed, ✓/✗), a progress bar, and a summary (blocks, txs, gas/s,
   Mgas/s). Plain-line output when not a TTY or with `--plain`.
4. Recipes: `just replay fetch [count]`, `just replay run [archive]`, `just replay`
   (fetch if missing, then run). Commit a small archive (about 10 blocks) under
   `etc/replay/fixtures/` only if it is under 10 MB compressed, and add a unit test that
   replays it in `zig build test`. Otherwise keep archives in `.cache/` and document the
   fetch.

## Demo recording

- Record a raw Ghostty session running `just replay fetch` (short) and `just replay run`.
  No intro cards, no editing beyond trimming dead time at the ends.
- Subtitles burned in (short, factual: what command runs, what is being checked, the
  result). The stock Homebrew ffmpeg 9 lacks `subtitles`/`drawtext`; install a build with
  libass (for example the `homebrew-ffmpeg/ffmpeg` tap with `--with-libass`, or
  `ffmpeg-full`). Tools are fine; they are not repo dependencies.
- Capture: `screencapture -v` of the Ghostty window rect (screen recording works from
  this machine). Launch Ghostty with a dedicated config (fixed window size/position, a
  clean theme, a minimal prompt such as `$ `), so nothing personal is visible: no
  username, hostname, home path, other windows, or notifications. Inspect sampled frames
  as images before committing; if anything personal or another window appears, re-record.
- Output: `docs/assets/demo.mp4` (H.264, under ~8 MB) and `docs/assets/demo.gif` (under
  ~10 MB). README: right under the intro paragraph,
  `[![needlefish replaying Base mainnet blocks](docs/assets/demo.gif)](docs/assets/demo.mp4)`.

## Backlog
- [x] Archive format (`NFRP`, canonical body, strict decoder, seeded fuzz).
- [x] Offline replayer (`base replay run`): partial-trie state, executor, root checks,
  first-difference diagnostics, gap report.
- [x] `base replay import <raw dir>`: archive from saved JSON-RPC results, every byte bound
  to the chain; collapse siblings derived from post-state proofs.
- [x] Pass on 10 consecutive Base mainnet blocks (53715983..53715992).
- [x] Witness fetcher (`base replay fetch`, default count 10): RPC, caching, backoff, and
  the in-process gap-fill loop (system-call contracts, precompiles, message passer).
- [x] TUI + plain mode.
- [x] `just replay` (fetch latest + run), `just replay-run`, `docs/REPLAY.md`, committed
  fixture (`src/infra/replay/testdata/`, 8.7 MB) replayed by `zig build test`.
- [x] Demo recording with burned-in subtitles; README embed near the top.
- [x] Fuzz the archive decoder; deterministic replay test (two replays, one in probe mode,
  compute the same roots); fuzz the fetcher's batch-response parser.
- [x] `just replay 100` from a cold cache: `[k/N]` progress, resumable cache, optional pinned
  first block (`just replay 100 53750445`) for a deterministic window.
- [x] Collect missing keys of every failing block per round (probe mode replays past
  failed blocks).
- [x] Pinned 100-block window check: `just replay-check` (53775088..53775187).
- [x] Fetch cost: drop the diffMode trace; changed keys come from pre/post proofs.
- [ ] (blocked) Third pinned window from an older fork era (pre-Isthmus, e.g. block
  29000000): keyless endpoints cannot serve it. drpc's free plan mostly times out tracing
  old blocks (one success: a 91 MB prestate trace, the next block timed out); blastapi
  allows core EVM methods only; publicnode has no debug_*; mainnet.base.org filters it.
  Revisit with a keyless archive tracer, or by deriving the prestate from proofs alone.

## Decisions

- 2026-11-05: code lives in `src/infra/replay/` (library, pure, no IO; it imports the
  consensus JSON decoders, so it cannot sit under `execution/`) and `bin/base/replay.zig`
  (RPC + files + TUI driver).
- 2026-11-05: no public endpoint serves `debug_executionWitness`, `debug_getRaw*`,
  `debug_storageRangeAt`, or batched calls on drpc (blastapi does batch `eth_getProof`).
  So headers and transactions are re-encoded from JSON and bound by the block hash and
  `transactionsRoot`; the witness is built from `prestateTracer` keys plus archive
  `eth_getProof` at each block's parent.
- 2026-11-05: replay is chained: one `SparseState` over the union of every block's proof
  nodes and codes, never reset between blocks, so block N+1 runs on needlefish's own
  post-state of block N (a wrong root would also break the next block). BLOCKHASH is
  served from 256 ancestor hashes plus the replayed blocks' hash-linked headers.
- 2026-11-05: branch collapses on deletion need the sibling node, which no proof of a
  touched key contains. Superseded (no grinding needed): after the collapse the sibling is
  merged into a node on the deleted key's post-state path, so every suffix of a post-state
  leaf or extension path is a candidate; the importer keeps a candidate whose hash a
  witness node references but no proof supplies. A sibling that is a branch shows up as an
  extension's child hash; it is recorded as opaque and resolves to a stand-in branch (only
  its kind matters to the collapse; its real hash stays the reference).
- 2026-11-05: keys no transaction trace shows (pre-block system calls: EIP-4788,
  EIP-2935; precompiles and system addresses the executor loads; the L2ToL1MessagePasser
  for the Isthmus withdrawals root) come from a gap-fill loop: replay, read the `GAPS` line,
  fetch `eth_getProof` + `eth_getCode` at the parent, store as `proofs_extra.json` /
  `codes_extra.json`, re-import. Bounded rounds.
- 2026-11-05: scope is 10 blocks (owner decision); the 100-block target is dropped.
- 2026-11-05: archive = `NFRP` frame (version, body size, keccak256 of the body) around a
  raw-deflate body (std.compress.flate). Body is canonical: nodes and codes sorted by
  keccak256, no duplicates; the decoder is strict.

## Log

- 2026-11-06: no more diffMode trace: changed keys = touched keys whose verified pre and
  post proof values differ. Halves trace downloads (a fresh 10-block fetch: 73 s, 10/10).
  The cached 100-block window re-imports 420 bytes smaller: 5 slots the per-transaction
  diff listed were restored by block end; replay-check stays 100/100.

- 2026-11-06: decision: no older-era window for now (see backlog); fork coverage beyond the
  current era stays with the EVM/state test vectors.

- 2026-11-06: summary line adds ms/block; throughput baseline for both pinned windows in
  docs/REPLAY.md (820-907 Mgas/s, 3.1-4.0 ms/block). Demo frames rechecked: bare `$` prompt,
  relative paths only, no titlebar.

- 2026-11-06: second pinned window in `just replay-check`: 53811190..53811209 (314 txs,
  70.6 Mgas, 1 gap round) 20/20.

- 2026-11-06: unit test for replaying past a failed block: the fixture without its pre-state
  root node; normal mode stops after block 1, probe mode replays all 10 recording gaps.

- 2026-11-06: one gap round fills every block lacking state: cached window 53775088..+100
  with its 3 gap blocks cleared needs 1 round (was 3), same archive bytes, 100/100.

- 2026-11-06: cold `just replay 100` (build + fetch + run, one command): 53775088..53775187,
  1571 txs, 271.9 Mgas, 3 gap rounds, 100/100 in 13m24s.

- 2026-11-06: probe mode: the gap search reads a missing account as absent and a missing
  slot as zero, so one replay collects all of a block's missing keys. 50-block window
  53747405..53747454: 21 gap rounds -> 3, same archive bytes, fetch rerun 19 s from cache.

- 2026-11-05: 100-block milestone from an empty cache: 53750445..53750544 (1747 txs,
  320.9 Mgas, busiest block 25.7 Mgas) 100/100 in 13m49s with 13 gap rounds; 50 blocks
  53747405..53747454 (825 txs) 50/50 with 21 rounds. No state-root or receipt mismatch.

- 2026-11-05: demo (`docs/assets/demo.{mp4,gif}`, in the README): raw Ghostty recording of
  `just replay` on an empty cache, blocks 53741014..53741023, 172 txs, 10/10, 0 gap rounds.
- 2026-11-05: decision: some `eth_getProof` servers also list a node shorter than 32 bytes
  that its parent inlines; the importer drops such nodes (past the root) instead of
  loosening the shared verifier. Found on blocks 53734749..53734758.
- 2026-11-05: `fill.py` and `fetch_raw.py` are retired; `base replay fetch` does both.

- 2026-11-05: `just replay` end to end from an empty cache: latest blocks
  53731432..53731441 (150 txs) fetched in 80 s with one gap round, 10/10 reproduce.
- 2026-11-05: fixture lives in `src/infra/replay/testdata/` (not `etc/replay/fixtures/`):
  `@embedFile` cannot reach outside the `src/` module root.

- 2026-11-05: first real-data run. Blocks 53715983..53715992 (253 txs): all 10 reproduce
  the transactions root, gas used, logs bloom, blob gas used, receipts root, state root,
  withdrawals root and block hash. Archive 8.7 MB. The one divergence found was an EVM bug:
  a new frame inherited the previous call's RETURNDATASIZE, so EIP-1167 proxies forwarded
  zeroed calldata (block 53715983 tx 3). Fixed in `evm.zig` with a regression test.
