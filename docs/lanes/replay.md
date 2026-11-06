# Lane: replay

Owns `src/execution/replay/*` (or `src/infra/replay`, decide), the `base replay`
subcommand, `etc/replay/`, the `just replay` recipes, `docs/REPLAY.md`, and the README demo
(`docs/assets/demo.*`).

Goal: **prove needlefish executes real Base mainnet blocks correctly.** Fetch the last
10-100 Base mainnet blocks plus a stateless witness of the state they touch, then replay
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
- [ ] Witness fetcher (`base replay fetch`) with caching, batching, backoff, archive format.
- [ ] Offline replayer (`base replay run`): partial-trie state, executor, root checks,
  first-difference diagnostics.
- [ ] Pass on 10 consecutive recent Base mainnet blocks; then 100.
- [ ] TUI + plain mode.
- [ ] `just replay` recipes, `docs/REPLAY.md`, fixture + unit test if small enough.
- [ ] Demo recording with burned-in subtitles; README embed near the top.
- [ ] Fuzz the archive decoder; DST-style deterministic replay test.

## Decisions

- 2026-11-05: code lives in `src/execution/replay/` (library, pure, no IO) and
  `bin/base/replay.zig` (RPC + files + TUI driver). It sits next to the executor and
  `db/witness.zig` it drives.
- 2026-11-05: no public endpoint serves `debug_executionWitness`, `debug_getRaw*`,
  `debug_storageRangeAt`, or batched calls on drpc (blastapi does batch `eth_getProof`).
  So headers and transactions are re-encoded from JSON and bound by the block hash and
  `transactionsRoot`; the witness is built from `prestateTracer` keys plus archive
  `eth_getProof` at each block's parent.
- 2026-11-05: replay is chained: one `SparseState` over the union of every block's proof
  nodes and codes, never reset between blocks, so block N+1 runs on needlefish's own
  post-state of block N (a wrong root would also break the next block). BLOCKHASH is
  served from the archive's hash-linked header chain (256 ancestors + the blocks).
- 2026-11-05: branch collapses on deletion need the sibling node, which no proof of a
  touched key contains. The fetcher replays the archive itself; on a missing node it
  finds the node's trie path through the pool (child -> parent index up to a state or
  storage root), grinds an address or slot whose keccak256 has that nibble prefix, fetches
  its proof at the block's parent, and retries. Bounded rounds.
- 2026-11-05: archive = `NFRP` frame (version, body size, keccak256 of the body) around a
  raw-deflate body (std.compress.flate). Body is canonical: nodes and codes sorted by
  keccak256, no duplicates; the decoder is strict.

## Log
