# Lane: follow

Owns `src/infra/follow/*`, the `base follow` subcommand (`bin/base/follow.zig`), and the
verification checker of docs/SYNC_PLAN.md (M1). Reuses `src/infra/replay` (header checks,
gaps, opaque stand-in branches).

Goal: a stateless validating follower that re-executes every live block of Base Sepolia,
then Base mainnet, checks every header field, and runs 24 h on each with zero mismatches.

## Design

- One long-lived `SparseState`. Its node store is keyed by keccak256, so a node fetched at
  any block only ever serves the trie reference that names its hash. The store also keeps
  every node the follower's own commits compute (`SparseState.keep_new_nodes`), so a rebase
  (drop the trie, keep the store) loses nothing.
- Per block: probe passes (execute without committing; a missing account reads as absent, a
  missing slot as zero, a missing code as empty; failed transactions are skipped so later
  ones still reveal keys), fetch `eth_getProof` and `eth_getCode` at the parent for every
  gap, repeat. Then verify: execute, commit, check every header field
  (`replay.replayer.check_header`). A retryable failure (witness gap while committing, a
  full pool) rebases; a full node store resets.
- Deletions: after a failed commit, fetch post-state proofs (at the block) for the keys
  the clean pass deleted and derive collapse siblings (`add_post_nodes`); branch siblings
  resolve to the opaque stand-in, which `advance` drops from the trie once the block
  verifies.
- BLOCKHASH: a ring of 256 verified hashes, seeded by hash-linking ancestors at start.
- Reorg (parent hash is not the verified head): re-anchor at the new parent.
- On mismatch: first failed check, first differing receipt (`eth_getBlockReceipts`), first
  differing account or slot (`eth_getProof` at the block for every changed key), exit 1.

## Endpoints (keyless, measured 2026-11-06)

| Endpoint | Use | Limits |
| --- | --- | --- |
| base-sepolia-rpc.publicnode.com | blocks, receipts, `eth_getProof` at `latest` only | batches of 50 fine |
| sepolia.base.org | `eth_getProof` at recent blocks | about 5 items per second, then -32011 |
| base.drpc.org | mainnet `eth_getProof`, archive | free plan timeouts |

## Backlog

- [x] Follower state machine over the fixture: 10 mainnet blocks verify with the witness
  served on demand, including a rebase midway.
- [x] `base follow` RPC driver, Sepolia defaults, status file, mismatch report.
- [x] Bounded lag: past `--max-behind` blocks (default 8000, inside the 10,000-block proof
  window) the follower re-anchors at the tip and counts the blocks it never verified
  (`skipped`); a block abandoned for want of data is counted too, never a mismatch.
- [ ] (blocked) Real-time coverage on Sepolia: needs an `eth_getProof` endpoint at recent
  blocks with far more than 5 items/s (own node or a keyed provider).
- [ ] Parallel workers on disjoint block segments if one follower cannot keep up.
- [ ] 24 h Sepolia run, zero mismatches.
- [ ] 24 h mainnet run, zero mismatches.
- [ ] Head comparison checker and state sampling against a reference node.

## Decisions

- 2026-11-06: no `latest` prefetch. Measured on Sepolia: the keys a block needs are mostly
  the ones it writes, whose proofs at `latest` no longer match the parent state, so gap
  counts did not drop and each pass paid an extra round trip. Reverted.
- 2026-11-06: keyless Sepolia proof capacity is about 5 `eth_getProof` items/s
  (sepolia.base.org, -32011 beyond); publicnode, tenderly and drpc serve no usable window at
  recent blocks or rate-limit at once. A block needs 30 to 300 proofs while cold, so a
  keyless follower verifies contiguous segments, not every block.

## Log

- 2026-11-06: first live run on Base Sepolia from the tip: 8 consecutive blocks verified,
  zero mismatches. Uncached blocks take 1 to 17 s, bounded by the proof endpoint's rate
  limit, so it falls behind the 200 ms cadence. Not a soak.
