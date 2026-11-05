# Roadmap

Phase 1 (lanes in `docs/lanes/`): primitives, crypto, evm, trie-db, io-net, node,
consensus, batcher-devnet, dst-fuzz. Milestone: `just devnet up` runs an all-Zig L1 +
L2 sequencer + batcher + verifier and `just devnet smoke` passes.

Phase 2 lanes (spawn when a phase-1 lane finishes):
- **p2p**: discv5, libp2p (noise, yamux/mplex, multistream), gossipsub for unsafe
  blocks, peer scoring (`crates/consensus/{disc,gossip,peers}`).
- **builder**: regular block builder at native 200 ms subsecond blocks (no flashblocks;
  `crates/builder/core` non-flashblocks parts, `crates/execution/payload`).
- **proof**: fault-proof program (client/host/preimage oracle), MPT proofs, executor,
  proposer, challenger (`crates/proof/*`).
- **infra-tools**: basectl, websocket-proxy, roxy, load tester, balance monitor,
  withdrawer, health (`crates/infra/*`, `crates/utilities/*`).
- **sync-perf**: snap/historical sync from L1 + archive, staged sync, extreme perf
  tuning (io_uring batching, huge pages, parallel execution).
