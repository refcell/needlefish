# Lanes

Work is split into lanes. Each lane is owned by one autonomous agent session and owns
the directories listed in its file. A lane file is the lane's living backlog and log:
the owning agent keeps its checklist current, records decisions, and appends a short
dated log line after each push. Other lanes may read it to find interfaces.

| Lane | File | Owns |
| --- | --- | --- |
| primitives | primitives.md | `src/common/{primitives,rlp,consensus,genesis,chains}` (backlog done; session retired, other lanes may extend) |
| crypto | crypto.md | `src/common/crypto` (backlog done; session retired, other lanes may extend) |
| evm | evm.md | `src/execution/evm` |
| trie-db | trie-db.md | `src/execution/{trie,db}` |
| io-net | io-net.md | `src/utilities/*` (backlog done; session retired, other lanes may extend) |
| node | node.md | `src/execution/{chainspec,txpool,payload,engine,rpc,node}`, `bin/node` |
| consensus | consensus.md | `src/consensus/*`, `bin/consensus` |
| batcher-devnet | batcher-devnet.md | `src/batcher/*`, `bin/batcher`, `etc/devnet`, `docs/DEVNET.md` |
| dst-fuzz | dst-fuzz.md | `src/testing/*`, `etc/ci/`, benches, perf |
| p2p | p2p.md | `src/consensus/p2p/*`, `docs/P2P.md` (backlog done; session retired, other lanes may extend) |
| replay | replay.md | `base replay`, `etc/replay`, `just replay`, README demo |
| builder | builder.md | `src/builder/*`, payload building, `bin/base builder`; removes flashblocks |
| proof | proof.md | `src/proof/*`, `bin/base {proof,proposer,challenger}` |
| infra-tools | infra-tools.md | `src/infra/*`, `bin/base {basectl,websocket-proxy,roxy,load-test,withdrawer,balance-monitor}` |
| sync-perf | sync-perf.md | `src/execution/sync/*`, `bin/base {sync,import,export}`, sync benches, measured perf edits |

Future lanes (spawned when capacity frees up) are listed in `docs/ROADMAP.md`.

## Lane protocol

1. Read `AGENTS.md`, `docs/TIGER_STYLE.md`, `docs/ARCHITECTURE.md`, your lane file.
2. Pick the first unchecked item. Study the matching base/base crate in
   `~/.cache/needlefish/base-ref` and the public spec. Implement it with tests + fuzz.
3. `zig build test && just tidy`, then rebase and `git push origin HEAD:main`.
4. Tick the item, add a log line, push. Repeat. When the backlog is empty, extend it
   with the next most valuable work toward a fast, correct, devnet-capable Base node.
