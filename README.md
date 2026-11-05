# needlefish

[![Zig](https://img.shields.io/badge/Zig-0.17.1-F7A41D?style=for-the-badge&logo=zig&logoColor=white)](#installation)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=for-the-badge&logo=linux&logoColor=white)](#installation)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen?style=for-the-badge)](#design)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange?style=for-the-badge)](#status)
[![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)](LICENSE)

needlefish is [Base](https://base.org), the Ethereum L2, rewritten from scratch in Zig: execution
client, rollup consensus node, block builder, batcher, and tooling, with zero dependencies.
L2 blocks are full blocks at Base's native 200 ms subsecond cadence; there are no flashblocks.

It is a ground-up port of the public [base/base](https://github.com/base/base) repository and
keeps its layout, so every crate there has an obvious home here.

> [!WARNING]
> Pre-alpha. Components are landing daily and the devnet is being assembled now. Do not run it
> against a real network or with real funds.

## Design

- **Zero dependencies.** Only the Zig standard library: no C libraries, no vendored code,
  `build.zig.zon` has an empty `.dependencies`. Keccak, secp256k1, BN254, BLS12-381, KZG,
  brotli, the EVM, the trie, the storage engine, HTTP, and JSON-RPC are all implemented here.
- **TigerStyle.** Assertions on every precondition, postcondition, and invariant; static
  allocation at startup; every loop and queue bounded; no recursion; functions ≤ 70 lines.
  See [docs/TIGER_STYLE.md](docs/TIGER_STYLE.md).
- **Deterministic simulation testing.** All network, disk, time, and randomness go through an
  injected IO layer. The simulator runs the real component code on simulated infrastructure
  with fault injection, and any run replays exactly from its seed.
- **Fuzzed.** Every decoder, parser, and state machine has a coverage-guided fuzz target and a
  seeded fuzz run that executes with the normal test suite.
- **io_uring.** Completion-based IO on Linux, kqueue on macOS, the same API in simulation.
- **Fast.** Performance is designed in and measured. Results live in [docs/PERF.md](docs/PERF.md).

## Status

| Component | Path | Scope | State |
| --- | --- | --- | --- |
| Primitives | `src/common/{primitives,rlp,consensus,chains,genesis}` | hex, RLP, all tx types incl. deposits, headers, receipts, chain configs, L1 fees | in progress |
| Crypto | `src/common/crypto` | keccak, sha256, ripemd160, blake2f, secp256k1, modexp, BN254, BLS12-381, KZG, P256 | in progress |
| EVM | `src/execution/evm` | interpreter, gas schedules, OP Stack deposit and fee rules, precompiles, state tests | in progress |
| Trie and storage | `src/execution/{trie,db}` | Merkle Patricia Trie, proofs, state root, chain store, storage engine | in progress |
| IO and networking | `src/utilities` | io_uring, kqueue, simulated IO, HTTP, JSON-RPC, JWT, WebSocket, metrics | in progress |
| Execution node | `src/execution/{chainspec,txpool,payload,engine,node}` | block executor, txpool, payload builder, Engine API, `eth_` RPC, L1 dev mode | in progress |
| Consensus node | `src/consensus` | protocol types, derivation pipeline, engine driver, sequencer | in progress |
| P2P | `src/consensus/p2p` | discv5, libp2p (noise, multiplexing), gossipsub, peer scoring | in progress |
| Block builder | `src/builder` | regular block builder for native 200 ms blocks, Engine API payload jobs | in progress |
| Batcher | `src/batcher` | channels, frames, compression, span batches, blobs, submission | in progress |
| Simulator | `src/testing` | cluster simulator, swarm runs, seed minimization, fuzz targets, benches | in progress |
| Proofs | `src/proof` | fault-proof program, preimage oracle, proposer, challenger | planned |

Each area has a backlog with its decisions and progress log in [docs/lanes](docs/lanes). The
plan for what comes next is in [docs/ROADMAP.md](docs/ROADMAP.md).

## Installation

needlefish builds from source with Zig 0.17.1 and nothing else.

```sh
git clone https://github.com/refcell/needlefish && cd needlefish
sh etc/scripts/install-zig.sh .cache/zig && export PATH="$PWD/.cache/zig:$PATH"  # if needed
zig build -Doptimize=ReleaseFast
```

Binaries are written to `zig-out/bin`. [`just`](https://github.com/casey/just) wraps the common
commands; `just release` builds optimized binaries with the git revision baked in.

## Usage

Everything ships in one multi-tool binary, `base`, mirroring base/base's `bin/` entry points as
subcommands.

```sh
base version                    # version and git revision
base devnet init --out .devnet  # generate a local devnet: genesis, rollup config, JWT
```

Subcommands for the node, consensus, and batcher join `base` as their components land.

### Local devnet

The devnet runs natively, with no Docker and no external L1: needlefish brings its own L1 dev
chain.

```sh
just devnet up       # init configs, start every component that has landed
just devnet status   # pids and chain heads
just devnet smoke    # end to end: L2 tx sequenced, batched to L1, derived by the verifier
just devnet logs     # tail all logs
just devnet down     # stop everything
just devnet reset    # wipe .devnet/ and start fresh
```

| Process | Command | Ports |
| --- | --- | --- |
| L1 dev chain | `base node --dev-l1` | http 8545, beacon 5052 |
| L2 sequencer EL | `base node` | http 9545, engine 9551 |
| L2 sequencer CL | `base consensus --sequencer` | rpc 7545 |
| Batcher | `base batcher` | metrics 7300 |
| L2 verifier EL | `base node` | http 10545, engine 10551 |
| L2 verifier CL | `base consensus` | rpc 8547 |

L1 is chain 900 with 2 s blocks; L2 is chain 901 with native 200 ms blocks and every hardfork
active at genesis. Prefunded accounts come from the public dev mnemonic
`test test test test test test test test test test test junk`. Everything the devnet writes,
including the generated JWT secret, stays in the git-ignored `.devnet/` directory.
[docs/DEVNET.md](docs/DEVNET.md) has the full process contract, flags, and smoke test.

## Testing

```sh
just test                 # unit tests, seeded fuzz runs included
just test rlp             # only tests matching "rlp"
just test-linux           # full suite in a Linux container, exercising io_uring
just fuzz                 # coverage-guided fuzzing of every fuzz target
just sim 42               # one deterministic cluster simulation, seed 42
just sim-swarm 1000       # 1000 seeds with randomized configs and faults
just sim-minimize 1234    # shrink a failing seed's config to a minimal reproduction
just vectors              # fetch public Ethereum test vectors into .cache/
zig build statetest -- .cache/vectors/ethereum-tests/GeneralStateTests
```

The simulator drives the cluster through latency, packet loss, reordering, duplication,
partitions, crashes and restarts, disk faults, and clock skew, and checks safety and liveness
invariants throughout. A failing seed is a complete bug report; minimized seeds become
regression tests.

## Performance

Selected results from `just bench` (ReleaseFast, Apple Silicon). Full tables, methodology, and
history are in [docs/PERF.md](docs/PERF.md).

| Case | ns/op |
| --- | ---: |
| BN254 field multiply | 19.7 |
| BLS12-381 field multiply | 31.5 |
| keccak256, 32 B, SIMD batch | 74.0 |
| sha256, 32 B | 25.3 |
| trie get, 100k keys | 168 |

## Development

```
bin/
  base/            multi-tool CLI entry point
src/
  base.zig         root of the single `base` module
  common/          primitives, rlp, crypto, consensus types, chains, genesis, l1_fees, flz
  utilities/       io (io_uring, kqueue, sim), http, json, rpc, jwt, metrics, cli
  execution/       evm, trie, db, chainspec, txpool, payload, engine, node
  consensus/       protocol, derive, p2p (disc, gossip, libp2p, peers)
  batcher/         channel, frame, comp, blobs, source, txdata, rpc, devnet
  proof/           fault-proof program (planned)
  testing/         prng, simulator, fuzz targets, bench harness
etc/
  devnet/          devnet supervisor and recipes
  scripts/         tidy, toolchain install, vector fetch
  ci/              CI workflow
docs/              architecture, style, devnet, performance, lanes, roadmap
```

```sh
just              # list recipes
just build        # debug build
just release      # optimized build
just fmt          # zig fmt
just tidy         # formatting, line length, secret scan, zero-dependency check
just ci           # what CI runs: tidy + test
just bench        # micro benchmarks
just assert-density src/execution/   # asserts per function, lowest first
```

- Every directory under `src/<group>/` is a module with a `root.zig`, re-exported by its
  group, so `zig build test` reaches all of it.
- base/base's `crates/<group>/<name>` maps to `src/<group>/<name>`; see
  [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- `just tidy` must pass before every push. It rejects lines over 100 columns, unformatted
  code, any dependency, and anything that looks like a secret or private data.
- The CI workflow is staged in `etc/ci/ci.yml`; [etc/ci/README.md](etc/ci/README.md) explains
  how to enable it.
- Contributor and agent rules are in [AGENTS.md](AGENTS.md).

## Releases

No releases yet. Build from `main`; `just release` produces optimized binaries tagged with the
commit they came from.

## License

[MIT](LICENSE).
