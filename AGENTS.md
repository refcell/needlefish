# AGENTS.md — needlefish

needlefish is a from-scratch Zig rewrite of the public [base/base](https://github.com/base/base)
repository (the Base L2 node stack: execution, consensus, batcher, proofs, tooling).
Zero dependencies, TigerStyle, deterministic simulation testing (DST), heavy fuzzing,
io_uring, and extreme performance.

Read this whole file before you change anything. These rules are not optional.

## Hard rules

1. **Push straight to `main`.** No branches on the remote, no pull requests.
   Your local worktree may sit on any local branch, but you publish with:
   ```sh
   git fetch origin main && git rebase origin/main
   zig build test && just tidy        # must pass
   git push origin HEAD:main
   ```
   If the push is rejected, fetch, rebase, re-test, push again. Push often: every
   coherent, green step (at least every hour of work). Never force-push `main`.
2. **Public content only.** Only rewrite what is in the public base/base repository
   (reference clone: `~/.cache/needlefish/base-ref`, refresh with
   `git -C ~/.cache/needlefish/base-ref pull`), public Ethereum/OP Stack specs, and
   public test vectors. Never commit anything from internal or company systems,
   internal hostnames, internal tickets, Slack, or private repositories.
3. **No secrets, no personal data.** Never commit private keys (except the
   publicly-known dev mnemonic `test test test test test test test test test test test junk`
   accounts used by every Ethereum devnet), tokens, `.env` files, API keys, home
   directory paths, usernames, or email addresses. `just tidy` scans for these; it is
   a backstop, not a license. Devnet secrets (JWT) are generated at runtime into
   `.devnet/` which is git-ignored.
4. **Zero dependencies.** `build.zig.zon` `.dependencies` stays empty. Only the Zig
   standard library. No C libraries, no linking libc unless strictly needed for a
   syscall the std lacks. Implement it yourself.
5. **Zig 0.17.1 exactly.** APIs changed a lot (`std.Io`, `std.process.Init`, new
   `std.Io.Writer`/`Reader`, unmanaged `ArrayList`). When unsure, read the std source in
   `$(zig env | grep lib_dir)` — do not guess from memory of older Zig versions.
6. **Main stays green.** `zig build test` and `just tidy` must pass before every push.
   If main is broken by someone else, fixing it is your top priority (smallest fix).
7. **Never stop, never block.** You are autonomous. When a decision is ambiguous, pick
   the option closest to base/base behavior and TigerStyle, write the decision in your
   lane file, and continue. Never ask the human; they are away. If a task is too big,
   split it and do the first piece. If blocked on another lane, build a minimal
   version of what you need inside your own lane (or stub behind an interface) and
   keep going.
8. **Own your lane.** Each lane owns directories listed in `docs/lanes/<lane>.md`.
   Edit other lanes' files only for tiny integration fixes (build breaks, a missing
   `pub`). Shared files (`build.zig`, `src/base.zig`, `src/*/root.zig`, `Justfile`,
   `README.md`) take small, additive edits; resolve rebase conflicts by keeping both.
9. **Never write `.github/workflows/`** — the push token lacks workflow scope and the push is
   rejected. CI lives in `etc/ci/ci.yml`.
10. **No flashblocks. Native 200 ms blocks.** The project owner decided needlefish does not
   implement flashblocks (no flashblock stream, websocket feed, or pending-flashblock RPC).
   L2 blocks are full blocks built by a regular block builder at Base's native subsecond
   cadence: 200 ms (`SubsecondBlocks`, active from Denim), sealed 150 ms into each slot.
   The devnet runs 200 ms L2 blocks. Do not add flashblocks code; delete it where found.

## Style: TigerStyle (see docs/TIGER_STYLE.md)

- Safety, then performance, then developer experience.
- Assert preconditions, postconditions, invariants. Aim for ≥ 2 asserts per function.
  Assert both the positive and negative space. Use `comptime` asserts for sizes/layout.
- Static allocation: allocate at startup from configured limits, then no allocation
  on hot paths. Every queue, buffer, and loop has an explicit upper bound.
- No recursion (bounded iteration with explicit stacks instead).
- Functions ≤ 70 lines. Lines ≤ 100 columns. `zig fmt` always.
- Explicitly-sized integer types (`u64`, `u32`), not `usize`, except for indexing.
- Names: `snake_case` functions/vars, `PascalCase` types, units last
  (`timeout_ms`, `size_bytes`). No abbreviations.
- Errors are handled, never ignored. `catch unreachable` only with a proof comment.
- All I/O goes through `utilities.io` so the deterministic simulator can replace it.
  Never read the wall clock, sockets, files, or randomness directly in library code.

## Testing

- `zig build test` — every module has unit tests next to the code.
- **Fuzz**: every parser/decoder/state machine gets a `std.testing.fuzz` test and a
  deterministic seeded fuzz (via `base.testing.Prng`) that runs in normal `zig build test`.
  Long fuzz: `zig build test --fuzz -Doptimize=ReleaseSafe`.
- **DST**: components are written as state machines over an injected IO/time
  interface. `zig build sim -- <seed>` runs the full cluster in simulation; same seed,
  same execution. A failing seed is a bug report.
- **Differential/vectors**: EVM, RLP, trie, and tx tests run against public Ethereum
  test vectors (fetched by `just vectors` into `.cache/`, git-ignored; only small
  curated vectors are committed).
- Linux io_uring tests: `just test-linux` runs the suite in a Docker Linux container
  (`--security-opt seccomp=unconfined` so io_uring is allowed).

## Layout (mirrors base/base, Zig conventions)

```
bin/<name>/main.zig        binaries (base, node, consensus, batcher, ...)
src/base.zig               root of the single `base` module
src/common/                shared protocol types: primitives, rlp, crypto, consensus, genesis, chains
src/utilities/             io (io_uring/kqueue/sim), time, net, http, json, rpc, jwt, metrics, cli, log
src/execution/             evm, trie, db, chainspec, txpool, payload, engine, rpc, node
src/consensus/             protocol, derive, engine driver, sequencer, sources, p2p, rpc, service
src/batcher/               channel/frame encoding, compression, submission service
src/proof/                 fault-proof program, preimage oracle, mpt, proposer, challenger
src/testing/               prng, simulator, fuzz helpers, bench
etc/                       devnet configs, scripts, docker
docs/                      architecture, style, lanes
```

Each sub-module is a directory with `root.zig`, e.g. `src/common/rlp/root.zig`, and is
re-exported from its group's `root.zig`. Cross-module imports use relative paths.

## Commits

- Conventional, imperative subject: `feat(evm): add CALL family gas`.
- Small and frequent. Never commit generated `zig-out/`, `.zig-cache/`, `.devnet/`,
  `.cache/`, `.pi/`, `.claude/`.
- Commits must be GPG-signed (global config already does this; never bypass hooks).
