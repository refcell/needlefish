# needlefish

Base, the Ethereum L2, rewritten from scratch in Zig.

- **Zero dependencies.** Only the Zig standard library.
- **TigerStyle.** Assertions everywhere, static allocation, bounded everything.
- **Deterministic simulation testing.** The whole stack runs on simulated network,
  disk, and time from a single seed: `just sim <seed>`.
- **Fuzzed.** Every decoder, parser, and state machine.
- **io_uring** on Linux, kqueue on macOS.

A rewrite of the public [base/base](https://github.com/base/base) repository, laid out
the same way (`bin/`, `src/{common,utilities,execution,consensus,batcher,proof}`).

## Quick start

```sh
# Zig 0.17.1
just build      # build all binaries
just test       # unit tests
just sim 42     # deterministic simulation, seed 42
just devnet up  # local all-Zig devnet (L1, L2 sequencer, batcher, verifier)
```

See [AGENTS.md](AGENTS.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/TIGER_STYLE.md](docs/TIGER_STYLE.md), and [docs/lanes](docs/lanes).

## License

MIT
