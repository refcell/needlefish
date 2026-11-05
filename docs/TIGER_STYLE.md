# TigerStyle in needlefish

Our coding style, in our own words, after the TigerBeetle approach. Design goals in
order: **safety, performance, developer experience**.

## Safety

- **Assertions everywhere.** Assert arguments, return values, and invariants. Pair
  assertions: check data before writing it and after reading it. Assert what must
  never happen as well as what must. A crashed node is better than a corrupted one.
- **Compile-time assertions** for struct sizes, alignment, and constant relationships.
- **Bounded everything.** Every loop has a known maximum iteration count; every queue
  and buffer has a fixed capacity set from config at startup. Hitting a bound is an
  explicit, handled condition.
- **No recursion.** Use explicit, bounded stacks (EVM call depth, trie walks, RLP).
- **Static memory.** Allocate everything at startup. After init, hot paths do not
  allocate. Pass allocators explicitly; prefer fixed pools and ring buffers.
- **Simple control flow.** Keep branching shallow; push `if`s up and `for`s down.
  Handle every error. No hidden allocation, no hidden I/O.
- **Smallest scope** for variables. Compute values right before use.
- **Explicit types.** Use sized integers (`u64`, `u32`, `u256`). Avoid `usize` except
  for indexing and lengths of in-memory slices.
- **Function size ≤ 70 lines**, line length ≤ 100 columns.

## Performance

- Think about performance at design time with back-of-envelope numbers for network,
  disk, memory, and CPU — in that order of cost.
- Batch work. Amortize syscalls (io_uring submission batching), cache misses, and
  hashing. Avoid copies; parse in place.
- Separate control plane from data plane. Hot loops are branch-light and
  allocation-free. Use SIMD (`@Vector`) where it clearly wins.
- Benchmarks live in `src/testing/bench_main.zig`. Claim a speedup only with numbers.

## Determinism and testing

- All I/O (network, disk, time, randomness) flows through injected interfaces in
  `src/utilities/io` so the simulator can replace them. Library code never touches
  the OS directly.
- Components are state machines driven by events: `tick()`, completions, messages.
- The simulator (`zig build sim -- <seed>`) runs real component code on simulated
  network/disk/time with fault injection (latency, reorder, drop, partition, crash,
  restart, disk faults). Every run reproduces from its seed.
- Every decoder, parser, and state transition is fuzzed.

## Naming and docs

- `snake_case` functions and variables, `PascalCase` types, `SCREAMING` never.
- Units and qualifiers last, most significant first: `latency_ms_max`.
- No abbreviations except well-known protocol terms (`rlp`, `evm`, `rpc`, `tx`).
- Comments explain *why*. Every file starts with a `//!` doc comment.
