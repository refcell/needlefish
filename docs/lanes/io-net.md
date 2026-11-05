# Lane: io-net

Owns `src/utilities/*`. This lane unblocks everyone: land the IO interface early.

## Backlog
- [x] `io`: completion-based IO interface (TigerBeetle-style): `accept/connect/recv/send/read/write/fsync/timeout/close`, callbacks with user context, `run_for_ns`/`tick`. Backends: io_uring (Linux, own ring setup via std.os.linux), kqueue (macOS), and `SimIo` (deterministic: simulated time, network with latency/drop/reorder/partition, disk with faults) seeded by `testing.Prng`. Same API, chosen at comptime.
- [x] `time`: monotonic + realtime via IO; simulated clock for DST.
- [ ] `json`: fast zero-alloc JSON tokenizer/writer for JSON-RPC (hex quantities, 0x data) — fuzzed.
- [ ] `http`: HTTP/1.1 server + client on the IO interface (keep-alive, pipelining, bounded buffers), fuzzed parser.
- [ ] `rpc`: JSON-RPC 2.0 server framework (method table, batch requests, typed params/results), client.
- [ ] `jwt`: HS256 JWT create/verify for Engine API auth (HMAC-SHA256), `iat` window.
- [ ] `ws`: WebSocket server/client (subscriptions, flashblocks feed later).
- [ ] `cli`: flag parsing (zero-alloc), env fallback; `log`: structured, leveled, fixed messages; `metrics`: Prometheus text endpoint, counters/gauges/histograms with static registry.
- [ ] `ring-buffer`, `retry`/backoff (deterministic under sim), `health` endpoint.
- [ ] Linux CI coverage for io_uring (`just test-linux`).

## Decisions
- IO API (`src/utilities/io`): caller-owned `IO.Completion` (init with `.{}`), typed calls
  `io.op(*Ctx, ctx, callback, &completion, args...)`, callback
  `fn (ctx: *Ctx, c: *IO.Completion, result: io.ResultType(IO.Fd, .op)) void`. Callbacks run
  only from `tick()`/`run_for_ns()`, never inline. Components take `comptime IO: type`;
  use `io.IO` in production and `io.SimIo` in DST. Setup calls are synchronous:
  `open_socket_tcp`, `listen` (returns bound address), `open_file`, `close_now`.
  Clocks: `now_monotonic_ns`, `now_realtime_ns`.
- SimIo: one `SimWorld` (seed, time, network, faults) shared by many `SimIo` nodes, each
  with its own host address, fd table, and in-memory disk (current + durable image;
  `crash()` drops unsynced data). Stream model is TCP-like: per-direction order, bounded
  receive ring as flow control, per-segment latency, partitions stall, resets surface as
  `ConnectionResetByPeer`. Packet drop is modeled as delay (TCP retransmits) not loss.
- kqueue disk ops run synchronously (no async file IO on macOS); macOS is a dev platform.
- io_uring: absolute monotonic timeouts; SQ overflow goes to a retry queue; setup denial
  (EPERM/EACCES/ENOSYS) returns `error.IoUringUnavailable` and OS tests skip.
  `just test-linux` adds `--security-opt label=disable` (SELinux on Docker VMs blocks
  io_uring_setup with EACCES).

## Log
- 2026-11-05: io: common API, SimIo (net + disk + faults), kqueue, io_uring backends;
  SimIo echo/partition/crash/timeout tests + seeded and std.testing fuzz; Linux green.
- 2026-11-05: time: Clock(IO) with monotonic clamp, Deadline, drift-free Ticker, ManualClock.
