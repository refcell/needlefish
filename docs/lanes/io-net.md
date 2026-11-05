# Lane: io-net

Owns `src/utilities/*`. This lane unblocks everyone: land the IO interface early.

## Backlog
- [x] `io`: completion-based IO interface (TigerBeetle-style): `accept/connect/recv/send/read/write/fsync/timeout/close`, callbacks with user context, `run_for_ns`/`tick`. Backends: io_uring (Linux, own ring setup via std.os.linux), kqueue (macOS), and `SimIo` (deterministic: simulated time, network with latency/drop/reorder/partition, disk with faults) seeded by `testing.Prng`. Same API, chosen at comptime.
- [x] `time`: monotonic + realtime via IO; simulated clock for DST.
- [x] `json`: fast zero-alloc JSON tokenizer/writer for JSON-RPC (hex quantities, 0x data) — fuzzed.
- [x] `http`: HTTP/1.1 server + client on the IO interface (keep-alive, pipelining, bounded buffers), fuzzed parser.
- [x] `rpc`: JSON-RPC 2.0 server framework (method table, batch requests, typed params/results), client.
- [x] `jwt`: HS256 JWT create/verify for Engine API auth (HMAC-SHA256), `iat` window.
- [ ] `ws`: WebSocket server/client (subscriptions, flashblocks feed later).
- [x] `cli`: flag parsing (zero-alloc), env fallback; `log`: structured, leveled, fixed messages; `metrics`: Prometheus text endpoint, counters/gauges/histograms with static registry.
- [x] `ring-buffer`, `retry`/backoff (deterministic under sim), `health` endpoint.
- [ ] Linux CI coverage for io_uring (`just test-linux`).
- [ ] `io`: `cancel` operation (IORING_OP_ASYNC_CANCEL / kqueue EV_DELETE / SimIo) so a
  server can stop with an accept in flight and a client can abandon a request on timeout.
- [ ] `http`: per-connection idle/read timeouts on the server; request timeout on client.

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
- HTTP server: fixed connection pool, one op in flight per connection, synchronous
  handler writing into `ResponseBuilder` (body first, head prepended, no copy). Client:
  one keep-alive connection, one request in flight, retries once only when a reused
  connection dies before any response byte (never resends after a partial response).
- JSON-RPC: `Router(Ctx, &methods)` dispatches by comptime table into a fixed writer; a
  failed handler's partial output is rewound and replaced by an error object. Handlers use
  `call.params` (positional cursor: quantity/data/fixed/string/boolean/raw) and
  `call.writer`; `call.fail(code, message)` for typed errors. Batches capped at 100.
  `rpc.Client(IO)` sends one call at a time with optional bearer auth (JWT).
- CLI: a spec struct is the flag table (`field_name` -> `--field-name`, env
  `<PREFIX>FIELD_NAME`); precedence flag > env > default; no default and not optional means
  required. Environment is injected (`cli.Env.from_map(init.environ_map)`).
- Logging: fixed messages + typed fields, logfmt or JSON, one sink call per line,
  timestamps from an injected clock (simulated time under DST).
- kqueue disk ops run synchronously (no async file IO on macOS); macOS is a dev platform.
- io_uring: absolute monotonic timeouts; SQ overflow goes to a retry queue; setup denial
  (EPERM/EACCES/ENOSYS) returns `error.IoUringUnavailable` and OS tests skip.
  `just test-linux` adds `--security-opt label=disable` (SELinux on Docker VMs blocks
  io_uring_setup with EACCES).

## Log
- 2026-11-05: io: common API, SimIo (net + disk + faults), kqueue, io_uring backends;
  SimIo echo/partition/crash/timeout tests + seeded and std.testing fuzz; Linux green.
- 2026-11-05: time: Clock(IO) with monotonic clamp, Deadline, drift-free Ticker, ManualClock.
- 2026-11-05: json: validating zero-alloc Scanner (skip, unescape), Writer, QUANTITY/DATA hex; fuzzed.
- 2026-11-05: http: incremental HTTP/1.1 parser (pipelining, in-place chunked, smuggling checks); fuzzed.
- 2026-11-05: http: Server(IO, Ctx, handler) and Client(IO) with keep-alive and pipelining; SimIo + kqueue + io_uring tests.
- 2026-11-05: rpc: JSON-RPC 2.0 Router (batches, notifications, typed params, error rewind) and Client; fuzzed.
- 2026-11-05: jwt: HS256 create/verify, +-60s iat window, alg-none rejection, hex secret; fuzzed.
- 2026-11-05: metrics: atomic Counter/Gauge/Histogram, static Registry, Prometheus text. log: leveled logfmt/JSON Logger with fixed messages, typed fields, injected sink and clock.
- 2026-11-05: cli: spec-struct flags with env fallback, required/optional, help text; fuzzed.
- 2026-11-05: ring_buffer (comptime capacity, asserted ordering, binary-search first_after), retry (base/base defaults, seeded SplitMix64 jitter), health (GET / liveness, GET /healthz version).
- 2026-11-05: ws: RFC 6455 frame codec (in-place unmask, minimal-length/control/mask checks), accept key, close parsing; fuzzed. Next: ws client/server on IO.
- 2026-11-05: io: `shutdown_now(fd)` on all backends: wakes pending recvs with 0 and sends FIN, so components with concurrent recv+send can tear down before `close_now` without fd reuse races.
- 2026-11-05: ws: Client(IO, Context) with concurrent recv/send, ping auto-reply, fragment reassembly, close handshake, shutdown-based teardown; SimIo tests with 7-byte segments. Next: ws server.
