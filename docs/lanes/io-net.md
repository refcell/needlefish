# Lane: io-net

Owns `src/utilities/*`. This lane unblocks everyone: land the IO interface early.

## Backlog
- [x] `io`: completion-based IO interface (TigerBeetle-style): `accept/connect/recv/send/read/write/fsync/timeout/close`, callbacks with user context, `run_for_ns`/`tick`. Backends: io_uring (Linux, own ring setup via std.os.linux), kqueue (macOS), and `SimIo` (deterministic: simulated time, network with latency/drop/reorder/partition, disk with faults) seeded by `testing.Prng`. Same API, chosen at comptime.
- [x] `time`: monotonic + realtime via IO; simulated clock for DST.
- [x] `json`: fast zero-alloc JSON tokenizer/writer for JSON-RPC (hex quantities, 0x data) — fuzzed.
- [x] `http`: HTTP/1.1 server + client on the IO interface (keep-alive, pipelining, bounded buffers), fuzzed parser.
- [x] `rpc`: JSON-RPC 2.0 server framework (method table, batch requests, typed params/results), client.
- [x] `jwt`: HS256 JWT create/verify for Engine API auth (HMAC-SHA256), `iat` window.
- [x] `ws`: WebSocket server/client (subscriptions, flashblocks feed later).
- [x] `rpc.ws`: JSON-RPC over WebSocket (`WsClient` with id-matched calls in flight and
  `eth_subscription` notifications; `serve_message`/`write_notification` for servers).
- [x] `cli`: flag parsing (zero-alloc), env fallback; `log`: structured, leveled, fixed messages; `metrics`: Prometheus text endpoint, counters/gauges/histograms with static registry.
- [x] `ring-buffer`, `retry`/backoff (deterministic under sim), `health` endpoint.
- [x] Linux CI coverage for io_uring (`just test-linux`).
- [x] `io`: `cancel` operation (IORING_OP_ASYNC_CANCEL / kqueue EV_DELETE / SimIo) so a
  server can stop with an accept in flight and a client can abandon a request on timeout.
- [x] `http`: per-connection idle/read timeouts on the server; request timeout on client.
- [x] `trusted_proxy`: client IP via trusted forwarding proxies (base/base `trusted-proxy`).
- [x] `http`: expose the peer address to handlers (`ResponseBuilder.peer`, from a sync
  `peer_address(fd)` on every IO backend) so `trusted_proxy` can be wired in.
- [x] `balance_monitor`: periodic balance polling over `rpc.Client` with `tick()`.
- [x] `l1_head`: shared L1 head helpers for proof services (`json.find_path` added for it).
- [x] `upgrade_signal` core: packed versions, `ProtocolVersions` ABI (strict), upgrade IDs,
  default contracts, IO `Reader` pinned to one L1 block. Applying schedules (modes, chain spec
  / rollup config) is left to execution/consensus, which own those types.
- [x] `upgrade_signal` observer: live polling on the tag interval, change detection, metrics
  (`base_upgrade_signal_*`). Startup retry policy is the applying lane's (use `retry`).
- [x] io UDP completions: `recvfrom` -> `Datagram{length, from}` and `sendto(buffer, address)`
  ops on io_uring (recvmsg/sendmsg), kqueue (non-blocking retry) and SimIo (over the p2p
  lane's polled datagram pool, with `World.datagram_stats`); polled `*_now` calls stay.

## Decisions
- base/base `crates/utilities` coverage: `tx-manager` lives in the batcher lane
  (`src/batcher/txmgr`); `runtime` (tokio spawner/clock/cancellation, deterministic runtime)
  is covered by `io` + `time` + `SimIo`; `reth-cli` is reth node glue (execution lane);
  `test-utils` maps to `src/testing`. `optimism-rpc` is skipped (see log).
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
- WebSocket: one frame engine (`ws/stream.zig`) shared by client and server; owners embed
  it and get hooks via `@fieldParentPtr`. Server broadcast drops consumers whose send buffer
  is full (`SlowConsumer`) instead of blocking the feed. Protocol violations fail without a
  close frame; handshake rejections flush a 400 first.
- Timeouts are driven by the owner calling `tick()` from its loop; expired sockets are
  `shutdown_now`-ed so their pending op completes and normal teardown runs. No timers are
  left in flight, which avoids needing `cancel` for teardown.
- `cancel(target)` is synchronous with no completion of its own; the target's callback
  runs exactly once (Canceled or its real result). io_uring uses ASYNC_CANCEL with
  user_data 0 (CQE ignored) and a deferred queue when the SQ is full; kqueue unlinks queued
  ops or EV_DELETEs parked kevents synchronously; SimIo flags the completion.
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
- 2026-11-05: ws: shared Stream engine, Server(IO, Context) with connection ids, broadcast, slow-consumer drop, 400 on non-upgrade; client refactored onto Stream. Tests: client<->server on SimIo (13-byte segments) and kqueue.
- 2026-11-05: http: server idle/io timeouts and client request timeout via tick() + shutdown_now; SimIo tests.
- 2026-11-05: test-linux (io_uring, Docker): 1040/1047 pass incl. ws/shutdown; fixed a timing-flaky file test (waits for each callback instead of a fixed 1 ms).
- 2026-11-05: `-Drequire-io-uring=true` (CI ubuntu + `just test-linux`) turns io_uring-unavailable skips into failures; shared `io.init_for_test()`. test-linux green with it.
- 2026-11-05: io: `cancel` on io_uring/kqueue/SimIo; tests for timeout/accept/recv cancel and completion reuse, green on io_uring in Docker.
- 2026-11-05: http/ws servers: `stop()` cancels the in-flight accept and closes the listener from its callback (no io_uring accept outliving the server), shuts down idle keep-alive connections. ws `deinit` asserts `stopped()`; http `deinit` stays lenient because execution/node deinits without stopping (it tears the IO down together).
- 2026-11-05: trusted_proxy: CIDR matching (v4/v6, mapped v4), right-to-left XFF scan across header occurrences, peer fallback; fuzzed.
- 2026-11-05: `io.peer_address(fd)` (getpeername; SimIo records host+ephemeral port per side); http handlers read `response.peer`; resolve with `trusted_proxy.Config.client_ip(response.peer, request.headers.slice())`.
- 2026-11-05: balance_monitor: own rpc.Client + Ticker, immediate first poll, publish every success (`updates` as watch version), skip polls while a read is in flight; `Ticker.stop` now cancels its pending timeout.
- 2026-11-05: json.find_path (raw value at an object key path); l1_head: `cap_head` + `Calculator(IO)` (outputAtBlock -> finalized -> capped block hash), SimIo-tested against a fake node.
- 2026-11-05: upgrade_signal core (version, contract ABI with comptime keccak selectors, Reader: block by tag -> eth_call x2 at blockHash); decode fails closed (canonical offset, length <= 256, zero-padded uint64).
- 2026-11-05: upgrade_signal Observer: immediate + tag-interval single-attempt polls, keeps last schedule on failure, on_update on first/changed, per-upgrade labeled metrics.
- 2026-11-05: http: close-delimited responses (no length, no chunking) were parsed as empty bodies; now `.incomplete` until EOF, finished by `parse_response_at_eof` from the client (keep_alive=false). optimism-rpc skipped: thin typed wrappers over `rpc.Client`, call sites live in consensus/batcher.
- 2026-11-05: rpc.ws: WsClient (bounded pending ids, notifications raw, pending fail on close), server adapter over ws.Server + Router; rpc.client gains parse_response_any and module-level build_request.
- 2026-11-05 (p2p lane, additive): minimal UDP for discv5: `open_socket_udp`, `bind_udp`, non-blocking `recvfrom_now`/`sendto_now` (polled, no completion op) on kqueue, io_uring (plain syscalls), and SimIo (world datagram queue with latency, partitions, `datagram_loss_ppm`, purge on close); `udp_test.zig`. A completion-based `recvfrom` can replace polling later.
- 2026-11-05: io UDP completions on top of the p2p lane's polled path (kept for its transport). io_uring opens UDP sockets blocking (the polled path passes MSG_DONTWAIT). SimIo sendto: unbound socket SocketNotConnected, oversize MessageTooBig, full in-flight table SystemResources; recvfrom on an unbound socket fails fast with SocketNotConnected (the OS would block forever). Fixed sim `bind_udp` dropping the port of a 0.0.0.0:port bind.
