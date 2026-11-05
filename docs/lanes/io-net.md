# Lane: io-net

Owns `src/utilities/*`. This lane unblocks everyone: land the IO interface early.

## Backlog
- [ ] `io`: completion-based IO interface (TigerBeetle-style): `accept/connect/recv/send/read/write/fsync/timeout/close`, callbacks with user context, `run_for_ns`/`tick`. Backends: io_uring (Linux, own ring setup via std.os.linux), kqueue (macOS), and `SimIo` (deterministic: simulated time, network with latency/drop/reorder/partition, disk with faults) seeded by `testing.Prng`. Same API, chosen at comptime.
- [ ] `time`: monotonic + realtime via IO; simulated clock for DST.
- [ ] `json`: fast zero-alloc JSON tokenizer/writer for JSON-RPC (hex quantities, 0x data) — fuzzed.
- [ ] `http`: HTTP/1.1 server + client on the IO interface (keep-alive, pipelining, bounded buffers), fuzzed parser.
- [ ] `rpc`: JSON-RPC 2.0 server framework (method table, batch requests, typed params/results), client.
- [ ] `jwt`: HS256 JWT create/verify for Engine API auth (HMAC-SHA256), `iat` window.
- [ ] `ws`: WebSocket server/client (subscriptions, flashblocks feed later).
- [ ] `cli`: flag parsing (zero-alloc), env fallback; `log`: structured, leveled, fixed messages; `metrics`: Prometheus text endpoint, counters/gauges/histograms with static registry.
- [ ] `ring-buffer`, `retry`/backoff (deterministic under sim), `health` endpoint.
- [ ] Linux CI coverage for io_uring (`just test-linux`).

## Decisions

## Log
