# Lane: p2p

Owns `src/consensus/p2p/*` (submodules `peers`, `disc`, `libp2p`, `gossip`) and
`docs/P2P.md`. Reference: base/base `crates/consensus/{peers,disc,gossip}` (~7k lines of
Rust over `discv5` + `libp2p`), the public discv5 wire spec, the libp2p specs (noise,
yamux, multistream-select, identify, ping, gossipsub v1.1), and the OP Stack rollup-node
p2p spec. Everything is implemented from scratch: no libp2p, no discv5 crate.

The consensus lane owns the rest of `src/consensus/*`; this lane exposes a
`p2p.Service` state machine that consensus wires in (replacing its p2p stub). All sockets
and timers go through `src/utilities/io` so the cluster simulator can drive it.
Crypto (secp256k1, sha256, keccak, AES-GCM/ChaCha20-Poly1305, X25519) comes from
`src/common/crypto` or `std.crypto`; if a primitive has not landed, use `std.crypto`
behind a small interface and switch later.

## Backlog
- [x] `peers`: node records (ENR, EIP-778: RLP, `v4` identity scheme, secp256k1 sig,
  `opstack` key with chain id + version), ENR text form (`enr:` base64url), peer ids
  (libp2p multihash of secp256k1 pubkey, base58), multiaddr encode/decode, boot node
  lists for Base mainnet/sepolia (public, from base/base `boot.rs`), node key load/gen.
  Vectors from EIP-778 + fuzz all decoders.
- [x] `peers`: bounded peer store, peer scoring params (port `score.rs`: topic params
  from block time, thresholds, decay), connection gater (ip/subnet bans, dial limits;
  port `gater.rs`/`gate.rs`).
- [x] `disc`: discv5 wire protocol: packet masking (AES-CTR), header, ordinary /
  WHOAREYOU / handshake packets, session key derivation (ECDH + HKDF), AES-GCM message
  encryption, messages PING/PONG/FINDNODE/NODES/TALKREQ/TALKRESP. Spec test vectors.
- [x] `disc`: Kademlia routing table (bounded k-buckets, 256 log distances), lookup
  iteration, bootstrap, ENR filter on `opstack` chain id, discovery driver state machine
  (port `driver.rs`), DST test with a simulated network of N nodes.
- [x] `libp2p`: multistream-select 1.0, noise XX handshake (X25519, ChaCha20-Poly1305,
  SHA256, libp2p signed static key payload), yamux framing + flow control (bounded
  streams/windows). Interop vectors; fuzz each codec.
- [x] `libp2p`: IO-free connection pipeline (`connection.zig`): multistream -> noise ->
  multistream -> yamux, per-stream meshsub/identify/ping, fuzzed.
- [x] `libp2p`: TCP transport over utilities/io (`transport.zig`, `Transport(IO)`) feeding
  `p2p.Service`; SimIo cluster tests (discovery -> dial -> libp2p -> block delivery,
  partition heal, 16-seed sweep behind `-Dslow-tests`).
- [ ] `libp2p`: interop test against a real go/rust libp2p peer (needs a devnet peer).
- [x] Transport closes with io `shutdown_now`, then `close_now` once the link is idle, so a
  reused descriptor never meets a stale recv (asserted on every new descriptor).
- [ ] io ask (io lane): UDP (`open_socket_udp`, `recvfrom`, `sendto`) so discv5 runs over
  io; then wire `Service.on_datagram`/`pop_datagram` into the transport.
- [x] `libp2p`: yamux go-away: a received go-away closes the connection
  (`remote_go_away`); `close()` sends go-away first and the transport closes the socket
  after it is sent (2 s linger cap). Service disconnects (bans) are graceful.
- [x] ~~`libp2p`: backpressure instead of `buffer_overflow`~~ won't do: only a peer flooding stream negotiation can fill the outbound buffers (the transport flushes after every receive), and closing that peer is the right response.
- [x] `rpc.zig`: the 18 `opp2p_*` admin methods over `Service` for `utilities/rpc.Router` (base/base shapes; untracked fields reported as zero; blockPeer also disconnects).
- [x] `metrics.zig`: base/base `base_node_*` gossip/discovery metrics (peer counts, per-version
  topic peers/mesh/subscribed, connections, block validation, bytes) mirrored from `Stats`
  by `Metrics.update` / `Network.update_metrics`; hot paths stay atomic-free.
- [x] RPC peer info: `Service.on_identified`/`on_ping` (fed by the transport) keep bounded
  per-peer agent, protocol version, 8 protocols, 4 listen addresses, latency (ns, like
  op-node); `opp2p_self` reports base/base's agent `base`, protocol list, local multiaddr.
- [x] Perf: ChaCha20 16-block passes for full 1 KiB chunks (8-block tail): noise seal+open
  729 -> 785 MB/s on M4 Pro. Measured 4/12/32-block passes too: 458/363/740 MB/s.
- [x] `libp2p`: identify and ping protocols; connection manager (bounded inbound/outbound).
- [x] `gossip`: gossipsub v1.1 (hand-written protobuf RPC codec, mesh maintenance,
  heartbeat, IHAVE/IWANT, fanout, message cache, seen cache, peer scoring integration),
  OP Stack message id (sha256 of domain + snappy-decoded payload) [id: block worker].
- [x] `gossip`: router follow-ups: score retention across reconnects (`retain_score`),
  outbound mesh quota (D_out = 2), IWANT retransmission limit.
- [x] `gossip`: IDONTWANT (v1.2): sent to v1.2-capable mesh peers for messages over
  1000 B; received ids are skipped when forwarding (32-id ring per peer).
- [x] `gossip`: peer exchange on PRUNE — won't do: base/base disables it (rule 7); we send
  empty PRUNE peer lists and ignore received ones.
- [x] `gossip`: snappy block-format codec (own implementation, fuzzed round trip),
  unsafe block topics `/optimism/<chain_id>/{0,1,2,3}/blocks` (v1..v4), payload SSZ
  decode (ExecutionPayload v1..v4 envelopes), signature check against the unsafe block
  signer, block validity rules (port `block_validity.rs`: timestamp window, seen hashes
  per height limits, v3/v4 field rules).
- [x] `gossip`: Denim sub-second timestamp check (`validity.check_base_time`, via
  `common/consensus/base_time` and the rollup Denim schedule), before the seen table.
- [x] `gossip`: real Base mainnet block 30000000 (public base/base bench fixture) as a
  block-hash vector through `validity.header_from_payload`.
- [x] `gossip`: EIP-8130 (0x79) transactions decode through `Envelope` in validity
  (malformed ones reject instead of passing undecoded).
- [x] `Service` (`service.zig`): IO-free state machine tying disc + gater + connection
  limits + block gossip; dials every valid discovered record, bans peers under -100 for
  1 h every 15 s (disconnect + discv5 ban), publishes and delivers unsafe blocks.
- [x] `Service` DST: sequencer publishing every 2 s through random TCP resets
  (`reset_ppm` 5000): every node gets every block and reconnects.
- [x] `Service` DST: invalid-block attacker banned by every honest peer (discv5 ban +
  disconnect) while honest gossip continues; crash/restart reconnects and receives
  blocks; 8 nodes with resets behind `-Dslow-tests`.
- [x] Node integration: `options.zig` parses `--p2p.*` with base/base CLI defaults;
  `network.zig` `Network(IO)` builds the ENR, Service, and Transport, seeds bootnodes
  (chain defaults when none given), exposes `publish_block`/`pop_block`/`peer_count`.
  Consensus lane: `p2p.network.Network(IO).init(...)`, `start()`, then call
  `pop_block` each loop; sequencer calls `publish_block`.
- [x] Bootstore: `Network.load_bootstore(contents)` seeds discovery from the stored
  records; `save_bootstore(output)` merges the discovery table and returns JSON for the
  binary to write every 60 s. `--p2p.bootstore`/`--p2p.no-bootstore` parsed. Store
  replaces a node's record only with a higher sequence.
- [x] `--p2p.bootnodes-file`: `options.add_bootnodes_file(contents)` (lines or JSON array).
- [x] Benchmarks: handshake/sec, gossip msgs/sec, allocation-free hot paths
  (`src/consensus/p2p/bench.zig`, numbers in docs/PERF.md).
- [x] Perf: noise transport seal+open 338 -> 710 MB/s with `libp2p/chacha_poly.zig`
  (8 blocks per pass in column layout, keystream 599 -> 2260 MB/s; std Poly1305).
- [x] ~~Perf: Poly1305 2^26-limb vector path~~ won't do: measured std Poly1305 at
  4006 MB/s (64 KiB, M4 Pro); a 4-lane 26-bit version reached only 4314 MB/s because
  LLVM scalarizes the 32x32->64 lane products. ChaCha20 (2260 MB/s) dominates the AEAD,
  so the next AEAD win is there (`p2p/poly1305 std` bench kept).

## Decisions
- Lives under `src/consensus/p2p/` (matches base/base `crates/consensus/*`), owned by this
  lane even though the consensus lane owns the rest of `src/consensus/`.
- secp256k1 comes from `std.crypto` (Keccak-256 ECDSA, ECDH) behind
  `peers/secp256k1.zig` until `common/crypto` lands one. Signing normalizes to low-s;
  verification accepts both halves, like the `enr`/`discv5` crates.
- ENR signing uses std's deterministic nonce, so locally built records differ
  byte-for-byte from geth/rust signers for the same key; only verification is
  vector-tested (EIP-778 record + every public Base boot record).
- Spec test private keys are not committed (AGENTS rule 3); tests derive keys from
  `Prng` or tiny scalars instead.
- Multiaddr supports ip4/ip6/tcp/udp/dns/dns4/dns6/p2p/quic-v1 only; anything else is
  `UnsupportedProtocol`. Empty binary multiaddrs are rejected (no text form).
- Node key files are hex text; library code takes file contents, never paths.
- discv5 spec vectors embed identity secret keys; tests check every packet vector with
  public values only (dest node id unmasks, published read keys open, offline-derived
  pubkeys/ECDH outputs verify), and re-encode each packet byte for byte.
- discv5 `Service` is IO-free: `on_packet`/`tick` in, `pop_outgoing`/`pop_discovered`
  out, randomness from an injected `std.Random`. The DST test drives 16 nodes over a
  seeded in-test UDP network (latency 1-40 ms, 2% loss). It will move onto
  `testing/sim` once that network can carry byte payloads to more than 8 nodes.
- Topic messages (REGTOPIC..TOPICNODES) are not implemented: OP Stack does not use them.
- Routing table: 16 per bucket, 8 replacements, 1024 entries total, evict after 2
  failures, /24 limits 2 per bucket and 10 per table. Lookups: 16 candidates, 3 in
  flight, 48 queries max, distances = target log distance +-1 (geth style).
- WHOAREYOU is only answered when it echoes a pending request's nonce from the same
  endpoint; handshake keys are bound to `(node id, endpoint)`.
- Snappy/protobuf varints accept non-minimal encodings like reference decoders;
  multiaddr/ENR varints stay strict.

- Peer scoring params mirror base/base `score.rs` exactly, including its decay formula
  `(1 - 0.01)^(1/n)`, which shrinks counters to 99% (not 1%) per decay period; op-node
  uses `0.01^(1/n)`. We follow base/base (rule 7); revisit if base/base changes.
- Boot store: FIFO-evicting ring of ENRs (2048), JSON array of `enr:` strings like
  base/base; undecodable entries skipped on load. Library code never opens files.
- Gater: fixed-capacity sets; `peer_redialing = null` means any redial within the dial
  period (1 h) is refused (base/base default); protected peers bypass the redial limit.
  DNS multiaddrs are allowed outbound unresolved, inbound needs an IP.
- `PeerId` zero-fills bytes past `length` so struct equality agrees with `eql`.
- Gossip router: IO-free; peers are slots 0..63 with `u64` bitset peer sets; transport
  pulls framed RPCs via `drain(slot, buffer)` (backpressure for free). Config matches
  base/base (D 8/6/12, Dlazy 6, 500 ms heartbeat, mcache 12/3, seen TTL 65 s, flood
  publish off, anonymous messages). Messages are forwarded only after the app's
  `validate` (accept/reject/ignore). Without a mesh, publish goes to up to D topic
  peers above the publish threshold (no persistent fanout map). One IWANT promise per
  IHAVE (random id), like libp2p. Graylisted peers' RPCs are dropped. Slow peers drop
  their oldest queued message (queue 256, base/base `MAX_OUTBOUND_QUEUE`).
  Retained scores: 64 entries, soonest-expiring replaced. IWANT retransmission limit
  is 1 per peer per message (libp2p default is 3); the D_out swap may displace one of
  the D_score best peers.
- Seen cache: open addressing + backward-shift deletion + insertion FIFO; when full it
  evicts the oldest early (costs a re-validation, never correctness).
- Message cache: FIFO byte arena allocated once (64 MiB default); arena pressure evicts
  the oldest message. Lookup is linear (1024 entries); index it if profiling says so.
- Test time: the 16-node discv5 sim takes ~70 s in Debug, so `zig build test` runs a
  6-node variant (<2 s) and the large one needs `-Dslow-tests` (build option added).

- libp2p (worker): multistream messages <= 1024 B, 16 protocols/role, listener takes
  <= 32 proposals and answers `ls` with `na`. Noise accepts only secp256k1 identity
  keys, both s halves, ignores extensions and any message-1 payload; caller compares
  `Transport.remote_peer` with the expected id. Cacophony XX vector verified locally but
  not committed (contains test private keys). Yamux: comptime stream count (<= 1024),
  256 KiB window per stream, update after 128 KiB read; new streams must use the peer's
  parity and increase; full table or go-away refuses streams with RST; data for unknown
  streams is dropped; protocol errors send go-away on next flush.
- Identify: zero-copy decode, 16 listen addrs, 32 protocols, 4 KiB cap; unsupported
  multiaddrs skipped; protocol version "" (base/base). `check_peer` binds key to the
  noise peer id. Ping: 32 B, every 15 s, 20 s timeout (libp2p defaults).
- Connection limits mirror base/base `ConnectionLimitsConfig`: pending in 5 / out 16,
  established 30, per peer 1.

- Block gossip (worker): message id = sha256(domain || topic_len u64 LE || topic ||
  data)[0..20] with domain 1 + decompressed data, or 0 + raw data when snappy fails or
  declares > 10 MiB (base/base golden vector passes). Withdrawals decoded up to 16 then
  rejected by validity (base/base rejects at decode; same outcome). v byte accepts
  0/1, 27/28, 35..255 like alloy; high-s accepted. EIP-4844 txs rejected; 0x79 txs not
  decoded yet. Seen table: 1000 heights x 5 hashes, lowest height dropped when full.
  Reuses `common/crypto` secp256k1 recovery, `RollupConfig`, header and trie code.
- discv5 bans: 256 node ids; banned nodes are evicted, their packets, handshakes and
  records ignored until expiry; re-banning keeps the later expiry. The Service will ban
  gossip peers scoring under -100 for 1 h every 15 s (base/base `PeerMonitoring`).

- Block gossip handler (`gossip/handler.zig`): heap-allocated so the router's
  message-id hook (now `fn(context, topic, data)`) can use its 10 MiB scratch. Blocks
  are validated synchronously inside `on_rpc`, so valid ones are forwarded before it
  returns. Accepted blocks queue by id (64, oldest dropped) and `pop_block` re-decodes
  from the message cache. Our own published blocks enter the seen-hash table. Topics
  retire on heartbeat once their fork leaves the 60 s window and are never rejoined.

- Service: commands out (dial, disconnect) and calls in; the transport must report every
  dial result (`on_connected` or `on_dial_failed`) so pending limits never leak. Inbound
  is reserved before the handshake (`reserve_inbound`), like libp2p's pending limit.
  Invalid RPC frames disconnect the peer; graylisted frames are dropped silently.

- Transport plan (utilities/io landed, TCP only): `transport.zig` = `fn Transport(comptime
  IO: type)` owning a listener and fixed connection slots, each running the libp2p
  `connection.zig` pipeline, feeding `p2p.Service`. DST uses `SimIo`/`SimWorld`
  (latency, partitions). discv5 needs UDP, which io lacks: datagrams stay behind
  `Service.on_datagram`/`pop_datagram` until the io lane adds UDP; DST delivers them
  in-process meanwhile.

- Connection (worker): yamux Session(16) (4 MiB windows), <= 12 inbound streams, 64
  events (gossip stops at 60), ~24 MiB per connection at 10 MiB frames (one init
  allocation). Handshake timeout 10 s. Ping both ways 15 s; 20 s unanswered closes
  (rust-libp2p only reports). Listener tolerates lazy multistream dialers. One inbound
  meshsub stream per peer (second reset). Identify key mismatch closes. Gossip frame
  slices live until the next receive/tick after all gossip events are popped.

- Transport: one recv + one send in flight per link, 16 KiB socket buffers, timer 50 ms
  drives `Service.tick`. Gossip is drained from the router only when a full frame fits
  the connection's send queue (2 frames), so the router never drops a block. Closing uses
  `close_now` and quarantines the link until in-flight completions return (noise makes a
  stale read on a reused fd a liveness, not safety, issue). Simultaneous dials: both
  sides keep the connection dialed by the smaller peer id. Time is `now_realtime_ns`
  (block validity needs wall time).

- Redial: discv5 now republishes known nodes from every lookup (base/base forwards every
  lookup result), and the service's gater default is base/base's CLI default of 500
  redials per 60 min (`peer_redialing = null` in the bare gater stays the library
  default). Without both, a dropped peer was never reconnected.

- Options: base/base defaults (`ban.peers` false, `topic-scoring` false, `redial` 500 per
  60 min, peers.hi 30). `Service`/handler library defaults keep topic scoring on, which
  the handler tests rely on; the options layer sets base/base's CLI value.

## Log
- 2026-11-05: lane created by coordinator.
- 2026-11-05: `peers` identity: ENR (EIP-778 v4, opstack key, text form), peer ids,
  base58, varint, ip text, multiaddr, enode, Base boot nodes, node keys; all fuzzed.
- 2026-11-05: `disc` wire: packet codec, handshake crypto, messages; all 4 spec packet
  vectors + KDF + id-signature vectors pass.
- 2026-11-05: `gossip` snappy block codec and gossipsub protobuf RPC codec (worker).
- 2026-11-05: `disc` routing table, session cache, lookups, discovery service; 16-node
  seeded simulation converges through one boot node.
- 2026-11-05: `peers` scoring params, boot store, connection gater.
- 2026-11-05: `gossip` seen cache, message cache, peer-score counters, and gossipsub
  router; 20-node seeded cluster delivers every message deterministically, attacker
  publishing invalid blocks is scored negative and pruned, IHAVE/IWANT path tested.
- 2026-11-05: shrank discv5 cluster test (73 s -> <2 s); large run behind -Dslow-tests.
- 2026-11-05: router follow-ups: score retention, outbound quota, IWANT resend limit.
- 2026-11-05: `libp2p` multistream-select, noise XX, yamux (worker, 736304d..eb8d70c).
- 2026-11-05: `libp2p` identify, ping, connection limits.
- 2026-11-05: p2p benchmarks (handshake, transport, snappy, rpc, seen, router).
- 2026-11-05: `gossip` SSZ payloads v1-v4, block topics/ids/envelopes, validity (worker,
  06d1ae2..8e11d37).
- 2026-11-05: `disc` node bans.
- 2026-11-05: `gossip` block handler (validate before forward, publish, topic retirement).
- 2026-11-05: `gossip` v1.2 IDONTWANT.
- 2026-11-05: `Service` orchestrator with score bans and end-to-end block test.
- 2026-11-05: vectorized ChaCha20 for noise (2.1x transport throughput).
- 2026-11-05: libp2p connection pipeline (worker, 1624507).
- 2026-11-05: TCP transport over utilities/io; SimIo cluster gossips blocks end to end.
- 2026-11-05: redial from lookups; gossip survives random connection resets in DST.
- 2026-11-05: DST attacker/crash/8-node scenarios.
- 2026-11-05: `--p2p.*` options and embeddable `Network(IO)`.
- 2026-11-05: yamux go-away handling and graceful disconnects.
- 2026-11-05: bootstore persistence through `Network`.
- 2026-11-05: bootnodes file parsing.
- 2026-11-05: opp2p admin RPC; backpressure closed as won't-do.
- 2026-11-05: transport uses io shutdown_now before close.
- 2026-11-05: Poly1305 vector path measured (+8%) and dropped; std kept.
- 2026-11-05: p2p Prometheus metrics.
- 2026-11-05: RPC peer info from identify and ping.
- 2026-11-05: ChaCha20 16-block passes (+8% seal+open).
- 2026-11-05: Denim BaseTime schedule check in block gossip validity.
- 2026-11-05: real Base mainnet block-hash vector.
- 2026-11-05: block validity decodes EIP-8130 transactions.
