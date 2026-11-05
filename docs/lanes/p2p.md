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
  Skipped for now (coordinator, 2026-11-05): no external peer is available; the
  loopback, in-process, and devnet interop tests cover our own stack end to end.
- [x] Bounded memory under gossip floods: an authenticated peer floods decodable junk
  publishes (8 per 10 ms) on the live block topic while 200 ms blocks flow, with topic
  scoring off (the production default, so junk costs no score) and consensus popping
  only once a second. Found: accepted blocks lived only in the router's mcache, so
  junk cycling through its FIFO evicted unpopped accepted blocks and `pop_block`
  silently skipped them. Fix: accepted blocks are copied (compressed) into their own
  FIFO store (`handler.Config.accepted_bytes`, default 32 MiB, 64 entries) that only
  signature-checked blocks enter; new `accepted_evicted` stat. Tests: the flood DST
  (`transport_test`, failed before the fix) and a slow-consumer unit test
  (`handler_test`: oldest dropped, the rest in order).
- [x] Gossip control-message flood (IHAVE/IWANT/IDONTWANT/GRAFT/PRUNE): every IWANT and
  IDONTWANT id was a linear scan of the 1024-entry cache or delivery log, so one
  hostile 5000-id RPC (170 KB) cost 3.8 ms of CPU (~45 MB/s from one peer pins a core).
  Fix: per-peer, per-heartbeat id budgets (`iwant_ids_max`, `idontwant_ids_max` = 256;
  honest peers ask only for ids we advertised, <= 64 per heartbeat), excess counted in
  `stats.control_ids_ignored`; now 53 us per hostile RPC (decode). IHAVE was already
  capped (10/heartbeat, 64 requested ids), GRAFT-in-backoff penalized, IWANT
  retransmission limited to once per peer. Router DST: an attacker sends 100 hostile
  RPCs while the victim's messages reach an honest mesh-less peer only via IHAVE/IWANT;
  all delivered, budgets hold, attacker sinks below the gossip threshold. Negative
  control: unlimited budgets fail it.
- [x] Bound connection memory when one peer opens many yamux streams. Memory was already
  static (16 streams x 256 KiB windows, buffers from `init`), inbound capped at 12 so
  outbound slots stay free, one inbound meshsub stream per peer. Gap found: a stream
  that never finishes multistream negotiation held its inbound slot forever. Fix:
  inbound streams not negotiated within `stream_negotiation_timeout_ns` (10 s,
  rust-libp2p's substream upgrade timeout) are reset (`stream_negotiation_timeouts`).
  Test (`connection_test`): through the real noise session a peer opens 40 stalled
  streams, waits out the timeout, then churns 2000 SYN+RST pairs and duplicate meshsub
  streams; inbound stays <= 12, gossip_in <= 1, gossip flows both ways throughout.
  Negative control: a 1000 s timeout fails it.
- [x] Scoring parity: `peers/score.zig` already mirrors base/base `score.rs` formula for
  formula (thresholds, topic and peer params, `score_decay`); covered by its tests.
- [x] Req/resp sync at 5 blocks/s: not applicable; base/base has no p2p req/resp
  (its `gossip/src/rpc` is the admin RPC). Decision below unchanged.
- [x] Fuzz: hostile bytes on a live, authenticated connection.
  Connection level (`connection_test.zig`): an established pair is snapshotted (struct +
  backing memory + the dialer's noise transport) and rewound per input; the dialer seals
  hostile plaintext with its real keys: random bytes, random yamux headers/flags/ids/
  lengths, and fresh SYN streams negotiating meshsub/ping/identify followed by huge,
  truncated, or junk gossipsub frames. Seeded (256 inputs; both closes and survivals occur,
  junk reaches the gossip layer) plus `fuzz.run_bytes`. Invariant: every byte is consumed
  or the connection closes with a reason; state stays established-xor-closed.
  Network level (`transport_test.zig`): in a 4-node cluster an authenticated attacker sends
  junk RPC frames every 100 ms and wrong-signer blocks every 500 ms for 12 s; honest nodes
  get every honest block, keep honest links, disconnect it (`invalid_rpcs`), and reject
  its blocks (`invalid_signer`).
- [x] Gossip bench end to end: `p2p/block gossip end to end 128 KiB` (sequencer `Service`
  -> noise seal/open -> verifier `Service`, a real signed v3 block per op, validated and
  popped) and `p2p/block gossip sequencer 128 KiB`; 1.09 ms and 0.30 ms per block (M4 Pro,
  ReleaseFast, noisy run), split recorded in `docs/PERF.md`. Decision: in-memory services
  with real noise instead of SimIo, so the numbers are CPU only, not simulated latency.
- [x] Completion-based UDP for discovery: the transport keeps one `recvfrom` and one
  `sendto` completion in flight (io-net's ops on io_uring/kqueue/SimIo) instead of polling
  on each tick, so datagrams reach discv5 on arrival rather than up to a tick later.
  Receive errors retry on the next tick (`datagram_receive_errors`). `stop` cancels both
  and closes the socket only after both return; `Transport.busy` (now part of
  `Network.busy`) is true until then, so a reused descriptor never meets a stale op.
- [x] Perf: verifier stage benches (`p2p/stage *`) and `pop_block` reuses the payload hash
  validation computed (`block.decode_known_hash`): end to end 1.02 -> 0.83 ms per block.
- [x] Real-socket interop (`loopback_test.zig`): two `Network`s on the OS backend
  (kqueue on macOS, io_uring on Linux via `just test-linux`) over 127.0.0.1 and ::1, on
  kernel-assigned free ports (never the devnet's fixed ports). Each knows only the other's
  ENR; the test waits for a completed discv5 handshake on both sides (a real UDP round
  trip; boot ENRs are also dialed over TCP, so a connection alone proves nothing), then
  gossips a block each way and drains the UDP completions on stop. Negative control:
  dropping received datagrams in the transport fails it with `NotConnected`. Decision:
  this replaces the devnet recheck of completion UDP, whose p2p ports are fixed.
- [x] Native 200 ms blocks (AGENTS.md rule 10, no flashblocks): p2p has no flashblocks
  topics or handling (only a comment naming a public base/base fixture path). Gossip
  validation already runs base/base's Denim schedule check (`check_base_time`, after the
  version checks, before the seen-hash check, as `validate_block_internal`). New DST
  (`transport_test`): a 4-node SimIo cluster with every upgrade through Denim active from
  genesis publishes 50 schedule-valid blocks sealed 150 ms into each 200 ms slot; every
  node pops each block, in order, before the next seal; nothing rejected or dropped.
  Negative control: a wrong millis part fails it. Decisions: topic score params keep
  base/base's `rollup.block_time` (seconds) input; at 5 blocks/s the delivery thresholds
  are met with margin. Per-block CPU (0.83 ms/hop at 128 KiB, `docs/PERF.md`) is ~0.4% of
  a core at 5 blocks/s.
- [x] Fuzz: hostile discv5 messages inside an established session (`disc/service_test`).
  Node 0 completes a real handshake with node 1, then seals hostile plaintext with its
  session keys: junk with random type bytes, PING with huge seq, PONG with spoofed
  endpoints (answering a real pending ping when one exists), FINDNODE with junk distances,
  NODES answering node 1's real pending FINDNODE (valid and bogus totals; junk, truncated,
  foreign-chain, and valid random records), TALKREQ. 512 seeded rounds plus `run_bytes`.
  Invariants: no crash, junk records rejected, invented nodes never become live, the
  honest node stays in the table and keeps talking. Decision: records at a requested
  distance from the responder are learned unverified, as in sigp discv5; liveness (a
  ping/handshake) is what keeps them out of the live set.
- [x] Fix: publishing the same block again, or more than `blocks_per_height_max` blocks at
  one height, hit the `SeenHashes.insert` assert (a crash in a retrying sequencer). Our
  own block is now recorded only when `check` passes; regression test in `service_test`.
- [x] Perf: decompress each gossip block once per message: the handler tags its scratch
  with the message id whose bytes it holds (`block.message_id_and_bytes`), and validation
  decodes from it when the tag matches (`stats.decompress_reused`), else decompresses.
  Saves one ~20 µs decompression per 128 KiB block; below this machine's bench noise.
- Survey 2026-11-05: base/base `peers/monitoring.rs` (ban threshold/duration) and
  `peers/nodes.rs` (per-chain bootnodes) are already covered; gossipsub IDONTWANT exists.
- [x] DST: crash-restart under loss (4 seeds, 10% datagram loss, 0.05% resets):
  `SimIo.crash` node 0 while a block is in flight, rebuild it on the same disk via
  `Network.deinit_after_crash` (`Transport`/`StoreFile.forget_after_crash`: nothing is
  closed twice), and require it to reload its bootstore, reconnect, and gossip both ways.
  (The peer may also redial; the clean-restart DST isolates the bootstore path.)
- [x] Devnet discovery: handed to batcher-devnet as a backlog note with the exact
  `devnet.sh` change (their lane owns the script); verified by hand on 2026-11-05.
- [x] Peerstore/bootstore observability (local, not in base/base):
  `base_node_p2p_peerstore_peers`, `_peerstore_evictions`, `_bootstore_records`,
  `_bootstore_file{type=open_error|load|load_error|save|save_error|save_skipped|invalid}`.
- [x] Real-process interop on the all-Zig devnet (`just devnet up`, kqueue sockets),
  checked by hand on 2026-11-05:
  1. As scripted (enode bootnode, discovery off): the verifier CL's unsafe head tracked
     the sequencer (54 vs 53) ahead of its safe head (49).
  2. Both CLs rerun with discovery on, the verifier given only the sequencer's ENR plus
     `--p2p.bootstore`: found over real UDP, unsafe heads equal (152 / 152, safe 127),
     and the bootstore file was written with the sequencer's ENR after 60 s.
  3. Verifier restarted with only the bootstore: gossip resumed (unsafe 215 = sequencer,
     safe 209). Not conclusive for the file alone, since the sequencer may redial; the
     sim DST covers that.
  Fixed: `p2p.rpc.Merged(Inner, inner_methods)` merges another method table with
  `opp2p_*` over one context (batches included; -32601 when p2p is off), and the node's
  RPC server now serves it (small integration edit in `service/node.zig`).
- [x] In-process interop (`interop_test.zig`): two full `Network`s find each other via discv5
  over SimIo UDP only (ENR bootnodes, no enode), gossip randomized Ecotone (v3) and Isthmus
  (v4) blocks both ways, and every received block round-trips through the consensus
  `gossip_bridge` (decode -> engine envelope -> encode) to the published block hash.
- [x] Bootstore persistence through `utilities.io` (base/base `BootStoreFile`, 60 s sync):
  `peers/store_file.zig` (`StoreFile(IO, Owner, hooks)`: read once, then write + fsync every
  60 s and on stop; shorter images are space-padded since io has no truncate/rename; seeded
  crash fuzz: a reload always equals the last fsynced image). `Network` uses it for
  `--p2p.bootstore`; `Network.busy()` must be false before `deinit` (the node's
  `deinit_p2p` now drains it). Interop DST: both nodes restart, node 0 has no bootnode for
  node 1, and reconnects from its file alone (fails with the file off).
  Decision: no default path (base/base uses `~/.base/<chain>/bootstore.json`); the store is
  memory-only unless `--p2p.bootstore` is given, so library code never derives home paths.
- [x] `--p2p.bootnodes-file` read through `utilities.io` at start (read-only `StoreFile`):
  entries append to `--p2p.bootnodes` as in base/base `bootnode_strings`; chain defaults
  only when both are empty, including when the file is missing or unreadable (base/base
  fails startup there; we keep running and count `open_errors`). Interop tests: a node
  whose only route to its peer is the file connects; a missing file seeds the defaults.
- [x] Identify peerstore (base/base `max_identify_peerstore_peers` = 1024):
  `peers/peerstore.zig` (fixed capacity, evicts the least recently updated disconnected
  peer, else the least recently updated; reference-model fuzz + `run_bytes`). Fed by
  identify, connect and disconnect; `opp2p_peers(false)` lists disconnected peers as
  NotConnected (banned: CannotConnect) with score 0 and direction 0.
- [x] Dial rate limiting (base/base gater `peer_redialing` / `dial_period`): already in
  `peers/gater.zig` (500 redials per 60 min, protected peers exempt).
- [x] DST: chaos seed sweep (8 seeds, 5 nodes, 5% datagram loss, connection resets, a 3 s
  partition of one node, then a block must reach everyone) (`-Dslow-tests`).
- [x] discv5 unverifiable ENRs (sigp `UnverifiableEnr` + base/base NAT handling): a handshake
  record enters the table only if it advertises the packet's source socket; otherwise it is
  forwarded for dialing and, when only the port differs, its advertised socket is pinged and a
  PONG there inserts it. Tested with a conntrack-style NAT in the disc sim. Also: the
  one-handshake-per-node rule now keys on (node, endpoint).
- [x] `rpc_calls{method}`: every opp2p handler is wrapped at comptime to count calls in
  `Service.stats.rpc_calls`; exported as `base_node_rpc_calls`.
- [x] discovery metrics parity (base/base `disc/src/metrics.rs`, scope `base_node_disc`):
  renamed `base_node_discovery_peer_count` -> `base_node_disc_discovery_peer_count`; added
  `discovery_event{type}`, `discovery_dropped{reason}`, `find_node_request`. `enr_store_time` is
  not exported (bootstore writes belong to the caller).
- [x] `peers/secp256k1` on `common.crypto.secp256k1` (crypto lane): noise handshake 770 -> 633
  µs; RFC 6979 signing now reproduces the EIP-778 example ENR byte for byte (tested), and a
  differential test checks keys/ECDH/cross-verification against std.
- [x] metrics parity: `block_validation_failed{reason}` (base/base reasons incl.
  `timestamp_future`/`timestamp_past` and `invalid_base_time_schedule`), `block_version{version}`;
  validation counters count decoded envelopes only (`stats.decode_failed` separate).
- [x] metrics parity: `dial_peer_error{type}` and `inbound_connection_error{type}` from the
  service/gater refusal reasons. Fixed with it: the transport passed a null remote address, so
  inbound gater address/subnet blocks and IP colocation scoring never applied; it now passes
  `io.peer_address` for accept and connect.
- [x] metrics parity: `peer_scores` and `gossip_peer_connection_duration_seconds` histograms,
  observed on every ping and on disconnect (as base/base) into plain service buckets
  (`observations.zig`), copied into `metrics.Histogram` by `update`.
- [x] metrics parity: `gossip_event{type}`, `block_topic_retirements_total{version}`,
  `block_topic_blocked_total{version,direction}` from new `Router.stats` (message, peer
  subscribe/unsubscribe, slow-peer queue drops, inbound on unsubscribed topics) and handler
  stats (retirements, refused publishes). `not_supported` stays 0 (transport closes such peers).
- [x] DST: discovery-only swarm (16 nodes, one ENR bootnode, no enode dial) converges over SimIo
  UDP with 5% datagram loss and a healed partition, then gossips blocks (`-Dslow-tests`).
- [x] DST: 10% datagram loss; discv5 handshakes and lookups still fill tables. The DSTs found
  three discv5 bugs, all fixed: (1) concurrent requests to one node each started a handshake,
  the second replacing the first session (its response failed authentication) — requests
  now wait behind one handshake per node; (2) no request retry — added sigp
  `request_retries = 1`; (3) a node whose boot exchanges were lost evicted its boot node and
  stayed isolated forever — boot records are re-added when the table is empty.
- [x] Transport closes with io `shutdown_now`, then `close_now` once the link is idle, so a
  reused descriptor never meets a stale recv (asserted on every new descriptor).
- [x] UDP discovery over io: added a minimal polled UDP path to io (all backends, noted in
  `docs/lanes/io-net.md`); the transport binds `Config.discovery_listen` and moves up to
  256 datagrams each way per 50 ms tick; `Network` binds `--p2p.listen.udp` unless
  `--p2p.no-discovery`. SimIo cluster tests now discover over UDP (no manual relay).
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
- [x] Protected peers (`opp2p_protectPeer`): bypass pending-outbound and established limits
  (up to `Limits.bypass_max` = 8 extra; per-peer limit still applies) and are never
  score-banned (base/base `bypass_peer_id`, `can_disconnect`).
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

- Req/resp (block sync by number): base/base has none; its `opp2p_peerStats` reports
  `ReqRespScores` as zeros, so this lane does the same and does not implement req/resp.
- Validation duration histogram is not exported: the gossip state machine has no wall clock.

- Bans stay base/base-shaped (discovery ban + disconnect, no TCP gate): a banned peer may
  redial, but its retained gossipsub score keeps it graylisted and it is banned again.

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
- 2026-11-05: protected peers bypass limits and score bans.
- 2026-11-05: discv5 runs over io UDP (SimIo + kqueue/io_uring).
- 2026-11-05: validation failure reasons and block versions as labeled metrics.
- 2026-11-05: dial/inbound error reasons; transport now passes real peer IPs to the gater.
- 2026-11-05: peer score and connection duration histograms.
- 2026-11-05: gossip event, topic retirement, and blocked-topic metrics.
- 2026-11-05 (crypto lane): `common.crypto.secp256k1` now has everything `peers/secp256k1.zig` takes from std: `compress_public_key`/`decompress_public_key`, `verify` (accepts high s like std; `is_low_s` available), `ecdh` (compressed shared point, constant time), `sign` (RFC 6979, low s), `public_key`. verify 24us vs std 63us, ecdh 29us vs 69us, sign 11us vs 74us, public_key 9us vs 67us.
- 2026-11-05: discovery DSTs (loss, 16-node swarm); discv5 handshake/retry/rebootstrap fixes.
- 2026-11-05: secp256k1 adapter on common.crypto (handshake 770 -> 633 us, EIP-778 re-sign vector).
- 2026-11-05: discovery metrics under base/base's `base_node_disc` scope.
- 2026-11-05: per-method admin RPC call metrics.
- 2026-11-05: discv5 unverifiable-ENR handling (table poisoning guard + NAT verification ping).
- 2026-11-05: chaos seed sweep DST.
- 2026-11-05: in-process p2p<->consensus interop test; backlog extended (bootstore/bootnodes-file persistence via io, identify peerstore).
- 2026-11-05: bootstore file persistence through utilities.io (StoreFile + crash fuzz + restart DST).
- 2026-11-05: --p2p.bootnodes-file read through the io layer.
- 2026-11-05: identify peerstore + opp2p_peers(false) disconnected peers.
- 2026-11-05: devnet real-process interop checked (enode, discv5 ENR, bootstore restart).
- 2026-11-05: opp2p_* served by the consensus node RPC via p2p.rpc.Merged.
- 2026-11-05: crash-restart DST under packet loss.
- 2026-11-05: peerstore/bootstore metrics; devnet discovery note for batcher-devnet.
- 2026-11-05: hostile authenticated-plaintext fuzz (connection + network level).
- 2026-11-05: end-to-end block gossip bench (1.09 ms/128 KiB block; verifier ~0.6 ms).

- 2026-11-05: discv5 UDP moved to recvfrom/sendto completions; stop drains them.
- 2026-11-05: verifier stage benches; pop_block reuses the validated payload hash (e2e -19%). Devnet recheck of completion UDP skipped: another lane's devnet held the ports.

- 2026-11-05: gossip validation reuses the message-id decompression.
- 2026-11-05: real-socket loopback interop (IPv4+IPv6, kqueue+io_uring); fixed republish crash.
- 2026-11-05: hostile in-session discv5 fuzz (seeded + run_bytes).
- 2026-11-05: direction change (no flashblocks, 200 ms blocks): Denim gossip DST added; nothing to remove.
- 2026-11-05: gossip flood DST found accepted blocks evictable by junk; added a dedicated accepted-block store.
- 2026-11-05: per-peer IWANT/IDONTWANT id budgets (control flood 3.8 ms -> 53 us per RPC).
- 2026-11-05: inbound yamux stream negotiation timeout (10 s); many-streams bound test.
