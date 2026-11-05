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
- [ ] `libp2p`: multistream-select 1.0, noise XX handshake (X25519, ChaCha20-Poly1305,
  SHA256, libp2p signed static key payload), yamux framing + flow control (bounded
  streams/windows), TCP transport over utilities/io. Interop vectors; fuzz each codec.
- [ ] `libp2p`: identify and ping protocols; connection manager (bounded inbound/outbound).
- [x] `gossip`: gossipsub v1.1 (hand-written protobuf RPC codec, mesh maintenance,
  heartbeat, IHAVE/IWANT, fanout, message cache, seen cache, peer scoring integration),
  OP Stack message id (sha256 of domain + snappy-decoded payload) [id: block worker].
- [x] `gossip`: router follow-ups: score retention across reconnects (`retain_score`),
  outbound mesh quota (D_out = 2), IWANT retransmission limit.
- [ ] `gossip`: IDONTWANT (v1.2) and peer exchange on PRUNE (both off in base/base's
  libp2p config; low priority).
- [ ] `gossip`: snappy block-format codec (own implementation, fuzzed round trip) [done],
  unsafe block topics `/optimism/<chain_id>/{0,1,2,3}/blocks` (v1..v4), payload SSZ
  decode (ExecutionPayload v1..v4 envelopes), signature check against the unsafe block
  signer, block validity rules (port `block_validity.rs`: timestamp window, seen hashes
  per height limits, v3/v4 field rules).
- [ ] `Service`: one state machine tying disc + libp2p + gossip; publish signed unsafe
  blocks (sequencer), deliver validated blocks to consensus; DST of a 5-node cluster
  gossiping blocks with partitions/latency.
- [ ] Benchmarks: handshake/sec, gossip msgs/sec, allocation-free hot paths.

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
