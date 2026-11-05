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
- [ ] `peers`: bounded peer store, peer scoring params (port `score.rs`: topic params
  from block time, thresholds, decay), connection gater (ip/subnet bans, dial limits;
  port `gater.rs`/`gate.rs`).
- [ ] `disc`: discv5 wire protocol: packet masking (AES-CTR), header, ordinary /
  WHOAREYOU / handshake packets, session key derivation (ECDH + HKDF), AES-GCM message
  encryption, messages PING/PONG/FINDNODE/NODES/TALKREQ/TALKRESP. Spec test vectors.
- [ ] `disc`: Kademlia routing table (bounded k-buckets, 256 log distances), lookup
  iteration, bootstrap, ENR filter on `opstack` chain id, discovery driver state machine
  (port `driver.rs`), DST test with a simulated network of N nodes.
- [ ] `libp2p`: multistream-select 1.0, noise XX handshake (X25519, ChaCha20-Poly1305,
  SHA256, libp2p signed static key payload), yamux framing + flow control (bounded
  streams/windows), TCP transport over utilities/io. Interop vectors; fuzz each codec.
- [ ] `libp2p`: identify and ping protocols; connection manager (bounded inbound/outbound).
- [ ] `gossip`: gossipsub v1.1 (protobuf RPC codec written by hand, mesh maintenance,
  heartbeat, IHAVE/IWANT, fanout, message cache, seen cache, peer scoring integration),
  OP Stack message id (sha256 of domain + snappy-decoded payload).
- [ ] `gossip`: snappy block-format codec (own implementation, fuzzed round trip),
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

## Log
- 2026-11-05: lane created by coordinator.
- 2026-11-05: `peers` identity: ENR (EIP-778 v4, opstack key, text form), peer ids,
  base58, varint, ip text, multiaddr, enode, Base boot nodes, node keys; all fuzzed.
