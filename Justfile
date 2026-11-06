# needlefish — Base in Zig. `just` lists recipes.

set positional-arguments := true

# Local devnet: L1 dev chain, L2 sequencer (execution + consensus), batcher, verifier
mod devnet 'etc/devnet/devnet.just'

alias t := test
alias b := build

default:
    @just --list

# Build all binaries (debug)
build *args:
    zig build {{ args }}

# Build all binaries optimized
release:
    zig build -Doptimize=ReleaseFast -Dgit-rev=$(git rev-parse --short HEAD)

# Run unit tests, optionally filtered: just test rlp
test filter='':
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{ filter }}" ]; then zig build test -Dtest-filter="{{ filter }}"; else zig build test; fi

# Run the test suite inside a Linux container (exercises io_uring)
test-linux:
    docker run --rm --security-opt seccomp=unconfined --security-opt label=disable -v "$PWD":/src -w /src \
      alpine:3.20 sh -c 'apk add --no-cache curl xz >/dev/null && \
      etc/scripts/install-zig.sh /tmp/zig && /tmp/zig/zig build test -Drequire-io-uring=true'

# Coverage-guided fuzzing of all fuzz tests
fuzz:
    zig build test --fuzz -Doptimize=ReleaseSafe

# Seeded fuzz soak: every seeded fuzz test, `factor` times the iterations, fresh seed
fuzz-soak factor='100' seed='1':
    zig build test -Doptimize=ReleaseSafe -Dtest-filter=fuzz -Dfuzz-soak={{ factor }} -Dfuzz-seed={{ seed }}

# Deterministic simulation: just sim [seed]
sim seed='':
    zig build sim -Doptimize=ReleaseSafe -- {{ seed }}

# Run many simulator seeds in-process: just sim-swarm 1000 [first-seed]
sim-swarm count='200' first='':
    #!/usr/bin/env bash
    set -euo pipefail
    first="{{ first }}"; [ -n "$first" ] || first=$RANDOM$RANDOM
    zig build sim -Doptimize=ReleaseSafe -- swarm "$first" {{ count }}

# Shrink a failing simulator seed's config: just sim-minimize 1234
sim-minimize seed:
    zig build sim -Doptimize=ReleaseSafe -- minimize {{ seed }}

# Micro benchmarks
bench *args:
    zig build bench -Doptimize=ReleaseFast -- {{ args }}

# Format sources
fmt:
    zig fmt build.zig build.zig.zon src bin

# Formatting, line length, secrets, and dependency checks
tidy:
    etc/scripts/tidy.sh

# Slowest unit tests: just test-times 20
test-times count='20':
    etc/scripts/test-times.sh {{ count }}

# Asserts per function, lowest first (informational): just assert-density src/testing/
assert-density prefix='src/':
    etc/scripts/assert-density.sh {{ prefix }}

# Fetch the latest Base mainnet blocks + witness from public RPC, replay them offline, and
# check every header field (docs/REPLAY.md): just replay [count] [first block]. Responses are
# cached, so an interrupted run resumes; a pinned first block reruns the same window.
replay count='10' from='':
    zig build -Doptimize=ReleaseFast
    zig-out/bin/base replay fetch --count {{ count }} \
        {{ if from == "" { "" } else { "--from " + from } }} --out .cache/replay/latest.nfrp
    zig-out/bin/base replay run .cache/replay/latest.nfrp

# Pinned 100-block mainnet window (53775088..53775187, 1571 txs): every block's state root,
# receipts root, logs bloom, gas used and hash must match. Fetches once, then from the cache.
replay-check:
    just replay 100 53775088

# Replay a saved archive offline (default: the committed 10-block fixture)
replay-run archive='src/infra/replay/testdata/base-mainnet-53715983-10.nfrp':
    zig build -Doptimize=ReleaseFast
    zig-out/bin/base replay run {{ archive }}

# Everything CI runs
ci: tidy test

# Fetch public Ethereum test vectors into .cache/ (git-ignored)
vectors:
    etc/scripts/fetch-vectors.sh

clean:
    rm -rf zig-out .zig-cache
