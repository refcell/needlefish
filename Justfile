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
    docker run --rm --security-opt seccomp=unconfined -v "$PWD":/src -w /src \
      alpine:3.20 sh -c 'apk add --no-cache curl xz >/dev/null && \
      etc/scripts/install-zig.sh /tmp/zig && /tmp/zig/zig build test'

# Coverage-guided fuzzing of all fuzz tests
fuzz:
    zig build test --fuzz -Doptimize=ReleaseSafe

# Deterministic simulation: just sim [seed]
sim seed='':
    zig build sim -Doptimize=ReleaseSafe -- {{ seed }}

# Run many simulator seeds: just sim-swarm 100
sim-swarm count='50':
    #!/usr/bin/env bash
    set -euo pipefail
    zig build -Doptimize=ReleaseSafe
    for i in $(seq 1 {{ count }}); do
      seed=$RANDOM$RANDOM
      zig build sim -Doptimize=ReleaseSafe -- "$seed" >/dev/null 2>&1 || { echo "FAIL seed=$seed"; exit 1; }
    done
    echo "sim-swarm: {{ count }} seeds ok"

# Micro benchmarks
bench *args:
    zig build bench -Doptimize=ReleaseFast -- {{ args }}

# Format sources
fmt:
    zig fmt build.zig build.zig.zon src bin

# Formatting, line length, secrets, and dependency checks
tidy:
    etc/scripts/tidy.sh

# Everything CI runs
ci: tidy test

# Fetch public Ethereum test vectors into .cache/ (git-ignored)
vectors:
    etc/scripts/fetch-vectors.sh

clean:
    rm -rf zig-out .zig-cache
