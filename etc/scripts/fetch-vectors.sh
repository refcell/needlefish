#!/usr/bin/env bash
# Fetch public Ethereum test vectors into .cache/vectors (git-ignored).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
mkdir -p .cache/vectors
if [ ! -d .cache/vectors/ethereum-tests ]; then
  git clone --depth 1 https://github.com/ethereum/tests .cache/vectors/ethereum-tests
fi
# Public base/base genesis files for `zig build genesischeck`.
mkdir -p .cache/vectors/base-genesis
for name in base sepolia_base zeronet_base; do
  if [ ! -f ".cache/vectors/base-genesis/$name.json" ]; then
    curl -fsSL -o ".cache/vectors/base-genesis/$name.json" \
      "https://raw.githubusercontent.com/base/base/main/crates/common/chains/res/genesis/$name.json"
  fi
done
# Public snailtracer bytecode (revm bench fixture) for the evm bench.
mkdir -p .cache/vectors/bench
if [ ! -f .cache/vectors/bench/snailtracer.hex ]; then
  curl -fsSL -o .cache/vectors/bench/snailtracer.hex \
    "https://raw.githubusercontent.com/bluealloy/revm/main/bins/revme/src/cmd/bench/snailtracer.hex"
fi
echo "vectors in .cache/vectors"
