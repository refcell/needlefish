#!/usr/bin/env bash
# Fetch public Ethereum test vectors into .cache/vectors (git-ignored).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
mkdir -p .cache/vectors
if [ ! -d .cache/vectors/ethereum-tests ]; then
  git clone --depth 1 https://github.com/ethereum/tests .cache/vectors/ethereum-tests
fi
echo "vectors in .cache/vectors"
