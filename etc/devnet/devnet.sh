#!/usr/bin/env bash
# Devnet process supervisor. Grows with the batcher-devnet lane.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
cmd="${1:-status}"
case "$cmd" in
  up)
    zig build -Doptimize=ReleaseSafe
    mkdir -p .devnet/logs
    echo "devnet: components not implemented yet (see docs/lanes/batcher-devnet.md)"
    ;;
  down) echo "devnet: nothing running" ;;
  status) echo "devnet: not implemented yet" ;;
  logs) tail -n 100 -F .devnet/logs/*.log ;;
  smoke) echo "devnet: smoke not implemented yet"; exit 1 ;;
  *) echo "usage: devnet.sh up|down|status|logs|smoke"; exit 2 ;;
esac
