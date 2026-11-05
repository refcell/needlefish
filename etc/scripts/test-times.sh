#!/usr/bin/env bash
# Slowest unit tests: builds the test binary, runs it without a TTY (the runner then
# prints "i/N name...OK" per test), timestamps each line, and lists the slowest.
# Usage: etc/scripts/test-times.sh [count] [extra zig build args...]
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
count="${1:-20}"
shift || true
zig build test "$@" >/dev/null 2>&1 || true
binary=$(ls -t .zig-cache/o/*/test 2>/dev/null | head -1)
[ -n "$binary" ] || { echo "test-times: test binary not found"; exit 1; }
"$binary" 2>&1 </dev/null | perl -MTime::HiRes=time -ne '
  BEGIN { $|=1; $last = time; }
  # Each test prints "i/N name..." then its result; time from one result to the next.
  while (/(\d+)\/\d+ (.+?)\.\.\.(OK|SKIP|FAIL[^\n]*)/g) {
    $now = time; printf "%9.1f ms  %s %s\n", ($now - $last) * 1000, $2, ($3 eq "OK" ? "" : $3);
    $last = $now;
  }' | sort -rn | head -n "$count"
