#!/usr/bin/env bash
# Assert density report (informational, never fails): asserts per non-test function
# for each Zig file under src/, lowest first. TigerStyle aims for >= 2 per function.
# Usage: etc/scripts/assert-density.sh [path-prefix]
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
prefix="${1:-src/}"
git ls-files -co --exclude-standard "${prefix}*.zig" "${prefix}**/*.zig" | sort -u \
  | xargs awk '
    FNR == 1 { if (file != "") emit(); file = FILENAME; fns = 0; asserts = 0; in_test = 0 }
    /^test / { in_test = 1 } /^}/ { in_test = 0 }
    !in_test && /^[ ]*(pub )?(inline )?fn [A-Za-z0-9_]+\(/ && $0 !~ /\) type \{/ { fns++ }
    !in_test { asserts += gsub(/assert\(/, "&") }
    function emit() {
      if (fns > 0) printf "%6.2f %5d %5d %s\n", asserts / fns, asserts, fns, file
      total_fns += fns; total_asserts += asserts
    }
    END {
      emit()
      if (total_fns > 0) printf "%6.2f %5d %5d TOTAL\n", total_asserts / total_fns, total_asserts, total_fns
    }' \
  | sort -n | awk 'BEGIN { print "ratio asserts   fns file" } /TOTAL/ { t = $0; next } { print } END { print t }'
