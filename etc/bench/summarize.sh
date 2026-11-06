#!/bin/sh
# Summarizes `BENCH` lines (from `base replay bench` or the base/base harness) into one
# Markdown table row per phase:
#   | label | phase | blocks | Mgas | warm runs | Mgas/s warm median | Mgas/s cold |
#   ms/block warm median | ms/block warm p90 | ms/block cold median |
# Run 0 is cold; runs 1..N are warm. Per-block statistics use
# every (block, warm run) sample, nearest rank. Mgas/s is total gas over total time.
#
# usage: etc/bench/summarize.sh <label> <bench output file>
set -eu
label=$1
file=$2

grep -q '^BENCH' "$file" || { echo "no BENCH lines in $file" >&2; exit 1; }
if grep '^BENCH' "$file" | grep -qv 'ok=1'; then
    echo "$file: a block did not reproduce its canonical header" >&2
    exit 1
fi

field() { # field <name> <run filter: cold|warm>
    awk -v name="$1" -v which="$2" '/^BENCH/ {
        cold = ($2 == "run=0")
        if ((which == "cold") != cold) next
        for (i = 2; i <= NF; i++) { split($i, kv, "="); if (kv[1] == name) print kv[2] }
    }' "$file"
}

percentile() { # percentile <p in 0..1>, numbers on stdin
    sort -n | awk -v p="$1" '{ v[NR] = $1 } END {
        rank = int(p * NR); if (rank < p * NR) rank++; if (rank < 1) rank = 1
        printf "%.2f", v[rank] / 1e6
    }'
}

mgas_per_second() { # mgas_per_second <ns field> <cold|warm>; warm: median over runs
    awk -v name="$1" -v which="$2" '/^BENCH/ {
        cold = ($2 == "run=0")
        if ((which == "cold") != cold) next
        for (i = 2; i <= NF; i++) {
            split($i, kv, "=")
            if (kv[1] == "run") run = kv[2]
            if (kv[1] == "gas") gas = kv[2]
            if (kv[1] == name) ns = kv[2]
        }
        g[run] += gas; t[run] += ns
    } END { for (r in g) printf "%.0f\n", g[r] * 1000 / t[r] }' "$file" |
        sort -n | awk '{ v[NR] = $1 } END { print v[int((NR + 1) / 2)] }'
}

blocks=$(field gas cold | wc -l | tr -d ' ')
runs=$(field gas warm | wc -l | tr -d ' ')
runs=$((runs / blocks))
mgas=$(field gas cold | awk '{ s += $1 } END { printf "%.1f", s / 1e6 }')
for phase in exec total; do
    echo "| $label | $phase | $blocks | $mgas | $runs" \
        "| $(mgas_per_second ${phase}_ns warm)" \
        "| $(mgas_per_second ${phase}_ns cold)" \
        "| $(field ${phase}_ns warm | percentile 0.5)" \
        "| $(field ${phase}_ns warm | percentile 0.9)" \
        "| $(field ${phase}_ns cold | percentile 0.5) |"
done
