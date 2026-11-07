#!/bin/sh
# Phase B2 of docs/BENCHMARK_PLAN.md: CPU profiles of both executors replaying the pinned
# 100-block window, single-threaded, as flame graphs in docs/assets/bench/. Only stacks
# inside the timed region are kept (needlefish `Replayer.replay_next`, base/base
# `StatelessL2Builder::build_block`), so archive loading and witness hashing do not show.
#
# usage: etc/bench/profile.sh [passes]       (default 10 passes over the window)
#
# Run after etc/bench/reproduce.sh (it builds the binaries and fetches the window). Needs
# perf; sampling uses the `cpu-clock` software event, so it also works in a VM without a
# PMU, and DWARF call graphs. base/base is built with its `release-symbols` profile (release
# codegen plus line tables) and native CPU tuning; needlefish is ReleaseSafe, native.
set -eu

flamegraph_repository=https://github.com/brendangregg/FlameGraph
flamegraph_commit=41fee1f99f9276008b7cd112fca19dc3ea84ac32
passes=${1:-10}
out=.cache/bench
rust_dir=${BENCH_RUST_DIR:-$out/base}
cpu=${BENCH_CPU_SINGLE:-2}
window=$out/window-53775088-100.nfrp
parent=$out/parent-53775088.json
assets=docs/assets/bench
needlefish=$out/bin/nf-ReleaseSafe-native/bin/base
harness=$rust_dir/target-native/release-symbols/nf-replay-bench
flamegraph=$out/FlameGraph
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"

if [ ! -e "$flamegraph/.git" ]; then
    git clone --quiet "$flamegraph_repository" "$flamegraph"
    git -C "$flamegraph" checkout --quiet --detach "$flamegraph_commit"
fi
(cd "$rust_dir" && CARGO_TARGET_DIR=target-native RUSTFLAGS="-C target-cpu=native" \
    cargo build --profile release-symbols --locked -p nf-replay-bench)
mkdir -p "$assets"

profile() { # profile <name> <timed frame> <title> <command...>
    name=$1 frame=$2 title=$3
    shift 3
    perf record --quiet -F 1999 -e cpu-clock --call-graph dwarf,32768 -o "$out/$name.perf" \
        -- taskset -c "$cpu" "$@" >/dev/null
    perf script -i "$out/$name.perf" 2>/dev/null | "$flamegraph/stackcollapse-perf.pl" |
        grep -F "$frame" >"$out/$name.folded"
    "$flamegraph/flamegraph.pl" --title "$title" --width 1600 --hash \
        "$out/$name.folded" >"$assets/$name.svg"
    # Top frames by inclusive share of the timed region, for docs/BENCHMARKS.md.
    awk '{ n = $NF; $NF = ""; total += n; split($0, frames, ";")
        delete seen
        for (i in frames) { f = frames[i]; sub(/ +$/, "", f); if (!(f in seen)) { seen[f] = 1; inclusive[f] += n } }
    } END { for (f in inclusive) printf "%5.1f%% %s\n", 100 * inclusive[f] / total, f }' \
        "$out/$name.folded" | sort -rn | head -60 >"$out/$name.top.txt"
    echo "$name: $(awk '{ s += $NF } END { print s }' "$out/$name.folded") samples in the" \
        "timed region -> $assets/$name.svg, $out/$name.top.txt"
}

profile flame-needlefish replay_next \
    "needlefish: 100-block window, ReleaseSafe native, 0 recovery threads" \
    "$needlefish" replay bench "$window" "$passes" --recovery-threads 0
profile flame-base build_block \
    "base/base StatelessL2Builder: 100-block window, release-symbols native" \
    "$harness" "$window" "$parent" "$passes"
