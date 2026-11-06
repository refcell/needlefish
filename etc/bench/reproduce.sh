#!/bin/sh
# Reproduces docs/BENCHMARKS.md: needlefish and base/base execute the same Base mainnet blocks
# from the same pre-state (a needlefish replay archive), and both must reproduce every
# canonical header. Run from the repository root on an otherwise idle machine.
#
# usage: etc/bench/reproduce.sh [warm runs]        (default 5)
#
# Needs: Zig 0.17.1, git, curl, a Rust toolchain (base/base pins 1.96.0 via
# rust-toolchain.toml), and network access to github.com and public Base RPC.
# Everything it writes stays under the git-ignored .cache/.
set -eu

base_repository=https://github.com/base/base
base_commit=a8b34b69ee43d12fd9f4b4f9335521315f6953ff
window_first=53775088
window_count=100
warm=${1:-5}
out=.cache/bench
rust_dir=${BENCH_RUST_DIR:-$out/base}
fixture=$(ls src/infra/replay/testdata/*.nfrp)
window=$out/window-$window_first-$window_count.nfrp

mkdir -p "$out"

echo "== needlefish: build (ReleaseFast)"
zig build -Doptimize=ReleaseFast

echo "== archives"
if [ ! -f "$window" ]; then
    zig-out/bin/base replay fetch --count "$window_count" --from "$window_first" --out "$window"
fi

# The base/base executor needs the full parent header of the first block (needlefish needs
# only its state root and hash, which the archive carries). The harness checks its hash.
parent_json() { # parent_json <first block> <file>
    [ -s "$2" ] && return 0
    hex=$(printf '0x%x' $(($1 - 1)))
    curl -sf -X POST -H 'content-type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBlockByNumber\",\"params\":[\"$hex\",false]}" \
        https://mainnet.base.org >"$2"
}
parent_json 53715983 "$out/parent-fixture.json"
parent_json "$window_first" "$out/parent-window.json"

echo "== base/base: clone at $base_commit, apply etc/bench/base-harness.patch, build (release)"
if [ ! -e "$rust_dir/.git" ]; then
    git clone --quiet "$base_repository" "$rust_dir"
    git -C "$rust_dir" checkout --quiet --detach "$base_commit"
    git -C "$rust_dir" apply "$PWD/etc/bench/base-harness.patch"
fi
[ "$(git -C "$rust_dir" rev-parse HEAD)" = "$base_commit" ] || {
    echo "$rust_dir is not at $base_commit" >&2
    exit 1
}
(cd "$rust_dir" && cargo build --release --locked -p nf-replay-bench)
harness=$rust_dir/target/release/nf-replay-bench

# Peak resident set size in MiB, from /usr/bin/time's report.
peak_rss() {
    awk '/maximum resident set size/ { printf "%.0f", $1 / 1048576 }
         /Maximum resident set size/ { printf "%.0f", $NF / 1024 }' "$1"
}
if [ "$(uname)" = Darwin ]; then time_flag=-l; else time_flag=-v; fi

run() { # run <name> <command...>; BENCH lines to $out/<name>.txt
    name=$1
    shift
    /usr/bin/time $time_flag "$@" >"$out/$name.txt" 2>"$out/$name.time"
    echo "$name peak RSS: $(peak_rss "$out/$name.time") MiB"
}

echo "== machine"
uname -sm
sysctl -n machdep.cpu.brand_string 2>/dev/null || true
uptime

echo "== run ($warm warm runs after one cold run, per archive and implementation)"
run needlefish-fixture zig-out/bin/base replay bench "$fixture" "$warm"
run base-fixture "$harness" "$fixture" "$out/parent-fixture.json" "$warm"
run needlefish-window zig-out/bin/base replay bench "$window" "$warm"
run base-window "$harness" "$window" "$out/parent-window.json" "$warm"

echo "== results"
echo "| implementation | phase | blocks | Mgas | warm runs | Mgas/s warm median |" \
    "Mgas/s cold | ms/block warm median | ms/block warm p90 | ms/block cold median |"
echo "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
for name in needlefish-fixture base-fixture needlefish-window base-window; do
    etc/bench/summarize.sh "$name" "$out/$name.txt"
done

echo "== binaries (bytes)"
wc -c zig-out/bin/base "$harness"
