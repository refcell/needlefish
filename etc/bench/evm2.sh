#!/bin/sh
# Benchmark B1 (docs/BENCHMARKS.md): needlefish against evm2 (alloy-rs/evm2, the EVM reth
# ships) and revm on evm2's own fixture suite (`data/*.json`, one transaction per state-test
# case), with the same timing loop on both sides: `statetest --bench`
# (src/execution/evm/state_test_bench.zig) and the `nf` runner that
# etc/bench/evm2-harness.patch adds to evm2's CLI crate. Every case must reproduce the
# fixture's logs (and, on the needlefish side, its post-state root), and every engine must
# report the same gas used for it. Run from the repository root on an otherwise idle machine.
#
# usage: etc/bench/evm2.sh [rounds]        (default 10)
#
# Every run is a fresh process; each round runs every configuration once, in a rotated order.
# Configurations (all -C target-cpu=native / -Dcpu=native):
#   nf-safe-native, nf-fast-native   needlefish ReleaseSafe and ReleaseFast, keccak memo off
#   nf-fast-native-memo  needlefish ReleaseFast with its KECCAK256 memo (on by default in the
#                     node; `statetest --no-keccak-memo` turns it off for the configs above)
#   evm2-tco          evm2's tail-call dispatch (nightly Rust), keccak memo off
#   evm2-packed       evm2's stable-Rust dispatch (what evm2's CI benches), keccak memo off
#   evm2-tco-memo     evm2-tco with alloy's process-global keccak memo (`keccak-cache-global`,
#                     on in evm2's own bench and in reth); compare with nf-fast-native-memo
#   revm              revm 43 through the same runner (stable build, memo off)
#
# Environment:
#   BENCH_CPU_SINGLE   CPU every run is pinned to (default 2)
#   BENCH_CPUS         CPUs of the benchmark cgroup when BENCH_ISOLATE=1 (default 2-3)
#   BENCH_ISOLATE      1: run inside bench.slice (etc/bench/reproduce.sh confines the rest)
#   BENCH_FIXTURES     fixture names without .json (default every data/*.json but precompile-*)
#   BENCH_TARGET_MS    warm-up and timed time per case and process (default 20)
#   BENCH_EVM2_DIR     evm2 checkout (default .cache/bench/evm2)
#   BENCH_SKIP_BUILD   1: reuse the binaries under .cache/bench/bin
#
# Needs: Zig 0.17.1, git, rustup with a stable and a nightly toolchain, cmake and a C/C++
# compiler (evm2's precompile backends), and network access to github.com and crates.io.
# Everything it writes stays under .cache/.
set -eu

evm2_repository=https://github.com/alloy-rs/evm2
evm2_commit=37fb326b91a76dd07308c703b3f3c85152a6230b
rounds=${1:-10}
cpu_single=${BENCH_CPU_SINGLE:-2}
cpus=${BENCH_CPUS:-2-3}
target_ms=${BENCH_TARGET_MS:-20}
out=.cache/bench
evm2_dir=${BENCH_EVM2_DIR:-$out/evm2}
results=$out/results/evm2
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
mkdir -p "$out/bin"

build_needlefish() {
    for optimize in ReleaseSafe ReleaseFast; do
        echo "== needlefish: zig build bench-tools -Doptimize=$optimize -Dcpu=native"
        zig build bench-tools -Doptimize="$optimize" -Dcpu=native \
            --prefix "$out/bin/nf-$optimize-native"
    done
}

checkout_evm2() {
    if [ ! -e "$evm2_dir/.git" ]; then
        git clone --quiet "$evm2_repository" "$evm2_dir"
        git -C "$evm2_dir" checkout --quiet --detach "$evm2_commit"
        git -C "$evm2_dir" apply "$PWD/etc/bench/evm2-harness.patch"
    fi
    [ "$(git -C "$evm2_dir" rev-parse HEAD)" = "$evm2_commit" ] || {
        echo "$evm2_dir is not at $evm2_commit" >&2
        exit 1
    }
}

build_evm2() { # build_evm2 <label> <toolchain> <backend> [<cargo feature args>...]
    label=$1 toolchain=$2 backend=$3
    shift 3
    echo "== evm2: $label (cargo +$toolchain, EVM2_DISPATCH_BACKEND=$backend $*)"
    binary=$(cd "$evm2_dir" && CARGO_TARGET_DIR="target-$label" \
        RUSTFLAGS="-C target-cpu=native" EVM2_DISPATCH_BACKEND="$backend" \
        cargo "+$toolchain" bench --locked -p evm2-cli --bench nf --no-run "$@" 2>&1 |
        sed -n 's/.*Executable benches\/nf.rs (\(.*\))/\1/p')
    [ -n "$binary" ] || { echo "evm2 $label build failed" >&2; exit 1; }
    cp "$evm2_dir/$binary" "$out/bin/evm2-$label"
}

launch() { # launch <command...>: pinned, and in bench.slice when isolating
    if [ "${BENCH_ISOLATE:-0}" = 1 ]; then
        sudo systemd-run --quiet --scope --slice=bench.slice -p AllowedCPUs="$cpus" \
            --uid="$(id -u)" --gid="$(id -g)" -- taskset -c "$cpu_single" "$@"
    else
        taskset -c "$cpu_single" "$@"
    fi
}

# Configurations, one per line: `<label> <binary> [<arguments>]`.
configs() {
    echo "nf-safe-native $out/bin/nf-ReleaseSafe-native/bin/statetest --bench --no-keccak-memo"
    echo "nf-fast-native $out/bin/nf-ReleaseFast-native/bin/statetest --bench --no-keccak-memo"
    echo "nf-fast-native-memo $out/bin/nf-ReleaseFast-native/bin/statetest --bench"
    echo "evm2-tco $out/bin/evm2-tco --engine evm2"
    echo "evm2-packed $out/bin/evm2-packed --engine evm2"
    echo "evm2-tco-memo $out/bin/evm2-tco-memo --engine evm2"
    echo "revm $out/bin/evm2-packed --engine revm"
}

etc/bench/env.sh
checkout_evm2
if [ "${BENCH_SKIP_BUILD:-0}" != 1 ]; then
    build_needlefish
    build_evm2 tco nightly tco --no-default-features --features mimalloc
    build_evm2 packed stable packed --no-default-features --features mimalloc
    build_evm2 tco-memo nightly tco
fi

fixtures=
for name in ${BENCH_FIXTURES:-$(cd "$evm2_dir/data" && ls *.json | grep -v '^precompile-' |
    sed 's/\.json$//')}; do
    fixtures="$fixtures $evm2_dir/data/$name.json"
done

rm -rf "$results"
mkdir -p "$results"
configs >"$results/configs.txt"
total=$(wc -l <"$results/configs.txt")
round=1
while [ "$round" -le "$rounds" ]; do
    start=$(((round - 1) % total + 1))
    { tail -n +"$start" "$results/configs.txt"; head -n $((start - 1)) "$results/configs.txt"; } |
        while read -r label binary arguments; do
            # shellcheck disable=SC2086 # word splitting of arguments and fixtures is intended
            launch "$binary" $arguments --target-ms "$target_ms" $fixtures >"$results/run.tmp" ||
                { echo "$label round $round failed" >&2; exit 1; }
            awk -v tag="cfg=$label mode=warm iter=$round" \
                '/^BENCH/ { sub(/^BENCH /, "BENCH " tag " "); print }' \
                "$results/run.tmp" >>"$results/results.txt"
        done
    echo "evm2 round $round/$rounds: $(etc/bench/env.sh --check)"
    round=$((round + 1))
done
rm -f "$results/run.tmp"

echo "== results: evm2 fixtures, median us per transaction over $rounds processes"
zig run -OReleaseSafe etc/bench/stats.zig -- --cases \
    --pair nf-safe-native/evm2-tco \
    --pair nf-fast-native/evm2-tco \
    --pair nf-fast-native/evm2-packed \
    --pair nf-fast-native-memo/evm2-tco-memo \
    --pair evm2-tco/revm \
    <"$results/results.txt"
