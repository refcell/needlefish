#!/bin/sh
# Reproduces docs/BENCHMARKS.md: needlefish and base/base execute the same Base mainnet blocks
# from the same pre-state (needlefish replay archives), and both must reproduce every
# canonical header. Run from the repository root on an otherwise idle Linux machine.
#
# usage: etc/bench/reproduce.sh [runs]        (default 30 per configuration and mode)
#
# Every run is a fresh process. Configurations run interleaved (each round runs every
# configuration once, starting one later each round), in two modes:
#   cold   page cache dropped (`echo 3 > /proc/sys/vm/drop_caches`), first pass
#   warm   page cache warm, first pass; the same process's second pass is mode `repeat`
# A round where the CPU frequency moved is discarded (etc/bench/env.sh --check).
#
# Environment (defaults suit a 2-core, 4-thread machine; set them for a larger server):
#   BENCH_CPUS         CPUs of the benchmark cgroup (default 2-3: one core, both threads)
#   BENCH_CPU_SINGLE   CPU of single-threaded runs; its SMT sibling stays idle (default 2)
#   BENCH_THREADS      needlefish recovery workers in the threaded configuration (default 1,
#                      on the sibling thread of BENCH_CPU_SINGLE)
#   BENCH_SYSTEM_CPUS  CPUs left to everything else when BENCH_ISOLATE=1 (default 0-1)
#   BENCH_ISOLATE      1: confine every other systemd slice to BENCH_SYSTEM_CPUS (needs sudo)
#   BENCH_WORKLOADS    any of: fixture window100 window1000 evm100 (default all four;
#                      evm100 is the 100-block window with --evm-only, phase B3)
#   BENCH_RUNS_1000    runs for the 1,000-block window (default 5; headline configs only,
#                      no in-process repeat: one base/base pass takes minutes)
#   BENCH_SKIP_BUILD   1: reuse the binaries under .cache/bench
#
# Needs: Zig 0.17.1, git, curl, a Rust toolchain (base/base pins 1.96.0 via
# rust-toolchain.toml), GNU time, numactl, sudo for drop_caches and isolation, and network
# access to github.com and public Base RPC. Everything it writes stays under .cache/.
set -eu

base_repository=https://github.com/base/base
base_commit=a8b34b69ee43d12fd9f4b4f9335521315f6953ff
window_first=53775088
window_count=100
long_first=54048836
long_count=1000
runs=${1:-30}
runs_long=${BENCH_RUNS_1000:-5}
cpus=${BENCH_CPUS:-2-3}
cpu_single=${BENCH_CPU_SINGLE:-2}
threads=${BENCH_THREADS:-1}
system_cpus=${BENCH_SYSTEM_CPUS:-0-1}
workloads=${BENCH_WORKLOADS:-fixture window100 window1000 evm100}
out=.cache/bench
rust_dir=${BENCH_RUST_DIR:-$out/base}
fixture=src/infra/replay/testdata/base-mainnet-53715983-10.nfrp
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
export BENCH_CPUS="$cpus" BENCH_SYSTEM_CPUS="$system_cpus" BENCH_RUST_DIR="$rust_dir"
export BENCH_BASE_COMMIT="$base_commit"

mkdir -p "$out"

nf_bin() { # nf_bin <optimize> <cpu>
    echo "$out/bin/nf-$1-$2/bin/base"
}
base_bin() { # base_bin <profile> <native|generic>
    if [ "$2" = native ]; then target=target-native; else target=target; fi
    echo "$rust_dir/$target/$1/nf-replay-bench"
}

build_needlefish() {
    for optimize in ReleaseSafe ReleaseFast; do
        for cpu in native baseline; do
            echo "== needlefish: zig build -Doptimize=$optimize -Dcpu=$cpu"
            zig build -Doptimize="$optimize" -Dcpu="$cpu" --prefix "$out/bin/nf-$optimize-$cpu"
        done
    done
}

build_base() {
    if [ ! -e "$rust_dir/.git" ]; then
        git clone --quiet "$base_repository" "$rust_dir"
        git -C "$rust_dir" checkout --quiet --detach "$base_commit"
        git -C "$rust_dir" apply "$PWD/etc/bench/base-harness.patch"
    fi
    [ "$(git -C "$rust_dir" rev-parse HEAD)" = "$base_commit" ] || {
        echo "$rust_dir is not at $base_commit" >&2
        exit 1
    }
    for profile in maxperf release; do
        for tune in native generic; do
            echo "== base/base: cargo build --profile $profile ($tune)"
            if [ "$tune" = native ]; then
                (cd "$rust_dir" && CARGO_TARGET_DIR=target-native \
                    RUSTFLAGS="-C target-cpu=native" \
                    cargo build --profile "$profile" --locked -p nf-replay-bench)
            else
                (cd "$rust_dir" && env -u RUSTFLAGS \
                    cargo build --profile "$profile" --locked -p nf-replay-bench)
            fi
        done
    done
}

# The base/base executor needs the full parent header of the first block (needlefish needs
# only its state root and hash, which the archive carries). The harness checks its hash.
parent_json() { # parent_json <first block> <file>
    [ -s "$2" ] && return 0
    hex=$(printf '0x%x' $(($1 - 1)))
    curl -sf -X POST -H 'content-type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getBlockByNumber\",\"params\":[\"$hex\",false]}" \
        https://mainnet.base.org >"$2"
}

archive() { # archive <first> <count>: fetches once into .cache/bench
    file=$out/window-$1-$2.nfrp
    if [ ! -f "$file" ]; then
        "$(nf_bin ReleaseSafe native)" replay fetch --count "$2" --from "$1" \
            --cache "$out/replay-$1-$2" --out "$file" >&2
    fi
    echo "$file"
}

# Configurations, one per line: `<label> <cpus> <kind> <binary> [<recovery threads>]`.
configs() { # configs <full|headline|evm>
    if [ "$1" = evm ]; then
        echo "nf-safe-native-evm $cpu_single nf-evm $(nf_bin ReleaseSafe native)"
        echo "nf-fast-native-evm $cpu_single nf-evm $(nf_bin ReleaseFast native)"
        echo "base-node-native-evm $cpu_single base-node-evm $(base_bin maxperf native)"
        echo "base-maxperf-native-evm $cpu_single base-evm $(base_bin maxperf native)"
        echo "base-release-native-evm $cpu_single base-evm $(base_bin release native)"
        return
    fi
    for optimize in ReleaseSafe ReleaseFast; do
        short=safe
        [ "$optimize" = ReleaseFast ] && short=fast
        for cpu in native baseline; do
            [ "$1" = headline ] && { [ "$short-$cpu" = safe-native ] || continue; }
            echo "nf-$short-$cpu-t0 $cpu_single nf $(nf_bin "$optimize" "$cpu") 0"
            echo "nf-$short-$cpu-t$threads $cpus nf $(nf_bin "$optimize" "$cpu") $threads"
        done
    done
    for profile in maxperf release; do
        for tune in native generic; do
            [ "$1" = headline ] && { [ "$profile-$tune" = maxperf-native ] || continue; }
            echo "base-$profile-$tune $cpu_single base $(base_bin "$profile" "$tune")"
        done
    done
}

# Runs from a cgroup of their own when isolating, else directly; always pinned.
launch() { # launch <cpus> <command...>
    pin=$1
    shift
    if [ "${BENCH_ISOLATE:-0}" = 1 ]; then
        sudo systemd-run --quiet --scope --slice=bench.slice -p AllowedCPUs="$cpus" \
            --uid="$(id -u)" --gid="$(id -g)" -- taskset -c "$pin" numactl --membind=0 "$@"
    else
        taskset -c "$pin" numactl --membind=0 "$@"
    fi
}

drop_caches() {
    sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
}

run_one() { # run_one <dir> <iteration> <mode> <label> <cpus> <kind> <binary> [<threads>]
    dir=$1 iteration=$2 mode=$3 label=$4 pin=$5 kind=$6 binary=$7
    passes=1
    [ "$mode" = cold ] && passes=0
    # No in-process repeat on the 1,000-block window: one base/base pass takes minutes.
    [ "$dir" = "$out/results/window1000" ] && passes=0
    case $kind in
    nf) set -- "$binary" replay bench "$archive" "$passes" --recovery-threads "$8" ;;
    nf-evm) set -- "$binary" replay bench "$archive" "$passes" --evm-only ;;
    base) set -- "$binary" "$archive" "$parent" "$passes" ;;
    base-evm) set -- "$binary" "$archive" "$parent" "$passes" --evm-only "$prestate" ;;
    base-node-evm)
        set -- "$binary" "$archive" "$parent" "$passes" --evm-only "$prestate" --node ;;
    esac
    [ "$mode" = cold ] && drop_caches
    launch "$pin" /usr/bin/time -v -o "$dir/time.tmp" "$@" >"$dir/bench.tmp" ||
        { echo "$label $mode run $iteration failed" >&2; exit 1; }
    awk -v tag="cfg=$label mode=$mode iter=$iteration" \
        '/^BENCH/ { sub(/^BENCH /, "BENCH " tag " "); print }' "$dir/bench.tmp" >>"$dir/round.tmp"
    awk -v label="$label" '/Maximum resident set size/ { print label, $NF }' \
        "$dir/time.tmp" >>"$dir/rss.txt"
}

run_workload() { # run_workload <name> <archive> <parent json> <runs> <full|headline>
    name=$1 archive=$2 parent=$3 count=$4
    dir=$out/results/$name
    rm -rf "$dir"
    mkdir -p "$dir"
    configs "$5" >"$dir/configs.txt"
    total=$(wc -l <"$dir/configs.txt")
    discarded=0
    iteration=1
    while [ "$iteration" -le "$count" ]; do
        before=$(etc/bench/env.sh --check)
        : >"$dir/round.tmp"
        # Rotate the start so no configuration always runs first.
        start=$(((iteration - 1) % total + 1))
        { tail -n +"$start" "$dir/configs.txt"; head -n $((start - 1)) "$dir/configs.txt"; } |
            while read -r label pin kind binary threads_arg; do
                for mode in cold warm; do
                    run_one "$dir" "$iteration" "$mode" "$label" "$pin" "$kind" "$binary" \
                        "${threads_arg:-0}"
                done
            done
        after=$(etc/bench/env.sh --check)
        echo "$name round $iteration/$count: $before -> $after"
        mhz_before=$(echo "$before" | sed 's/.*mhz=\([0-9]*\).*/\1/')
        mhz_after=$(echo "$after" | sed 's/.*mhz=\([0-9]*\).*/\1/')
        if [ $((mhz_before - mhz_after)) -gt $((mhz_before / 100)) ] ||
            [ $((mhz_after - mhz_before)) -gt $((mhz_before / 100)) ]; then
            echo "$name round $iteration: frequency moved, discarded" | tee -a "$dir/discarded.txt"
            discarded=$((discarded + 1))
            [ "$discarded" -le "$count" ] || { echo "frequency unstable" >&2; exit 1; }
            continue
        fi
        cat "$dir/round.tmp" >>"$dir/results.txt"
        iteration=$((iteration + 1))
    done
    rm -f "$dir/round.tmp" "$dir/bench.tmp" "$dir/time.tmp"
}

summarize() { # summarize <name>
    dir=$out/results/$1
    t=t$threads
    echo "== results: $1"
    if [ "$1" = evm100 ]; then
        zig run -OReleaseSafe etc/bench/stats.zig -- \
            --pair nf-safe-native-evm/base-node-native-evm \
            --pair nf-fast-native-evm/base-node-native-evm \
            --pair nf-safe-native-evm/base-maxperf-native-evm \
            --pair nf-fast-native-evm/base-maxperf-native-evm \
            --pair nf-safe-native-evm/base-release-native-evm <"$dir/results.txt"
    else
        zig run -OReleaseSafe etc/bench/stats.zig -- \
        --pair "nf-safe-native-t0/base-maxperf-native" \
        --pair "nf-safe-native-$t/base-maxperf-native" \
        --pair "nf-safe-native-$t/nf-safe-native-t0" \
        $( [ "$(wc -l <"$dir/configs.txt")" -gt 3 ] && echo \
            --pair "nf-fast-native-$t/nf-safe-native-$t" \
            --pair "nf-safe-native-t0/nf-safe-baseline-t0" \
            --pair "base-maxperf-native/base-release-generic" \
            --pair "nf-safe-baseline-t0/base-maxperf-generic" \
            --pair "nf-fast-native-$t/base-release-generic" ) \
            <"$dir/results.txt"
    fi
    echo "| configuration | peak RSS MiB |"
    echo "| --- | ---: |"
    sort -k1,1 -k2,2n "$dir/rss.txt" | awk '{ max[$1] = $2 } END {
        for (label in max) printf "| %s | %.0f |\n", label, max[label] / 1024 }' | sort
    [ -f "$dir/discarded.txt" ] && echo "discarded rounds: $(wc -l <"$dir/discarded.txt")"
    echo
}

isolate() { # isolate <cpus>: confine every top-level unit but bench.slice to <cpus>
    # An empty AllowedCPUs does not widen a cpuset again, so lifting passes every CPU.
    for path in /sys/fs/cgroup/*.slice /sys/fs/cgroup/*.scope; do
        unit=$(basename "$path")
        [ "$unit" = bench.slice ] && continue
        sudo systemctl set-property --runtime "$unit" AllowedCPUs="$1"
    done
}
all_cpus=0-$(($(nproc --all) - 1))

etc/bench/env.sh
if [ "${BENCH_SKIP_BUILD:-0}" != 1 ]; then
    build_needlefish
    build_base
fi
if [ "${BENCH_ISOLATE:-0}" = 1 ]; then
    isolate "$system_cpus"
    trap 'isolate "$all_cpus"' EXIT
fi

echo "== archives"
parent_json 53715983 "$out/parent-fixture.json"
for workload in $workloads; do
    case $workload in
    fixture)
        run_workload fixture "$fixture" "$out/parent-fixture.json" "$runs" full ;;
    window100)
        file=$(archive "$window_first" "$window_count")
        parent_json "$window_first" "$out/parent-$window_first.json"
        run_workload window100 "$file" "$out/parent-$window_first.json" "$runs" full ;;
    window1000)
        file=$(archive "$long_first" "$long_count")
        parent_json "$long_first" "$out/parent-$long_first.json"
        run_workload window1000 "$file" "$out/parent-$long_first.json" "$runs_long" headline ;;
    evm100)
        file=$(archive "$window_first" "$window_count")
        parent_json "$window_first" "$out/parent-$window_first.json"
        # The flat pre-state both EVM-only harnesses load (needlefish records it).
        prestate=$out/prestate-$window_first-$window_count.nfps
        [ -f "$prestate" ] || "$(nf_bin ReleaseSafe native)" replay bench "$file" 0 \
            --evm-only --prestate-out "$prestate" >/dev/null
        run_workload evm100 "$file" "$out/parent-$window_first.json" "$runs" evm ;;
    *)
        echo "unknown workload $workload" >&2
        exit 1 ;;
    esac
done
etc/bench/env.sh --check

for workload in $workloads; do
    summarize "$workload"
done
echo "== binaries (bytes)"
wc -c "$(nf_bin ReleaseSafe native)" "$(base_bin maxperf native)"
