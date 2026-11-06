#!/bin/sh
# Prints the benchmark environment block for docs/BENCHMARKS.md: hardware by model, kernel,
# toolchains, CPU frequency control, core isolation and load. Nothing machine-identifying
# (no hostname, user, paths or addresses).
#
# usage: etc/bench/env.sh [--check]
#   (no flag)  the full environment block
#   --check    one `ENV` line (load, frequency, temperature) for before and after each batch;
#              etc/bench/reproduce.sh compares the frequencies and discards a batch that moved
set -eu

value() { # value <file>: its contents, or "unavailable"
    if [ -r "$1" ]; then cat "$1"; else echo unavailable; fi
}

# Mean of the per-CPU current frequencies in MHz: cpufreq when the kernel exposes it, else
# /proc/cpuinfo (a VM reports its nominal clock there).
frequency_mhz() {
    if [ -r /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq ]; then
        cat /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_cur_freq |
            awk '{ s += $1; n++ } END { printf "%.0f", s / n / 1000 }'
    else
        awk -F: '/^cpu MHz/ { s += $2; n++ } END { printf "%.0f", s / n }' /proc/cpuinfo
    fi
}

temperature_c() { # Hottest thermal zone, or "unavailable"
    zones=$(ls -d /sys/class/thermal/thermal_zone* 2>/dev/null || true)
    [ -n "$zones" ] || { echo unavailable; return; }
    cat /sys/class/thermal/thermal_zone*/temp | sort -n | tail -1 | awk '{ printf "%.1f", $1 / 1000 }'
}

if [ "${1:-}" = --check ]; then
    echo "ENV load=$(cut -d' ' -f1 /proc/loadavg) mhz=$(frequency_mhz) temp_c=$(temperature_c)"
    exit 0
fi

echo "== environment"
echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "needlefish: $(git rev-parse HEAD 2>/dev/null || echo unknown)$(git diff --quiet 2>/dev/null || echo ' (dirty)')"
[ -n "${BENCH_BASE_COMMIT:-}" ] && echo "base/base: $BENCH_BASE_COMMIT"
echo "zig: $(zig version 2>/dev/null || echo unavailable)"
echo "rustc: $(cd "${BENCH_RUST_DIR:-.}" 2>/dev/null && rustc --version 2>/dev/null || echo unavailable)"
echo "kernel: $(uname -sr) $(uname -m)"
if [ -r /etc/os-release ]; then
    echo "os: $(. /etc/os-release && echo "$PRETTY_NAME")"
fi
virt=$(systemd-detect-virt 2>/dev/null || true)
echo "virtualization: ${virt:-unknown}"
lscpu | awk -F: '
    /^Model name/ { gsub(/^ +/, "", $2); print "cpu: " $2 }
    /^Socket\(s\)/ { gsub(/ /, "", $2); sockets = $2 }
    /^Core\(s\) per socket/ { gsub(/ /, "", $2); cores = $2 }
    /^Thread\(s\) per core/ { gsub(/ /, "", $2); threads = $2 }
    /^NUMA node\(s\)/ { gsub(/ /, "", $2); numa = $2 }
    /^L3 cache/ { gsub(/^ +/, "", $2); l3 = $2 }
    END {
        print "topology: " sockets " socket(s) x " cores " core(s) x " threads " thread(s)"
        print "numa nodes: " numa
        if (l3 != "") print "l3: " l3
    }'
echo "smt: $(value /sys/devices/system/cpu/smt/control)"
for cpu in /sys/devices/system/cpu/cpu[0-9]*; do
    echo "  $(basename "$cpu") siblings $(value "$cpu/topology/thread_siblings_list")"
done
awk '/^MemTotal/ { printf "ram: %.1f GiB\n", $2 / 1048576 }' /proc/meminfo
lsblk -dno NAME,MODEL,SIZE,ROTA 2>/dev/null | awk '{ print "disk: " $0 }' || true
echo "governor: $(value /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
echo "intel_pstate no_turbo: $(value /sys/devices/system/cpu/intel_pstate/no_turbo)"
echo "cpufreq boost: $(value /sys/devices/system/cpu/cpufreq/boost)"
echo "frequency: $(frequency_mhz) MHz"
echo "isolated cpus (kernel): $(value /sys/devices/system/cpu/isolated)"
echo "benchmark cpus: ${BENCH_CPUS:-unset} (other work: ${BENCH_SYSTEM_CPUS:-unset})"
echo "perf hardware counters: $(perf stat -x, -e instructions true 2>&1 |
    grep -q 'not supported\|<not' && echo unavailable || echo available)"
echo "load: $(cut -d' ' -f1-3 /proc/loadavg)"
echo "temperature: $(temperature_c) C"
