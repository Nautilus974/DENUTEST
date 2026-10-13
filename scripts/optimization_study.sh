#!/usr/bin/env bash
# optimization_study.sh — build the benchmark at -O0/-O1/-O2/-O3 and compare,
# quantifying how compiler optimization affects both the native checksum and
# the virtualized interpreter. Emits a table consumed by docs/02-results.md.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=build/opt
mkdir -p "$OUT"
CXX=${CXX:-g++}
BYTES=${1:-8192}
ITERS=${2:-3000}

echo "compiler: $($CXX --version | head -1)"
echo "workload: bytes=$BYTES iters=$ITERS"
echo
printf "%-6s | %-14s %-14s %-18s %-12s\n" "opt" "crc32 ns/B" "keyed ns/B" "VM ns/B" "VM slowdown"
printf -- "-------+------------------------------------------------------------------\n"

for O in O0 O1 O2 O3; do
  "$CXX" -std=c++17 -$O -I src \
     src/integrity.cpp src/vm_mini.cpp bench/bench_vm.cpp \
     -o "$OUT/bench_$O" 2>/dev/null
  line=$("$OUT/bench_$O" "$BYTES" "$ITERS")
  crc=$(echo "$line"  | awk '/^crc32/{print $4}')
  keyed=$(echo "$line"| awk '/keyed_checksum\(native\)/{print $4}')
  vm=$(echo "$line"   | awk '/keyed_checksum\(VM\)/{print $4}')
  slow=$(echo "$line" | awk -F'= ' '/slowdown/{print $2}')
  printf "%-6s | %-14s %-14s %-18s %-12s\n" "-$O" "$crc" "$keyed" "$vm" "$slow"
done
echo
echo "Interpretation: optimization speeds up BOTH paths. The virtualization tax"
echo "is largest at -O0 (the interpreter's dispatch/bookkeeping is un-optimized)"
echo "and drops sharply once -O1+ tightens both paths, then settles. The exact"
echo "ratio is machine- and run-dependent; re-run to see the spread. The durable"
echo "fact is order-of-magnitude: a VM'd routine costs single-digit-to-low-double"
echo "-digit x its native form, which is why only hot-but-small routines are VM'd."
