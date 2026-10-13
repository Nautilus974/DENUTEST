#!/usr/bin/env bash
# analyze.sh — static + dynamic analysis of our OWN demo binary, to show what
# an analyst sees and why virtualization/obfuscation raises the cost. Operates
# only on build/at_demo (a program we built from source in this repo).
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=build/at_demo
[ -x "$BIN" ] || { echo "build first: cmake -S . -B build && cmake --build build"; exit 1; }

echo "############ STATIC ANALYSIS ############"
echo "## file / sections ##"
readelf -h "$BIN" | sed -n '1,6p' || true
echo
echo "## symbols for our functions (nm) ##"
# Native checksum symbols are visible; the VM's work hides behind run().
nm -C "$BIN" 2>/dev/null | grep -Ei 'integrity|vm::|keyed|crc32' || echo "(stripped?)"
echo
echo "## the embedded FNV/splitmix constants are visible in native code ##"
# These literals are the kind of fingerprint a static analyst greps for.
objdump -d -C "$BIN" 2>/dev/null | grep -iE '1099511628211|0xff51afd7|ed558ccd' | head -5 \
  || echo "(constants folded/not shown at this opt level)"
echo
echo "## disassembly size of native keyed_checksum vs the VM run() dispatch ##"
for sym in 'keyed_checksum' 'vm.*run'; do
  n=$(objdump -d -C "$BIN" 2>/dev/null \
      | awk -v s="$sym" 'BEGIN{p=0} /^[0-9a-f]+ </{p=($0 ~ s)} p&&/\t/{c++} END{print c+0}')
  printf "    %-28s ~%s instructions\n" "$sym" "$n"
done

echo
echo "############ DYNAMIC ANALYSIS ############"
# NOTE: strace is itself a tracer, so the demo's own anti-debug signals will
# report 'triggered' here — that is the point. We do NOT pass -f: following the
# demo's self_ptrace child fork would deadlock against its PTRACE_TRACEME.
echo "## syscall summary of a clean run (strace -c) ##"
strace -c "$BIN" >/dev/null 2>/tmp/at_strace.txt || true
sed -n '1,12p' /tmp/at_strace.txt
echo
echo "## the /proc files our integrity + anti-debug code reads ##"
strace -e trace=openat "$BIN" 2>/tmp/at_open.txt >/dev/null || true
grep -E 'proc/self/(maps|status)' /tmp/at_open.txt | head || true

echo
echo "Done. See docs/ for interpretation."
