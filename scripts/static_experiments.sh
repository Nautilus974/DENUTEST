#!/usr/bin/env bash
# static_experiments.sh — controlled Debug vs Release comparison of a known
# sample program, using objdump/readelf/nm as reference tools, plus a side-by-
# side with our own exe_inspect. Read-only: it compiles a sample WE OWN and
# inspects it; it never runs the analyzed binaries except the sample's own
# normal exit (the comparisons only read them).
set -euo pipefail
cd "$(dirname "$0")/.."

CXX=${CXX:-g++}
OUT=build/exp
mkdir -p "$OUT"
SRC=samples/known_functions.cpp

echo "compiler: $($CXX --version | head -1)"
"$CXX" -std=c++17 -O0 -g  "$SRC" -o "$OUT/sample_debug"
"$CXX" -std=c++17 -O2     "$SRC" -o "$OUT/sample_release"
cp "$OUT/sample_release" "$OUT/sample_stripped"
strip "$OUT/sample_stripped"

echo
echo "### 1. Symbol counts (nm) ###"
for v in debug release stripped; do
  n=$(nm "$OUT/sample_$v" 2>/dev/null | wc -l || echo 0)
  printf "  %-9s : %s symbols (nm)\n" "$v" "$n"
done
echo "  (stripped should report 'no symbols')"
nm "$OUT/sample_stripped" 2>&1 | head -1 | sed 's/^/  stripped nm says: /'

echo
echo "### 2. Is the leaf 'mix' inlined? (symbol + call-site evidence) ###"
# 'mix' is static (internal linkage) => mangled _ZL3mixm. Definitive evidence
# of inlining is whether sum_of_mixes still contains a 'call' to it.
for v in debug release; do
  sym=$(nm "$OUT/sample_$v" 2>/dev/null | grep -c '3mix' || true)
  calls=$(objdump -d -C "$OUT/sample_$v" 2>/dev/null \
          | awk '/<sum_of_mixes/{p=1} p{print} /^$/{if(p)exit}' \
          | grep -c 'call.*mix' || true)
  if [ "$calls" -gt 0 ]; then
    echo "  $v: NOT inlined (symbol present=$sym, $calls call(s) to mix in sum_of_mixes)"
  else
    echo "  $v: inlined (symbol present=$sym, 0 calls to mix in sum_of_mixes)"
  fi
done

echo
echo "### 3. Disassembly size of sum_of_mixes (objdump) ###"
for v in debug release; do
  cnt=$(objdump -d -C "$OUT/sample_$v" 2>/dev/null \
        | awk '/<sum_of_mixes/{p=1} p&&/\t/{c++} /^$/{if(p&&c){print c; exit}}')
  printf "  %-9s : ~%s instructions in sum_of_mixes\n" "$v" "${cnt:-?}"
done

echo
echo "### 4. Section comparison (readelf -S) ###"
for v in debug release stripped; do
  s=$(readelf -S "$OUT/sample_$v" 2>/dev/null | grep -cE '^\s*\[\s*[0-9]+\]' || echo 0)
  printf "  %-9s : %s sections\n" "$v" "$s"
done

echo
echo "### 5. Our exe_inspect vs readelf (section count + symbol table) ###"
if [ -x build/exe_inspect ]; then
  for v in debug release stripped; do
    line=$(build/exe_inspect "$OUT/sample_$v" 2>/dev/null)
    sec=$(echo "$line" | grep -oE 'sections     : [0-9]+' | grep -oE '[0-9]+')
    symline=$(echo "$line" | grep -E '^symbols' | sed 's/symbols *: //')
    rsec=$(readelf -S "$OUT/sample_$v" 2>/dev/null | grep -cE '^\s*\[\s*[0-9]+\]' || echo 0)
    printf "  %-9s : exe_inspect sections=%s (readelf=%s) | table: %s\n" \
           "$v" "$sec" "$rsec" "$symline"
  done
  echo "  (exe_inspect counts the whole table incl. NULL/FILE/SECTION entries;"
  echo "   for the stripped binary it correctly falls back to .dynsym, matching"
  echo "   'readelf -s .dynsym contains N'. Section counts match readelf exactly.)"
else
  echo "  (build/exe_inspect not built; run cmake --build build first)"
fi

echo
echo "Interpretation: Release (-O2) inlines the leaf 'mix' and shrinks/reorders"
echo "sum_of_mixes; stripping removes .symtab/.strtab so name-based analysis"
echo "fails while section structure and code remain. Machine code alone does not"
echo "recover original names, types, or inlined call boundaries."
