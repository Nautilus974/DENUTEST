# Static Executable-Analysis Laboratory (Step 2)

A read-only static inspector for ELF and (limited) PE images, plus controlled
Debug/Release experiments. Everything here **inspects** bytes we own; nothing is
executed or loaded from an analyzed file.

> **Scope & honesty.** ELF is the primary, fully-tested path and is cross-checked
> against `readelf`/`nm`/`objdump` on real binaries. PE support is limited to the
> header/section/data-directory/import fields actually exercised by a hand-built
> fixture — **no real PE was available** (no MinGW/MSVC in this environment), so
> PE behavior is *not* validated against real-world Windows binaries. See
> "Windows features not validated" below. No Denuvo claim is made here.

---

## 1. Tool architecture

```
src/exe_inspect.hpp / .cpp     the inspector library (namespace at_demo::exe)
src/exe_inspect_main.cpp       CLI front end `exe_inspect <file> ...`
tests/test_exe_inspect.cpp     unit tests (Reader, fixtures, real ELF)
samples/known_functions.cpp    a subject program for the experiments
scripts/static_experiments.sh  Debug vs Release comparison via readelf/nm/objdump
```

The design has one safety chokepoint: a **bounds-checked `Reader`**. It owns the
`(data, size)` pair and is the only thing that touches raw bytes. Every accessor
(`u8/u16/u32/u64/cstr/match`) validates its range first and returns
`std::optional` (or `false`) when out of range — it never reads past the buffer.
`in_bounds(off, len)` is overflow-safe:

```cpp
bool in_bounds(uint64_t off, uint64_t len) const {
    if (len > size_) return false;              // len alone too big
    return off <= uint64_t(size_) - len;        // off+len <= size, no wrap
}
```

Parsers (`parse_elf`, `parse_pe`) accumulate findings into a `Report`:
`errors` (fatal → `malformed=true`) and `warnings` (non-fatal anomalies). They
**never throw out of `analyze`** and never dereference unchecked offsets, so
analyzing truncated or hostile input is a supported, test-covered case.

Reading guarantees: `analyze(const uint8_t*, size_t)` works on an in-memory
buffer; `analyze_file()` opens the path with `std::ifstream` in binary mode
(read-only) and feeds the bytes to `analyze`. There is no `exec`, no `dlopen`,
no `system`, no mapping as executable anywhere in the module.

---

## 2. Binary-format structures documented

### 2.1 ELF (Linux) — essentials actually parsed

| Structure | Fields used | Validation performed |
|-----------|-------------|----------------------|
| **ELF header** (`Ehdr`) | magic, `EI_CLASS` (32/64), `EI_DATA` (LE/BE), `e_type`, `e_machine`, `e_entry`, `e_phoff/shoff`, `e_phentsize/num`, `e_shentsize/num`, `e_shstrndx` | magic; class ∈{1,2}; data ∈{1,2}; header fits; table offsets+sizes in range (overflow-safe); `e_shstrndx < e_shnum` |
| **Section headers** (`Shdr`) | `sh_name`, `sh_type`, `sh_flags`, `sh_addr`, `sh_offset`, `sh_size`, `sh_link`, `sh_entsize` | each `sh_offset+sh_size ≤ file` (except `SHT_NOBITS`); names resolved via `.shstrtab` with bounds |
| **Program headers** (`Phdr`, segments) | `p_type`, `p_offset`, `p_vaddr`, `p_filesz`, `p_memsz`, `p_flags` | `p_offset+p_filesz ≤ file` |
| **Symbols** (`.symtab`/`.dynsym`) | `st_name`, `st_info` (type), count = `sh_size/sh_entsize` | entries bounded; names via linked `strtab` with bounds; counts functions/objects/named |
| **Relocations** | *noted, not decoded* — see limits | — |

### 2.2 PE (Windows) — limited, tested subset

| Structure | Fields used | Validation |
|-----------|-------------|-----------|
| **DOS header** | `MZ` magic, `e_lfanew` | `e_lfanew` in range |
| **PE signature** | `PE\0\0` at `e_lfanew` | present |
| **COFF file header** | `Machine`, `NumberOfSections`, `SizeOfOptionalHeader`, `Characteristics` | fits |
| **Optional header** | `Magic` (PE32/PE32+), `AddressOfEntryPoint`, `ImageBase`, `NumberOfRvaAndSizes` | magic ∈ {0x10b,0x20b}; `NumberOfRvaAndSizes` clamped ≤16 |
| **Data directories** | 16 `(RVA,size)` entries, names | bounded reads |
| **Section table** | `Name`, `VirtualSize/Address`, `SizeOfRawData`, `PointerToRawData`, `Characteristics` | table in range; each raw range `≤ file` |
| **Imports** | `IMAGE_IMPORT_DESCRIPTOR.Name` → DLL names, via RVA→offset mapping | RVA mapped through sections; descriptor walk capped; names bounded |
| **Exports / relocations** | *not parsed* — out of tested scope | — |

### 2.3 File vs. loaded image — why offsets ≠ addresses

A file on disk and the image the OS loader builds in memory are **not** the same
layout:

- **ELF:** section/segment `sh_offset`/`p_offset` are *file* offsets; `sh_addr`/
  `p_vaddr` are the *virtual addresses* after loading. `SHT_NOBITS` (`.bss`)
  occupies memory (`memsz`) but **zero file bytes** (`filesz`), so `p_memsz ≥
  p_filesz`. PIE/`ET_DYN` images are relocated by a load bias chosen at runtime.
- **PE:** the section table gives both `PointerToRawData` (file offset) and
  `VirtualAddress` (an **RVA**, relative to `ImageBase`). On-disk raw size and
  in-memory virtual size differ (alignment, uninitialized tails). Resolving an
  import table therefore requires an **RVA→file-offset** translation through the
  section table — which is exactly what the inspector does and tests.

The inspector reports **file-offset** ranges (what exists on disk); it does not
simulate loading, apply relocations, or compute runtime addresses.

---

## 3. Build & reproduce

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure      # includes the exe_inspect suite

# Inspect any ELF/PE we own (read-only):
./build/exe_inspect ./build/exe_inspect          # the tool on itself
./build/exe_inspect /bin/ls                       # any local ELF

# Controlled Debug vs Release experiments (compiles samples/known_functions.cpp):
./scripts/static_experiments.sh
```

---

## 4. Observed results (real output, this environment)

### 4.1 The inspector on a real ELF (itself), cross-checked
```
format      : ELF
class        : ELF64
machine      : x86-64 (AMD64)
type         : DYN (shared object / PIE)
entry        : 0x3820
sections     : 39
symbols      : 699 in .symtab (funcs=663 objs=20 named=697)
```
Ground-truth cross-check:

| field | exe_inspect | reference tool | match |
|-------|-------------|----------------|:----:|
| entry | `0x3820` | `readelf -h` → `0x3820` | ✓ |
| machine | x86-64 | `readelf -h` → Advanced Micro Devices X86-64 | ✓ |
| sections (`e_shnum`) | 39 | `readelf -h` → 39 | ✓ |
| `.symtab` entries | 699 | `readelf -s` → "contains 699 entries" | ✓ |

### 4.2 The inspector on the PE32+ fixture
```
format      : PE
class       : PE32+
machine     : x86-64 (AMD64)
type        : EXE (image)
entry       : 0x1000
image base  : 0x140000000
sections    : 1
  [0] .idata  off=0x400 size=0x200 vaddr=0x1000
data dirs   :
    Import: rva=0x1000 size=0x28
imports     : 1 DLL(s)
    - KERNEL32.dll
```
This is a **hand-built fixture** (`tests/test_exe_inspect.cpp::make_min_pe`), not
a real Windows binary. It exercises the DOS/PE/COFF/optional headers, the section
table, the import data directory, and the RVA→offset import-name resolution.

### 4.3 Malformed / truncated inputs are reported, never crashed
```
truncated ELF (64 bytes):  ERROR section header table out of bounds ... → exit 1
junk bytes              :  ERROR unrecognized format (no ELF or MZ/PE magic) → exit 1
missing file            :  ERROR cannot open file: ... → exit 1
```
The unit suite additionally confirms: invalid `EI_CLASS`/`EI_DATA`, huge
`e_shnum`/section counts (overflow-safe rejection), out-of-range `e_shstrndx`
(non-fatal warning), bad PE signature, `e_lfanew` past EOF, and a 4-byte MZ stub
— all reported cleanly with no crash and no sanitizer error.

### 4.4 Debug vs Release experiment (real `scripts/static_experiments.sh` output)
```
### 1. Symbol counts (nm)
  debug:34  release:33  stripped:0 ("no symbols")
### 2. Is the leaf 'mix' inlined?  (static, internal linkage)
  debug  : NOT inlined (symbol present=1, 1 call to mix in sum_of_mixes)
  release: inlined     (symbol present=0, 0 calls to mix in sum_of_mixes)
### 3. sum_of_mixes disassembly size (objdump)
  debug:~26 instrs   release:~25 instrs
### 4/5. Sections (readelf == exe_inspect)
  debug:37==37   release:31==31   stripped:29==29
  stripped symbol table: exe_inspect falls back to .dynsym (8), matches readelf
```
**Observations (measured, not assumed):**
- Optimization **inlines** the leaf `mix` at `-O2`: it vanishes as a symbol and
  the `call` disappears from `sum_of_mixes`. The *instruction count barely
  changes* (26→25) — the visible evidence of inlining is the missing call, not a
  size blow-up. Conclusions drawn purely from raw instruction counts would miss
  this.
- **Stripping** removes `.symtab`/`.strtab`: `nm` reports "no symbols" and
  name-based analysis fails, while sections and code remain. `.dynsym` survives
  (dynamic linking needs it), which is why the inspector still finds 8 symbols
  there.
- `exe_inspect`'s section counts match `readelf` **exactly** for all three
  builds.

---

## 5. Limits of static analysis (honest)

- **Names and types are not in the machine code.** They live in symbol/debug
  tables that optimization and stripping remove. After `strip`, the algorithm is
  still there but its names, parameter types, and source structure are gone.
- **Inlining erases call boundaries.** A function that was `call`ed at `-O0` is
  dissolved into its caller at `-O2`; you cannot recover the original function
  decomposition from the bytes alone.
- **The inspector parses structure, not behavior.** It does not disassemble,
  emulate, relocate, or follow control flow. It will tell you a `.text` section
  exists and how big it is, not what it computes.
- **Relocations, exports, and PE resource/CLR/TLS directories are not decoded.**
  Only the fields in §2 are parsed; everything else is reported at the
  directory-entry level or not at all.
- **A valid parse is not a trust statement.** "Not malformed" means the headers
  are internally consistent and in-bounds, nothing more.

## 6. Windows features not validated

- No real PE/Windows binary was analyzed. PE parsing is validated **only** against
  the hand-built PE32+ fixture, covering the fields in §2.2.
- Exports, base relocations, resources, TLS, delay imports, CLR headers, and
  bound imports are **not** parsed.
- Import parsing resolves **DLL names** only; it does not walk the thunk arrays to
  list imported function names.
- The `#ifdef _WIN32` self-location path in the separate `integrity` module
  remains documentation-only (consistent with `docs/03-independent-audit.md`).

Treat all PE results as "works on a controlled fixture," not "validated on
Windows."
