# Independent Technical Audit

**Auditor stance.** This audit treats the README and `docs/01`–`docs/02` claims
as *unverified* until reproduced. Every result below was observed on this
project's Linux x86-64 container on **2026-10-13**. Nothing is reported as
"validated" unless its output was observed; no conclusion was softened to look
better. Where a claim failed to reproduce, it is recorded as a finding and the
source was corrected.

- **Host:** Linux 6.18 x86-64, Ubuntu 24.04 container.
- **Toolchain observed:** g++ 13.3.0, clang++ 18.1.3, cmake 3.28.3, gdb 15.1,
  binutils 2.42 (`objdump`/`nm`/`readelf`), strace 6.8, valgrind 3.22.
  `perf`, `ltrace`, MinGW: **absent**. Clang compiler-rt (ASan runtime):
  **absent** → sanitizer runs used GCC.
- **Commit audited:** `5de20a2`, confirmed present on
  `origin/claude/denuvo-anti-tampering-analysis-iu2s38` (local == remote).

---

## A. Repository verification

```
git status / git log --oneline --stat / git ls-remote --heads origin
git rev-parse HEAD  == git rev-parse origin/<branch>  == 5de20a2
```

- Single commit `5de20a2`; working tree clean; local HEAD equals remote. The
  "pushed" claim is **confirmed**.
- 17 tracked files; `build/` correctly git-ignored.
- `grep -rniE 'todo|fixme|xxx|hack|stub|unimplemented'`: only two "stub"
  mentions, both the documented `#ifdef _WIN32` `self_text_region()` path and a
  descriptive comment. **No hidden TODOs / dead stubs in active code.**
- **CMake / options / deps:** `grep` for `find_package|FetchContent|ExternalProject`
  → none. **Zero external dependencies.** Standard: C++17, `-Wall -Wextra`,
  default build type Release. Verified by reading `CMakeLists.txt`.

## B. Build & test matrix (observed)

| Compiler | Build | Warnings | CTest |
|----------|-------|:--------:|:-----:|
| g++ 13     | Debug   | 0 | 100% (4/4) |
| g++ 13     | Release | 0 | 100% (4/4) |
| clang++ 18 | Debug   | 0 | 100% (4/4) |
| clang++ 18 | Release | 0 | 100% (4/4) |

Commands:
```
cmake -S . -B <dir> -DCMAKE_C_COMPILER=<cc> -DCMAKE_CXX_COMPILER=<cxx> -DCMAKE_BUILD_TYPE=<bt>
cmake --build <dir> -j4
ctest --test-dir <dir>
```
All four configurations **built clean with zero warnings and passed all four
tests** (`integrity`, `anti_debug`, `demo_clean`, `demo_tamper`). Observed, not
assumed.

## C. Undefined-behavior / memory audit (sanitizers)

GCC `-fsanitize=address,undefined -fno-sanitize-recover=all`:

- Full CTest suite under ASan+UBSan: **4/4 pass, no diagnostics.**
- Direct runs of `test_integrity`, `test_anti_debug`, and `at_demo --tamper`
  under the sanitizer produced **zero** sanitizer output; `--tamper` exits `2`
  via the genuine tamper-detection path (verified it is not an ASan abort masked
  by CTest's `WILL_FAIL`).

So the **exercised** code paths — including the `/proc/self/maps` self-`.text`
checksum, the VM pointer reconstruction, and the `fork`+`PTRACE_TRACEME` probe —
are free of detectable UB / invalid memory access.

**However**, auditing `vm::run` revealed it trusted its bytecode. Two malformed
inputs were crafted and confirmed to be **real UB** under UBSan/ASan (see §F1).

## D. Benchmark audit (raw measurements)

Each cell is a separate observed run of `bench_vm 8192 3000`.

| Config | native total (ns) | VM total (ns) | slowdown |
|--------|------------------:|--------------:|---------:|
| g++ Release r1 | 17457.6 | 123606.7 | 7.1× |
| g++ Release r2 | 17753.7 | 122994.2 | 6.9× |
| g++ Release r3 | 17747.4 | 122913.3 | 6.9× |
| g++ Debug  r1  | 45419.2 | 525467.2 | 11.6× |
| g++ Debug  r2  | 45000.9 | 548358.1 | 12.2× |
| g++ Debug  r3  | 48800.3 | 510940.9 | 10.5× |
| clang Release r1 | — | — | 7.2× |
| clang Release r2 | — | — | 7.3× |

`scripts/optimization_study.sh 8192 3000` (one observed run):

| opt | crc32 ns/B | keyed native ns/B | keyed VM ns/B | slowdown |
|-----|-----------:|------------------:|--------------:|---------:|
| -O0 | 4.102 | 5.710 | 82.747 | 14.5× |
| -O1 | 2.860 | 2.232 | 16.138 | 7.2× |
| -O2 | 2.816 | 2.106 | 12.917 | 6.1× |
| -O3 | 2.840 | 2.119 | 12.505 | 5.9× |

**Verdicts:**
- **Slowdown claim ("~6–13×").** Supported and slightly widened by observation:
  measured range is **5.9× (-O3)** to **~14.5× (-O0)**, with optimized Release
  builds clustering at **~7×** on both GCC and Clang. The original README
  headline "8.9×" was a single-run figure; the honest statement is a *range*,
  which `docs/02` already frames as machine-dependent. No correction needed
  beyond noting the range; `-O0` can exceed 13×.
- **"Compares equivalent computations."** Confirmed: the test suite asserts
  native == VM bit-for-bit, and an independent **5000-case random fuzz**
  (lengths 0–1999, random seeds) produced **0 mismatches** (§E). The benchmark
  runs both over the same buffer and seed.
- **"Prevents optimizations that remove the measured work."** Confirmed
  empirically: native checksum time **scales linearly** with buffer size
  (2.09–2.28 ns/byte across 1 KiB→16 KiB). Had the `volatile sink` guard failed
  and the compiler hoisted the constant-input computation out of the 2000-iter
  loop, total time would not track size. It does, so the work is really measured.
- **Disassembly-readability claim.** Partially overstated; corrected (§F3).

## E. Edge-case / equivalence testing (observed)

- **Equivalence fuzz** (5000 random cases incl. empty region):
  `keyed_checksum(native) == vm::run(build_checksum_program(...))` in **all**
  cases.
- **Empty region** (`len == 0`): native == VM (also a unit test).
- **CRC-32 vector:** `crc32("123456789") == 0xCBF43926` — unit test passes
  (canonical IEEE value).
- **Tamper detection:** single-bit flip detected; restoring the byte re-verifies
  (unit test passes; demo exits 2 under `--tamper`).

## F. Findings

### F1 — Latent UB in `vm::run` on malformed bytecode — *Low severity, FIXED*
`run()` indexed an 8-element register array with a `uint8_t` operand and shifted
by `ShrI.imm` without bounds. Crafted programs confirmed real UB under
sanitizers:
```
vm_mini.cpp:26  runtime error: shift exponent 99 is too large for 64-bit type
vm_mini.cpp:15  AddressSanitizer: store ... out-of-bounds (register index 200)
```
**Reachability:** only via a hand-built malformed `Program`; the shipped
`build_checksum_program` emits only register indices 0–6 and shifts 29/33, so no
shipped path triggers it. Severity **low** (latent), but `run()` is a public
API whose header stated no precondition.
**Fix applied:** a one-time `is_well_formed()` validation *before* the dispatch
loop rejects out-of-range register indices and shifts ≥ 64, returning a no-op
(`0`, `steps=0`) instead of invoking UB. Placed outside the hot loop so
benchmark semantics are unchanged. Header now documents the precondition.
**Post-fix verification:** malformed probes return `0` with **no** sanitizer
error; equivalence fuzz still **0 mismatches**; all four build configs + the
ASan/UBSan suite still pass.

### F2 — Anti-debug signal table / README not reproducible as written — *Medium, FIXED*
`docs/02 §2` and the README claimed plain `strace` trips **both** `tracer_pid`
and `self_ptrace`. Independent runs:
```
strace    -e trace=none at_demo  →  self_ptrace triggered=false
strace -f -e trace=none at_demo  →  self_ptrace triggered=true
gdb -batch ...                   →  self_ptrace triggered=false
```
The `self_ptrace` signal only trips when strace **follows the fork** (`-f`); the
README's command omitted `-f`, so the stated result did not reproduce. The
original Phase-1 session had used `strace -f`, but the README and results table
dropped the flag.
**Fix applied:** README reproduce block and the `docs/02 §2` table now
distinguish `strace` vs `strace -f`; `docs/01 §2.4` likewise corrected. The
qualitative lesson ("single signals are weak") is unchanged and in fact
reinforced — the *same* tool trips different signals depending on a flag.

### F3 — "Algorithm not visible in disassembly" overstated — *Low–Medium, FIXED (docs)*
`docs/02 §3/§4` implied virtualization removes the algorithm's constants from
the binary. Verified with `objdump`: the splitmix constant `0xff51afd7ed558ccd`
is **absent from `run()`** (the interpreter is genuinely generic ✓) but
**present in `build_checksum_program`**, because that builds the bytecode at
runtime in native code. A real protector ships *precompiled* bytecode as inert
data and contains no such builder, so the constant would not appear.
**Fix applied:** `docs/02 §3` point 3 and §4 now state the hiding is a property
of `run()`, not of this demo binary, and that true removal requires shipping
precompiled bytecode. No code change (the demo's runtime builder is pedagogically
intentional).

### F4 — `demo_tamper` test asserts only "non-zero exit" — *Informational, not fixed*
CTest `WILL_FAIL TRUE` passes on *any* non-zero exit, so an unrelated crash
could masquerade as success. Verified manually that the real exit is `2` via the
tamper path with no sanitizer error, so the test is currently sound. Left as-is
(CTest cannot easily assert a specific exit code); noted for future hardening.

### F5 — `self_text_region()` picks the first `r-x` mapping — *Informational, not fixed*
The comment calls the result "self.text". On this PIE the first executable
mapping is the main binary, but "first `r-x` in `/proc/self/maps`" is not
guaranteed to be the main image on every layout. The integrity check is
self-consistent regardless (same region enrolled and verified), so no functional
defect; the *labeling* is mildly optimistic. Noted only.

## G. Documentation claim audit (Denuvo / facts vs. hypotheses)

- The architecture doc's **facts** are standard, correctly-attributed software-
  protection knowledge: self-checking/guards (Aucsmith 1996; Chang & Atallah
  2001), guard networks and virtualization (Collberg & Nagra, *Surreptitious
  Software*, 2009), and documented Windows anti-debug APIs (`IsDebuggerPresent`,
  `CheckRemoteDebuggerPresent`, PEB `BeingDebugged`,
  `NtQueryInformationProcess`, DR registers, `RDTSC`). These are accurate as
  *general technique* statements. **Note:** this audit verified their *internal
  consistency and labeling*, not each external citation line-by-line (no network
  access was used); they are well-known results but are cited from the author's
  knowledge, not re-fetched here.
- All Denuvo-specific internal claims are confined to the **`[Hypothesis]`**
  section and are not asserted as fact — this is correct discipline. The audit
  did **not** inspect any Denuvo binary (out of scope by constraint), and the
  document does not claim to have.
- **ELF/Linux vs PE/Windows separation** is present but was thin. Summary of the
  real differences the demo relies on:

  | Concern | Linux / ELF (what runs here) | Windows / PE (documented only) |
  |---------|------------------------------|--------------------------------|
  | Locate own code | parse `/proc/self/maps` for `r-x` | `GetModuleHandle(NULL)` + parse PE sections for `IMAGE_SCN_CNT_CODE` |
  | Debugger flag | `/proc/self/status` `TracerPid` | PEB `BeingDebugged` / `IsDebuggerPresent` |
  | Self-trace probe | `ptrace(PTRACE_TRACEME)` | `NtQueryInformationProcess(ProcessDebugPort)` / `CheckRemoteDebuggerPresent` |
  | Timing | `RDTSC` / `steady_clock` | identical concept |

  The Windows paths are **not compiled or executed** in this container (no
  MinGW/MSVC); they remain `#ifdef _WIN32` documentation. This audit therefore
  validates the **Linux** behavior only and makes no claim about the Windows
  code beyond "it compiles-guards out and is documented."

## H. Checksum-primitive limitations (reviewed, accurate)

- **CRC-32** — a linear, non-cryptographic error-detection code. An attacker who
  patches bytes can trivially recompute a matching CRC; CRC is also reversible
  and length-extendable. Suitable only for detecting *accidental*/naive change.
- **FNV-1a** — fast non-cryptographic hash; no keying, so the expected value is
  recomputable by anyone. Collisions are constructible. Fingerprint, not a MAC.
- **`keyed_checksum`** — FNV mixing plus a runtime `seed` and a splitmix
  finalizer. The seed hides the *expected value* from a static reader, but the
  construction is **not** a cryptographic MAC: the mixing is invertible and the
  seed is a plain parameter (in the demo it is even a compile-time constant). It
  demonstrates the *shape* of "the reference is not greppable," not real forgery
  resistance. `docs/02 §5` already states this; the audit confirms the code
  matches the caveat (seed is a parameter, primitives are non-cryptographic).

## I. Corrections applied in this audit

| # | File(s) | Change |
|---|---------|--------|
| F1 | `src/vm_mini.cpp`, `src/vm_mini.hpp` | add `is_well_formed()` pre-execution validation; document precondition |
| F2 | `README.md`, `docs/01-architecture.md`, `docs/02-results.md` | correct `strace` vs `strace -f` self_ptrace behavior |
| F3 | `docs/02-results.md` | scope the disassembly-hiding claim to `run()`; note runtime builder leaks constants |

No benchmark numbers in the docs were edited to look more favorable; the audit
adds its own raw tables above instead.

## J. Final verdict — what is actually validated

**Validated by observation on Linux x86-64 (this commit + the F1 fix):**
- ✅ Repo/remote state and absence of hidden stubs.
- ✅ Clean build, zero warnings, 4/4 tests — GCC & Clang, Debug & Release.
- ✅ No detectable UB/memory errors in exercised paths (ASan+UBSan), after
  fixing the malformed-bytecode UB (F1).
- ✅ Native == VM checksum equivalence — unit tests **and** 5000-case fuzz.
- ✅ Tamper detection (single-bit) and CRC-32 canonical vector.
- ✅ Virtualization slowdown is real and reproducible (5.9×–~14.5× by build;
   ~7× optimized Release), with the measured work provably not elided.
- ✅ Anti-debug signals trip under observers — **with the corrected command
   matrix** (F2): `tracer_pid` under any tracer; `self_ptrace` only under
   `strace -f`.

**Not validated / out of scope:**
- ❌ Any Windows/PE behavior — not compiled or run (no MinGW/MSVC); documentation
  only.
- ❌ External citations not re-fetched (no network); checked for consistency and
  correct labeling only.
- ❌ No commercial protector (Denuvo or other) was inspected — forbidden by the
  project constraints and not done.
- ⚠️ The crypto strength of the integrity primitives is explicitly weak by
  design (§H) — validated as *concept demonstrations*, not as production
  anti-tamper.

**Overall:** the project's runnable, Linux-scoped claims hold up under
independent scrutiny; the defects found were one latent UB (fixed) and two
documentation overstatements (corrected). The work is sound as an educational
demonstration and now reproduces as documented.
