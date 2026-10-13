# Experimental Results, Limitations, and Improvements

All numbers below were produced on the project's Linux x86-64 container with the
scripts in `scripts/`. Timings are machine- and load-dependent; re-run to see
the spread. The **durable** findings are the orders of magnitude and the
qualitative asymmetries, not the exact nanosecond figures.

## 1. Tamper detection (correctness)

`tests/test_integrity.cpp` (run via `ctest`) establishes:

- CRC-32 matches the standard test vector (`crc32("123456789") == 0xCBF43926`).
- A **single flipped bit** in a guarded region is detected; restoring the byte
  makes it verify again.
- Different seeds yield different checksums (the expected reference value is not
  a fixed, greppable constant).
- The virtualized checksum equals the native checksum **bit-for-bit**, including
  the empty-region edge case — proving the VM faithfully executes the algorithm.

The end-to-end demo exits `0` on a clean run and non-zero under `--tamper`;
CTest asserts both (`demo_clean`, `demo_tamper` with `WILL_FAIL`).

## 2. Anti-debug signal verification (dynamic)

Running the demo under different observers (reproducible with the commands in
`README.md`):

| Launcher | `tracer_pid` | `self_ptrace` | Lesson |
|----------|:---:|:---:|--------|
| direct      | false | false | baseline, no observer |
| `strace`    | **true** | false | the main process is traced, but the fork child is not followed, so its `PTRACE_TRACEME` succeeds |
| `strace -f` | **true** | **true** | following the fork traces the child too, so its `PTRACE_TRACEME` fails |
| `gdb`       | **true** | false | debugger trips only the PID check; its forked child is untraced |

**Finding:** no single signal is reliable. `strace -f` and `gdb` are both
"debuggers," yet they trip *different* signals — and `strace`'s own `self_ptrace`
result flips depending on the `-f` flag. A real protector must combine many weak
signals; each one alone is trivially bypassed.

> **Audit correction (2026-10-13):** the original table and the README reproduce
> block claimed plain `strace` trips *both* signals. Independent re-runs show
> plain `strace` (no `-f`) trips only `tracer_pid`; `self_ptrace` requires
> `strace -f`. Table and README corrected accordingly. See
> `docs/03-independent-audit.md` §F2.

## 3. Virtualization cost (performance)

`scripts/optimization_study.sh 8192 3000`, representative run (g++ 13):

| opt | crc32 ns/B | keyed native ns/B | keyed VM ns/B | VM slowdown |
|-----|-----------:|------------------:|--------------:|------------:|
| -O0 | 4.01 | 5.98 | 80.1 | **13.4×** |
| -O1 | 2.81 | 2.11 | 12.6 | **6.0×** |
| -O2 | 2.89 | 2.22 | 15.6 | **7.0×** |
| -O3 | 2.90 | 2.15 | 15.3 | **7.1×** |

**Findings:**

1. **Virtualization is expensive but bounded.** The same routine costs ~6–13×
   its native form. This is why protectors virtualize only small, critical
   routines (integrity/entitlement checks), never whole games.
2. **Optimization helps both paths, most at the first level.** The tax is
   largest at `-O0` (un-optimized interpreter bookkeeping) and collapses at
   `-O1`, then settles. The VM is dominated by unpredictable `switch` dispatch
   branches that optimization cannot remove, so it never catches up to native.
3. **Static footprint asymmetry** (`scripts/analyze.sh`): native `keyed_checksum`
   disassembles to ≈31 instructions with its constants in plain sight
   (`movabs $0xff51afd7ed558ccd`); the VM `run` dispatcher is ≈145 instructions
   and the algorithm it executes is **not present in `run()`** — the interpreter
   is generic. (Audit note: in *this demo* the algorithm's constants are still
   visible, because `build_checksum_program()` constructs the bytecode at
   runtime in native code and therefore contains the same `movabs` constant. A
   real virtualizing protector ships the bytecode as precompiled inert data with
   no native builder, so the constants would not appear anywhere. The hiding
   property is a property of `run()`, not of the demo binary as a whole. See
   `docs/03-independent-audit.md` §F3.)

## 4. What static analysis leaks (and virtualization hides)

From `scripts/analyze.sh` on our own binary at default optimization:
- Function **symbol names** (`keyed_checksum`, `crc32`, `vm::run`) — removed by
  stripping.
- **Literal algorithm constants** (FNV prime, splitmix finalizer) — these are a
  grep-able fingerprint of the algorithm. Virtualization moves the *executed*
  algorithm into bytecode so it is absent from the interpreter `run()`; note,
  however, that this demo's runtime bytecode builder still contains the
  constants (see §3 audit note). True removal requires shipping precompiled
  bytecode as data.
- The exact **`/proc/self/{maps,status}`** accesses that reveal the
  integrity/anti-debug behavior dynamically.

## 5. Limitations (honest)

- **Platform.** The experiments run on Linux with POSIX analogues
  (`/proc`, `ptrace`). The *concepts* transfer to Windows, but the concrete
  Windows APIs (PEB, `NtQueryInformationProcess`, PE section checksums) are
  documented, not executed, here.
- **Strength.** The demo primitives are intentionally simple and readable:
  CRC-32 and FNV are **not** cryptographic; the VM is **not** obfuscated; the
  seed is a parameter, not a runtime-derived secret. They illustrate mechanism
  and cost, not production-grade resistance.
- **No mutual guarding implemented.** We describe guard networks but implement a
  single-layer guard; a real network's robustness is not measured here.
- **Microbenchmark caveats.** Figures vary with CPU frequency scaling, cache
  state, and container noise. Treat ratios, not absolutes, as the result.
- **We did not analyze any commercial protector.** By constraint, no Denuvo
  binary was inspected; claims about Denuvo are sourced to public documentation
  or marked `[Hypothesis]` in `01-architecture.md`.

## 6. Improvement directions (future work, all defensive)

1. **Keyed/cryptographic integrity** — replace FNV with a keyed MAC (e.g.
   SipHash/HMAC) and derive the key at runtime so the reference cannot be
   precomputed offline. Measure the added cost vs. forgery resistance.
2. **Overlapping guard network** — implement mutually-checking guards and
   quantify how many must be broken simultaneously; model attacker cost.
3. **VM hardening** — polymorphic handlers, encrypted bytecode decrypted
   per-dispatch, and dispatch obfuscation; measure the slowdown each adds.
4. **Check scheduling** — spread verification across time/events to cap the
   steady-state performance cost; measure p99 frame-time impact in a loop.
5. **Windows port** — build the `#ifdef _WIN32` paths under MinGW/MSVC and
   repeat the signal-verification matrix with x64dbg and a DBI tool.
6. **Devilization resistance study** — attempt to devirtualize our *own* VM
   (we own it) to quantify, defensively, how much obfuscation raises that cost.
