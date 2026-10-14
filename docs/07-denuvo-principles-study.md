# Anti-Tamper Principles — Educational Study (Denuvo, Onimusha as context)

**Purpose.** Explain, for education, the generic technical principles behind
executable anti-tamper protections of the Denuvo class, using *Onimusha: Way of
the Sword* only as a **documentary context**. This study does **not** inspect,
modify, run, or bypass the game or any commercial binary. Every runnable artifact
here operates on code we built ourselves.

**Honesty constraints (carried from `docs/03`).**
- No network access was available when writing this, and no primary source
  specific to Onimusha's protection build was consulted. Therefore essentially
  **everything game-specific is marked `[HYPOTHESIS]` or `[UNVERIFIABLE HERE]`**,
  never asserted as fact.
- No claim about proprietary Denuvo internals is presented as established.
- No DRM/license circumvention is described or performed.

---

## 1. Generic principles (documented, mechanism-level)

These are general, publicly-documented software-protection techniques (Aucsmith
1996; Chang & Atallah 2001; Collberg & Nagra, *Surreptitious Software*, 2009;
vendor materials for VMProtect/Themida). They describe a *class* of protectors;
they are not a description of any specific Denuvo build.

### 1.1 Code virtualization
A chosen routine is translated from native machine code into a **custom
bytecode** executed by an embedded interpreter. A disassembler then sees only
the interpreter's dispatch loop, not the original algorithm; recovering the
logic first requires reconstructing the VM's semantics.
- *In this repo:* `src/vm_mini.*` is a register bytecode VM that runs the exact
  same checksum as native code. Measured cost: ~6–14× native (see `docs/02`),
  which is why only small, critical routines get virtualized.
- *Observed here:* in `lab_demo`, `native==VM : yes (2062 VM instructions)` for a
  256-byte checksum — the virtualized form does the same work through many more
  dispatched steps.

### 1.2 Integrity verification
Trusted bytes (code pages, specific data, the checks themselves) are
checksummed; the value is recomputed at runtime and compared. Robustness comes
from *where the reference lives* and from overlapping checks, not from the hash
alone.
- *In this repo:* `src/integrity.*` (`IntegrityGuard`). A single flipped bit is
  detected; `lab_demo --tamper` flips one byte and the guard reports `TAMPERED`
  (exit 2).
- *Limit:* CRC-32/FNV are non-cryptographic and recomputable; the demo's keyed
  checksum hides the *expected value* via a runtime seed but is not a crypto MAC
  (`docs/03 §H`).

### 1.3 Anti-debugging
The process detects observable side effects of debuggers/instrumentation
(tracer presence, single-step timing, breakpoint artifacts) and may alter
behavior when observed.
- *In this repo:* `src/anti_debug.*` — `/proc` TracerPid, self-`ptrace`, RDTSC-
  style timing. Documented Windows equivalents (`IsDebuggerPresent`, PEB,
  `NtQueryInformationProcess`) are `#ifdef`'d, not executed here.
- *Limit (measured in `docs/03 §F2`):* no single signal is reliable — `strace -f`
  and `gdb` trip *different* signals.

### 1.4 Environment verification
The process inspects the execution environment (VM/hypervisor presence, CPU
count, sandbox artifacts) as one weak input among many.
- *In this repo (new):* `src/env_checks.*` — CPUID hypervisor bit, hypervisor
  vendor leaf, logical CPU count. **Every signal carries an explicit
  false-positive caveat.**
- *Limit:* these fire on legitimate systems (see §4). A protector that blocked
  every VM would block paying customers, so real systems use them only as soft,
  combined signals — never as a sole gate.

---

## 2. Onimusha / its Denuvo version — facts vs hypotheses

| Statement | Status |
|-----------|--------|
| Denuvo Anti-Tamper is a commercial anti-tamper layer that wraps a game's existing checks | **Documented (general)** — widely reported industry description |
| Denuvo-class protectors use code virtualization, integrity checks, anti-debug and environment checks | **Documented (general)** — true of the *class*; see §1 sources |
| *Onimusha: Way of the Sword* ships with Denuvo | **[UNVERIFIABLE HERE]** — no primary source consulted; do not treat as fact |
| The specific Denuvo *version/build* used by Onimusha, its trigger placement, VM handler set, or check frequency | **[HYPOTHESIS]** — proprietary and per-build; not published, not inspected here |
| Any claim that a specific byte/offset/registration in Onimusha does X | **Not made** — would require inspecting the binary, which is out of scope and not done |

**Discipline:** this study deliberately refuses to attribute any concrete
internal mechanism to Onimusha. The game is a *context* for discussing the
generic class, nothing more. Statements about the class are not statements about
the game.

---

## 3. Why a protected executable is hard to examine (static-analysis limits)

Our own read-only inspector (`exe_inspect`) and the reference tools
(`nm`/`objdump`/`readelf`) make the limits concrete on binaries we built:

- **Unprotected binaries leak everything.** `nm build/lab_demo` lists our logic
  by name:
  ```
  at_demo::env::hypervisor_bit_signal()
  at_demo::integrity::keyed_checksum(void const*, unsigned long, unsigned long)
  ```
  `exe_inspect` reports `518 in .symtab` with function names in plain sight.
- **Optimization dissolves structure.** At `-O2` a static leaf (`mix`) is inlined:
  its symbol and call site both vanish (`docs/06 §4.4`) — the source function
  boundary is gone from the machine code.
- **Stripping removes names.** After `strip`, `.symtab` is gone and name-based
  analysis fails, though `.dynsym` and the code remain.
- **A real protector removes exactly what static analysis relies on.** Code
  virtualization replaces native instructions (and their constant fingerprints)
  with interpreted bytecode; integrity checks make patching self-defeating;
  anti-debug frustrates the dynamic analysis you would fall back to. The
  combination is why examining a *protected* image costs far more than examining
  our unprotected demo.
- **Static tools parse structure, not behavior.** `exe_inspect` tells you a
  `.text` section exists and how big it is — not what it computes, and not
  whether it is virtualized. It also never executes the target.

---

## 4. Demo results, false positives, and limits of conclusions

Real output of `./build/lab_demo` in this environment (a cloud container):

```
(1) INTEGRITY            protected OK / self.text OK
(2) CODE VIRTUALIZATION  native==VM : yes  (2062 VM instructions)
(3) ANTI-DEBUG           tracer_pid - , self_ptrace - , timing -      (none tripped)
(4) ENVIRONMENT          hypervisor_bit TRIP (CPUID.1:ECX[31]=1)
                         hypervisor_vendor - (leaf 0x40000000 empty)
                         low_cpu_count  - (online CPUs=4)
POSTURE: integrity violations=0, heuristic signals=1 tripped  → exit 0
```

### 4.1 A real, observed false positive
The `hypervisor_bit` signal **tripped** — correctly: we *are* in a virtualized
container. For an anti-tamper heuristic this is a **false positive**: a
legitimate host flagged as "suspicious." The demo therefore:
- counts it as a *heuristic* signal, not a tamper signal, and
- **exits 0** anyway. Only a real integrity violation (`--tamper` → exit 2)
  changes the outcome.

This is the central lesson: environment/anti-debug signals are **soft** and
noisy. The `hypervisor_vendor` leaf returned empty in this container even though
the hypervisor bit was set — two environment signals *disagreeing* about the same
machine, which is exactly why no single one can be trusted.

### 4.2 `--tamper` path
Flipping one byte: integrity reports `TAMPERED`, posture `integrity
violations=1`, exit `2`. The direct tamper signal behaves as designed while the
heuristics stay noisy in the background.

### 4.3 Limits of these conclusions
- The demo's primitives are intentionally weak/readable (non-crypto checksums,
  an un-obfuscated VM, plain seeds). They demonstrate *mechanism and cost*, not
  production resistance.
- Environment signals are x86-specific (CPUID) and container-dependent; results
  differ on bare metal, on ARM, and on other hypervisors.
- "No heuristic tripped" does **not** mean "no debugger/VM" (false negatives are
  equally possible — e.g. a hypervisor that hides its bit).
- Nothing here was measured on, or concluded about, Onimusha or any commercial
  protector. The game-specific rows in §2 remain hypotheses by construction.

---

## 5. Reproduce

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
ctest --test-dir build --output-on-failure      # 8 tests incl. env_checks, lab_demo
./build/lab_demo                                 # posture on this host (exit 0)
./build/lab_demo --tamper                        # integrity fires (exit 2)
./build/exe_inspect build/lab_demo               # static view: names in plain sight
nm -C build/lab_demo | grep at_demo::env         # what a protector would hide
```

**Verified:** GCC 13 and Clang 18, Debug and Release, 0 warnings, 8/8 CTest;
GCC ASan+UBSan clean. Environment observations above are real outputs from this
container, not estimates.
