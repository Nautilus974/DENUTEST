# Anti-Tamper Architecture — Technical Study

**Scope and ethics.** This document studies the *generic, publicly documented*
architecture of executable anti-tamper protection, using Denuvo Anti-Tamper as
the reference case. It contains **no** reverse-engineering of any commercial
product, no license/activation bypass, and no circumvention technique. All code
in this repository protects *its own* bytes only. Where a claim about Denuvo's
internals is not publicly documented, it is explicitly labelled **[Hypothesis]**.

---

## 1. What problem anti-tamper solves

A shipped game binary runs on hardware the adversary fully controls. The
adversary can read every byte, set breakpoints anywhere, patch instructions,
and dump decrypted memory. Anti-tamper cannot make this impossible — it raises
the *time and skill cost* of producing a working modified executable, ideally
past the window where a crack has commercial value (release-day sales).

Two distinct goals are often conflated:

| Goal | Mechanism family | In this repo |
|------|------------------|--------------|
| **Anti-tamper** — detect/resist modification of the code or its checks | integrity checksums, code virtualization, control-flow obfuscation | `integrity`, `vm_mini` |
| **DRM / licensing** — tie a copy to an entitlement | activation servers, hardware fingerprinting, encrypted entitlement blobs | *out of scope by constraint* |

Denuvo is primarily an **anti-tamper** layer that protects a game's *existing*
DRM/activation checks from being located and patched out. This study addresses
only the anti-tamper half.

---

## 2. Documented architecture (facts)

The following are supported by public reverse-engineering writeups, vendor
statements, academic literature on software protection, and direct observation
of protected binaries by third parties. They are design *patterns*; specific
Denuvo implementation details are not published by the vendor.

### 2.1 Integrity verification
A protector snapshots trusted bytes (code pages, specific data, its own check
routines) and recomputes a checksum at runtime, comparing against a reference
the attacker should not be able to trivially recompute or locate.

- **Fact:** checksum-of-code is a standard, decades-old technique (tripwire-style
  self-checking; see Aucsmith 1996, Chang & Atallah 2001 on "guards").
- **Fact:** naive CRC/hash checks are defeated by recomputing the expected value
  after patching; robustness comes from *where the reference lives* and *how many
  overlapping checks* guard each other.
- Demonstrated here by `src/integrity.*`: `IntegrityGuard` enrolls regions and
  re-verifies them; a single flipped bit is detected (`tests/test_integrity.cpp`).

### 2.2 Code virtualization
Selected routines are compiled from native x86-64 into a **custom bytecode** and
executed by an embedded interpreter. A static disassembler then sees only the
interpreter's dispatch loop, not the original algorithm; recovering the logic
requires reconstructing the VM's instruction semantics first.

- **Fact:** code virtualization is the defining technique of modern heavy
  protectors (VMProtect, Themida/WinLicense, and — by widespread third-party
  analysis — Denuvo). It is well described in academic and practitioner
  literature.
- **Fact:** virtualization imposes a large per-instruction dispatch cost, so
  only small, hot-but-critical routines (the integrity/entitlement checks) are
  virtualized, not the whole game.
- Demonstrated here by `src/vm_mini.*`: a register VM runs the same checksum as
  native code, bit-for-bit, at a measured single-to-double-digit × slowdown
  (see `docs/02-results.md`). Static analysis of our own binary confirms the
  asymmetry: native `keyed_checksum` ≈ 31 instructions vs. the VM `run` dispatch
  loop ≈ 145 instructions (`scripts/analyze.sh`).

### 2.3 Redundancy and mutual guarding
Checks are duplicated and arranged so that each guard verifies other guards.
Removing one check leaves others that detect its removal.

- **Fact:** mutual-guard networks are documented (Chang & Atallah; Collberg &
  Nagra, *Surreptitious Software*, 2009). They convert a single point of failure
  into a graph an attacker must break *simultaneously*.

### 2.4 Anti-debugging / anti-instrumentation signals
The protected process detects the observable side effects of debuggers,
emulators, and single-stepping, and can alter behavior when observed.

- **Fact:** the signals are standard and documented: on Windows,
  `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `PEB.BeingDebugged`,
  `NtQueryInformationProcess(ProcessDebugPort)`, hardware-breakpoint (DR)
  register inspection, and timing deltas (`RDTSC`) around short code spans.
- Demonstrated here (portable analogues) by `src/anti_debug.*`:
  `/proc/self/status` `TracerPid`, a self-`PTRACE_TRACEME` probe, and an
  `RDTSC`-style timing probe. Verified: under `strace` both the tracer-PID and
  self-ptrace signals trip; under `gdb` only the tracer-PID signal trips (its
  forked child is not traced). **This asymmetry is the key lesson: any single
  signal is weak; protectors combine many.**

### 2.5 Hardware / environment binding (DRM-adjacent — described, not built)
- **Fact:** Denuvo-protected titles are widely reported to derive values from
  the host configuration and an online activation, producing machine-specific
  protected blobs. This is the licensing boundary we deliberately do **not**
  implement or analyze, per the project constraints.

---

## 3. Hypotheses (explicitly not established fact)

- **[Hypothesis]** Denuvo generates per-build, per-machine *unique* virtualized
  check streams so that one machine's crack does not transfer. Third-party
  analysts report build-to-build variation consistent with this, but the vendor
  does not document the mechanism.
- **[Hypothesis]** The frequency and placement of integrity triggers are tied to
  game events (level load, save) to spread cost; reported anecdotally, not
  specified.
- **[Hypothesis]** Specific mappings between Denuvo's bytecode and native
  semantics. Any such mapping is proprietary and is **not** reproduced,
  reconstructed, or distributed here.

Treat every bullet above as an open research question, not a result.

---

## 4. Reverse-engineering concepts relevant to the study

These are the analyst-side concepts the architecture is designed to frustrate;
we exercise the defensive side only, on our own binary.

- **Static analysis** — disassembly (`objdump`), symbol inspection (`nm`),
  header/section parsing (`readelf`). Defeated/raised in cost by stripping,
  packing, and virtualization. Our `scripts/analyze.sh` shows what leaks at
  default optimization: symbol names and literal constants (e.g. the splitmix
  finalizer constant `0xff51afd7ed558ccd`) are plainly visible in native code —
  exactly the fingerprints virtualization removes.
- **Dynamic analysis** — tracing syscalls (`strace`), stepping (`gdb`),
  instrumentation (DBI such as Pin/DynamoRIO, not installed here). Raised in cost
  by anti-debug signals and timing checks.
- **Patching** — modifying bytes to neutralize a check. Raised in cost by
  integrity verification + mutual guards: a patch must also forge every checksum
  that covers it.
- **Devirtualization** — reconstructing original logic from a VM. The dominant
  research direction against virtualized protectors; costly and VM-specific.

---

## 5. Tools used and justification

| Tool | Role | Why |
|------|------|-----|
| g++ 13 / clang++ 18 | build, optimization study | two compilers to show codegen/opt effects |
| CMake + CTest | build + automated tests | reproducible, CI-friendly |
| `objdump` | disassembly, instruction counts | shows native-vs-VM footprint asymmetry |
| `nm` / `readelf` | symbols, headers | shows what static analysis leaks |
| `strace` | syscall + `/proc` access trace | reveals integrity/anti-debug behavior dynamically |
| `gdb` | debugger for signal verification | confirms anti-debug signals trip (and which) |
| `valgrind` (available) | memory correctness (optional) | sanity for the VM memory reads |

Native Windows tooling (x64dbg, IDA, VMProtect, Themida) and MinGW are **not**
available in this Linux container; Windows-specific APIs are therefore
*documented* and guarded behind `#ifdef _WIN32`, and the runnable experiments
use portable POSIX analogues that exercise the identical concepts.
