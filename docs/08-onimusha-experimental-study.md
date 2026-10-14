# Phase 4 — Experimental Study: Onimusha as a Case Study

**Bottom line up front.** No experiment was performed on *Onimusha: Way of the
Sword*, because **the game binary is not available in this environment and no
authorization or lawful means to obtain it exists here.** This report records
that as a verifiable negative result, states exactly what would be required to
proceed, and instead carries out the *permitted* experimental work — on our own
executables — that the mission points to (§3). Nothing here is transposed to
Onimusha, and no mechanism is attributed to Denuvo without proof (there is no
proof here, so no such attribution is made).

---

## 1. Experimental scope and test conditions

### 1.1 What is actually available (audited 2026-10-14, commit `90a1578`+)
- **No Onimusha artifact** anywhere: `git ls-files` and a filesystem search for
  `*onimusha*`/`*.exe`/game binaries return nothing.
- **No outbound network**: the agent proxy returns `403` on a connectivity
  probe. (Even with network, downloading a commercial game is out of scope and
  was not attempted.)
- **No ownership / license / authorization** for the game in this environment.
- **Tools present**: our own `exe_inspect` (read-only ELF/PE inspector, now with
  entropy/heuristics), plus `objdump`, `readelf`, `nm`. Platform: Linux x86-64.

### 1.2 Consequence for the scope
| Intended activity | Possible here? | Why |
|-------------------|:--------------:|-----|
| Static inspection of the Onimusha binary | **No** | binary absent; nothing to read |
| Dynamic observation of the game | **No** | no binary, and running/attaching is out of scope |
| Characterizing *its* Denuvo build | **No** | requires the binary + authorization |
| General principles & experiments on our own code | **Yes** | our binaries, our rights |

**Direct observations of Onimusha in this study: zero.** Any statement that would
require the binary is therefore *not made*.

### 1.3 What would be required before any Onimusha-specific work
Stated so the prerequisite is explicit, not so it is pursued here:
1. A **lawfully owned copy** of the game, with the exact **platform and version/
   build number** recorded (protection differs across builds/patches).
2. **Written authorization** from the rights holder for reverse-engineering
   where the licence/EULA or local law requires it; analysis must not neutralize
   or circumvent the protection, activation, or licensing.
3. An **isolated, disposable test environment** (offline VM/snapshot) dedicated
   to analysis.
4. A method that is **read-only / non-circumventing** (format and metadata
   inspection, not defeat of the protection).

Absent items 1–2, this phase cannot lawfully or technically proceed on the game,
and it does not.

---

## 2. Permitted experimental work (on our own executables)

Because the mission explicitly allows complementary experiments on our own
binaries to probe the *general* hypotheses, Phase 4 extended `exe_inspect` with
the generic static heuristics an analyst applies to *any* unknown or
suspected-packed binary, and exercised them on code we own.

### 2.1 Method and tools
- **`exe_inspect` (extended):** per-section **Shannon entropy** (bits/byte),
  plus three soft "looks packed/protected?" signals — high-entropy *executable*
  sections, **W^X** (writable+executable) sections, and unnamed executable
  sections. All read-only; the tool never executes the target.
- **Reference cross-checks:** `readelf`/`nm`/`objdump` (as in `docs/06`).
- Entropy math and each heuristic are unit-tested
  (`tests/test_exe_inspect.cpp`, 54 assertions incl. the new entropy/heuristic
  cases; 8/8 CTest overall).

### 2.2 Results actually observed
Normal, compiled binaries (our own tools) — **no heuristic signals**:
```
exe_inspect on build/exe_inspect :  .text  X H=5.55   .rodata H=5.30   → 0 signals
exe_inspect on build/lab_demo    :  .text  X H=5.58   .rodata H=5.16   → 0 signals
```
A **synthetic** high-entropy executable ELF we generated (to represent what a
packed/encrypted code section *looks* like):
```
[1] (unnamed) ... PROGBITS X H=7.96
heuristics : 2 soft signal(s) (NOT proof)
   ? high-entropy executable section '' (H=7.96) — consistent with packing/
     encryption/virtualization, but ALSO with compressed/encrypted data; NOT proof
   ? executable section with no name
```

**Interpretation (observed vs. supposed):**
- *Observed:* ordinary compiled `.text` sits around **H≈5.5 bits/byte**; a
  near-random executable section reaches **H≈8** and trips the heuristics.
- *Supposed (general hypothesis, not a claim about any product):* packers,
  encryptors and code-virtualization engines tend to leave high-entropy regions
  and sometimes self-modifying (W^X) sections.
- *Why this is not proof:* compressed resources, encrypted assets, embedded
  archives and legitimately obfuscated code produce the **same** high-entropy
  signature (see §3.1 false positives). The signal says "worth a closer look,"
  never "this is Denuvo."

### 2.3 Limits of static analysis confirmed on our own code (negative results)
- **Names/structure are not in the bytes.** On our *unprotected* demo, `nm`
  lists `at_demo::env::hypervisor_bit_signal`, `keyed_checksum`, etc.; after
  `-O2` inlining the leaf `mix` disappears and after `strip` `.symtab` is gone
  (`docs/06 §4.4`). A real protector removes exactly these, which is *why* a
  protected image is hard to examine — demonstrated on code we own, not inferred
  from the game.
- **`exe_inspect` parses structure, not behavior.** It reports section
  entropy/flags; it cannot tell you what code computes or whether it is
  virtualized.
- **Entropy is coarse.** It is computed over whole sections; a small virtualized
  stub inside a mostly-normal `.text` would be diluted and *missed* (false
  negative). We did not implement sliding-window entropy.

---

## 3. Relating observations to the laboratory (carefully, no transposition)

The lab (`lab_demo`, `integrity`, `vm_mini`, `anti_debug`, `env_checks`)
demonstrates the *mechanisms* in isolation; the static heuristics above
demonstrate what those mechanisms might *look like* from the outside. These are
connected only as general illustrations:

- Our `vm_mini` shows virtualization costs ~6–14× and hides the algorithm from
  `run()` (`docs/02`, `docs/06`). **Hypothesis (general):** a virtualized region
  in any binary could read as higher-entropy, unusual code. **We did not and
  cannot confirm this shape in Onimusha.**
- Our `env_checks` shows environment heuristics produce false positives (the
  hypervisor bit tripped on this legitimate container, `docs/07`). **This is a
  property we measured on our own code; it is not evidence about the game.**

**Explicit non-transposition:** none of the lab's numbers, shapes, or behaviors
are claimed to hold for Onimusha. They are hypotheses about the *general class*,
testable only on binaries we are authorized to analyze.

### 3.1 Documented false positives / negatives of the heuristics
| Signal | False positive | False negative |
|--------|----------------|----------------|
| high-entropy exec section | compressed/encrypted/obfuscated-but-benign code | small virt. stub diluted in a large normal `.text` |
| W^X section | JITs, legitimate self-modifying runtimes, some loaders | protector that fixes up permissions before checks run |
| unnamed exec section | fully stripped benign binaries | named sections that still hide virtualized code |

---

## 4. Remaining hypotheses and study limits

- **[HYPOTHESIS, unproven]** Denuvo-class protection generally combines code
  virtualization, integrity checks, anti-debug and environment checks (true of
  the *class* per public literature; not demonstrated on Onimusha here).
- **[UNVERIFIABLE HERE]** Whether Onimusha ships Denuvo, which version, and any
  of its concrete internals. No binary, no source, no claim.
- **Reproducibility limits:** entropy/heuristic results depend on the specific
  binary and build; our figures come from our own GCC/Clang outputs on Linux
  x86-64 and will differ elsewhere. The synthetic "packed-like" file is a
  construct to exercise the detector, not a sample of any real protector.
- **Tooling limits:** no sliding-window entropy, no disassembly/CFG recovery, no
  dynamic analysis, PE path validated only on a fixture (`docs/06`).

## 5. Experiments that would confirm/refute the general hypotheses

All of these run on **our own** executables (authorized), never the game:
1. **Sliding-window entropy** in `exe_inspect` to catch small high-entropy stubs
   embedded in normal `.text` (addresses the false negative in §2.3).
2. **Virtualize a real hot function** with `vm_mini`, link it into a sample, and
   check whether the heuristic detects the virtualized region vs. the native
   build — measuring detector sensitivity on a *known* ground truth.
3. **Pack a sample we own** with a general-purpose packer (e.g. a self-made XOR/
   compress stub) and confirm the entropy/W^X signals fire, then confirm a
   benign compressed-resource binary *also* fires (quantifying the false-positive
   rate).
4. **Strip vs. unstripped vs. `-O0/-O2`** matrix feeding `exe_inspect`, to chart
   how much each transformation degrades static analysis (extends `docs/06`).
5. **Import-table heuristics** (PE): flag imports commonly associated with anti-
   debug (`IsDebuggerPresent`, `NtQueryInformationProcess`) — tested on our PE
   fixture, with explicit false-positive notes.

## 6. Reproduce (our own binaries only)

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
ctest --test-dir build --output-on-failure          # 8 tests incl. entropy/heuristics
./build/exe_inspect build/exe_inspect build/lab_demo # normal: entropy ~5.5, 0 signals
# (the synthetic high-entropy ELF used in §2.2 is generated by a throwaway
#  helper; exe_inspect reports H≈8 + 2 soft signals on it.)
```

**Verified:** GCC 13 and Clang 18, Debug and Release, 0 warnings, 8/8 CTest; GCC
ASan+UBSan clean. Every number above is a real output on a binary we own. No data
about Onimusha was produced, because none could be obtained lawfully here.
