# Phase 6b — Timing-Detection Experiment (working code + measured results)

**What this is.** A concrete, reproducible experiment turning our most serious
research lead into working, measured code. The corroborated hypervisor-bypass
class defeats Denuvo-style checks by **manipulating CPU timing so in-process
checks "see normal behavior"** (Phase 6, `docs/10`). This experiment builds a
real timing-based detector, measures its discrimination on *this* host, and
measures the exact clock-scaling factor that defeats it.

**What it is not.** No game was tested. No hypervisor was built. No product was
circumvented. The "deceiver" is modeled honestly by substituting the detector's
own tick source (dependency injection) — not by attacking anything. Nothing here
is attributed to Onimusha.

Code: `src/timing_probe.{hpp,cpp}`, `src/timing_experiment_main.cpp`,
`tests/test_timing_probe.cpp`. Lab base commit `a86df8c`.

---

## 1. What the available evidence lets us test (and what it does not)

**Testable on this controlled host — and done:**
- The real cost, in CPU cycles (RDTSC), of a *trap-prone* instruction (CPUID,
  serializing, commonly causing a VM-exit) vs. a syscall vs. cheap arithmetic.
- Whether *this* host is timing-detectable as virtualized (it reports the
  hypervisor bit — Phase 3 — so this is a real instance, not a simulation).
- That a timing detector is a pure function of its clock, and the exact clock
  scale `k*` at which its verdict flips — verified by **re-measuring** the same
  operation through a scaled clock.

**Not testable here (stated precisely, not faked):**
- A **bare-metal reference** machine (to contrast "no VM-exit" CPUID cost). We
  are inside a hypervisor we do not control and have no bare-metal access.
- A **controllable Ring-1 hypervisor** that actually intercepts CPUID/RDTSC for
  a target process. Building or running one is out of scope; we model the clock
  substitution in-process instead.
- Anything about **Onimusha** or Denuvo internals. No binary; not tested.

## 2. Method

`measure(op, now, samples)` brackets each of `samples` individual calls of `op`
with the tick source `now()` (RDTSC+LFENCE), after a warmup, and reports
min/median/p99/mean/stddev. Ops: `op_cpuid` (leaf 0), `op_syscall` (getpid),
`op_arith` (LCG step). Detector: an op is "elevated" iff its **median ≥
`ratio_threshold` × baseline(arith) median** (threshold = 3× here). The
deceiver: `scaled_ticks(k)` returns real ticks divided by `k`, so observed
durations shrink by `k` — the measurable analogue of a slowed clock.

Reproduce:
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
./build/timing_experiment 200000 3.0     # prints the numbers below
ctest --test-dir build -R timing_probe --output-on-failure
```

## 3. Measured results (this host; 3 runs, 200k samples each)

Per-call cost in RDTSC ticks (median), and ratio vs. the arithmetic baseline:

| run | arith | syscall | cpuid | syscall/arith | cpuid/arith |
|----:|------:|--------:|------:|--------------:|------------:|
| 1 | 78 | 294 | 28 804 | 3.8× | **369×** |
| 2 | 64 | 294 | 28 776 | 4.6× | **450×** |
| 3 | 64 | 294 | 31 226 | 4.6× | **488×** |

**Finding 3.1 — this host is strongly timing-detectable as virtualized.**
CPUID costs ~**29 000 cycles** vs ~**64** for arithmetic — a **~370–490×**
ratio, stable across runs. That three-orders-of-magnitude gap is the signature
of a CPUID **VM-exit**: the instruction traps into the hypervisor. A naive
anti-tamper timing check would (correctly, here) flag "running under a
hypervisor." This is a real measurement of the exact phenomenon the research
lead describes — obtained on our own process, no game involved.

**Finding 3.2 — the detector is defeated by controlling its clock (measured).**
Predicted evasion crossover `k* = ratio/threshold` (e.g. run 2: 449.62/3 ≈
**149.9**). Re-measuring the *same* CPUID op through `scaled_ticks(k)`:

| run | k* (predicted) | at k≈0.9·k* | at k≈1.1·k* |
|----:|---------------:|-------------|-------------|
| 1 | 123.1 | 3.35× → elevated **YES** | 2.73× → elevated **no** |
| 2 | 149.9 | 3.34× → elevated **YES** | 2.73× → elevated **no** |
| 3 | 162.6 | 4.36× → elevated **YES** | 3.11× → elevated **YES** (noise) |

Below `k*` the op still reads "elevated"; above `k*` it generally flips to "not
elevated". This is the concrete, measured statement of the lead: **a layer that
controls the clock the check reads controls the verdict** — the check's entire
assurance is the integrity of its time source.

**Finding 3.3 — timing checks are noisy near the boundary (honest limitation).**
Run 3 at k≈1.1·k* still read 3.11× (just over the 3× threshold): measurement
noise near the exact crossover keeps the verdict marginally "elevated". So the
crossover is exact on the *medians* but re-measurement jitter matters at the
boundary. Consequence both ways: robust *evasion* scales well past `k*`; robust
*detection* needs margin and multiple probes. The unit test deliberately checks
the flip at `2·k*` (well clear of boundary noise) so it is deterministic.

## 4. What these results demonstrate — and what they do not

**Demonstrated (reproducible, on our own code):**
- A trap-prone instruction is ~370–490× costlier than arithmetic on this
  virtualized host — a real, measurable VM-exit timing signal.
- A median-ratio timing detector's verdict is a pure, measured function of its
  clock: scaling the clock past `k*`≈120–160 flips "virtualized" → "clean",
  confirmed by re-measurement.
- Timing checks have a noisy decision boundary (3.3).

**NOT demonstrated:**
- Anything about Onimusha, Denuvo, or any real protector's thresholds/behavior.
- A real Ring-1 interception (we substituted the clock in-process; we did not
  intercept CPUID/RDTSC from a more-privileged layer).
- Bare-metal CPUID cost (no bare-metal access) — so we show "VM is detectable
  here", not the full "bare-metal vs VM" contrast.

## 5. Missing data for any Onimusha-specific conclusion
- The game binary and whether its Denuvo build actually uses CPUID/RDTSC timing
  checks, and with what thresholds/aggregation.
- A bare-metal reference and a *controllable* hypervisor to measure real
  interception rather than an in-process clock substitution.
- Independent corroboration of the single Onimusha bypass report (`docs/10` §1).
Without these, this experiment supports only the **general** property that
timing-based environment checks are clock-trust-bound and defeatable by a clock
controller — consistent with the reported class, **not** proof about the game.

## 6. Defensive takeaway (why this matters for protection design)
A timing check that reads an in-process/guest clock delegates its trust to
whatever controls that clock. Hardening directions (future work, our own code):
cross-check multiple independent time sources (TSC vs. an external/monotonic
reference), require a trusted time anchor the guest cannot scale, and treat
timing as one weak signal combined with others — never a sole gate. This mirrors
the Phase-5/6 conclusion that in-process environment checks are not trust
boundaries, now backed by measured cycle counts rather than a boolean model.

---
**Verification:** GCC 13 & Clang 18, Debug & Release, 0 warnings, 11/11 CTest;
GCC ASan+UBSan clean. All numbers in §3 are real `./build/timing_experiment`
output on this host. The game was not tested and no bypass was produced.
