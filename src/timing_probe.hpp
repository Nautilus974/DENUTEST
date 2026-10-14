// timing_probe.hpp — a measurable timing-based instrumentation/VM detector and
// a controlled model of how such a detector is defeated when its clock is not
// trustworthy.
//
// Why this exists: the most serious, corroborated technical lead from our
// research is that hypervisor-class bypasses work by MANIPULATING CPU TIMING so
// that in-process anti-tamper timing checks "see normal behavior". This module
// turns that lead into a reproducible experiment ON OUR OWN CODE:
//   * measure, in real CPU cycles, how costly a trap-prone instruction (CPUID)
//     is versus cheap arithmetic on this host (which is itself virtualized);
//   * show that a timing detector built on those measurements is a pure
//     function of the CLOCK it reads, and MEASURE the exact clock-scaling factor
//     at which the detector flips from "instrumented" to "clean".
//
// It contains NO hypervisor, NO game code, and NO circumvention of any product.
// The "deceiver" is modeled only by substituting the detector's own tick source
// (dependency injection) — the honest way to measure the property.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace at_demo::timing {

// A tick source the detector reads "current time" from. The whole point is that
// this is the trust anchor: whoever controls it controls the verdict.
using TickSource = std::function<std::uint64_t()>;

// Serialized timestamp counter (RDTSC + fences) on x86; a steady-clock ns
// fallback elsewhere so the module still builds and tests run.
std::uint64_t tsc_now() noexcept;

// The real, trustworthy tick source (tsc_now).
TickSource real_ticks();

// A "deceiving" tick source: reports real ticks divided by `scale` (>=1), i.e.
// it compresses observed durations by `scale` — the measurable analogue of a
// privileged layer slowing its clock so operations look cheap. scale==1 is the
// honest source.
TickSource scaled_ticks(double scale);

struct Stats {
    std::size_t n = 0;
    std::uint64_t min = 0, median = 0, p99 = 0, max = 0;
    double mean = 0.0, stddev = 0.0;
};

Stats summarize(std::vector<std::uint64_t> samples);

// Measure the per-call duration (in whatever units `now` returns) of `op`,
// over `samples` timed iterations after `warmup` untimed ones. Each iteration
// is individually bracketed by `now()`.
Stats measure(const std::function<void()>& op, const TickSource& now,
              std::size_t samples, std::size_t warmup = 1024);

// --- Operations under test --------------------------------------------------
// A trap-prone instruction: CPUID (serializing; commonly intercepted by
// hypervisors, causing a VM-exit). On non-x86 it is a cheap portable stand-in.
void op_cpuid() noexcept;
// A system call (getpid): crosses the user/kernel boundary, also interceptable.
void op_syscall() noexcept;
// Cheap arithmetic baseline the optimizer cannot delete.
void op_arith() noexcept;

// --- Detector ---------------------------------------------------------------
// Verdict: the measured op cost is "elevated" (instrumentation/VM-like) iff its
// median exceeds `ratio_threshold` times the baseline median. Pure function of
// the two Stats it is given — which is exactly the weakness being measured.
bool looks_elevated(const Stats& op, const Stats& baseline,
                    double ratio_threshold) noexcept;

// Given a real op/baseline, the smallest clock `scale` that makes the detector
// report "not elevated" (i.e. the evasion crossover). Returns 0.0 if the op is
// not elevated even at scale 1 (nothing to evade). Computed, then verifiable by
// re-measuring through scaled_ticks(scale).
double evasion_crossover_scale(const Stats& op_real, const Stats& baseline_real,
                               double ratio_threshold) noexcept;

}  // namespace at_demo::timing
