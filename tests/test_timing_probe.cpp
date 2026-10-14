// test_timing_probe.cpp — deterministic properties of the timing detector and
// the clock-deception model. Timing magnitudes are environment-dependent, so
// these tests assert the MACHINERY and the DETERMINISTIC evasion property, not
// a specific cycle count. (Real magnitudes are printed by timing_experiment.)
#include <cstdint>
#include <cstdio>
#include <vector>

#include "timing_probe.hpp"

static int g_fails = 0;
#define CHECK(cond, msg)                                              \
    do {                                                             \
        if (!(cond)) { std::printf("  FAIL: %s\n", msg); ++g_fails; }\
        else         { std::printf("  ok:   %s\n", msg); }          \
    } while (0)

using namespace at_demo::timing;

static void test_tsc_monotonic_nonzero() {
    std::uint64_t a = tsc_now();
    for (volatile int i = 0; i < 1000; ++i) {}
    std::uint64_t b = tsc_now();
    CHECK(a != 0 && b != 0, "tsc_now returns nonzero");
    CHECK(b >= a, "tsc_now is non-decreasing over a short interval");
}

static void test_summarize() {
    std::vector<std::uint64_t> v{5, 1, 3, 2, 4};
    Stats s = summarize(v);
    CHECK(s.n == 5, "summarize counts samples");
    CHECK(s.min == 1 && s.max == 5, "summarize min/max");
    CHECK(s.median == 3, "summarize median");
    CHECK(s.mean > 2.9 && s.mean < 3.1, "summarize mean ~3");
}

static void test_detector_logic() {
    Stats base; base.median = 100; base.n = 10;
    Stats slow; slow.median = 500; slow.n = 10;   // 5x
    Stats fast; fast.median = 150; fast.n = 10;    // 1.5x
    CHECK(looks_elevated(slow, base, 3.0), "detector flags 5x as elevated at 3x threshold");
    CHECK(!looks_elevated(fast, base, 3.0), "detector does not flag 1.5x at 3x threshold");
    Stats zero; zero.median = 0;
    CHECK(!looks_elevated(slow, zero, 3.0), "zero baseline -> not elevated (no divide-by-zero)");
}

static void test_crossover_math_and_measurement() {
    // Synthetic: op is 6x baseline, threshold 3x => crossover k* = 6/3 = 2.0.
    Stats base; base.median = 100; base.n = 10;
    Stats op;   op.median   = 600; op.n   = 10;
    double k = evasion_crossover_scale(op, base, 3.0);
    CHECK(k > 1.99 && k < 2.01, "crossover k* = ratio/threshold = 2.0");

    Stats not_elev; not_elev.median = 120;
    CHECK(evasion_crossover_scale(not_elev, base, 3.0) == 0.0,
          "no crossover when op is not elevated (nothing to evade)");
}

static void test_scaled_clock_defeats_a_real_measurement() {
    // Measure a genuinely-timed op with the real clock, then re-measure the
    // SAME op through a clock scaled by a large factor. The observed duration
    // must shrink, proving the detector's input is controlled by its clock.
    // (Uses op_syscall: reliably > 0 ticks on any host.)
    Stats real = measure(op_syscall, real_ticks(), 20000, 2000);
    CHECK(real.median > 0, "syscall has a measurable real cost");

    // A huge scale compresses observed duration toward 0.
    Stats deceived = measure(op_syscall, scaled_ticks(1e9), 20000, 2000);
    CHECK(deceived.median <= real.median,
          "scaled (deceiving) clock reports a duration <= real");

    // Determinism of the property: against a baseline, a large-enough scale
    // always makes 'elevated' become false. Build a baseline and verify flip.
    Stats base = measure(op_arith, real_ticks(), 20000, 2000);
    if (looks_elevated(real, base, 3.0)) {
        double k = evasion_crossover_scale(real, base, 3.0);
        Stats seen = measure(op_syscall, scaled_ticks(k * 2.0), 20000, 2000);
        CHECK(!looks_elevated(seen, base, 3.0),
              "clock scaled past crossover flips verdict elevated -> not elevated");
    } else {
        std::printf("  note: syscall not elevated vs arith on this host; "
                    "evasion crossover trivially 0 (reported, not a failure)\n");
    }
}

int main() {
    std::puts("test_timing_probe:");
    test_tsc_monotonic_nonzero();
    test_summarize();
    test_detector_logic();
    test_crossover_math_and_measurement();
    test_scaled_clock_defeats_a_real_measurement();
    if (g_fails) { std::printf("FAILED (%d)\n", g_fails); return 1; }
    std::puts("ALL PASS");
    return 0;
}
