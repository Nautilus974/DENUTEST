// timing_experiment_main.cpp — runs the timing-detection experiment and prints
// REAL measured numbers for this host. Observational (no asserts); the unit
// test (test_timing_probe) covers the deterministic properties. Read-only, no
// game, no circumvention.
#include <cstdio>
#include <cstdlib>

#include "timing_probe.hpp"

using namespace at_demo::timing;

static void print_stats(const char* name, const Stats& s) {
    std::printf("  %-10s n=%zu  min=%llu  median=%llu  p99=%llu  mean=%.1f  sd=%.1f\n",
                name, s.n, (unsigned long long)s.min, (unsigned long long)s.median,
                (unsigned long long)s.p99, s.mean, s.stddev);
}

int main(int argc, char** argv) {
    std::size_t samples = 200000;
    double threshold = 3.0;  // "elevated" if op median >= 3x baseline median
    if (argc > 1) samples = static_cast<std::size_t>(std::atol(argv[1]));
    if (argc > 2) threshold = std::atof(argv[2]);

    std::puts("=== timing-detection experiment (this host) ===");
    std::printf("samples=%zu  elevated-threshold=%.2fx baseline median\n\n", samples, threshold);

    Stats arith   = measure(op_arith,   real_ticks(), samples);
    Stats syscall = measure(op_syscall, real_ticks(), samples);
    Stats cpuid   = measure(op_cpuid,   real_ticks(), samples);

    std::puts("[1] Measured per-call cost (RDTSC ticks, real clock):");
    print_stats("arith",   arith);
    print_stats("syscall", syscall);
    print_stats("cpuid",   cpuid);

    auto ratio = [&](const Stats& s) {
        return arith.median ? (double)s.median / (double)arith.median : 0.0;
    };
    std::printf("\n[2] Cost ratio vs arithmetic baseline:\n");
    std::printf("  syscall/arith = %.2fx   -> elevated? %s\n", ratio(syscall),
                looks_elevated(syscall, arith, threshold) ? "YES" : "no");
    std::printf("  cpuid/arith   = %.2fx   -> elevated? %s\n", ratio(cpuid),
                looks_elevated(cpuid, arith, threshold) ? "YES" : "no");

    std::puts("\n[3] Evasion: scale the detector's clock until the verdict flips.");
    // Use whichever op is actually elevated on this host as the demonstrator.
    bool use_cpuid = looks_elevated(cpuid, arith, threshold);
    const Stats& demo = use_cpuid ? cpuid : syscall;
    const char* demo_name = use_cpuid ? "cpuid" : "syscall";
    void (*demo_op)() = use_cpuid ? op_cpuid : op_syscall;
    double k = evasion_crossover_scale(demo, arith, threshold);
    if (k <= 0.0) {
        std::printf("  neither op is 'elevated' at %.2fx here; nothing to evade\n", threshold);
        std::printf("  (this host may not trap these ops measurably; see docs/11)\n");
    } else {
        std::printf("  predicted crossover for %s: clock scale k* = %.2f\n", demo_name, k);
        // Verify by RE-MEASURING the same op through a deceiving clock just
        // below and just above the predicted crossover.
        double below = k * 0.9, above = k * 1.1;
        Stats seen_below = measure(demo_op, scaled_ticks(below), samples);
        Stats seen_above = measure(demo_op, scaled_ticks(above), samples);
        std::printf("  re-measured through deceiving clock:\n");
        std::printf("    at k=%.2f (below k*): %s/arith=%.2fx -> elevated? %s\n", below, demo_name,
                    arith.median ? (double)seen_below.median / arith.median : 0.0,
                    looks_elevated(seen_below, arith, threshold) ? "YES" : "no");
        std::printf("    at k=%.2f (above k*): %s/arith=%.2fx -> elevated? %s\n", above, demo_name,
                    arith.median ? (double)seen_above.median / arith.median : 0.0,
                    looks_elevated(seen_above, arith, threshold) ? "YES" : "no");
        std::puts("  => controlling the clock defeats the timing check (measured).");
    }
    return 0;
}
