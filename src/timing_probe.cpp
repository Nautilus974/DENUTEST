#include "timing_probe.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#include <cpuid.h>
#define AT_X86 1
#endif

#if defined(__linux__) || defined(__unix__)
#include <sys/types.h>
#include <unistd.h>
#define AT_HAVE_GETPID 1
#endif

namespace at_demo::timing {

namespace {
// Sink the optimizer cannot discard.
volatile std::uint64_t g_sink = 0;
}

std::uint64_t tsc_now() noexcept {
#if defined(AT_X86)
    _mm_lfence();
    std::uint64_t t = __rdtsc();
    _mm_lfence();
    return t;
#else
    // Fallback: steady_clock nanoseconds (not cycle-accurate, but monotonic).
    return static_cast<std::uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
#endif
}

TickSource real_ticks() { return [] { return tsc_now(); }; }

TickSource scaled_ticks(double scale) {
    if (scale < 1.0) scale = 1.0;
    return [scale] {
        return static_cast<std::uint64_t>(static_cast<double>(tsc_now()) / scale);
    };
}

Stats summarize(std::vector<std::uint64_t> s) {
    Stats st;
    if (s.empty()) return st;
    std::sort(s.begin(), s.end());
    st.n = s.size();
    st.min = s.front();
    st.max = s.back();
    st.median = s[s.size() / 2];
    st.p99 = s[std::min(s.size() - 1, static_cast<std::size_t>(s.size() * 0.99))];
    double sum = 0.0;
    for (auto v : s) sum += static_cast<double>(v);
    st.mean = sum / static_cast<double>(s.size());
    double var = 0.0;
    for (auto v : s) {
        double d = static_cast<double>(v) - st.mean;
        var += d * d;
    }
    st.stddev = std::sqrt(var / static_cast<double>(s.size()));
    return st;
}

Stats measure(const std::function<void()>& op, const TickSource& now,
              std::size_t samples, std::size_t warmup) {
    for (std::size_t i = 0; i < warmup; ++i) op();
    std::vector<std::uint64_t> d;
    d.reserve(samples);
    for (std::size_t i = 0; i < samples; ++i) {
        std::uint64_t t0 = now();
        op();
        std::uint64_t t1 = now();
        d.push_back(t1 >= t0 ? t1 - t0 : 0);
    }
    return summarize(std::move(d));
}

void op_cpuid() noexcept {
#if defined(AT_X86)
    unsigned a = 0, b = 0, c = 0, d = 0;
    __get_cpuid(0, &a, &b, &c, &d);   // leaf 0; serializing, often trapped
    g_sink += a ^ b ^ c ^ d;
#else
    g_sink += 1;
#endif
}

void op_syscall() noexcept {
#if defined(AT_HAVE_GETPID)
    g_sink += static_cast<std::uint64_t>(::getpid());
#else
    g_sink += 2;
#endif
}

void op_arith() noexcept {
    std::uint64_t x = g_sink;
    x = x * 6364136223846793005ull + 1442695040888963407ull;
    g_sink = x;
}

bool looks_elevated(const Stats& op, const Stats& baseline,
                    double ratio_threshold) noexcept {
    if (baseline.median == 0) return false;
    double ratio = static_cast<double>(op.median) /
                   static_cast<double>(baseline.median);
    return ratio >= ratio_threshold;
}

double evasion_crossover_scale(const Stats& op_real, const Stats& baseline_real,
                               double ratio_threshold) noexcept {
    if (baseline_real.median == 0) return 0.0;
    double ratio = static_cast<double>(op_real.median) /
                   static_cast<double>(baseline_real.median);
    if (ratio < ratio_threshold) return 0.0;  // nothing to evade
    // Scaling the clock by k divides the observed op duration by k, so the
    // observed ratio becomes ratio/k. It drops below threshold once
    // k > ratio / ratio_threshold.
    return ratio / ratio_threshold;
}

}  // namespace at_demo::timing
