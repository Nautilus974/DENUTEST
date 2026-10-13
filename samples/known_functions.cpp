// known_functions.cpp — a small program with deliberately recognizable
// functions, used by scripts/static_experiments.sh to observe how Debug vs
// Release builds affect symbols, inlining, and disassembly. It is a *subject*
// for static analysis, not part of the library. It does nothing security
// sensitive and is safe to run, though the experiments only inspect it.
#include <cstdint>
#include <cstdio>

// A tiny leaf function that is a strong inlining candidate at -O2.
static std::uint64_t mix(std::uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    return x;
}

// A loop the optimizer can vectorize / strength-reduce.
std::uint64_t sum_of_mixes(const std::uint8_t* data, std::size_t n) {
    std::uint64_t acc = 0;
    for (std::size_t i = 0; i < n; ++i) acc += mix(data[i]);
    return acc;
}

// A function kept out-of-line via an external-ish side effect.
std::uint64_t recognizable_marker(std::uint64_t seed) {
    volatile std::uint64_t sink = 0;
    for (int i = 0; i < 1000; ++i) sink += mix(seed + i);
    return sink;
}

int main(int argc, char** argv) {
    std::uint8_t buf[64];
    for (int i = 0; i < 64; ++i) buf[i] = static_cast<std::uint8_t>(i * 7 + 1);
    std::uint64_t r = sum_of_mixes(buf, sizeof(buf)) ^ recognizable_marker(argc);
    std::printf("%llu\n", static_cast<unsigned long long>(r));
    return static_cast<int>(r & 1) & (argc > 999 ? 1 : 0);
}
