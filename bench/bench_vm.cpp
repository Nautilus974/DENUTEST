// bench_vm.cpp — measure the cost of virtualization and of hash primitives,
// and expose the effect of compiler optimization (build the same source at
// -O0/-O2/-O3 and compare). Results feed docs/02-results.md.
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#include "integrity.hpp"
#include "vm_mini.hpp"

using clock_t_ = std::chrono::steady_clock;

template <class F>
static double time_ns(int iters, F&& f) {
    auto t0 = clock_t_::now();
    for (int i = 0; i < iters; ++i) f();
    auto t1 = clock_t_::now();
    return std::chrono::duration<double, std::nano>(t1 - t0).count() / iters;
}

int main(int argc, char** argv) {
    std::size_t n = 4096;
    int iters = 2000;
    if (argc > 1) n = std::strtoul(argv[1], nullptr, 10);
    if (argc > 2) iters = std::atoi(argv[2]);

    std::vector<std::uint8_t> buf(n);
    for (std::size_t i = 0; i < n; ++i) buf[i] = std::uint8_t(i * 131 + 7);
    const std::uint64_t seed = 0x9E3779B97F4A7C15ull;

    using namespace at_demo;

    volatile std::uint64_t sink = 0;

    double t_crc = time_ns(iters, [&] { sink ^= integrity::crc32(buf.data(), n); });
    double t_fnv = time_ns(iters, [&] { sink ^= integrity::fnv1a64(buf.data(), n); });
    double t_keyed =
        time_ns(iters, [&] { sink ^= integrity::keyed_checksum(buf.data(), n, seed); });

    // Build the VM program once (compilation cost is amortized), then time
    // only execution — the fair comparison to the native keyed checksum.
    auto prog = vm::build_checksum_program(buf.data(), n, seed);
    double t_vm = time_ns(iters, [&] {
        std::uint64_t s = 0;
        sink ^= vm::run(prog, &s);
    });

    std::uint64_t steps = 0;
    (void)vm::run(prog, &steps);

    std::printf("bytes=%zu iters=%d\n", n, iters);
    std::printf("%-22s %10.1f ns   %6.3f ns/byte\n", "crc32", t_crc, t_crc / n);
    std::printf("%-22s %10.1f ns   %6.3f ns/byte\n", "fnv1a64", t_fnv, t_fnv / n);
    std::printf("%-22s %10.1f ns   %6.3f ns/byte\n", "keyed_checksum(native)",
                t_keyed, t_keyed / n);
    std::printf("%-22s %10.1f ns   %6.3f ns/byte  (%llu VM instrs)\n",
                "keyed_checksum(VM)", t_vm, t_vm / n,
                (unsigned long long)steps);
    std::printf("virtualization slowdown vs native = %.1fx\n",
                t_keyed > 0 ? t_vm / t_keyed : 0.0);
    (void)sink;
    return 0;
}
