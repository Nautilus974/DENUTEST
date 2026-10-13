// demo_main.cpp — end-to-end demonstration of the integrity / anti-debug /
// virtualization primitives. This is the reproducible example program the
// report refers to. It protects *its own* code and data only.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "anti_debug.hpp"
#include "integrity.hpp"
#include "vm_mini.hpp"

namespace {

// A "licensed feature" guarded by an integrity check: a byte buffer whose
// contents must not be modified at runtime. In a real program this might be a
// decrypted code stub; here it is plain data so the demo is self-contained.
alignas(64) unsigned char g_protected_blob[256];

void fill_blob() {
    for (int i = 0; i < 256; ++i)
        g_protected_blob[i] = static_cast<unsigned char>((i * 37 + 11) & 0xFF);
}

int run_demo(bool simulate_tamper) {
    using namespace at_demo;

    std::puts("== Anti-tamper concept demo ==");

    // --- Anti-debug signals -------------------------------------------------
    std::puts("\n[1] Debugger / instrumentation signals:");
    for (const auto& s : anti_debug::collect_all())
        std::printf("    %-12s triggered=%-5s  %s\n", s.name.c_str(),
                    s.triggered ? "true" : "false", s.detail.c_str());

    // --- Integrity: enroll, (optionally tamper), verify ---------------------
    std::puts("\n[2] Integrity guard over protected data + own code:");
    fill_blob();
    const std::uint64_t seed = 0x9E3779B97F4A7C15ull;  // runtime-derived in reality
    integrity::IntegrityGuard guard(seed);
    guard.enroll({"protected_blob", g_protected_blob, sizeof(g_protected_blob)});
    integrity::Region text = integrity::self_text_region();
    if (text.begin)
        guard.enroll(text);
    else
        std::puts("    (self .text region unavailable on this platform)");

    if (simulate_tamper) {
        std::puts("    >> simulating tamper: flipping one byte of protected_blob");
        g_protected_blob[123] ^= 0x01;
    }

    int bad = 0;
    for (const auto& r : guard.verify()) {
        std::printf("    %-16s %s (expected=%016llx actual=%016llx)\n",
                    r.region.c_str(), r.ok ? "OK" : "TAMPERED",
                    static_cast<unsigned long long>(r.expected),
                    static_cast<unsigned long long>(r.actual));
        if (!r.ok) ++bad;
    }

    // --- Virtualization: native vs. VM checksum of the same bytes -----------
    std::puts("\n[3] Code virtualization (native vs. bytecode VM):");
    std::uint64_t native =
        integrity::keyed_checksum(g_protected_blob, sizeof(g_protected_blob), seed);
    std::uint64_t steps = 0;
    auto prog = vm::build_checksum_program(g_protected_blob,
                                           sizeof(g_protected_blob), seed);
    std::uint64_t virt = vm::run(prog, &steps);
    std::printf("    native   = %016llx\n", (unsigned long long)native);
    std::printf("    virtual  = %016llx  (%llu VM instructions dispatched)\n",
                (unsigned long long)virt, (unsigned long long)steps);
    std::printf("    match    = %s\n", native == virt ? "yes" : "NO");

    std::puts("\n== Done ==");
    return bad == 0 ? 0 : 2;
}

}  // namespace

int main(int argc, char** argv) {
    bool tamper = false;
    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], "--tamper") == 0) tamper = true;
    return run_demo(tamper);
}
