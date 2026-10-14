// lab_demo_main.cpp — independent demonstration program for the Denuvo-
// principles study (docs/07). It reproduces, on ITS OWN bytes only, four
// generic anti-tamper mechanisms and reports a combined "posture", while making
// the limits explicit: environment and debugger signals produce false
// positives, and a tripped signal is NOT proof of tampering.
//
// Read/observe only: it never inspects, modifies, or bypasses any third-party
// software. `--tamper` flips a byte of its own protected buffer to show the
// integrity check firing.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "anti_debug.hpp"
#include "env_checks.hpp"
#include "integrity.hpp"
#include "vm_mini.hpp"

namespace {

alignas(64) unsigned char g_protected[256];

void fill() {
    for (int i = 0; i < 256; ++i)
        g_protected[i] = static_cast<unsigned char>((i * 29 + 7) & 0xFF);
}

int run(bool tamper) {
    using namespace at_demo;
    std::puts("=== anti-tamper principles lab (demo on its own bytes) ===\n");

    // (1) Integrity verification --------------------------------------------
    fill();
    const std::uint64_t seed = 0xA5A5F00DD00DF00Dull;
    integrity::IntegrityGuard guard(seed);
    guard.enroll({"protected", g_protected, sizeof(g_protected)});
    integrity::Region text = integrity::self_text_region();
    if (text.begin) guard.enroll(text);

    if (tamper) {
        std::puts("[*] simulating tamper: flipping protected[77]");
        g_protected[77] ^= 0x40;
    }

    int integrity_fail = 0;
    std::puts("(1) INTEGRITY");
    for (const auto& r : guard.verify()) {
        std::printf("    %-12s %s\n", r.region.c_str(), r.ok ? "OK" : "TAMPERED");
        if (!r.ok) ++integrity_fail;
    }

    // (2) Code virtualization: native vs VM over the same bytes --------------
    std::uint64_t nat = integrity::keyed_checksum(g_protected, sizeof(g_protected), seed);
    std::uint64_t steps = 0;
    auto prog = vm::build_checksum_program(g_protected, sizeof(g_protected), seed);
    std::uint64_t virt = vm::run(prog, &steps);
    std::puts("\n(2) CODE VIRTUALIZATION");
    std::printf("    native==VM : %s  (%llu VM instructions)\n",
                nat == virt ? "yes" : "NO", (unsigned long long)steps);

    // (3) Anti-debug signals (each individually weak) ------------------------
    int susp = 0;
    std::puts("\n(3) ANTI-DEBUG (heuristic — false positives possible)");
    for (const auto& s : anti_debug::collect_all()) {
        std::printf("    %-12s %-6s %s\n", s.name.c_str(),
                    s.triggered ? "TRIP" : "-", s.detail.c_str());
        if (s.triggered) ++susp;
    }

    // (4) Environment verification (false positives on legit VMs) ------------
    std::puts("\n(4) ENVIRONMENT (heuristic — trips on legitimate VMs/cloud)");
    for (const auto& s : env::collect_all()) {
        std::printf("    %-18s %-6s %s\n", s.name.c_str(),
                    s.triggered ? "TRIP" : "-", s.detail.c_str());
        if (s.triggered) ++susp;
    }

    // Combined posture + honest disclaimer -----------------------------------
    std::puts("\n=== POSTURE ===");
    std::printf("    integrity violations : %d\n", integrity_fail);
    std::printf("    heuristic signals    : %d tripped (anti-debug + environment)\n", susp);
    std::puts(
        "    NOTE: heuristic trips are NOT proof of tampering. This process is\n"
        "    almost certainly running in a VM/container, so environment signals\n"
        "    fire on a perfectly legitimate host — a textbook false positive.\n"
        "    Only the integrity check is a direct tamper signal here.");

    // Exit non-zero only on a real integrity violation, never on heuristics.
    return integrity_fail ? 2 : 0;
}

}  // namespace

int main(int argc, char** argv) {
    bool tamper = false;
    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], "--tamper") == 0) tamper = true;
    return run(tamper);
}
