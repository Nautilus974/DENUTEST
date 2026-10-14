#include "env_checks.hpp"

#include <string>

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#define AT_HAVE_CPUID 1
#endif

#if defined(__linux__) || defined(__unix__)
#include <unistd.h>
#define AT_HAVE_SYSCONF 1
#endif

namespace at_demo::env {

bool hypervisor_bit_from_ecx(std::uint32_t ecx) noexcept {
    return (ecx >> 31) & 1u;  // CPUID.1:ECX[31] = "hypervisor present" hint
}

EnvSignal hypervisor_bit_signal() {
    EnvSignal s{"hypervisor_bit", false, "unsupported on this platform",
                "n/a"};
#if defined(AT_HAVE_CPUID)
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (__get_cpuid(1, &a, &b, &c, &d)) {
        bool set = hypervisor_bit_from_ecx(c);
        s.triggered = set;
        s.detail = std::string("CPUID.1:ECX[31]=") + (set ? "1" : "0");
    } else {
        s.detail = "CPUID leaf 1 unavailable";
    }
    s.false_positive =
        "set by every hypervisor; any legitimate player in a VM or on a cloud "
        "host trips this — it does NOT mean tampering";
#endif
    return s;
}

EnvSignal hypervisor_vendor_signal() {
    EnvSignal s{"hypervisor_vendor", false, "unsupported on this platform",
                "n/a"};
#if defined(AT_HAVE_CPUID)
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (__get_cpuid(0x40000000u, &a, &b, &c, &d)) {
        char v[13];
        // Vendor is returned in EBX, ECX, EDX (12 bytes).
        for (int i = 0; i < 4; ++i) v[i] = static_cast<char>((b >> (8 * i)) & 0xff);
        for (int i = 0; i < 4; ++i) v[4 + i] = static_cast<char>((c >> (8 * i)) & 0xff);
        for (int i = 0; i < 4; ++i) v[8 + i] = static_cast<char>((d >> (8 * i)) & 0xff);
        v[12] = 0;
        // Keep only printable ASCII to avoid noise from empty leaves.
        std::string vendor;
        for (char ch : v)
            if (ch >= 0x20 && ch < 0x7f) vendor.push_back(ch);
        s.triggered = !vendor.empty();
        s.detail = vendor.empty() ? "no vendor string (leaf empty)"
                                  : ("vendor='" + vendor + "'");
    } else {
        s.detail = "CPUID leaf 0x40000000 unavailable";
    }
    s.false_positive =
        "identifies the hypervisor, not an attacker; present on all VMs and "
        "absent on some containers that still virtualize";
#endif
    return s;
}

EnvSignal low_cpu_count_signal(long suspicious_below) {
    EnvSignal s{"low_cpu_count", false, "unsupported on this platform", "n/a"};
#if defined(AT_HAVE_SYSCONF)
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n > 0) {
        s.triggered = (n < suspicious_below);
        s.detail = "online CPUs=" + std::to_string(n) +
                   " threshold=" + std::to_string(suspicious_below);
    } else {
        s.detail = "sysconf(_SC_NPROCESSORS_ONLN) failed";
    }
    s.false_positive =
        "legitimate low-core laptops and CPU-limited containers look identical "
        "to a 1-vCPU analysis sandbox";
#endif
    return s;
}

std::vector<EnvSignal> collect_all() {
    return {hypervisor_bit_signal(), hypervisor_vendor_signal(),
            low_cpu_count_signal(2)};
}

}  // namespace at_demo::env
