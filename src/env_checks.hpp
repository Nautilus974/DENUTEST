// env_checks.hpp — benign, read-only environment-verification signals.
//
// Anti-tamper systems often inspect the *execution environment* (is this a VM,
// a sandbox, an analysis box?) as one input among many. This module reproduces
// the GENERIC, publicly-documented idea with harmless, standard observations:
// the CPUID hypervisor-present bit, the hypervisor vendor leaf, and the logical
// CPU count. Nothing here evades anything, hides anything, or changes behavior
// to defeat analysis — it only *reports* signals and, crucially, documents why
// each one produces FALSE POSITIVES on legitimate systems (cloud VMs, players
// running in virtual machines, low-core laptops, accessibility setups).
//
// The educational point is precisely that these checks are unreliable: a real
// anti-tamper that blocked every VM would also block paying customers.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace at_demo::env {

struct EnvSignal {
    std::string name;
    bool triggered = false;     // "environment looks non-bare-metal / constrained"
    std::string detail;         // observed evidence
    std::string false_positive; // why this signal is unreliable
};

// Pure decision logic for the hypervisor-present hint: true iff CPUID.1:ECX[31]
// is set. Extracted so the verdict can be unit-tested against crafted inputs.
// Security note: the verdict is purely a function of what the environment
// *reports*. A more-privileged layer (a hypervisor at Ring -1) can report
// whatever it likes, so this is not a trust boundary — see docs/09.
bool hypervisor_bit_from_ecx(std::uint32_t ecx) noexcept;

// CPUID leaf 1, ECX bit 31: the "hypervisor present" hint. Set by virtually all
// hypervisors. False positive: cloud servers and any player in a VM set it.
EnvSignal hypervisor_bit_signal();

// CPUID leaf 0x40000000: hypervisor vendor string (e.g. "KVMKVMKVM",
// "VMwareVMware", "Microsoft Hv"). Empty when absent/hidden. False positive:
// same as above; also absent on some containers that still virtualize.
EnvSignal hypervisor_vendor_signal();

// Logical CPU count below `suspicious_below`. Some sandboxes pin 1 vCPU.
// False positive: legitimate low-core machines and constrained containers.
EnvSignal low_cpu_count_signal(long suspicious_below = 2);

// Run all available environment signals (platform-dependent).
std::vector<EnvSignal> collect_all();

}  // namespace at_demo::env
