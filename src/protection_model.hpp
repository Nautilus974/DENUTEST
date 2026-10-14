// protection_model.hpp — an abstract, two-gate model of a software protection,
// used to evaluate GENERAL security properties relevant to bypass feasibility.
//
// This is a teaching model on our OWN code. It is NOT a model of Denuvo or
// Onimusha, contains NO game code, and is NOT a bypass procedure. It separates
// two conceptually different gates so we can show, reproducibly, WHY an
// environment-level bypass can succeed while the "licensing core" can still
// resist it (i.e. why "bypassed" need not mean "fully cracked").
#pragma once

#include <cstdint>

namespace at_demo::protmodel {

// What a protection believes about its environment. A real protection reads
// this from the CPU/OS at runtime (CPUID, debug flags, timing). The point of
// the model is that this report is UNTRUSTED: a more-privileged layer can
// substitute any values it likes, so the protection's environment decision is
// only ever as trustworthy as the report it is handed.
struct EnvReport {
    bool debugger_present = false;
    bool hypervisor_present = false;
};

// ENVIRONMENT GATE — allow only if the environment "looks clean". The verdict
// is a pure function of the (untrusted) EnvReport, so whoever controls the
// report controls the gate. Returns true = allowed to proceed.
bool environment_gate(const EnvReport& reported) noexcept;

// ENTITLEMENT GATE — allow only if `presented_token` equals the correct keyed
// MAC over `challenge` under `secret`. The caller must POSSESS the secret (or
// break the MAC) to pass; controlling the environment does not help. Modeled
// with the lab's keyed checksum as the MAC primitive.
std::uint64_t expected_token(std::uint64_t challenge, std::uint64_t secret) noexcept;
bool entitlement_gate(std::uint64_t challenge, std::uint64_t presented_token,
                      std::uint64_t secret) noexcept;

}  // namespace at_demo::protmodel
