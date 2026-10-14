#include "protection_model.hpp"

#include "integrity.hpp"

namespace at_demo::protmodel {

bool environment_gate(const EnvReport& reported) noexcept {
    // Deny if the reported environment looks instrumented/virtualized.
    // NOTE: this trusts `reported`; see header. A privileged layer that reports
    // {false,false} is admitted regardless of the real machine state.
    return !reported.debugger_present && !reported.hypervisor_present;
}

std::uint64_t expected_token(std::uint64_t challenge, std::uint64_t secret) noexcept {
    // Keyed MAC over the challenge (reusing the lab's keyed checksum). Security
    // rests on `secret` staying unknown to the caller.
    return integrity::keyed_checksum(&challenge, sizeof(challenge), secret);
}

bool entitlement_gate(std::uint64_t challenge, std::uint64_t presented_token,
                      std::uint64_t secret) noexcept {
    return presented_token == expected_token(challenge, secret);
}

}  // namespace at_demo::protmodel
