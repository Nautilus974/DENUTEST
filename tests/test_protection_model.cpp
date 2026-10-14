// test_protection_model.cpp — Phase 6 reproducible property experiments.
//
// Evaluates, on our OWN abstract model (no game, no bypass procedure), the two
// security properties that bound bypass-feasibility reasoning:
//
//   G1 — An environment gate delegates trust to its (untrusted) environment
//        report, so a party controlling that report controls the verdict.
//        This is the GENERAL property behind publicly-reported hypervisor/
//        Ring -1 environment-deception techniques. It is NOT evidence about any
//        specific product.
//   G2 — A secret-dependent entitlement gate is NOT defeated by controlling the
//        environment; passing it requires possessing the secret (or breaking
//        the MAC). This is the GENERAL reason "environment bypass" need not
//        equal "full crack".
#include <cstdint>
#include <cstdio>
#include <random>

#include "protection_model.hpp"

static int g_fails = 0;
#define CHECK(cond, msg)                                              \
    do {                                                             \
        if (!(cond)) { std::printf("  FAIL: %s\n", msg); ++g_fails; }\
        else         { std::printf("  ok:   %s\n", msg); }          \
    } while (0)

using namespace at_demo::protmodel;

// G1: environment gate is a pure function of the reported environment.
static void test_environment_gate_trust_delegation() {
    EnvReport truthful_dirty{/*dbg=*/true, /*hv=*/true};   // real: instrumented VM
    EnvReport truthful_vm{/*dbg=*/false, /*hv=*/true};     // real: legit VM/cloud
    EnvReport lying_clean{/*dbg=*/false, /*hv=*/false};    // privileged layer lies

    CHECK(!environment_gate(truthful_dirty), "G1: honest 'debugger+VM' report is denied");
    CHECK(!environment_gate(truthful_vm),    "G1: honest 'VM present' report is denied (also a FALSE POSITIVE for legit VMs)");
    CHECK(environment_gate(lying_clean),     "G1: a report of 'clean' is admitted — whoever controls the report controls the gate");
}

// G2: entitlement gate requires the secret; environment control does not help.
static void test_entitlement_requires_secret() {
    const std::uint64_t secret = 0xC0FFEE1234567890ull;   // server/HW secret
    const std::uint64_t challenge = 0x0123456789ABCDEFull;

    std::uint64_t good = expected_token(challenge, secret);
    CHECK(entitlement_gate(challenge, good, secret),
          "G2: correct token (holder of the secret) passes");

    // Attacker WITHOUT the secret: try many tokens; none should pass.
    std::mt19937_64 rng(606);
    int passes = 0;
    for (int i = 0; i < 200000; ++i) {
        std::uint64_t guess = rng();
        if (guess == good) continue;  // exclude a lucky exact hit from the trial
        if (entitlement_gate(challenge, guess, secret)) ++passes;
    }
    CHECK(passes == 0, "G2: 200k forged tokens without the secret: 0 pass");
}

// G2 (cont.): controlling the environment does NOT satisfy the entitlement gate.
static void test_env_control_does_not_grant_entitlement() {
    const std::uint64_t secret = 0xA11CE5EED;
    const std::uint64_t challenge = 42;
    // Even with a perfectly "clean" (lying) environment that passes G1, a caller
    // lacking the secret cannot produce the right token for G2.
    EnvReport lying_clean{false, false};
    bool env_ok = environment_gate(lying_clean);
    std::uint64_t wrong_token = 0xDEADBEEF;  // attacker guess, no secret
    bool ent_ok = entitlement_gate(challenge, wrong_token, secret);
    CHECK(env_ok && !ent_ok,
          "G2: passing the environment gate does NOT pass the entitlement gate (bypass != full crack)");
}

int main() {
    std::puts("test_protection_model:");
    test_environment_gate_trust_delegation();
    test_entitlement_requires_secret();
    test_env_control_does_not_grant_entitlement();
    if (g_fails) { std::printf("FAILED (%d)\n", g_fails); return 1; }
    std::puts("ALL PASS");
    return 0;
}
