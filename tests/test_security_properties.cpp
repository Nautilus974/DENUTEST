// test_security_properties.cpp — Phase 5 security-property experiments on our
// OWN demo code. These evaluate GENERAL properties of integrity and
// environment-check mechanisms. They are NOT a model of Onimusha or Denuvo, and
// NOTHING here is a procedure to bypass any real product — the "attacker" is
// modeled only by calling our own functions with/without a secret value.
//
// Two properties are evaluated:
//   P1 — In-process integrity assurance reduces to the secrecy of its key.
//   P2 — In-process environment checks are a pure function of what the
//        environment reports, so they are spoofable AND false-positive-prone.
#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

#include "env_checks.hpp"
#include "integrity.hpp"

static int g_fails = 0;
#define CHECK(cond, msg)                                              \
    do {                                                             \
        if (!(cond)) { std::printf("  FAIL: %s\n", msg); ++g_fails; }\
        else         { std::printf("  ok:   %s\n", msg); }          \
    } while (0)

using namespace at_demo;

// ---- P1: integrity forgery resistance depends on key secrecy --------------
static void test_tamper_detected_with_secret_key() {
    std::vector<std::uint8_t> buf(512);
    for (std::size_t i = 0; i < buf.size(); ++i) buf[i] = std::uint8_t(i);
    const std::uint64_t secret = 0x1122334455667788ull;

    std::uint64_t ref = integrity::keyed_checksum(buf.data(), buf.size(), secret);
    buf[100] ^= 0x20;  // tamper
    std::uint64_t after = integrity::keyed_checksum(buf.data(), buf.size(), secret);
    CHECK(ref != after, "P1: tamper changes the keyed checksum (detected)");
}

static void test_known_key_makes_forgery_trivial() {
    // If the key is extractable from the binary (a real risk for in-process
    // checks), an attacker recomputes a matching reference for tampered data.
    // We model that by letting the "attacker" use the same key: the verdict is
    // deterministic, so a guard that stores a recomputable reference is void.
    std::vector<std::uint8_t> buf(256, 0xAB);
    const std::uint64_t leaked_key = 0xDEADBEEF;

    buf[10] ^= 0xFF;  // attacker's modification
    std::uint64_t forged_ref1 = integrity::keyed_checksum(buf.data(), buf.size(), leaked_key);
    std::uint64_t forged_ref2 = integrity::keyed_checksum(buf.data(), buf.size(), leaked_key);
    CHECK(forged_ref1 == forged_ref2,
          "P1: with the key known, the matching reference is deterministically forgeable");
}

static void test_secret_key_resists_forgery_statistically() {
    // Without the key, matching the reference is a 1-in-2^64 event. We sample
    // many wrong keys against a fixed secret reference and require ZERO matches
    // — evidence (not proof) of forgery resistance when the key stays secret.
    std::vector<std::uint8_t> buf(128);
    for (std::size_t i = 0; i < buf.size(); ++i) buf[i] = std::uint8_t(i * 3 + 1);
    const std::uint64_t secret = 0x0F1E2D3C4B5A6978ull;
    std::uint64_t ref = integrity::keyed_checksum(buf.data(), buf.size(), secret);

    // Attacker tampers and tries to hit `ref` using keys they do NOT know.
    buf[0] ^= 0x01;
    std::mt19937_64 rng(2026);
    int matches = 0;
    for (int i = 0; i < 200000; ++i) {
        std::uint64_t guess = rng();
        if (guess == secret) continue;  // exclude the real key from the trial
        if (integrity::keyed_checksum(buf.data(), buf.size(), guess) == ref) ++matches;
    }
    CHECK(matches == 0,
          "P1: 200k wrong-key forgery attempts on tampered data: 0 matches");
}

// ---- P2: environment checks trust their inputs ----------------------------
static void test_env_check_is_pure_function_of_report() {
    using env::hypervisor_bit_from_ecx;
    // Bit 31 set => "hypervisor present"; clear => "bare metal". The verdict is
    // whatever the environment reports in that bit.
    CHECK(hypervisor_bit_from_ecx(0x80000000u) == true,
          "P2: ECX[31]=1 is classified as hypervisor-present");
    CHECK(hypervisor_bit_from_ecx(0x00000000u) == false,
          "P2: ECX[31]=0 is classified as bare-metal");
    CHECK(hypervisor_bit_from_ecx(0x7FFFFFFFu) == false,
          "P2: all-low-bits-set but [31]=0 still reads bare-metal");
    CHECK(hypervisor_bit_from_ecx(0xFFFFFFFFu) == true,
          "P2: [31]=1 reads hypervisor regardless of other bits");
    // Consequence (documented, not a procedure): a layer that controls the
    // reported bit controls the verdict -> in-process env checks are NOT a
    // trust boundary (spoofable), and legitimate VMs set the bit (false
    // positive). This is a general property of our own check, not a claim
    // about any product.
}

int main() {
    std::puts("test_security_properties:");
    test_tamper_detected_with_secret_key();
    test_known_key_makes_forgery_trivial();
    test_secret_key_resists_forgery_statistically();
    test_env_check_is_pure_function_of_report();
    if (g_fails) { std::printf("FAILED (%d)\n", g_fails); return 1; }
    std::puts("ALL PASS");
    return 0;
}
