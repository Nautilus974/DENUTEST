// Minimal assertion-based tests (no external framework) wired into CTest.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "integrity.hpp"
#include "vm_mini.hpp"

static int g_fails = 0;
#define CHECK(cond, msg)                                              \
    do {                                                             \
        if (!(cond)) {                                              \
            std::printf("  FAIL: %s\n", msg);                       \
            ++g_fails;                                              \
        } else {                                                    \
            std::printf("  ok:   %s\n", msg);                       \
        }                                                           \
    } while (0)

using namespace at_demo;

static void test_crc32_known_vector() {
    // CRC-32 of "123456789" is the well-known 0xCBF43926.
    const char* s = "123456789";
    std::uint32_t c = integrity::crc32(s, std::strlen(s));
    CHECK(c == 0xCBF43926u, "crc32('123456789') == 0xCBF43926");
}

static void test_checksum_detects_tamper() {
    std::vector<std::uint8_t> buf(512);
    for (std::size_t i = 0; i < buf.size(); ++i) buf[i] = std::uint8_t(i);
    const std::uint64_t seed = 0xDEADBEEFCAFEBABEull;

    integrity::IntegrityGuard guard(seed);
    guard.enroll({"buf", buf.data(), buf.size()});
    CHECK(guard.all_ok(), "clean buffer verifies OK");

    buf[200] ^= 0x01;  // tamper one bit
    CHECK(!guard.all_ok(), "single-bit tamper is detected");

    buf[200] ^= 0x01;  // restore
    CHECK(guard.all_ok(), "restoring the byte makes it verify again");
}

static void test_seed_changes_value() {
    std::vector<std::uint8_t> buf(64, 0xAA);
    std::uint64_t a = integrity::keyed_checksum(buf.data(), buf.size(), 1);
    std::uint64_t b = integrity::keyed_checksum(buf.data(), buf.size(), 2);
    CHECK(a != b, "different seeds yield different checksums");
}

static void test_vm_matches_native() {
    std::vector<std::uint8_t> buf(300);
    for (std::size_t i = 0; i < buf.size(); ++i)
        buf[i] = std::uint8_t((i * 7 + 3) & 0xFF);
    const std::uint64_t seed = 0x0123456789ABCDEFull;

    std::uint64_t native = integrity::keyed_checksum(buf.data(), buf.size(), seed);
    auto prog = vm::build_checksum_program(buf.data(), buf.size(), seed);
    std::uint64_t steps = 0;
    std::uint64_t virt = vm::run(prog, &steps);
    CHECK(native == virt, "virtualized checksum == native checksum");
    CHECK(steps > buf.size(), "VM dispatched more steps than bytes (overhead)");
}

static void test_vm_empty_region() {
    const std::uint64_t seed = 42;
    std::uint64_t native = integrity::keyed_checksum(nullptr, 0, seed);
    auto prog = vm::build_checksum_program(nullptr, 0, seed);
    std::uint64_t virt = vm::run(prog);
    CHECK(native == virt, "empty region: VM == native");
}

int main() {
    std::puts("test_integrity:");
    test_crc32_known_vector();
    test_checksum_detects_tamper();
    test_seed_changes_value();
    test_vm_matches_native();
    test_vm_empty_region();
    if (g_fails) {
        std::printf("FAILED (%d)\n", g_fails);
        return 1;
    }
    std::puts("ALL PASS");
    return 0;
}
