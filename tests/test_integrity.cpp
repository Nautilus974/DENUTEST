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

// --- Regression tests for the two UB bugs found in the independent audit ---
// (docs/03-independent-audit.md F1). These exercise the public run() API with
// deliberately malformed bytecode; the documented contract is that a malformed
// program is a no-op (returns 0, steps_out=0) rather than invoking UB. Before
// the fix these crafted programs triggered an out-of-bounds register store and
// a shift-exponent-too-large error under ASan/UBSan.

// Bug F1a: a register operand outside [0,kNumRegs) must not index the register
// array out of bounds.
static void test_vm_rejects_oob_register() {
    using namespace at_demo::vm;
    Program prog{
        Instr{Op::Imm, 200, 0, 0, 5},  // reg index 200 >> kNumRegs (8)
        Instr{Op::Halt, 200},
    };
    std::uint64_t steps = 123;  // sentinel: must be overwritten to 0
    std::uint64_t r = run(prog, &steps);
    CHECK(r == 0, "malformed (OOB register index) returns 0");
    CHECK(steps == 0, "malformed (OOB register index) dispatches 0 steps");
}

// Bug F1b: a ShrI shift amount >= 64 is undefined for a 64-bit type and must be
// rejected.
static void test_vm_rejects_bad_shift() {
    using namespace at_demo::vm;
    Program prog{
        Instr{Op::Imm, 0, 0, 0, 1},
        Instr{Op::ShrI, 0, 0, 0, 99},  // shift exponent 99 >= 64
        Instr{Op::Halt, 0},
    };
    std::uint64_t steps = 123;
    std::uint64_t r = run(prog, &steps);
    CHECK(r == 0, "malformed (shift >= 64) returns 0");
    CHECK(steps == 0, "malformed (shift >= 64) dispatches 0 steps");
}

// Positive control: the exact boundary values (highest valid register index
// kNumRegs-1, shift of 63) must still be accepted and executed, so the
// validator is not over-rejecting valid programs.
static void test_vm_accepts_boundary_values() {
    using namespace at_demo::vm;
    const int top = kNumRegs - 1;  // highest legal register index
    Program prog{
        Instr{Op::Imm, static_cast<std::uint8_t>(top), 0, 0,
              0xFFFFFFFFFFFFFFFFull},
        Instr{Op::ShrI, static_cast<std::uint8_t>(top),
              static_cast<std::uint8_t>(top), 0, 63},  // legal: 63 < 64
        Instr{Op::Halt, static_cast<std::uint8_t>(top)},
    };
    std::uint64_t steps = 0;
    std::uint64_t r = run(prog, &steps);
    CHECK(r == 1, "boundary program executes: 0xFFFF...F >> 63 == 1");
    CHECK(steps == 3, "boundary program dispatches all 3 instructions");
}

int main() {
    std::puts("test_integrity:");
    test_crc32_known_vector();
    test_checksum_detects_tamper();
    test_seed_changes_value();
    test_vm_matches_native();
    test_vm_empty_region();
    test_vm_rejects_oob_register();
    test_vm_rejects_bad_shift();
    test_vm_accepts_boundary_values();
    if (g_fails) {
        std::printf("FAILED (%d)\n", g_fails);
        return 1;
    }
    std::puts("ALL PASS");
    return 0;
}
