// vm_mini.hpp — a tiny register-based bytecode virtual machine.
//
// Illustrates *code virtualization*, the concept at the heart of
// Denuvo-class protectors: instead of executing native x86-64, a routine is
// translated to a custom instruction set and run by an interpreter. A static
// disassembler then sees only the VM dispatch loop, not the original
// algorithm, and the per-instruction dispatch imposes a measurable cost.
//
// This VM is deliberately simple and *not* obfuscated; its purpose is to make
// the native-vs-virtualized trade-off measurable and the mechanism readable.
// Real virtualizing protectors add handler polymorphism, encrypted bytecode,
// and dispatch obfuscation on top of this basic idea. See docs/01-architecture.md.
#pragma once

#include <array>
#include <cstdint>
#include <vector>

namespace at_demo::vm {

// 8 general-purpose 64-bit registers: R0..R7.
inline constexpr int kNumRegs = 8;

enum class Op : std::uint8_t {
    Imm,     // reg[a] = imm
    LoadU8,  // reg[a] = *(uint8_t*)reg[b]   (reads guarded memory via a pointer)
    Mov,     // reg[a] = reg[b]
    Add,     // reg[a] = reg[b] + reg[c]
    Sub,     // reg[a] = reg[b] - reg[c]
    Xor,     // reg[a] = reg[b] ^ reg[c]
    Mul,     // reg[a] = reg[b] * reg[c]
    ShrI,    // reg[a] = reg[b] >> imm
    AddI,    // reg[a] = reg[b] + imm
    Jnz,     // if reg[a] != 0 goto imm (instruction index)
    Halt     // stop; result = reg[a]
};

struct Instr {
    Op op;
    std::uint8_t a = 0, b = 0, c = 0;
    std::uint64_t imm = 0;
};

using Program = std::vector<Instr>;

// Execute `prog`. On Halt returns reg[a] of the Halt instruction.
// `steps_out`, if non-null, receives the number of instructions dispatched
// (a direct measure of virtualization overhead vs. native execution).
//
// A well-formed program uses only register indices in [0,kNumRegs) and ShrI
// shift amounts < 64. `run` validates this once up front; a malformed program
// is treated as a no-op (returns 0, steps_out=0) rather than invoking undefined
// behavior. Jump targets outside the program simply halt (the pc<size guard).
std::uint64_t run(const Program& prog, std::uint64_t* steps_out = nullptr);

// Emit a VM program computing the exact same value as
// integrity::keyed_checksum() over [base, base+len). This lets a test assert
// native == virtualized, proving the VM faithfully executes the algorithm.
Program build_checksum_program(const std::uint8_t* base, std::uint64_t len,
                               std::uint64_t seed);

}  // namespace at_demo::vm
