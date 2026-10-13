#include "vm_mini.hpp"

namespace at_demo::vm {

namespace {
// Validate a program ONCE before execution so the dispatch loop stays free of
// per-instruction bounds checks (keeping the benchmark honest). Rejects the two
// malformed-input cases an independent audit demonstrated as undefined
// behavior: a register operand outside [0,kNumRegs) (out-of-bounds array
// access) and a ShrI shift amount >= 64 (shift wider than the type). Unused
// operand fields are 0 in every well-formed program, so this never rejects a
// valid one (verified by the equivalence fuzz and the test suite).
bool is_well_formed(const Program& prog) noexcept {
    for (const Instr& in : prog) {
        if (in.a >= kNumRegs || in.b >= kNumRegs || in.c >= kNumRegs)
            return false;
        if (in.op == Op::ShrI && in.imm >= 64)
            return false;
    }
    return true;
}
}  // namespace

std::uint64_t run(const Program& prog, std::uint64_t* steps_out) {
    if (!is_well_formed(prog)) {  // malformed bytecode => no-op, avoids UB
        if (steps_out) *steps_out = 0;
        return 0;
    }

    std::array<std::uint64_t, kNumRegs> reg{};
    std::uint64_t steps = 0;
    std::size_t pc = 0;
    std::uint64_t result = 0;

    while (pc < prog.size()) {
        const Instr& in = prog[pc];
        ++steps;
        switch (in.op) {
            case Op::Imm:    reg[in.a] = in.imm; ++pc; break;
            case Op::LoadU8:
                reg[in.a] = *reinterpret_cast<const std::uint8_t*>(
                    static_cast<std::uintptr_t>(reg[in.b]));
                ++pc;
                break;
            case Op::Mov:    reg[in.a] = reg[in.b]; ++pc; break;
            case Op::Add:    reg[in.a] = reg[in.b] + reg[in.c]; ++pc; break;
            case Op::Sub:    reg[in.a] = reg[in.b] - reg[in.c]; ++pc; break;
            case Op::Xor:    reg[in.a] = reg[in.b] ^ reg[in.c]; ++pc; break;
            case Op::Mul:    reg[in.a] = reg[in.b] * reg[in.c]; ++pc; break;
            case Op::ShrI:   reg[in.a] = reg[in.b] >> in.imm; ++pc; break;
            case Op::AddI:   reg[in.a] = reg[in.b] + in.imm; ++pc; break;
            case Op::Jnz:
                if (reg[in.a] != 0)
                    pc = static_cast<std::size_t>(in.imm);
                else
                    ++pc;
                break;
            case Op::Halt:   result = reg[in.a]; pc = prog.size(); break;
        }
    }
    if (steps_out) *steps_out = steps;
    return result;
}

Program build_checksum_program(const std::uint8_t* base, std::uint64_t len,
                               std::uint64_t seed) {
    // Register allocation:
    //   R0 = h (accumulator)   R1 = p (cursor)   R2 = end pointer
    //   R3 = loaded byte       R4 = FNV prime    R5 = temp / loop remaining
    //   R6 = splitmix constant
    constexpr std::uint64_t kBasis = 1469598103934665603ull;
    constexpr std::uint64_t kPrime = 1099511628211ull;
    constexpr std::uint64_t kMix = 0xff51afd7ed558ccdull;

    Program p;
    auto emit = [&](Op op, int a, int b = 0, int c = 0, std::uint64_t imm = 0) {
        p.push_back(Instr{op, static_cast<std::uint8_t>(a),
                          static_cast<std::uint8_t>(b),
                          static_cast<std::uint8_t>(c), imm});
    };

    emit(Op::Imm, 0, 0, 0, seed);                              // R0 = seed
    emit(Op::Imm, 5, 0, 0, kBasis);                            // R5 = basis
    emit(Op::Xor, 0, 0, 5);                                    // h = seed ^ basis
    emit(Op::Imm, 1, 0, 0, reinterpret_cast<std::uintptr_t>(base));  // R1 = base
    emit(Op::Imm, 2, 0, 0, len);                               // R2 = len
    emit(Op::Add, 2, 1, 2);                                    // R2 = base + len
    emit(Op::Imm, 4, 0, 0, kPrime);                            // R4 = prime

    if (len != 0) {
        std::size_t body = p.size();  // index of first body instruction
        emit(Op::LoadU8, 3, 1);                               // R3 = *p
        emit(Op::Xor, 0, 0, 3);                                // h ^= byte
        emit(Op::Mul, 0, 0, 4);                                // h *= prime
        emit(Op::ShrI, 5, 0, 0, 29);                           // R5 = h >> 29
        emit(Op::Xor, 0, 0, 5);                                // h ^= h>>29
        emit(Op::AddI, 1, 1, 0, 1);                            // p++
        emit(Op::Sub, 5, 2, 1);                                // R5 = end - p
        emit(Op::Jnz, 5, 0, 0, body);                          // loop while p != end
    }

    // Final avalanche (splitmix64-style), matching keyed_checksum().
    emit(Op::ShrI, 5, 0, 0, 33);                               // R5 = h>>33
    emit(Op::Xor, 0, 0, 5);                                    // h ^= h>>33
    emit(Op::Imm, 6, 0, 0, kMix);                              // R6 = mix const
    emit(Op::Mul, 0, 0, 6);                                    // h *= mix
    emit(Op::ShrI, 5, 0, 0, 33);                               // R5 = h>>33
    emit(Op::Xor, 0, 0, 5);                                    // h ^= h>>33
    emit(Op::Halt, 0);                                         // result = h
    return p;
}

}  // namespace at_demo::vm
