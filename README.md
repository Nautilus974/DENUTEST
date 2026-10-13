# DENUTEST — Anti-Tamper Concepts: A Reproducible Study

A hands-on, **defensive/educational** study of how executable anti-tamper
protection works, using **Denuvo Anti-Tamper** as the reference case. It pairs a
documented architecture analysis with a small, buildable C++17 project that
reproduces the *generic, public-domain* building blocks and **measures** their
cost on real hardware.

> **Ethics & scope.** This repository contains no reverse-engineering of any
> commercial product, no DRM/license/activation bypass, and no circumvention
> technique. Every runnable experiment operates on code we wrote and compiled
> ourselves. Claims about proprietary internals are either sourced to public
> documentation or explicitly marked `[Hypothesis]`. See
> [`docs/01-architecture.md`](docs/01-architecture.md).

## What's inside

| Path | What it demonstrates |
|------|----------------------|
| `src/integrity.*` | Runtime integrity verification: CRC-32, FNV-1a, a keyed checksum, an `IntegrityGuard` that enrolls regions and detects single-bit tampering, and self-`.text` location. |
| `src/anti_debug.*` | Portable debugger/instrumentation signals (`/proc` TracerPid, self-`ptrace`, RDTSC-style timing), with Windows equivalents documented behind `#ifdef _WIN32`. |
| `src/vm_mini.*` | A tiny **register-based bytecode VM** illustrating *code virtualization* — runs the exact same checksum as native, so the cost of virtualization is measurable. |
| `src/demo_main.cpp` | End-to-end demo tying the three together; protects its own code/data. |
| `tests/` | CTest suite: correctness of checksums, tamper detection, native==VM equivalence, anti-debug sanity. |
| `bench/bench_vm.cpp` | Native-vs-virtualized throughput and hash-primitive cost. |
| `scripts/analyze.sh` | Static (`objdump`/`nm`/`readelf`) + dynamic (`strace`) analysis of *our own* binary. |
| `scripts/optimization_study.sh` | Builds at `-O0..-O3` and tabulates the optimization/virtualization trade-off. |
| `docs/01-architecture.md` | Architecture, facts vs. hypotheses, RE concepts, tools & justification. |
| `docs/02-results.md` | Measured results, limitations, improvement directions. |

## Build & run

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure   # all tests

./build/at_demo            # clean run  -> exits 0
./build/at_demo --tamper   # simulated tamper -> detected, exits non-zero
./build/bench_vm 4096 2000 # benchmark
```

### Reproduce the key findings

```bash
# Anti-debug signals trip under observers (see docs/02-results.md §2):
./build/at_demo                                   # baseline: nothing trips
strace -e trace=none ./build/at_demo              # tracer_pid + self_ptrace trip
gdb -batch -ex run -ex quit ./build/at_demo       # only tracer_pid trips

# Virtualization cost across optimization levels (§3):
./scripts/optimization_study.sh 8192 3000

# What static/dynamic analysis leaks about our own binary (§4):
./scripts/analyze.sh
```

## Requirements

- Linux x86-64, C++17 compiler (tested: g++ 13, clang++ 18), CMake ≥ 3.16.
- Optional for the analysis scripts: `objdump`, `nm`, `readelf`, `strace`, `gdb`.
- Windows-specific code paths are documented and `#ifdef`-guarded; building them
  needs MSVC/MinGW (not required for the Linux experiments).

## Key takeaways (measured, not asserted)

- A single flipped bit in a guarded region is reliably detected.
- No single anti-debug signal is dependable: `strace` and `gdb` trip *different*
  signals — real protectors must combine many.
- Code virtualization costs ~6–13× native for the same routine, and hides the
  algorithm's constants/symbols from static disassembly — which is exactly why
  only small, critical routines get virtualized.

See [`docs/02-results.md`](docs/02-results.md) for the full tables, limitations,
and future work.
