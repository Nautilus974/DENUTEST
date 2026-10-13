// anti_debug.hpp — portable debugger-presence and environment signals.
//
// Demonstrates the *generic* observable differences a program can detect when
// running under a debugger / instrumentation, and documents the Windows
// equivalents. These are detection signals only — not evasion, not anti-AV.
// Each signal is heuristic and individually weak; protectors combine many.
#pragma once

#include <string>
#include <vector>

namespace at_demo::anti_debug {

struct Signal {
    std::string name;
    bool triggered = false;   // true => "a debugger/instrumentation looks present"
    std::string detail;       // human-readable evidence
};

// Linux: inspect /proc/self/status "TracerPid". Non-zero => a tracer (gdb,
// strace, ptrace) is attached. Windows documented equivalent:
// IsDebuggerPresent() / CheckRemoteDebuggerPresent() / PEB->BeingDebugged.
Signal tracer_pid_signal();

// Attempt a self-ptrace (PTRACE_TRACEME). If a debugger already traces us, the
// call fails — a classic, documented anti-debug probe. On non-Linux this
// returns an untriggered, "unsupported" signal.
Signal self_ptrace_signal();

// Timing probe: a trivial loop that should take well under a threshold when
// run natively. Single-stepping / heavy instrumentation inflates it. Returns
// the measured nanoseconds in `detail`; `triggered` if it exceeds `threshold_ns`.
Signal timing_signal(double threshold_ns);

// Run all available signals.
std::vector<Signal> collect_all();

}  // namespace at_demo::anti_debug
