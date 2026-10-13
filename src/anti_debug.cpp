#include "anti_debug.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>

#if defined(__linux__)
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace at_demo::anti_debug {

Signal tracer_pid_signal() {
    Signal s{"tracer_pid", false, "unsupported on this platform"};
#if defined(__linux__)
    std::FILE* f = std::fopen("/proc/self/status", "re");
    if (!f) {
        s.detail = "could not open /proc/self/status";
        return s;
    }
    char line[256];
    long tracer = 0;
    bool found = false;
    while (std::fgets(line, sizeof(line), f)) {
        if (std::strncmp(line, "TracerPid:", 10) == 0) {
            tracer = std::strtol(line + 10, nullptr, 10);
            found = true;
            break;
        }
    }
    std::fclose(f);
    if (found) {
        s.triggered = (tracer != 0);
        s.detail = "TracerPid=" + std::to_string(tracer);
    } else {
        s.detail = "TracerPid not found";
    }
#endif
    return s;
}

Signal self_ptrace_signal() {
    Signal s{"self_ptrace", false, "unsupported on this platform"};
#if defined(__linux__)
    // Fork so the probe does not leave the *main* process in a traced state
    // (which would break later debugging and confuse the timing signal). The
    // child performs PTRACE_TRACEME; if a debugger already traces the group,
    // the semantics differ and we report via exit status.
    pid_t child = fork();
    if (child == 0) {
        // In the child: try to become traced by our own parent-less context.
        long r = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        _exit(r == -1 ? 1 : 0);  // 1 => TRACEME failed => already traced
    } else if (child > 0) {
        int status = 0;
        waitpid(child, &status, 0);
        bool failed = WIFEXITED(status) && WEXITSTATUS(status) == 1;
        s.triggered = failed;
        s.detail = failed ? "PTRACE_TRACEME failed (already traced)"
                          : "PTRACE_TRACEME succeeded (no tracer)";
    } else {
        s.detail = "fork failed";
    }
#endif
    return s;
}

Signal timing_signal(double threshold_ns) {
    using clock = std::chrono::steady_clock;
    // A small volatile-accumulator loop the optimizer cannot delete.
    volatile std::uint64_t acc = 0;
    auto t0 = clock::now();
    for (int i = 0; i < 1000; ++i) acc += static_cast<std::uint64_t>(i) * 2654435761u;
    auto t1 = clock::now();
    double ns = std::chrono::duration<double, std::nano>(t1 - t0).count();
    Signal s{"timing", ns > threshold_ns,
             "loop_ns=" + std::to_string(ns) +
                 " threshold_ns=" + std::to_string(threshold_ns)};
    (void)acc;
    return s;
}

std::vector<Signal> collect_all() {
    return {tracer_pid_signal(), self_ptrace_signal(),
            timing_signal(50000.0)};
}

}  // namespace at_demo::anti_debug
