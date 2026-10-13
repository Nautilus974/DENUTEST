// Sanity tests for anti-debug signals. These assert *shape* and internal
// consistency, not a specific debugger verdict (which depends on how the test
// is launched). Under `ctest` there is normally no tracer attached.
#include <cstdio>

#include "anti_debug.hpp"

static int g_fails = 0;
#define CHECK(cond, msg)                                 \
    do {                                                \
        if (!(cond)) { std::printf("  FAIL: %s\n", msg); ++g_fails; } \
        else         { std::printf("  ok:   %s\n", msg); }            \
    } while (0)

using namespace at_demo;

int main() {
    std::puts("test_anti_debug:");

    auto all = anti_debug::collect_all();
    CHECK(all.size() == 3, "collect_all returns three signals");

    auto tp = anti_debug::tracer_pid_signal();
    CHECK(!tp.detail.empty(), "tracer_pid signal has a detail string");

    // Timing signal with an absurdly high threshold must not trigger.
    auto t_hi = anti_debug::timing_signal(1e12);
    CHECK(!t_hi.triggered, "timing does not trigger under a huge threshold");

    // Timing signal with a zero threshold must trigger (loop takes >0 ns).
    auto t_lo = anti_debug::timing_signal(0.0);
    CHECK(t_lo.triggered, "timing triggers under a zero threshold");

    if (g_fails) { std::printf("FAILED (%d)\n", g_fails); return 1; }
    std::puts("ALL PASS");
    return 0;
}
