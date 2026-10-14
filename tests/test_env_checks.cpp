// Tests for the environment-verification signals. These assert the *shape* and
// internal consistency of each signal, and deliberately DOCUMENT the observed
// values (which are environment-dependent) rather than asserting a specific
// verdict — because the whole point of these heuristics is that their verdict
// is unreliable. A specific-verdict assertion would itself be a false-positive
// trap (e.g. "hypervisor must be set" fails on bare metal; "must be unset"
// fails in this container).
#include <cstdio>
#include <string>

#include "env_checks.hpp"

static int g_fails = 0;
#define CHECK(cond, msg)                                              \
    do {                                                             \
        if (!(cond)) { std::printf("  FAIL: %s\n", msg); ++g_fails; }\
        else         { std::printf("  ok:   %s\n", msg); }          \
    } while (0)

using namespace at_demo::env;

static void test_shapes() {
    auto all = collect_all();
    CHECK(all.size() == 3, "collect_all returns three signals");
    for (const auto& s : all) {
        CHECK(!s.name.empty(), ("signal has a name: " + s.name).c_str());
        CHECK(!s.detail.empty(), ("signal has a detail: " + s.name).c_str());
    }
}

static void test_low_cpu_threshold_logic() {
    // With an absurd threshold the signal MUST trip; with threshold 0 it must
    // not (no machine has <0 CPUs). This tests the comparison logic without
    // depending on the actual core count.
    auto hi = low_cpu_count_signal(1000000);
    auto lo = low_cpu_count_signal(0);
    // On platforms without sysconf these are "unsupported" (never triggered);
    // guard accordingly so the test is portable.
    if (hi.detail.rfind("unsupported", 0) == 0) {
        std::printf("  skip: cpu-count signal unsupported here\n");
        return;
    }
    CHECK(hi.triggered, "low_cpu_count trips under an absurdly high threshold");
    CHECK(!lo.triggered, "low_cpu_count does not trip under threshold 0");
}

static void test_determinism() {
    // Environment signals must be stable across back-to-back calls in one run.
    auto a = hypervisor_bit_signal();
    auto b = hypervisor_bit_signal();
    CHECK(a.triggered == b.triggered && a.detail == b.detail,
          "hypervisor_bit signal is deterministic within a run");
}

static void test_false_positive_text_present() {
    // Every heuristic signal must carry an explicit false-positive caveat, so
    // callers cannot treat a trip as proof of tampering.
    for (const auto& s : collect_all()) {
        bool has = !s.false_positive.empty() && s.false_positive != "n/a";
        // "n/a" only acceptable when the signal is unsupported on this platform.
        bool unsupported = s.detail.rfind("unsupported", 0) == 0;
        CHECK(has || unsupported,
              ("signal documents a false-positive risk: " + s.name).c_str());
    }
}

// Observation (not an assertion): record what the environment actually reports,
// so the test log doubles as evidence for docs/07. These lines never fail.
static void observe_and_report() {
    std::puts("  -- observed environment signals (evidence, not assertions) --");
    for (const auto& s : collect_all())
        std::printf("     %-18s triggered=%-5s %s\n", s.name.c_str(),
                    s.triggered ? "true" : "false", s.detail.c_str());
}

int main() {
    std::puts("test_env_checks:");
    test_shapes();
    test_low_cpu_threshold_logic();
    test_determinism();
    test_false_positive_text_present();
    observe_and_report();
    if (g_fails) { std::printf("FAILED (%d)\n", g_fails); return 1; }
    std::puts("ALL PASS");
    return 0;
}
