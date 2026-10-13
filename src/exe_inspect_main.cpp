// exe_inspect_main.cpp — command-line front end for the read-only inspector.
//
// Usage: exe_inspect <file> [<file> ...]
// Exit code: 0 if every file parsed without a fatal error, 1 otherwise.
// It opens each file read-only and NEVER executes or loads code from it.
#include <cstdio>
#include <string>

#include "exe_inspect.hpp"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <file> [<file> ...]\n", argv[0]);
        return 2;
    }
    int rc = 0;
    for (int i = 1; i < argc; ++i) {
        std::string path = argv[i];
        std::printf("==== %s ====\n", path.c_str());
        std::string io_err;
        at_demo::exe::Report r = at_demo::exe::analyze_file(path, &io_err);
        std::fputs(at_demo::exe::format_report(r).c_str(), stdout);
        if (r.malformed) rc = 1;
        std::printf("\n");
    }
    return rc;
}
