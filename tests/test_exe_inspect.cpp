// Tests for the read-only executable inspector. Covers: the bounds-checked
// Reader (offsets out of range, overflow-safe in_bounds, unterminated strings),
// crafted malformed ELF/PE fixtures (must report, never crash), a hand-built
// valid PE32+ fixture with one import (deterministic PE-path coverage), and a
// real ELF (/proc/self/exe) to exercise the full ELF parser on live data.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "exe_inspect.hpp"

using namespace at_demo::exe;

static int g_fails = 0;
#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        if (!(cond)) { std::printf("  FAIL: %s\n", msg); ++g_fails; }        \
        else         { std::printf("  ok:   %s\n", msg); }                   \
    } while (0)

// ---- little-endian writers for fixtures -----------------------------------
static void put16(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    if (off + 2 > b.size()) b.resize(off + 2);
    b[off] = v & 0xff; b[off + 1] = (v >> 8) & 0xff;
}
static void put32(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    if (off + 4 > b.size()) b.resize(off + 4);
    for (int i = 0; i < 4; ++i) b[off + i] = (v >> (8 * i)) & 0xff;
}
static void put64(std::vector<std::uint8_t>& b, std::size_t off, std::uint64_t v) {
    if (off + 8 > b.size()) b.resize(off + 8);
    for (int i = 0; i < 8; ++i) b[off + i] = (v >> (8 * i)) & 0xff;
}

// Minimal, internally-consistent 64-byte ELF64 header (no sections/segments).
static std::vector<std::uint8_t> make_min_elf64() {
    std::vector<std::uint8_t> b(64, 0);
    b[0] = 0x7f; b[1] = 'E'; b[2] = 'L'; b[3] = 'F';
    b[4] = 2;   // EI_CLASS = ELF64
    b[5] = 1;   // EI_DATA  = little-endian
    b[6] = 1;   // EI_VERSION
    put16(b, 16, 2);        // e_type = EXEC
    put16(b, 18, 0x3e);     // e_machine = x86-64
    put32(b, 20, 1);        // e_version
    put64(b, 24, 0x401000); // e_entry
    put64(b, 32, 0);        // e_phoff
    put64(b, 40, 0);        // e_shoff
    put32(b, 48, 0);        // e_flags
    put16(b, 52, 64);       // e_ehsize
    put16(b, 54, 56);       // e_phentsize
    put16(b, 56, 0);        // e_phnum
    put16(b, 58, 64);       // e_shentsize
    put16(b, 60, 0);        // e_shnum
    put16(b, 62, 0);        // e_shstrndx
    return b;
}

// Minimal ELF64 with ONE real section whose bytes and flags we control, so we
// can test entropy + the packing/protection heuristics deterministically.
// `flags`: ELF sh_flags (0x1=WRITE, 0x4=EXECINSTR). `high_entropy`: fill the
// section with all 256 byte values (entropy ~8) vs a constant byte (entropy 0).
static std::vector<std::uint8_t> make_elf_with_section(std::uint64_t flags,
                                                       bool high_entropy) {
    auto b = make_min_elf64();
    const std::uint64_t shoff = 64, shent = 64, data_off = 64 + 2 * 64;  // 192
    const std::uint64_t data_sz = 256;
    put64(b, 40, shoff);     // e_shoff
    put16(b, 58, shent);     // e_shentsize
    put16(b, 60, 2);         // e_shnum (0=NULL, 1=our section)
    put16(b, 62, 0);         // e_shstrndx = 0 (NULL => names unavailable; fine)
    b.resize(data_off + data_sz, 0);
    // Section header #1 at shoff + 64.
    std::uint64_t s = shoff + 64;
    put32(b, s + 4, 1);          // sh_type = PROGBITS
    put64(b, s + 8, flags);      // sh_flags
    put64(b, s + 24, data_off);  // sh_offset
    put64(b, s + 32, data_sz);   // sh_size
    // Section payload.
    for (std::uint64_t i = 0; i < data_sz; ++i)
        b[data_off + i] = high_entropy ? static_cast<std::uint8_t>(i & 0xff)
                                       : 0x00;
    return b;
}

// Hand-built valid PE32+ with one section (.idata) and one import (a DLL name).
static std::vector<std::uint8_t> make_min_pe() {
    std::vector<std::uint8_t> b(0x600, 0);
    b[0] = 'M'; b[1] = 'Z';
    const std::uint32_t lfanew = 0x40;
    put32(b, 0x3c, lfanew);
    b[lfanew] = 'P'; b[lfanew + 1] = 'E'; b[lfanew + 2] = 0; b[lfanew + 3] = 0;

    const std::uint32_t coff = lfanew + 4;      // 0x44
    put16(b, coff + 0, 0x8664);                 // Machine x86-64
    put16(b, coff + 2, 1);                      // NumberOfSections
    const std::uint16_t opt_size = 240;         // PE32+ optional header size
    put16(b, coff + 16, opt_size);              // SizeOfOptionalHeader
    put16(b, coff + 18, 0x0002);                // Characteristics = EXECUTABLE_IMAGE

    const std::uint32_t opt = coff + 20;        // 0x58
    put16(b, opt + 0, 0x20b);                   // Magic = PE32+
    put32(b, opt + 16, 0x1000);                 // AddressOfEntryPoint (RVA)
    put64(b, opt + 24, 0x140000000ull);         // ImageBase
    put32(b, opt + 108, 16);                    // NumberOfRvaAndSizes
    // Data directory [1] = Import: rva=0x1000 size=40
    put32(b, opt + 112 + 1 * 8 + 0, 0x1000);
    put32(b, opt + 112 + 1 * 8 + 4, 40);

    const std::uint32_t sect = opt + opt_size;  // 0x148
    const char* nm = ".idata";
    for (int i = 0; i < 8; ++i) b[sect + i] = (i < (int)std::strlen(nm)) ? nm[i] : 0;
    put32(b, sect + 8, 0x200);                  // VirtualSize
    put32(b, sect + 12, 0x1000);                // VirtualAddress (RVA)
    put32(b, sect + 16, 0x200);                 // SizeOfRawData
    put32(b, sect + 20, 0x400);                 // PointerToRawData (file off)
    put32(b, sect + 36, 0x40000040);            // Characteristics

    // Raw data at file offset 0x400 maps to RVA 0x1000.
    // Import descriptor (20 bytes): Name RVA = 0x1040, FirstThunk = 0x1080.
    put32(b, 0x400 + 12, 0x1040);               // Name
    put32(b, 0x400 + 16, 0x1080);               // FirstThunk (nonzero)
    // terminator descriptor at 0x414 is already all-zero.
    const char* dll = "KERNEL32.dll";
    std::size_t name_off = 0x400 + (0x1040 - 0x1000);  // = 0x440
    for (std::size_t i = 0; i <= std::strlen(dll); ++i) b[name_off + i] = dll[i];
    return b;
}

// ---- Reader bounds tests ---------------------------------------------------
static void test_reader_bounds() {
    std::uint8_t buf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    Reader r(buf, sizeof(buf));
    CHECK(r.u32(0, false).has_value(), "u32 at offset 0 in range");
    CHECK(r.u32(4, false).has_value(), "u32 at last valid offset (4) in range");
    CHECK(!r.u32(5, false).has_value(), "u32 at offset 5 rejected (would read past end)");
    CHECK(!r.u64(1, false).has_value(), "u64 at offset 1 rejected (8 bytes won't fit)");
    CHECK(r.u64(0, false).has_value(), "u64 at offset 0 fits exactly");
    // Overflow safety: a huge offset must not wrap and must be rejected.
    CHECK(!r.in_bounds(0xFFFFFFFFFFFFFFFFull, 8), "in_bounds rejects near-UINT64_MAX offset");
    CHECK(!r.in_bounds(4, 0xFFFFFFFFFFFFFFFFull), "in_bounds rejects huge length");
    CHECK(r.in_bounds(0, 8) && !r.in_bounds(0, 9), "in_bounds exact edge");
}

static void test_reader_cstr() {
    std::uint8_t ok[] = {'h', 'i', 0, 'x'};
    Reader r1(ok, sizeof(ok));
    auto s = r1.cstr(0, 16);
    CHECK(s && *s == "hi", "cstr reads NUL-terminated string");
    std::uint8_t noterm[] = {'a', 'b', 'c'};
    Reader r2(noterm, sizeof(noterm));
    CHECK(!r2.cstr(0, 16).has_value(), "cstr with no terminator returns nullopt");
    CHECK(!r2.cstr(99, 16).has_value(), "cstr at out-of-range offset returns nullopt");
}

// ---- format detection & robustness ----------------------------------------
static void test_detection() {
    CHECK(analyze(nullptr, 0).malformed, "null/empty input is malformed, no crash");
    std::uint8_t junk[] = {0x00, 0x01, 0x02, 0x03, 0x04};
    auto r = analyze(junk, sizeof(junk));
    CHECK(r.format == Format::Unknown && r.malformed, "unknown magic reported, not crashed");
}

static void test_elf_minimal_valid() {
    auto b = make_min_elf64();
    auto r = analyze(b.data(), b.size());
    CHECK(r.format == Format::Elf, "minimal ELF detected as ELF");
    CHECK(!r.malformed, "minimal ELF64 header is not fatal");
    CHECK(r.class_bits == "ELF64", "class ELF64");
    CHECK(r.endianness == "little", "endianness little");
    CHECK(r.machine.find("x86-64") != std::string::npos, "machine x86-64");
    CHECK(r.entry == 0x401000, "entry parsed");
}

static void test_elf_truncated() {
    auto b = make_min_elf64();
    b.resize(8);  // only magic + a couple ident bytes
    auto r = analyze(b.data(), b.size());
    CHECK(r.format == Format::Elf, "truncated ELF still detected by magic");
    CHECK(r.malformed, "truncated ELF header flagged malformed, no crash");
}

static void test_elf_bad_class_and_data() {
    auto b = make_min_elf64();
    b[4] = 5;  // invalid EI_CLASS
    auto r = analyze(b.data(), b.size());
    CHECK(r.malformed, "invalid EI_CLASS flagged");

    auto b2 = make_min_elf64();
    b2[5] = 9;  // invalid EI_DATA
    auto r2 = analyze(b2.data(), b2.size());
    CHECK(r2.malformed, "invalid EI_DATA flagged");
}

static void test_elf_section_table_oob() {
    auto b = make_min_elf64();
    put64(b, 40, 64);        // e_shoff = 64 (just past the 64-byte buffer)
    put16(b, 60, 0xFFFF);    // e_shnum huge
    auto r = analyze(b.data(), b.size());
    CHECK(r.malformed, "huge shnum * entsize beyond EOF rejected (overflow-safe)");
    bool found = false;
    for (auto& e : r.errors) if (e.find("section header table out of bounds") != std::string::npos) found = true;
    CHECK(found, "section-table-OOB error message present");
}

static void test_elf_shstrndx_oob_is_warning() {
    auto b = make_min_elf64();
    // one real-ish section header so parsing proceeds, but shstrndx too big
    put64(b, 40, 64);     // e_shoff
    put16(b, 58, 64);     // e_shentsize
    put16(b, 60, 1);      // e_shnum = 1
    put16(b, 62, 7);      // e_shstrndx = 7 (>= shnum)
    b.resize(64 + 64, 0); // room for 1 section header (all zero => SHT_NULL)
    auto r = analyze(b.data(), b.size());
    CHECK(!r.malformed, "bad shstrndx is non-fatal (warning, not error)");
    bool warned = false;
    for (auto& w : r.warnings) if (w.find("shstrndx") != std::string::npos) warned = true;
    CHECK(warned, "shstrndx warning emitted");
}

// ---- PE fixtures ----------------------------------------------------------
static void test_pe_valid_with_import() {
    auto b = make_min_pe();
    auto r = analyze(b.data(), b.size());
    CHECK(r.format == Format::Pe, "PE detected");
    CHECK(!r.malformed, "hand-built PE32+ is not malformed");
    CHECK(r.class_bits == "PE32+", "class PE32+");
    CHECK(r.machine.find("x86-64") != std::string::npos, "PE machine x86-64");
    CHECK(r.entry == 0x1000, "PE entry RVA parsed");
    CHECK(r.image_base == 0x140000000ull, "PE image base parsed");
    CHECK(r.sections.size() == 1 && r.sections[0].name == ".idata", "PE section parsed");
    bool kernel = false;
    for (auto& d : r.pe_imports) if (d == "KERNEL32.dll") kernel = true;
    CHECK(kernel, "PE import DLL name resolved via RVA mapping");
}

static void test_pe_bad_signature() {
    auto b = make_min_pe();
    b[0x40] = 'X';  // break the "PE\0\0" signature
    auto r = analyze(b.data(), b.size());
    CHECK(r.format == Format::Pe && r.malformed, "missing PE signature flagged, no crash");
}

static void test_pe_lfanew_out_of_range() {
    auto b = make_min_pe();
    put32(b, 0x3c, 0x7fffffff);  // e_lfanew far past EOF
    auto r = analyze(b.data(), b.size());
    CHECK(r.malformed, "e_lfanew past EOF rejected, no crash");
}

static void test_pe_truncated() {
    std::vector<std::uint8_t> b = {'M', 'Z', 0, 0};
    auto r = analyze(b.data(), b.size());
    CHECK(r.format == Format::Pe && r.malformed, "4-byte MZ stub flagged malformed, no crash");
}

static void test_pe_section_table_oob() {
    auto b = make_min_pe();
    // Claim many sections but keep the tiny optional-header-relative layout.
    const std::uint32_t coff = 0x44;
    put16(b, coff + 2, 0xFFFF);  // NumberOfSections huge
    auto r = analyze(b.data(), b.size());
    CHECK(r.malformed, "huge PE section count beyond EOF rejected");
}

// ---- real ELF (live data) --------------------------------------------------
static void test_real_self_exe() {
    std::string err;
    auto r = analyze_file("/proc/self/exe", &err);
    if (r.malformed && r.format == Format::Unknown) {
        std::printf("  skip: /proc/self/exe unavailable (%s)\n", err.c_str());
        return;  // non-Linux / no procfs: do not fail the suite
    }
    CHECK(r.format == Format::Elf, "self exe is ELF");
    CHECK(!r.malformed, "self exe parses without fatal error");
    CHECK(!r.sections.empty(), "self exe has sections");
    bool has_text = false;
    for (auto& s : r.sections) if (s.name == ".text") has_text = true;
    CHECK(has_text, "self exe has a .text section");
    CHECK(r.symbols.table_present && r.symbols.functions > 0,
          "self exe has a symbol table with function symbols");
}

// ---- entropy & packing/protection heuristics ------------------------------
static void test_entropy_math() {
    std::vector<std::uint8_t> flat(1024, 0x41);  // all 'A'
    CHECK(shannon_entropy(flat.data(), flat.size()) == 0.0,
          "entropy of a constant buffer is 0");
    std::vector<std::uint8_t> allbytes(256);
    for (int i = 0; i < 256; ++i) allbytes[i] = std::uint8_t(i);
    double h = shannon_entropy(allbytes.data(), allbytes.size());
    CHECK(h > 7.99, "entropy of all-256-values buffer is ~8 bits/byte");
    CHECK(shannon_entropy(nullptr, 0) == 0.0, "entropy of empty buffer is 0");
}

static void test_high_entropy_exec_flagged() {
    auto b = make_elf_with_section(/*flags=*/0x4 /*EXEC*/, /*high_entropy=*/true);
    auto r = analyze(b.data(), b.size());
    CHECK(!r.malformed, "entropy fixture parses");
    bool exec_hi = false, high_e = false;
    for (auto& s : r.sections)
        if (s.executable && s.entropy > 7.9) high_e = true;
    for (auto& a : r.anomalies)
        if (a.find("high-entropy executable") != std::string::npos) exec_hi = true;
    CHECK(high_e, "executable section reports entropy ~8");
    CHECK(exec_hi, "high-entropy executable section raises a heuristic signal");
}

static void test_high_entropy_data_not_flagged() {
    // Same high-entropy bytes but NOT executable (e.g. compressed resource):
    // the heuristic must NOT raise the executable-packing signal. This is the
    // explicit false-positive guard — data entropy alone means nothing.
    auto b = make_elf_with_section(/*flags=*/0x0, /*high_entropy=*/true);
    auto r = analyze(b.data(), b.size());
    bool exec_hi = false;
    for (auto& a : r.anomalies)
        if (a.find("high-entropy executable") != std::string::npos) exec_hi = true;
    CHECK(!exec_hi, "high-entropy NON-executable section does NOT trip the exec signal");
}

static void test_wx_violation_flagged() {
    auto b = make_elf_with_section(/*flags=*/0x1 | 0x4 /*WRITE|EXEC*/, false);
    auto r = analyze(b.data(), b.size());
    bool wx = false;
    for (auto& a : r.anomalies)
        if (a.find("W^X") != std::string::npos) wx = true;
    CHECK(wx, "writable+executable section raises a W^X heuristic signal");
}

static void test_normal_binary_no_false_alarm() {
    // A normally-compiled ELF (/proc/self/exe) must not trip W^X, and its .text
    // entropy must be a sane in-range value (compiled code, not ~8).
    std::string err;
    auto r = analyze_file("/proc/self/exe", &err);
    if (r.malformed && r.format == Format::Unknown) {
        std::printf("  skip: /proc/self/exe unavailable\n");
        return;
    }
    bool wx = false;
    for (auto& a : r.anomalies) if (a.find("W^X") != std::string::npos) wx = true;
    CHECK(!wx, "normal binary has no W^X section (no false alarm)");
    double text_h = -1.0;
    for (auto& s : r.sections) if (s.name == ".text") text_h = s.entropy;
    CHECK(text_h > 0.0 && text_h < 8.0, "normal .text has in-range entropy (not ~0, not ~8)");
}

int main() {
    std::puts("test_exe_inspect:");
    test_reader_bounds();
    test_reader_cstr();
    test_detection();
    test_elf_minimal_valid();
    test_elf_truncated();
    test_elf_bad_class_and_data();
    test_elf_section_table_oob();
    test_elf_shstrndx_oob_is_warning();
    test_pe_valid_with_import();
    test_pe_bad_signature();
    test_pe_lfanew_out_of_range();
    test_pe_truncated();
    test_pe_section_table_oob();
    test_real_self_exe();
    test_entropy_math();
    test_high_entropy_exec_flagged();
    test_high_entropy_data_not_flagged();
    test_wx_violation_flagged();
    test_normal_binary_no_false_alarm();
    if (g_fails) { std::printf("FAILED (%d)\n", g_fails); return 1; }
    std::puts("ALL PASS");
    return 0;
}
