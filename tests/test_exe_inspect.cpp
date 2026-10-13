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
    if (g_fails) { std::printf("FAILED (%d)\n", g_fails); return 1; }
    std::puts("ALL PASS");
    return 0;
}
