#include "exe_inspect.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

namespace at_demo::exe {

// ======================= Reader ============================================

std::optional<std::uint8_t> Reader::u8(std::uint64_t off) const noexcept {
    if (!in_bounds(off, 1)) return std::nullopt;
    return data_[off];
}

std::optional<std::uint16_t> Reader::u16(std::uint64_t off, bool big) const noexcept {
    if (!in_bounds(off, 2)) return std::nullopt;
    const std::uint8_t* p = data_ + off;
    return big ? static_cast<std::uint16_t>((p[0] << 8) | p[1])
               : static_cast<std::uint16_t>((p[1] << 8) | p[0]);
}

std::optional<std::uint32_t> Reader::u32(std::uint64_t off, bool big) const noexcept {
    if (!in_bounds(off, 4)) return std::nullopt;
    const std::uint8_t* p = data_ + off;
    if (big)
        return (std::uint32_t(p[0]) << 24) | (std::uint32_t(p[1]) << 16) |
               (std::uint32_t(p[2]) << 8) | std::uint32_t(p[3]);
    return (std::uint32_t(p[3]) << 24) | (std::uint32_t(p[2]) << 16) |
           (std::uint32_t(p[1]) << 8) | std::uint32_t(p[0]);
}

std::optional<std::uint64_t> Reader::u64(std::uint64_t off, bool big) const noexcept {
    if (!in_bounds(off, 8)) return std::nullopt;
    std::uint64_t lo, hi;
    if (big) {
        hi = *u32(off, true);
        lo = *u32(off + 4, true);
    } else {
        lo = *u32(off, false);
        hi = *u32(off + 4, false);
    }
    return (hi << 32) | lo;
}

bool Reader::match(std::uint64_t off, const char* lit, std::size_t n) const noexcept {
    if (!in_bounds(off, n)) return false;
    return std::memcmp(data_ + off, lit, n) == 0;
}

std::optional<std::string> Reader::cstr(std::uint64_t off,
                                        std::uint64_t max_scan) const {
    if (!in_bounds(off, 1)) return std::nullopt;
    std::uint64_t limit = off + max_scan;
    if (limit > size_) limit = size_;
    for (std::uint64_t i = off; i < limit; ++i) {
        if (data_[i] == 0)
            return std::string(reinterpret_cast<const char*>(data_ + off),
                               static_cast<std::size_t>(i - off));
    }
    return std::nullopt;  // no terminator within bound => treat as malformed
}

// ======================= helpers ===========================================

namespace {

std::string hex(std::uint64_t v) {
    std::ostringstream os;
    os << "0x" << std::hex << v;
    return os.str();
}

std::string elf_machine(std::uint16_t m) {
    switch (m) {
        case 0x00: return "none";
        case 0x03: return "x86 (i386)";
        case 0x08: return "MIPS";
        case 0x14: return "PowerPC";
        case 0x28: return "ARM";
        case 0x2a: return "SuperH";
        case 0x3e: return "x86-64 (AMD64)";
        case 0xb7: return "AArch64";
        case 0xf3: return "RISC-V";
        default:   return "unknown(" + hex(m) + ")";
    }
}

std::string elf_type(std::uint16_t t) {
    switch (t) {
        case 1: return "REL (relocatable)";
        case 2: return "EXEC (executable)";
        case 3: return "DYN (shared object / PIE)";
        case 4: return "CORE";
        default: return "unknown(" + hex(t) + ")";
    }
}

std::string elf_sh_type(std::uint32_t t) {
    switch (t) {
        case 0: return "NULL";
        case 1: return "PROGBITS";
        case 2: return "SYMTAB";
        case 3: return "STRTAB";
        case 4: return "RELA";
        case 6: return "DYNAMIC";
        case 7: return "NOTE";
        case 8: return "NOBITS";
        case 9: return "REL";
        case 11: return "DYNSYM";
        case 14: return "INIT_ARRAY";
        case 15: return "FINI_ARRAY";
        default: return "T" + std::to_string(t);
    }
}

std::string pe_machine(std::uint16_t m) {
    switch (m) {
        case 0x014c: return "x86 (i386)";
        case 0x8664: return "x86-64 (AMD64)";
        case 0x01c0: return "ARM";
        case 0xaa64: return "ARM64";
        case 0x0200: return "IA64";
        default:     return "unknown(" + hex(m) + ")";
    }
}

const char* pe_dir_name(std::size_t i) {
    static const char* names[] = {
        "Export", "Import", "Resource", "Exception", "Security", "BaseReloc",
        "Debug",  "Architecture", "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
        "IAT", "DelayImport", "CLRRuntime", "Reserved"};
    return (i < 16) ? names[i] : "?";
}

}  // namespace

// ======================= ELF ===============================================

namespace {

void parse_elf(Reader r, Report& rep) {
    rep.format = Format::Elf;

    auto ei_class = r.u8(4);
    auto ei_data = r.u8(5);
    if (!ei_class || !ei_data) {
        rep.errors.push_back("ELF: truncated e_ident");
        rep.malformed = true;
        return;
    }
    bool is64;
    if (*ei_class == 1) { is64 = false; rep.class_bits = "ELF32"; }
    else if (*ei_class == 2) { is64 = true; rep.class_bits = "ELF64"; }
    else {
        rep.errors.push_back("ELF: invalid EI_CLASS=" + std::to_string(*ei_class));
        rep.malformed = true;
        return;
    }
    bool big;
    if (*ei_data == 1) { big = false; rep.endianness = "little"; }
    else if (*ei_data == 2) { big = true; rep.endianness = "big"; }
    else {
        rep.errors.push_back("ELF: invalid EI_DATA=" + std::to_string(*ei_data));
        rep.malformed = true;
        return;
    }

    // Field offsets differ by class.
    auto e_type = r.u16(16, big);
    auto e_machine = r.u16(18, big);
    std::optional<std::uint64_t> e_entry, e_phoff, e_shoff;
    std::optional<std::uint16_t> e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
    if (is64) {
        e_entry = r.u64(24, big);
        e_phoff = r.u64(32, big);
        e_shoff = r.u64(40, big);
        e_phentsize = r.u16(54, big);
        e_phnum = r.u16(56, big);
        e_shentsize = r.u16(58, big);
        e_shnum = r.u16(60, big);
        e_shstrndx = r.u16(62, big);
    } else {
        e_entry = r.u32(24, big);
        e_phoff = r.u32(28, big);
        e_shoff = r.u32(32, big);
        e_phentsize = r.u16(42, big);
        e_phnum = r.u16(44, big);
        e_shentsize = r.u16(46, big);
        e_shnum = r.u16(48, big);
        e_shstrndx = r.u16(50, big);
    }
    if (!e_type || !e_machine || !e_entry || !e_phoff || !e_shoff || !e_phnum ||
        !e_shnum || !e_shstrndx || !e_phentsize || !e_shentsize) {
        rep.errors.push_back("ELF: header truncated (file smaller than ELF header)");
        rep.malformed = true;
        return;
    }
    rep.file_type = elf_type(*e_type);
    rep.machine = elf_machine(*e_machine);
    rep.entry = *e_entry;

    // ---- Program headers (segments) ----
    const std::uint64_t phsz_min = is64 ? 56 : 32;
    if (*e_phnum > 0) {
        if (*e_phentsize < phsz_min)
            rep.warnings.push_back("ELF: e_phentsize (" +
                                   std::to_string(*e_phentsize) +
                                   ") smaller than expected " +
                                   std::to_string(phsz_min));
        std::uint64_t total = std::uint64_t(*e_phnum) * *e_phentsize;
        if (!r.in_bounds(*e_phoff, total)) {
            rep.warnings.push_back(
                "ELF: program header table out of bounds (phoff=" +
                hex(*e_phoff) + ", " + std::to_string(*e_phnum) +
                " entries) — skipped");
        } else {
            for (std::uint16_t i = 0; i < *e_phnum; ++i) {
                std::uint64_t base = *e_phoff + std::uint64_t(i) * *e_phentsize;
                SegmentInfo s;
                if (is64) {
                    s.type = r.u32(base + 0, big).value_or(0);
                    s.flags = r.u32(base + 4, big).value_or(0);
                    s.offset = r.u64(base + 8, big).value_or(0);
                    s.vaddr = r.u64(base + 16, big).value_or(0);
                    s.filesz = r.u64(base + 32, big).value_or(0);
                    s.memsz = r.u64(base + 40, big).value_or(0);
                } else {
                    s.type = r.u32(base + 0, big).value_or(0);
                    s.offset = r.u32(base + 4, big).value_or(0);
                    s.vaddr = r.u32(base + 8, big).value_or(0);
                    s.filesz = r.u32(base + 16, big).value_or(0);
                    s.memsz = r.u32(base + 20, big).value_or(0);
                    s.flags = r.u32(base + 24, big).value_or(0);
                }
                if (s.filesz && !r.in_bounds(s.offset, s.filesz))
                    rep.warnings.push_back(
                        "ELF: segment " + std::to_string(i) +
                        " file range out of bounds (offset=" + hex(s.offset) +
                        ", filesz=" + hex(s.filesz) + ")");
                rep.segments.push_back(std::move(s));
            }
        }
    }

    // ---- Section headers ----
    const std::uint64_t shsz_min = is64 ? 64 : 40;
    if (*e_shnum == 0) {
        rep.warnings.push_back("ELF: no section headers (stripped or e_shnum=0)");
        return;
    }
    if (*e_shentsize < shsz_min)
        rep.warnings.push_back("ELF: e_shentsize (" + std::to_string(*e_shentsize) +
                               ") smaller than expected " + std::to_string(shsz_min));
    std::uint64_t sh_total = std::uint64_t(*e_shnum) * *e_shentsize;
    if (!r.in_bounds(*e_shoff, sh_total)) {
        rep.errors.push_back("ELF: section header table out of bounds (shoff=" +
                             hex(*e_shoff) + ", " + std::to_string(*e_shnum) +
                             " entries of " + std::to_string(*e_shentsize) + ")");
        rep.malformed = true;
        return;
    }
    if (*e_shstrndx >= *e_shnum) {
        rep.warnings.push_back("ELF: e_shstrndx (" + std::to_string(*e_shstrndx) +
                               ") >= e_shnum (" + std::to_string(*e_shnum) +
                               ") — section names unavailable");
    }

    struct Raw { std::uint32_t name; std::uint32_t type; std::uint64_t flags,
                 addr, offset, size; std::uint32_t link, info; std::uint64_t entsize; };
    std::vector<Raw> raws(*e_shnum);
    for (std::uint16_t i = 0; i < *e_shnum; ++i) {
        std::uint64_t b = *e_shoff + std::uint64_t(i) * *e_shentsize;
        Raw& x = raws[i];
        x.name = r.u32(b + 0, big).value_or(0);
        x.type = r.u32(b + 4, big).value_or(0);
        if (is64) {
            x.flags = r.u64(b + 8, big).value_or(0);
            x.addr = r.u64(b + 16, big).value_or(0);
            x.offset = r.u64(b + 24, big).value_or(0);
            x.size = r.u64(b + 32, big).value_or(0);
            x.link = r.u32(b + 40, big).value_or(0);
            x.info = r.u32(b + 44, big).value_or(0);
            x.entsize = r.u64(b + 56, big).value_or(0);
        } else {
            x.flags = r.u32(b + 8, big).value_or(0);
            x.addr = r.u32(b + 12, big).value_or(0);
            x.offset = r.u32(b + 16, big).value_or(0);
            x.size = r.u32(b + 20, big).value_or(0);
            x.link = r.u32(b + 24, big).value_or(0);
            x.info = r.u32(b + 28, big).value_or(0);
            x.entsize = r.u32(b + 36, big).value_or(0);
        }
    }

    // String table for section names.
    std::uint64_t shstr_off = 0, shstr_size = 0;
    bool have_shstr = false;
    if (*e_shstrndx < *e_shnum && raws[*e_shstrndx].type == 3 /*STRTAB*/) {
        shstr_off = raws[*e_shstrndx].offset;
        shstr_size = raws[*e_shstrndx].size;
        have_shstr = r.in_bounds(shstr_off, shstr_size);
        if (!have_shstr)
            rep.warnings.push_back("ELF: section-name string table out of bounds");
    }

    auto name_at = [&](std::uint32_t off) -> std::string {
        if (!have_shstr || off >= shstr_size) return "";
        auto s = r.cstr(shstr_off + off, shstr_size - off);
        return s.value_or("");
    };

    for (std::uint16_t i = 0; i < *e_shnum; ++i) {
        const Raw& x = raws[i];
        SectionInfo si;
        si.name = name_at(x.name);
        si.vaddr = x.addr;
        si.offset = x.offset;
        si.size = x.size;
        si.type = x.type;
        si.flags = x.flags;
        si.occupies_file = (x.type != 8 /*NOBITS*/);
        if (si.occupies_file && x.size && !r.in_bounds(x.offset, x.size))
            rep.warnings.push_back("ELF: section '" + si.name + "' (#" +
                                   std::to_string(i) +
                                   ") data out of bounds (offset=" +
                                   hex(x.offset) + ", size=" + hex(x.size) + ")");
        rep.sections.push_back(std::move(si));
    }

    // ---- Symbols: first SYMTAB else DYNSYM ----
    int sym_idx = -1;
    for (std::uint16_t i = 0; i < *e_shnum; ++i)
        if (raws[i].type == 2 /*SYMTAB*/) { sym_idx = i; break; }
    if (sym_idx < 0)
        for (std::uint16_t i = 0; i < *e_shnum; ++i)
            if (raws[i].type == 11 /*DYNSYM*/) { sym_idx = i; break; }

    if (sym_idx >= 0) {
        const Raw& st = raws[sym_idx];
        const std::uint64_t sym_entsz = is64 ? 24 : 16;
        std::uint64_t entsz = st.entsize ? st.entsize : sym_entsz;
        rep.symbols.table_present = true;
        rep.symbols.table_kind = raws[sym_idx].type == 2 ? ".symtab" : ".dynsym";
        if (entsz == 0 || !r.in_bounds(st.offset, st.size)) {
            rep.warnings.push_back("ELF: symbol table out of bounds or zero entsize");
        } else {
            std::uint64_t count = st.size / entsz;
            // linked string table
            std::uint64_t strtab_off = 0, strtab_size = 0;
            bool have_str = false;
            if (st.link < *e_shnum) {
                strtab_off = raws[st.link].offset;
                strtab_size = raws[st.link].size;
                have_str = r.in_bounds(strtab_off, strtab_size);
            }
            rep.symbols.total = static_cast<std::size_t>(count);
            for (std::uint64_t i = 0; i < count; ++i) {
                std::uint64_t b = st.offset + i * entsz;
                std::uint32_t st_name;
                std::uint8_t st_info;
                if (is64) {
                    st_name = r.u32(b + 0, big).value_or(0);
                    st_info = r.u8(b + 4).value_or(0);
                } else {
                    st_name = r.u32(b + 0, big).value_or(0);
                    st_info = r.u8(b + 12).value_or(0);
                }
                std::uint8_t type = st_info & 0xf;
                if (type == 2) ++rep.symbols.functions;      // STT_FUNC
                else if (type == 1) ++rep.symbols.objects;   // STT_OBJECT
                if (have_str && st_name && st_name < strtab_size) {
                    auto nm = r.cstr(strtab_off + st_name, strtab_size - st_name);
                    if (nm && !nm->empty()) {
                        ++rep.symbols.with_names;
                        if (rep.symbols.sample.size() < 12)
                            rep.symbols.sample.push_back(*nm);
                    }
                }
            }
        }
    }
}

// ======================= PE (limited) ======================================

void parse_pe(Reader r, Report& rep) {
    rep.format = Format::Pe;
    rep.endianness = "little";  // PE is always little-endian

    auto e_lfanew = r.u32(0x3c, false);
    if (!e_lfanew) {
        rep.errors.push_back("PE: file too small for DOS header (no e_lfanew)");
        rep.malformed = true;
        return;
    }
    if (!r.match(*e_lfanew, "PE\0\0", 4)) {
        rep.errors.push_back("PE: missing 'PE\\0\\0' signature at e_lfanew=" +
                             hex(*e_lfanew));
        rep.malformed = true;
        return;
    }
    std::uint64_t coff = *e_lfanew + 4;
    auto machine = r.u16(coff + 0, false);
    auto nsect = r.u16(coff + 2, false);
    auto opt_size = r.u16(coff + 16, false);
    auto characteristics = r.u16(coff + 18, false);
    if (!machine || !nsect || !opt_size || !characteristics) {
        rep.errors.push_back("PE: truncated COFF file header");
        rep.malformed = true;
        return;
    }
    rep.machine = pe_machine(*machine);
    rep.file_type = (*characteristics & 0x2000) ? "DLL"
                    : (*characteristics & 0x0002) ? "EXE (image)"
                                                  : "image";

    std::uint64_t opt = coff + 20;
    auto magic = r.u16(opt + 0, false);
    if (!magic) {
        rep.errors.push_back("PE: truncated optional header");
        rep.malformed = true;
        return;
    }
    bool plus;
    if (*magic == 0x10b) { plus = false; rep.class_bits = "PE32"; }
    else if (*magic == 0x20b) { plus = true; rep.class_bits = "PE32+"; }
    else {
        rep.errors.push_back("PE: unknown optional header magic " + hex(*magic));
        rep.malformed = true;
        return;
    }
    rep.entry = r.u32(opt + 16, false).value_or(0);  // AddressOfEntryPoint (RVA)
    if (plus)
        rep.image_base = r.u64(opt + 24, false).value_or(0);
    else
        rep.image_base = r.u32(opt + 28, false).value_or(0);

    // Data directories.
    std::uint64_t nrva_off = plus ? opt + 108 : opt + 92;
    std::uint64_t dir_off = plus ? opt + 112 : opt + 96;
    auto nrva = r.u32(nrva_off, false).value_or(0);
    if (nrva > 16) {
        rep.warnings.push_back("PE: NumberOfRvaAndSizes=" + std::to_string(nrva) +
                               " > 16, clamping to 16");
        nrva = 16;
    }
    std::uint64_t import_rva = 0, import_size = 0;
    for (std::uint32_t i = 0; i < nrva; ++i) {
        auto rva = r.u32(dir_off + i * 8, false);
        auto sz = r.u32(dir_off + i * 8 + 4, false);
        if (!rva || !sz) { rep.warnings.push_back("PE: truncated data directory"); break; }
        if (*rva || *sz)
            rep.pe_data_dirs.push_back(std::string(pe_dir_name(i)) +
                                       ": rva=" + hex(*rva) + " size=" + hex(*sz));
        if (i == 1) { import_rva = *rva; import_size = *sz; }
    }

    // Section table: located right after the optional header.
    std::uint64_t sect_off = opt + *opt_size;
    std::uint64_t sect_total = std::uint64_t(*nsect) * 40;
    if (*nsect > 0 && !r.in_bounds(sect_off, sect_total)) {
        rep.errors.push_back("PE: section table out of bounds (off=" +
                             hex(sect_off) + ", " + std::to_string(*nsect) +
                             " sections)");
        rep.malformed = true;
        return;
    }
    struct Sec { std::string name; std::uint32_t vsize, rva, rawsize, rawptr, chars; };
    std::vector<Sec> secs;
    for (std::uint16_t i = 0; i < *nsect; ++i) {
        std::uint64_t b = sect_off + std::uint64_t(i) * 40;
        Sec s{};
        char nm[9] = {0};
        bool ok = true;
        for (int k = 0; k < 8; ++k) {
            auto c = r.u8(b + k);
            if (!c) { ok = false; break; }
            nm[k] = static_cast<char>(*c);
        }
        if (!ok) { rep.warnings.push_back("PE: truncated section header"); break; }
        s.name = nm;
        s.vsize = r.u32(b + 8, false).value_or(0);
        s.rva = r.u32(b + 12, false).value_or(0);
        s.rawsize = r.u32(b + 16, false).value_or(0);
        s.rawptr = r.u32(b + 20, false).value_or(0);
        s.chars = r.u32(b + 36, false).value_or(0);
        if (s.rawsize && !r.in_bounds(s.rawptr, s.rawsize))
            rep.warnings.push_back("PE: section '" + s.name +
                                   "' raw data out of bounds (ptr=" + hex(s.rawptr) +
                                   ", size=" + hex(s.rawsize) + ")");
        SectionInfo si;
        si.name = s.name;
        si.vaddr = s.rva;
        si.offset = s.rawptr;
        si.size = s.rawsize;
        si.type = s.chars;
        si.flags = s.chars;
        rep.sections.push_back(std::move(si));
        secs.push_back(std::move(s));
    }

    // Map an RVA to a file offset using the section table (bounds-checked).
    auto rva_to_off = [&](std::uint32_t rva) -> std::optional<std::uint64_t> {
        for (const Sec& s : secs) {
            std::uint64_t end = std::uint64_t(s.rva) + (s.vsize ? s.vsize : s.rawsize);
            if (rva >= s.rva && rva < end) {
                std::uint64_t delta = rva - s.rva;
                if (delta < s.rawsize) return std::uint64_t(s.rawptr) + delta;
                return std::nullopt;  // in virtual-only tail (e.g. .bss)
            }
        }
        return std::nullopt;
    };

    // Imports (tested subset): walk the import descriptors, collect DLL names.
    if (import_rva && import_size) {
        auto base = rva_to_off(import_rva);
        if (!base) {
            rep.warnings.push_back("PE: import directory RVA " + hex(import_rva) +
                                   " not mapped by any section");
        } else {
            const std::uint64_t kDesc = 20;  // IMAGE_IMPORT_DESCRIPTOR size
            for (std::uint32_t i = 0; i < 4096; ++i) {  // hard cap, anti-runaway
                std::uint64_t d = *base + std::uint64_t(i) * kDesc;
                auto name_rva = r.u32(d + 12, false);  // Name field
                auto first_thunk = r.u32(d + 16, false);
                if (!name_rva || !first_thunk) {
                    rep.warnings.push_back("PE: truncated import descriptor");
                    break;
                }
                if (*name_rva == 0 && *first_thunk == 0) break;  // terminator
                auto noff = rva_to_off(*name_rva);
                if (!noff) {
                    rep.warnings.push_back("PE: import name RVA " + hex(*name_rva) +
                                           " not mapped");
                    continue;
                }
                auto nm = r.cstr(*noff, 256);
                if (nm && !nm->empty()) rep.pe_imports.push_back(*nm);
                else rep.warnings.push_back("PE: unterminated import name");
            }
        }
    }
}

}  // namespace

// ======================= dispatch / IO / render ============================

Report analyze(const std::uint8_t* data, std::size_t size) {
    Report rep;
    if (!data || size == 0) {
        rep.malformed = true;
        rep.errors.push_back("empty input");
        return rep;
    }
    Reader r(data, size);
    if (r.match(0, "\x7f""ELF", 4)) {
        parse_elf(r, rep);
    } else if (r.match(0, "MZ", 2)) {
        parse_pe(r, rep);
    } else {
        rep.format = Format::Unknown;
        rep.malformed = true;
        rep.errors.push_back("unrecognized format (no ELF or MZ/PE magic)");
    }
    return rep;
}

Report analyze_file(const std::string& path, std::string* io_error) {
    Report rep;
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        rep.malformed = true;
        std::string m = "cannot open file: " + path;
        rep.errors.push_back(m);
        if (io_error) *io_error = m;
        return rep;
    }
    std::vector<std::uint8_t> buf((std::istreambuf_iterator<char>(f)),
                                  std::istreambuf_iterator<char>());
    return analyze(buf.data(), buf.size());
}

std::string format_report(const Report& r) {
    std::ostringstream o;
    const char* fmt = r.format == Format::Elf ? "ELF"
                      : r.format == Format::Pe ? "PE"
                                               : "UNKNOWN";
    o << "format      : " << fmt << (r.malformed ? "  [MALFORMED]" : "") << "\n";
    if (!r.class_bits.empty())  o << "class        : " << r.class_bits << "\n";
    if (!r.endianness.empty())  o << "endianness   : " << r.endianness << "\n";
    if (!r.machine.empty())     o << "machine      : " << r.machine << "\n";
    if (!r.file_type.empty())   o << "type         : " << r.file_type << "\n";
    o << "entry        : " << hex(r.entry) << "\n";
    if (r.image_base)           o << "image base   : " << hex(r.image_base) << "\n";

    o << "sections     : " << r.sections.size() << "\n";
    for (std::size_t i = 0; i < r.sections.size(); ++i) {
        const auto& s = r.sections[i];
        o << "  [" << i << "] " << (s.name.empty() ? "(unnamed)" : s.name)
          << "  off=" << hex(s.offset) << " size=" << hex(s.size)
          << " vaddr=" << hex(s.vaddr);
        if (r.format == Format::Elf) o << " type=" << elf_sh_type(s.type);
        if (!s.occupies_file) o << " (no file bytes)";
        o << "\n";
    }
    if (!r.segments.empty()) {
        o << "segments     : " << r.segments.size() << "\n";
        for (std::size_t i = 0; i < r.segments.size(); ++i) {
            const auto& s = r.segments[i];
            o << "  [" << i << "] type=" << s.type << " off=" << hex(s.offset)
              << " vaddr=" << hex(s.vaddr) << " filesz=" << hex(s.filesz)
              << " memsz=" << hex(s.memsz) << "\n";
        }
    }
    if (r.symbols.table_present) {
        o << "symbols      : " << r.symbols.total << " in " << r.symbols.table_kind
          << " (funcs=" << r.symbols.functions << " objs=" << r.symbols.objects
          << " named=" << r.symbols.with_names << ")\n";
        for (const auto& s : r.symbols.sample) o << "    - " << s << "\n";
    } else if (r.format == Format::Elf) {
        o << "symbols      : none (stripped or absent)\n";
    }
    if (!r.pe_data_dirs.empty()) {
        o << "data dirs    :\n";
        for (const auto& d : r.pe_data_dirs) o << "    " << d << "\n";
    }
    if (!r.pe_imports.empty()) {
        o << "imports      : " << r.pe_imports.size() << " DLL(s)\n";
        for (const auto& d : r.pe_imports) o << "    - " << d << "\n";
    }
    for (const auto& w : r.warnings) o << "WARN  " << w << "\n";
    for (const auto& e : r.errors)   o << "ERROR " << e << "\n";
    return o.str();
}

}  // namespace at_demo::exe
