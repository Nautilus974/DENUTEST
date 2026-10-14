// exe_inspect.hpp — read-only static inspector for ELF and (limited) PE images.
//
// Design contract:
//   * READ ONLY. The analyzer maps a byte buffer; it never writes to it, never
//     maps it executable, and NEVER executes or loads code from the target.
//   * CRASH FREE. Every multi-byte access goes through a bounds-checked Reader.
//     Any truncated / malformed / inconsistent input is reported as a
//     diagnostic, never dereferenced out of bounds. Analyzing hostile bytes is
//     a supported use case, so there are no exceptions that escape `analyze`.
//   * HONEST SCOPE. ELF parsing (headers, sections, segments, symbols) is the
//     primary, tested path. PE parsing is limited to the DOS/PE/COFF/optional
//     headers, the section table, the data directories, and import DLL names —
//     i.e. only fields exercised by the test fixtures. See docs/06.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace at_demo::exe {

enum class Format { Unknown, Elf, Pe };

struct SectionInfo {
    std::string name;
    std::uint64_t vaddr = 0;
    std::uint64_t offset = 0;
    std::uint64_t size = 0;
    std::uint32_t type = 0;       // ELF sh_type, or PE characteristics
    std::uint64_t flags = 0;
    bool occupies_file = true;    // false for ELF SHT_NOBITS (.bss)
    double entropy = -1.0;        // Shannon bits/byte over file bytes; <0 = not computed
    bool writable = false;        // W flag set
    bool executable = false;      // X flag set
};

struct SegmentInfo {             // ELF program headers
    std::uint32_t type = 0;
    std::uint64_t offset = 0;
    std::uint64_t vaddr = 0;
    std::uint64_t filesz = 0;
    std::uint64_t memsz = 0;
    std::uint32_t flags = 0;
};

struct SymbolSummary {
    std::size_t total = 0;
    std::size_t functions = 0;
    std::size_t objects = 0;
    std::size_t with_names = 0;
    std::vector<std::string> sample;   // first few named symbols, for display
    bool table_present = false;
    std::string table_kind;            // ".symtab" / ".dynsym" / ""
};

struct Report {
    Format format = Format::Unknown;
    bool malformed = false;            // true => at least one fatal error

    // Fatal problems that make a structure unusable; non-fatal anomalies.
    std::vector<std::string> errors;
    std::vector<std::string> warnings;

    // Common summary (filled as far as parsing succeeds).
    std::string class_bits;            // "ELF32" / "ELF64" / "PE32" / "PE32+"
    std::string endianness;            // "little" / "big"
    std::string machine;               // human-readable arch
    std::string file_type;             // ELF e_type / PE image kind
    std::uint64_t entry = 0;
    std::uint64_t image_base = 0;      // PE only (0 for ELF here)

    std::vector<SectionInfo> sections;
    std::vector<SegmentInfo> segments;
    SymbolSummary symbols;

    // PE extras (tested subset).
    std::vector<std::string> pe_data_dirs;  // "name: rva=.. size=.."
    std::vector<std::string> pe_imports;     // imported DLL names

    // Heuristic "looks packed/protected?" observations (NOT proof — see docs/08).
    // High-entropy executable sections, W^X violations, anonymous code, etc.
    // Every entry is a *soft* signal with well-known false positives.
    std::vector<std::string> anomalies;
};

// Shannon entropy in bits/byte (0..8) over a buffer. 0 for empty input.
double shannon_entropy(const std::uint8_t* data, std::size_t len);

// ---- Bounds-checked reader (the single point that touches raw bytes) -------
class Reader {
public:
    Reader(const std::uint8_t* data, std::size_t size) noexcept
        : data_(data), size_(size) {}

    std::size_t size() const noexcept { return size_; }

    // Bounded raw pointer to [off, off+len); nullptr if out of range. Used only
    // for whole-range scans (e.g. entropy); still range-checked here.
    const std::uint8_t* bytes(std::uint64_t off, std::uint64_t len) const noexcept {
        return in_bounds(off, len) ? data_ + off : nullptr;
    }

    // True iff [off, off+len) lies fully within the buffer, overflow-safe.
    bool in_bounds(std::uint64_t off, std::uint64_t len) const noexcept {
        if (len > size_) return false;
        return off <= static_cast<std::uint64_t>(size_) - len;
    }

    std::optional<std::uint8_t>  u8(std::uint64_t off) const noexcept;
    std::optional<std::uint16_t> u16(std::uint64_t off, bool big) const noexcept;
    std::optional<std::uint32_t> u32(std::uint64_t off, bool big) const noexcept;
    std::optional<std::uint64_t> u64(std::uint64_t off, bool big) const noexcept;

    // Bytes equal to `lit` at `off` (bounded). False if out of range.
    bool match(std::uint64_t off, const char* lit, std::size_t n) const noexcept;

    // NUL-terminated C string starting at `off`, scanning at most `max_scan`
    // bytes and never past the buffer. nullopt if off is out of range or no
    // terminator is found within the bound.
    std::optional<std::string> cstr(std::uint64_t off,
                                     std::uint64_t max_scan = 4096) const;

private:
    const std::uint8_t* data_;
    std::size_t size_;
};

// Analyze an in-memory image. Never throws, never executes the bytes.
Report analyze(const std::uint8_t* data, std::size_t size);

// Read a file (read-only) into memory and analyze it. On I/O failure returns a
// Report with malformed=true and an error; *io_error, if given, gets the
// message. The file is opened read-only and never executed.
Report analyze_file(const std::string& path, std::string* io_error = nullptr);

// Render a human-readable text report.
std::string format_report(const Report& r);

}  // namespace at_demo::exe
