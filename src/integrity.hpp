// integrity.hpp — generic runtime integrity-verification primitives.
//
// Educational demo reproducing the *documented, generic* building blocks of
// anti-tamper integrity checks (checksum-of-code, tamper detection). Nothing
// here is derived from any proprietary protector; it illustrates public-domain
// concepts only. See docs/01-architecture.md for the facts-vs-hypotheses split.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace at_demo::integrity {

// Classic CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320). Used widely in
// real protectors as a cheap, fast integrity primitive. It is NOT
// cryptographically secure: an attacker who can recompute it can forge a
// matching patch. We use it to demonstrate detection of *accidental* or
// *naive* tampering and to contrast it with a keyed hash below.
std::uint32_t crc32(const void* data, std::size_t len) noexcept;

// FNV-1a 64-bit — another fast non-cryptographic rolling hash, kept so the
// benchmark can compare hash-primitive cost.
std::uint64_t fnv1a64(const void* data, std::size_t len) noexcept;

// A keyed checksum (seeded FNV mixing) standing in for "the correct value is
// not statically visible in the binary". Real protectors derive such seeds at
// runtime (from hardware, server tokens, or decrypted blobs) so the expected
// value cannot simply be read out of the file. Here the seed is a parameter so
// tests can supply it; the point is the *shape*, not cryptographic strength.
std::uint64_t keyed_checksum(const void* data, std::size_t len,
                             std::uint64_t seed) noexcept;

// Describes one contiguous region of memory to be guarded.
struct Region {
    std::string name;
    const void* begin = nullptr;
    std::size_t size = 0;
};

// Result of verifying a region against a stored reference value.
struct CheckResult {
    std::string region;
    std::uint64_t expected = 0;
    std::uint64_t actual = 0;
    bool ok = false;
};

// A self-checking "guard" that stores reference checksums for a set of regions
// and can later re-verify them. This mirrors the core loop of integrity-based
// anti-tamper: snapshot trusted bytes, then periodically recompute and compare.
class IntegrityGuard {
public:
    explicit IntegrityGuard(std::uint64_t seed) noexcept;

    // Snapshot a region's current checksum as the trusted reference.
    void enroll(const Region& region);

    // Recompute all enrolled regions and report any mismatch.
    std::vector<CheckResult> verify() const;

    // Convenience: true iff every enrolled region still matches.
    bool all_ok() const;

    std::size_t region_count() const noexcept { return regions_.size(); }

private:
    std::uint64_t seed_;
    std::vector<Region> regions_;
    std::vector<std::uint64_t> references_;
};

// Attempt to locate the process's own executable code region at runtime.
// Returns an empty Region if it cannot be determined on this platform. This is
// the portable analogue of "checksum my own .text section": on Linux we read
// /proc/self/maps; on Windows the documented approach parses the PE headers of
// the module returned by GetModuleHandle(nullptr).
Region self_text_region();

}  // namespace at_demo::integrity
