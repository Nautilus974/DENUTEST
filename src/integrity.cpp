#include "integrity.hpp"

#include <array>
#include <cstdio>
#include <cstring>

#if defined(__linux__)
#include <cstdlib>
#endif

namespace at_demo::integrity {

namespace {

// Build the CRC-32 lookup table once at startup.
std::array<std::uint32_t, 256> make_crc_table() noexcept {
    std::array<std::uint32_t, 256> t{};
    for (std::uint32_t i = 0; i < 256; ++i) {
        std::uint32_t c = i;
        for (int k = 0; k < 8; ++k)
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        t[i] = c;
    }
    return t;
}

const std::array<std::uint32_t, 256>& crc_table() noexcept {
    static const std::array<std::uint32_t, 256> t = make_crc_table();
    return t;
}

}  // namespace

std::uint32_t crc32(const void* data, std::size_t len) noexcept {
    const auto& t = crc_table();
    const auto* p = static_cast<const std::uint8_t*>(data);
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < len; ++i)
        crc = t[(crc ^ p[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

std::uint64_t fnv1a64(const void* data, std::size_t len) noexcept {
    const auto* p = static_cast<const std::uint8_t*>(data);
    std::uint64_t h = 1469598103934665603ull;  // FNV offset basis
    for (std::size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ull;  // FNV prime
    }
    return h;
}

std::uint64_t keyed_checksum(const void* data, std::size_t len,
                             std::uint64_t seed) noexcept {
    const auto* p = static_cast<const std::uint8_t*>(data);
    std::uint64_t h = seed ^ 1469598103934665603ull;
    for (std::size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 1099511628211ull;
        h ^= h >> 29;  // extra mixing so adjacent seeds diverge quickly
    }
    // Final avalanche (splitmix64-style) to spread the key through all bits.
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdull;
    h ^= h >> 33;
    return h;
}

IntegrityGuard::IntegrityGuard(std::uint64_t seed) noexcept : seed_(seed) {}

void IntegrityGuard::enroll(const Region& region) {
    regions_.push_back(region);
    references_.push_back(keyed_checksum(region.begin, region.size, seed_));
}

std::vector<CheckResult> IntegrityGuard::verify() const {
    std::vector<CheckResult> out;
    out.reserve(regions_.size());
    for (std::size_t i = 0; i < regions_.size(); ++i) {
        std::uint64_t actual =
            keyed_checksum(regions_[i].begin, regions_[i].size, seed_);
        out.push_back(CheckResult{regions_[i].name, references_[i], actual,
                                  actual == references_[i]});
    }
    return out;
}

bool IntegrityGuard::all_ok() const {
    for (const auto& r : verify())
        if (!r.ok) return false;
    return true;
}

#if defined(__linux__)
Region self_text_region() {
    // Parse /proc/self/maps for the first executable, readable mapping of the
    // main binary. This is the portable stand-in for "find my own .text".
    std::FILE* f = std::fopen("/proc/self/maps", "re");
    if (!f) return {};
    char line[512];
    Region region;
    while (std::fgets(line, sizeof(line), f)) {
        unsigned long long start = 0, end = 0;
        char perms[8] = {0};
        // Format: start-end perms offset dev inode pathname
        if (std::sscanf(line, "%llx-%llx %7s", &start, &end, perms) != 3)
            continue;
        if (perms[0] == 'r' && perms[2] == 'x') {  // readable + executable
            region.name = "self.text";
            region.begin = reinterpret_cast<const void*>(start);
            region.size = static_cast<std::size_t>(end - start);
            break;
        }
    }
    std::fclose(f);
    return region;
}
#elif defined(_WIN32)
// Documented Windows approach (not compiled on this Linux host): take
// GetModuleHandle(nullptr) as the image base, parse the DOS/NT headers to find
// the section whose characteristics include IMAGE_SCN_CNT_CODE, and use its
// VirtualAddress + Misc.VirtualSize. Left as a reference stub here.
Region self_text_region() { return {}; }
#else
Region self_text_region() { return {}; }
#endif

}  // namespace at_demo::integrity
