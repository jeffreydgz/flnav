/**
 * Copyright (c) 2026, Jeffrey Douglas
 *
 * All rights reserved.
 */

#ifndef lnav_ioc_matcher_hh
#define lnav_ioc_matcher_hh

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace lnav::forensics {

struct ioc_cidr_entry {
    int family{0};
    std::array<uint8_t, 16> network{};
    uint8_t prefix_bits{0};
    std::string label;
};

class ioc_matcher {
public:
    void clear();

    bool add_token(std::string candidate);

    bool empty() const;
    size_t entry_count() const;
    size_t exact_count() const;
    size_t cidr_count() const;

    bool matches(std::string candidate) const;

    std::vector<std::string> exact_ips() const;
    std::vector<std::string> cidr_labels() const;
    std::vector<std::string> fingerprint_entries() const;

private:
    std::unordered_set<std::string> im_exact_ips;
    std::vector<ioc_cidr_entry> im_cidrs;
};

std::optional<std::string> normalize_ioc_ip(std::string candidate);

std::string strip_ioc_token(std::string candidate);

}  // namespace lnav::forensics

#endif
