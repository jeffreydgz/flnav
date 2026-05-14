/**
 * Copyright (c) 2026, Jeffrey Douglas
 *
 * All rights reserved.
 */

#include "ioc_matcher.hh"

#include <arpa/inet.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <utility>

namespace lnav::forensics {

std::string
strip_ioc_token(std::string candidate)
{
    auto is_space = [](unsigned char ch) { return std::isspace(ch) != 0; };

    while (!candidate.empty()
           && is_space(static_cast<unsigned char>(candidate.front())))
    {
        candidate.erase(candidate.begin());
    }
    while (!candidate.empty()
           && is_space(static_cast<unsigned char>(candidate.back())))
    {
        candidate.pop_back();
    }

    bool changed;
    do {
        changed = false;
        if (candidate.size() >= 2
            && ((candidate.front() == '\'' && candidate.back() == '\'')
                || (candidate.front() == '"' && candidate.back() == '"')
                || (candidate.front() == '[' && candidate.back() == ']')
                || (candidate.front() == '(' && candidate.back() == ')')))
        {
            candidate = candidate.substr(1, candidate.size() - 2);
            changed = true;
        }
    } while (changed);

    while (!candidate.empty()
           && (candidate.back() == ',' || candidate.back() == ';'))
    {
        candidate.pop_back();
    }

    return candidate;
}

std::optional<std::string>
normalize_ioc_ip(std::string candidate)
{
    candidate = strip_ioc_token(std::move(candidate));
    if (candidate.empty()) {
        return std::nullopt;
    }

    in_addr addr4;
    if (inet_pton(AF_INET, candidate.c_str(), &addr4) == 1) {
        char buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &addr4, buf, sizeof(buf)) != nullptr) {
            return std::string(buf);
        }
    }

    in6_addr addr6;
    if (inet_pton(AF_INET6, candidate.c_str(), &addr6) == 1) {
        char buf[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &addr6, buf, sizeof(buf)) != nullptr) {
            return std::string(buf);
        }
    }

    return std::nullopt;
}

static std::optional<uint8_t>
parse_prefix_bits(const std::string& value, int max_bits)
{
    if (value.empty()) {
        return std::nullopt;
    }

    int prefix = 0;
    for (const auto ch : value) {
        if (!std::isdigit(static_cast<unsigned char>(ch))) {
            return std::nullopt;
        }
        prefix = (prefix * 10) + (ch - '0');
        if (prefix > max_bits) {
            return std::nullopt;
        }
    }

    return static_cast<uint8_t>(prefix);
}

static void
mask_network(std::array<uint8_t, 16>& bytes, size_t byte_count, uint8_t prefix)
{
    const auto full_bytes = static_cast<size_t>(prefix / 8);
    const auto partial_bits = static_cast<uint8_t>(prefix % 8);

    if (full_bytes < byte_count) {
        if (partial_bits > 0) {
            const auto mask = static_cast<uint8_t>(0xffu << (8 - partial_bits));
            bytes[full_bytes] &= mask;
        }

        const auto zero_start = full_bytes + (partial_bits > 0 ? 1 : 0);
        for (size_t lpc = zero_start; lpc < byte_count; ++lpc) {
            bytes[lpc] = 0;
        }
    }
}

static bool
cidr_contains(const ioc_cidr_entry& entry, const std::array<uint8_t, 16>& addr)
{
    const auto full_bytes = static_cast<size_t>(entry.prefix_bits / 8);
    const auto partial_bits = static_cast<uint8_t>(entry.prefix_bits % 8);

    if (full_bytes > 0
        && memcmp(entry.network.data(), addr.data(), full_bytes) != 0)
    {
        return false;
    }

    if (partial_bits == 0) {
        return true;
    }

    const auto mask = static_cast<uint8_t>(0xffu << (8 - partial_bits));
    return (entry.network[full_bytes] & mask) == (addr[full_bytes] & mask);
}

static std::optional<ioc_cidr_entry>
parse_cidr(std::string candidate)
{
    candidate = strip_ioc_token(std::move(candidate));
    auto slash = candidate.find('/');
    if (slash == std::string::npos) {
        return std::nullopt;
    }

    auto ip_part = candidate.substr(0, slash);
    auto prefix_part = candidate.substr(slash + 1);

    ioc_cidr_entry retval;
    in_addr addr4;
    if (inet_pton(AF_INET, ip_part.c_str(), &addr4) == 1) {
        auto prefix = parse_prefix_bits(prefix_part, 32);
        if (!prefix) {
            return std::nullopt;
        }
        retval.family = AF_INET;
        retval.prefix_bits = prefix.value();
        memcpy(retval.network.data(), &addr4, 4);
        mask_network(retval.network, 4, retval.prefix_bits);

        char buf[INET_ADDRSTRLEN];
        in_addr masked{};
        memcpy(&masked, retval.network.data(), 4);
        if (inet_ntop(AF_INET, &masked, buf, sizeof(buf)) == nullptr) {
            return std::nullopt;
        }
        retval.label = std::string(buf) + "/" + std::to_string(*prefix);
        return retval;
    }

    in6_addr addr6;
    if (inet_pton(AF_INET6, ip_part.c_str(), &addr6) == 1) {
        auto prefix = parse_prefix_bits(prefix_part, 128);
        if (!prefix) {
            return std::nullopt;
        }
        retval.family = AF_INET6;
        retval.prefix_bits = prefix.value();
        memcpy(retval.network.data(), &addr6, 16);
        mask_network(retval.network, 16, retval.prefix_bits);

        char buf[INET6_ADDRSTRLEN];
        in6_addr masked{};
        memcpy(&masked, retval.network.data(), 16);
        if (inet_ntop(AF_INET6, &masked, buf, sizeof(buf)) == nullptr) {
            return std::nullopt;
        }
        retval.label = std::string(buf) + "/" + std::to_string(*prefix);
        return retval;
    }

    return std::nullopt;
}

static std::optional<std::pair<int, std::array<uint8_t, 16>>>
parse_ip_bytes(std::string candidate)
{
    candidate = strip_ioc_token(std::move(candidate));

    std::array<uint8_t, 16> bytes{};
    in_addr addr4;
    if (inet_pton(AF_INET, candidate.c_str(), &addr4) == 1) {
        memcpy(bytes.data(), &addr4, 4);
        return std::make_pair(AF_INET, bytes);
    }

    in6_addr addr6;
    if (inet_pton(AF_INET6, candidate.c_str(), &addr6) == 1) {
        memcpy(bytes.data(), &addr6, 16);
        return std::make_pair(AF_INET6, bytes);
    }

    return std::nullopt;
}

void
ioc_matcher::clear()
{
    this->im_exact_ips.clear();
    this->im_cidrs.clear();
}

bool
ioc_matcher::add_token(std::string candidate)
{
    if (candidate.find('/') != std::string::npos) {
        auto cidr = parse_cidr(std::move(candidate));
        if (!cidr) {
            return false;
        }

        auto exists = std::any_of(
            this->im_cidrs.begin(),
            this->im_cidrs.end(),
            [&cidr](const auto& elem) { return elem.label == cidr->label; });
        if (!exists) {
            this->im_cidrs.emplace_back(std::move(cidr.value()));
        }
        return true;
    }

    auto ip = normalize_ioc_ip(std::move(candidate));
    if (!ip) {
        return false;
    }

    this->im_exact_ips.insert(ip.value());
    return true;
}

bool
ioc_matcher::empty() const
{
    return this->im_exact_ips.empty() && this->im_cidrs.empty();
}

size_t
ioc_matcher::entry_count() const
{
    return this->im_exact_ips.size() + this->im_cidrs.size();
}

size_t
ioc_matcher::exact_count() const
{
    return this->im_exact_ips.size();
}

size_t
ioc_matcher::cidr_count() const
{
    return this->im_cidrs.size();
}

bool
ioc_matcher::matches(std::string candidate) const
{
    auto ip = normalize_ioc_ip(candidate);
    if (!ip) {
        return false;
    }

    if (this->im_exact_ips.count(ip.value()) > 0) {
        return true;
    }

    auto parsed = parse_ip_bytes(candidate);
    if (!parsed) {
        return false;
    }

    const auto& [family, bytes] = parsed.value();
    return std::any_of(this->im_cidrs.begin(),
                       this->im_cidrs.end(),
                       [family, &bytes](const auto& cidr) {
                           return cidr.family == family
                               && cidr_contains(cidr, bytes);
                       });
}

std::vector<std::string>
ioc_matcher::exact_ips() const
{
    std::vector<std::string> retval(this->im_exact_ips.begin(),
                                    this->im_exact_ips.end());
    std::sort(retval.begin(), retval.end());
    return retval;
}

std::vector<std::string>
ioc_matcher::cidr_labels() const
{
    std::vector<std::string> retval;

    retval.reserve(this->im_cidrs.size());
    for (const auto& cidr : this->im_cidrs) {
        retval.emplace_back(cidr.label);
    }
    std::sort(retval.begin(), retval.end());
    return retval;
}

std::vector<std::string>
ioc_matcher::fingerprint_entries() const
{
    auto retval = this->exact_ips();
    for (const auto& cidr : this->im_cidrs) {
        retval.emplace_back(cidr.label);
    }
    std::sort(retval.begin(), retval.end());
    return retval;
}

}  // namespace lnav::forensics
