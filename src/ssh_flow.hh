/**
 * Copyright (c) 2026, Jeffrey Douglas
 *
 * All rights reserved.
 */

#ifndef lnav_ssh_flow_hh
#define lnav_ssh_flow_hh

#include <map>
#include <cstddef>
#include <set>
#include <string>
#include <tuple>
#include <vector>

#include "base/intern_string.hh"

namespace lnav::forensics {

using ssh_flow_key
    = std::tuple<std::string, std::string, std::string, std::string>;

struct ssh_flow_record {
    std::map<std::string, size_t> user_counts;
    size_t count{0};
};

struct ssh_event_counters {
    size_t accepted{0};
    size_t failed_password{0};
    size_t failed_publickey{0};
    size_t failed_keyboard_interactive{0};
    size_t failed_pam{0};
    size_t invalid_user{0};
    size_t too_many_auth_failures{0};
    size_t disconnected{0};
    size_t closed_preauth{0};
    size_t client_disconnect{0};
    size_t closed{0};
    size_t new_connection{0};
};

struct ssh_flow_stats {
    std::map<ssh_flow_key, ssh_flow_record> flows;
    std::set<std::string> unique_sources;
    std::map<std::string, size_t> ip_counts;
    ssh_event_counters counters;
    size_t total_ssh_events{0};
};

void scan_ssh_line(const string_fragment& sf,
                   const std::string& line,
                   ssh_flow_stats& stats);

std::vector<std::pair<ssh_flow_key, size_t>>
sorted_ssh_flows(const ssh_flow_stats& stats);

bool is_private_ip(const std::string& ip);

}  // namespace lnav::forensics

#endif
