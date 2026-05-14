/**
 * Copyright (c) 2026, Jeffrey Douglas
 *
 * All rights reserved.
 */

#ifndef lnav_session_trace_hh
#define lnav_session_trace_hh

#include <cstdint>
#include <cstddef>
#include <ctime>
#include <set>
#include <string>
#include <sys/time.h>
#include <vector>

#include "base/intern_string.hh"
#include "log_level.hh"

namespace lnav::forensics {

struct session_trace_line {
    timeval tv;
    time_t local_offset{0};
    std::string filename;
    std::string text;
    log_level_t level{log_level_t::LEVEL_UNKNOWN};
};

struct session_info {
    timeval start_tv;
    timeval end_tv;
    time_t local_offset{0};
    std::string source_ip;
    std::string user;
    std::string outcome;
    std::vector<size_t> line_indices;
};

struct session_summary {
    std::set<std::string> all_files;
    std::set<std::string> all_ips;
    std::set<std::string> all_users;
    size_t auth_accepted{0};
    size_t auth_failed{0};
    size_t outcome_closed{0};
    size_t outcome_opened{0};
    size_t outcome_unknown{0};
    size_t level_error{0};
    size_t level_warning{0};
    int64_t longest_duration{-1};
    size_t longest_index{0};
    int64_t total_span{0};
};

bool session_line_matches_target(const string_fragment& sf,
                                 const std::string& line,
                                 const std::string& target);

void collect_session_trace_suggestions(const string_fragment& sf,
                                       const std::string& line,
                                       std::set<std::string>& suggestions);

std::vector<session_info>
group_session_trace_lines(const std::vector<session_trace_line>& lines,
                          int64_t session_gap_us = 30LL * 60 * 1000000);

session_summary
summarize_session_trace(const std::vector<session_trace_line>& lines,
                        const std::vector<session_info>& sessions);

}  // namespace lnav::forensics

#endif
