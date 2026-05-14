/**
 * Copyright (c) 2026, Jeffrey Douglas
 *
 * All rights reserved.
 */

#ifndef lnav_log_gap_detector_hh
#define lnav_log_gap_detector_hh

#include <cstdint>
#include <ctime>
#include <string>
#include <sys/time.h>
#include <vector>

namespace lnav::forensics {

struct log_gap_file {
    std::string filename;
    std::vector<timeval> timestamps;
    time_t local_offset{0};
};

struct log_gap_record {
    std::string filename;
    timeval gap_start;
    timeval gap_end;
    time_t local_offset{0};
    int64_t duration_secs;
    bool other_files_active;
    std::string severity;
};

std::vector<log_gap_record>
detect_log_gaps(const std::vector<log_gap_file>& files,
                int64_t threshold_secs);

void sort_log_gaps_for_display(std::vector<log_gap_record>& gaps);

}  // namespace lnav::forensics

#endif
