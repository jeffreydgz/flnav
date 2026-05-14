/**
 * Copyright (c) 2026, Jeffrey Douglas
 *
 * All rights reserved.
 */

#ifndef lnav_forensic_time_hh
#define lnav_forensic_time_hh

#include <cstdint>
#include <ctime>
#include <string>
#include <sys/time.h>

namespace lnav::forensics {

std::string format_timestamp_for_view(const timeval& tv,
                                      time_t local_offset,
                                      bool normalize_timestamps);

std::string format_timestamp_for_sql(const timeval& tv,
                                     bool normalize_timestamps);

std::string format_duration(int64_t secs);

}  // namespace lnav::forensics

#endif
