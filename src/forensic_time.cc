/**
 * Copyright (c) 2026, Jeffrey Douglas
 *
 * All rights reserved.
 */

#include "forensic_time.hh"

#include "fmt/format.h"

namespace lnav::forensics {

std::string
format_timestamp_for_view(const timeval& tv,
                          time_t local_offset,
                          bool normalize_timestamps)
{
    char buf[64];
    struct tm tm;
    if (normalize_timestamps) {
        time_t true_utc = tv.tv_sec - local_offset;
        gmtime_r(&true_utc, &tm);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    } else {
        gmtime_r(&tv.tv_sec, &tm);
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    }

    return fmt::format(FMT_STRING("{}.{:06d}"),
                       buf,
                       static_cast<int>(tv.tv_usec));
}

std::string
format_timestamp_for_sql(const timeval& tv, bool normalize_timestamps)
{
    char buf[64];
    struct tm tm;
    if (normalize_timestamps) {
        gmtime_r(&tv.tv_sec, &tm);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    } else {
        localtime_r(&tv.tv_sec, &tm);
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    }

    return fmt::format(FMT_STRING("{}.{:06d}"),
                       buf,
                       static_cast<int>(tv.tv_usec));
}

std::string
format_duration(int64_t secs)
{
    if (secs >= 3600) {
        return fmt::format(FMT_STRING("{}h {:02d}m {:02d}s"),
                           secs / 3600,
                           (secs % 3600) / 60,
                           secs % 60);
    }
    if (secs >= 60) {
        return fmt::format(FMT_STRING("{}m {:02d}s"), secs / 60, secs % 60);
    }
    return fmt::format(FMT_STRING("{}s"), secs);
}

}  // namespace lnav::forensics
