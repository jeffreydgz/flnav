/**
 * Copyright (c) 2026, Jeffrey Douglas
 *
 * All rights reserved.
 */

#include "log_gap_detector.hh"

#include <algorithm>

namespace lnav::forensics {

std::vector<log_gap_record>
detect_log_gaps(const std::vector<log_gap_file>& files,
                int64_t threshold_secs)
{
    std::vector<log_gap_record> retval;

    for (size_t fi = 0; fi < files.size(); ++fi) {
        const auto& file = files[fi];
        for (size_t li = 1; li < file.timestamps.size(); ++li) {
            const auto& prev_tv = file.timestamps[li - 1];
            const auto& cur_tv = file.timestamps[li];

            auto delta
                = int64_t(cur_tv.tv_sec) - int64_t(prev_tv.tv_sec);
            if (delta < threshold_secs) {
                continue;
            }

            bool others_active = false;
            for (size_t oi = 0; oi < files.size(); ++oi) {
                if (oi == fi) {
                    continue;
                }

                const auto& other = files[oi];
                auto lb = std::lower_bound(
                    other.timestamps.begin(),
                    other.timestamps.end(),
                    prev_tv,
                    [](const timeval& a, const timeval& b) {
                        return timercmp(&a, &b, <);
                    });
                if (lb != other.timestamps.end()
                    && timercmp(&(*lb), &cur_tv, <))
                {
                    others_active = true;
                    break;
                }
            }

            retval.push_back({
                file.filename,
                prev_tv,
                cur_tv,
                file.local_offset,
                delta,
                others_active,
                others_active ? "suspicious" : "normal",
            });
        }
    }

    return retval;
}

void
sort_log_gaps_for_display(std::vector<log_gap_record>& gaps)
{
    std::sort(gaps.begin(), gaps.end(), [](const auto& a, const auto& b) {
        if (a.severity != b.severity) {
            return a.severity > b.severity;
        }
        return a.duration_secs > b.duration_secs;
    });
}

}  // namespace lnav::forensics
