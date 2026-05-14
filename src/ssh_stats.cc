/**
 * Copyright (c) 2026, Jeffrey Douglas
 *
 * All rights reserved.
 */

#include "ssh_stats.hh"

#include "logfile.hh"

namespace lnav::forensics {

ssh_flow_stats
collect_ssh_stats(logfile_sub_source& lss, const ssh_stats_progress& progress)
{
    ssh_flow_stats retval;
    const size_t line_count = lss.text_line_count();

    for (size_t vl_idx = 0; vl_idx < line_count; ++vl_idx) {
        if (progress) {
            progress(vl_idx, line_count);
        }

        auto cl = lss.at(vis_line_t(vl_idx));
        auto line_opt = lss.find_line_with_file(cl);
        if (!line_opt) {
            continue;
        }

        auto& [lf, ll_iter] = *line_opt;
        auto read_res = lf->read_line(ll_iter);
        if (read_res.isErr()) {
            continue;
        }

        auto sbr = read_res.unwrap();
        auto sf = sbr.to_string_fragment();
        auto line_str = sf.to_string();

        scan_ssh_line(sf, line_str, retval);
    }

    if (progress) {
        progress(0, 0);
    }

    return retval;
}

}  // namespace lnav::forensics
