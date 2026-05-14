/**
 * Copyright (c) 2026, Jeffrey Douglas
 *
 * All rights reserved.
 */

#ifndef lnav_ssh_stats_hh
#define lnav_ssh_stats_hh

#include <functional>
#include <string>

#include "logfile_sub_source.hh"
#include "ssh_flow.hh"

namespace lnav::forensics {

using ssh_stats_progress = std::function<void(size_t, size_t)>;

ssh_flow_stats collect_ssh_stats(logfile_sub_source& lss,
                                 const ssh_stats_progress& progress = {});

}  // namespace lnav::forensics

#endif
