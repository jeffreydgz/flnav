/**
 * Copyright (c) 2026, Jeffrey Douglas
 *
 * All rights reserved.
 */

#ifndef ssh_stats_vtab_hh
#define ssh_stats_vtab_hh

#include <sqlite3.h>

int register_ssh_stats_vtabs(sqlite3* db);

#endif
