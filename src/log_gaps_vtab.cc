/**
 * Copyright (c) 2024, Timothy Stack
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * * Neither the name of Timothy Stack nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "log_gaps_vtab.hh"

#include <algorithm>
#include <string>
#include <vector>

#include "base/lnav_log.hh"
#include "config.h"
#include "lnav.hh"
#include "sql_help.hh"
#include "vtab_module.hh"

enum {
    LG_COL_LOG_FILE,
    LG_COL_GAP_START,
    LG_COL_GAP_END,
    LG_COL_GAP_DURATION_SECONDS,
    LG_COL_OTHER_FILES_ACTIVE,
    LG_COL_SEVERITY,
    LG_COL_THRESHOLD,
};

struct log_gaps_row {
    std::string filename;
    std::string gap_start;
    std::string gap_end;
    int64_t duration_secs;
    bool other_files_active;
    std::string severity;
};

static std::string
format_timeval(const timeval& tv)
{
    bool normalize = lnav_data.ld_log_source.get_normalize_timestamps();
    char buf[64];
    struct tm tm;
    if (normalize) {
        gmtime_r(&tv.tv_sec, &tm);
        auto len = strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
        snprintf(buf + len, sizeof(buf) - len, ".%06ld",
                 static_cast<long>(tv.tv_usec));
    } else {
        localtime_r(&tv.tv_sec, &tm);
        auto len = strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
        snprintf(buf + len, sizeof(buf) - len, ".%06ld",
                 static_cast<long>(tv.tv_usec));
    }
    return std::string(buf);
}

struct log_gaps_vtab {
    static constexpr const char* NAME = "log_gaps";
    static constexpr const char* CREATE_STMT = R"(
-- The log_gaps() table-valued function detects periods where logging stopped
CREATE TABLE log_gaps (
    log_file text,
    gap_start text,
    gap_end text,
    gap_duration_seconds integer,
    other_files_active integer,
    severity text,

    threshold_seconds integer HIDDEN
);
)";

    struct cursor {
        sqlite3_vtab_cursor base;
        sqlite3_int64 c_rowid{0};
        int64_t c_threshold{300};
        std::vector<log_gaps_row> c_rows;

        cursor(sqlite3_vtab* vt) : base({vt}) {}

        int reset()
        {
            this->c_rowid = 0;
            this->c_rows.clear();
            return SQLITE_OK;
        }

        int next()
        {
            this->c_rowid += 1;
            return SQLITE_OK;
        }

        int eof()
        {
            return this->c_rowid >= (int64_t) this->c_rows.size();
        }

        int get_rowid(sqlite3_int64& rowid_out)
        {
            rowid_out = this->c_rowid;
            return SQLITE_OK;
        }
    };

    int get_column(const cursor& vc, sqlite3_context* ctx, int col)
    {
        if (vc.c_rowid >= (int64_t) vc.c_rows.size()) {
            sqlite3_result_null(ctx);
            return SQLITE_OK;
        }

        const auto& row = vc.c_rows[vc.c_rowid];

        switch (col) {
            case LG_COL_LOG_FILE:
                sqlite3_result_text(ctx,
                                    row.filename.c_str(),
                                    row.filename.length(),
                                    SQLITE_TRANSIENT);
                break;
            case LG_COL_GAP_START:
                sqlite3_result_text(ctx,
                                    row.gap_start.c_str(),
                                    row.gap_start.length(),
                                    SQLITE_TRANSIENT);
                break;
            case LG_COL_GAP_END:
                sqlite3_result_text(ctx,
                                    row.gap_end.c_str(),
                                    row.gap_end.length(),
                                    SQLITE_TRANSIENT);
                break;
            case LG_COL_GAP_DURATION_SECONDS:
                sqlite3_result_int64(ctx, row.duration_secs);
                break;
            case LG_COL_OTHER_FILES_ACTIVE:
                sqlite3_result_int(ctx, row.other_files_active ? 1 : 0);
                break;
            case LG_COL_SEVERITY:
                sqlite3_result_text(ctx,
                                    row.severity.c_str(),
                                    row.severity.length(),
                                    SQLITE_TRANSIENT);
                break;
            case LG_COL_THRESHOLD:
                sqlite3_result_int64(ctx, vc.c_threshold);
                break;
        }

        return SQLITE_OK;
    }
};

static int
rcBestIndex(sqlite3_vtab* tab, sqlite3_index_info* pIdxInfo)
{
    vtab_index_constraints vic(pIdxInfo);
    vtab_index_usage viu(pIdxInfo);

    for (auto iter = vic.begin(); iter != vic.end(); ++iter) {
        if (iter->op != SQLITE_INDEX_CONSTRAINT_EQ) {
            continue;
        }
        if (iter->iColumn == LG_COL_THRESHOLD) {
            viu.column_used(iter);
        }
    }

    viu.allocate_args(LG_COL_THRESHOLD, LG_COL_THRESHOLD, 0);
    return SQLITE_OK;
}

static int
rcFilter(sqlite3_vtab_cursor* pVtabCursor,
         int idxNum,
         const char* idxStr,
         int argc,
         sqlite3_value** argv)
{
    auto* pCur = (log_gaps_vtab::cursor*) pVtabCursor;
    pCur->reset();

    // Get threshold from argument (default 300 seconds)
    int64_t threshold = 300;
    if (argc >= 1 && sqlite3_value_type(argv[0]) != SQLITE_NULL) {
        threshold = sqlite3_value_int64(argv[0]);
        if (threshold <= 0) {
            threshold = 300;
        }
    }
    pCur->c_threshold = threshold;

    // Collect per-file timestamps
    struct file_ts {
        std::string filename;
        std::vector<timeval> timestamps;
    };
    std::vector<file_ts> files;

    auto& lss = lnav_data.ld_log_source;
    for (auto it = lss.begin(); it != lss.end(); ++it) {
        auto& ld = *it;
        if (!ld->is_visible()) {
            continue;
        }
        auto lf = ld->get_file();
        if (!lf || lf->size() == 0) {
            continue;
        }

        file_ts ft;
        ft.filename = lf->get_filename().filename().string();
        ft.timestamps.reserve(lf->size());
        for (auto ll = lf->cbegin(); ll != lf->cend(); ++ll) {
            ft.timestamps.push_back(ll->get_timeval());
        }
        files.push_back(std::move(ft));
    }

    // Detect gaps for each file
    for (size_t fi = 0; fi < files.size(); ++fi) {
        auto& f = files[fi];
        for (size_t li = 1; li < f.timestamps.size(); ++li) {
            auto& prev_tv = f.timestamps[li - 1];
            auto& cur_tv = f.timestamps[li];

            int64_t delta = int64_t(cur_tv.tv_sec) - int64_t(prev_tv.tv_sec);
            if (delta < threshold) {
                continue;
            }

            // Cross-reference: check if other files have entries during gap
            bool others_active = false;
            for (size_t oi = 0; oi < files.size(); ++oi) {
                if (oi == fi) {
                    continue;
                }
                auto& other = files[oi];
                auto lb = std::lower_bound(
                    other.timestamps.begin(), other.timestamps.end(), prev_tv,
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

            pCur->c_rows.push_back({
                f.filename,
                format_timeval(prev_tv),
                format_timeval(cur_tv),
                delta,
                others_active,
                others_active ? "suspicious" : "normal",
            });
        }
    }

    return SQLITE_OK;
}

int
register_log_gaps_vtab(sqlite3* db)
{
    static vtab_module<tvt_no_update<log_gaps_vtab>> LOG_GAPS_MODULE;
    static help_text log_gaps_help
        = help_text("log_gaps",
                    "A table-valued function that detects periods where "
                    "logging stopped or was potentially tampered with.")
              .sql_table_valued_function()
              .with_parameter(
                  help_text("threshold_seconds",
                            "The minimum gap in seconds to report "
                            "(default 300).")
                      .optional())
              .with_result({"log_file", "The name of the log file."})
              .with_result(
                  {"gap_start", "The timestamp of the last line before the gap."})
              .with_result(
                  {"gap_end", "The timestamp of the first line after the gap."})
              .with_result(
                  {"gap_duration_seconds", "The gap duration in seconds."})
              .with_result(
                  {"other_files_active",
                   "1 if other files have entries during the gap, 0 otherwise."})
              .with_result(
                  {"severity",
                   "'suspicious' if other files are active during the gap, "
                   "otherwise 'normal'."})
              .with_tags({"forensics"})
              .with_example({
                  "To find gaps longer than 5 minutes",
                  "SELECT * FROM log_gaps(300)",
              })
              .with_example({
                  "To find only suspicious gaps",
                  "SELECT * FROM log_gaps(300) WHERE severity = 'suspicious'",
              });

    int rc;

    LOG_GAPS_MODULE.vm_module.xBestIndex = rcBestIndex;
    LOG_GAPS_MODULE.vm_module.xFilter = rcFilter;

    rc = LOG_GAPS_MODULE.create(db, "log_gaps");
    sqlite_function_help.insert(std::make_pair("log_gaps", &log_gaps_help));
    log_gaps_help.index_tags();

    ensure(rc == SQLITE_OK);

    return rc;
}
