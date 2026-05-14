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

#include <string>
#include <vector>

#include "base/lnav_log.hh"
#include "config.h"
#include "forensic_time.hh"
#include "lnav.hh"
#include "log_gap_detector.hh"
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
        std::vector<lnav::forensics::log_gap_record> c_rows;

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
        const auto normalize
            = lnav_data.ld_log_source.get_normalize_timestamps();

        switch (col) {
            case LG_COL_LOG_FILE:
                sqlite3_result_text(ctx,
                                    row.filename.c_str(),
                                    row.filename.length(),
                                    SQLITE_TRANSIENT);
                break;
            case LG_COL_GAP_START:
            {
                auto formatted = lnav::forensics::format_timestamp_for_sql(
                    row.gap_start,
                    normalize);
                sqlite3_result_text(ctx,
                                    formatted.c_str(),
                                    formatted.length(),
                                    SQLITE_TRANSIENT);
                break;
            }
            case LG_COL_GAP_END:
            {
                auto formatted = lnav::forensics::format_timestamp_for_sql(
                    row.gap_end,
                    normalize);
                sqlite3_result_text(ctx,
                                    formatted.c_str(),
                                    formatted.length(),
                                    SQLITE_TRANSIENT);
                break;
            }
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

    std::vector<lnav::forensics::log_gap_file> files;

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

        lnav::forensics::log_gap_file ft;
        ft.filename = lf->get_filename().filename().string();
        ft.timestamps.reserve(lf->size());
        for (auto ll = lf->cbegin(); ll != lf->cend(); ++ll) {
            ft.timestamps.push_back(ll->get_timeval());
        }
        files.push_back(std::move(ft));
    }

    pCur->c_rows = lnav::forensics::detect_log_gaps(files, threshold);

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
