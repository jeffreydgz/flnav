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
 *
 * @file entity_vtab_impl.cc
 */

#include "entity_vtab_impl.hh"

#include <cstring>

#include "base/auto_mem.hh"
#include "base/lnav_log.hh"
#include "config.h"
#include "sql_util.hh"

namespace {

enum {
    ENT_COL_LOG_LINE,
    ENT_COL_LOG_TIME,
    ENT_COL_LOG_TIME_MSECS,
    ENT_COL_LOG_PATH,
    ENT_COL_LOG_FORMAT,
    ENT_COL_ENTITY_TYPE,
    ENT_COL_ENTITY_VALUE,
    ENT_COL_SOURCE_FIELD,
    ENT_COL_CONFIDENCE,
};

static const char* const ENTITY_VTAB_CREATE = R"(
-- Exposes extracted entities from log lines as a queryable table.
CREATE TABLE lnav_db.lnav_entities (
    log_line       INTEGER,
    log_time       TEXT,
    log_time_msecs INTEGER,
    log_path       TEXT,
    log_format     TEXT,
    entity_type    TEXT,
    entity_value   TEXT,
    source_field   TEXT,
    confidence     REAL
);
)";

struct entity_vtab {
    sqlite3_vtab base;
    sqlite3* db;
    entity_index* eidx;
    logfile_sub_source* lss;
};

struct entity_vtab_cursor {
    sqlite3_vtab_cursor base;
    std::vector<entity_index::flat_row> rows;
    size_t row_index{0};
    std::string filter_type;
    std::string filter_value;
};

static int
evt_create(sqlite3* db,
           void* pAux,
           int argc,
           const char* const* argv,
           sqlite3_vtab** pp_vt,
           char** pzErr)
{
    auto* aux = (entity_vtab*)(pAux);

    auto* p_vt
        = (entity_vtab*)(sqlite3_malloc(sizeof(entity_vtab)));
    if (p_vt == nullptr) {
        return SQLITE_NOMEM;
    }

    memset(&p_vt->base, 0, sizeof(sqlite3_vtab));
    p_vt->db = db;
    p_vt->eidx = aux->eidx;
    p_vt->lss = aux->lss;

    *pp_vt = &p_vt->base;

    return sqlite3_declare_vtab(db, ENTITY_VTAB_CREATE);
}

static int
evt_disconnect(sqlite3_vtab* pVtab)
{
    sqlite3_free(pVtab);
    return SQLITE_OK;
}

static int
evt_destroy(sqlite3_vtab* pVtab)
{
    sqlite3_free(pVtab);
    return SQLITE_OK;
}

static int
evt_open(sqlite3_vtab* p_svt, sqlite3_vtab_cursor** pp_cursor)
{
    auto* p_cur = new entity_vtab_cursor();
    p_cur->base.pVtab = p_svt;
    *pp_cursor = &p_cur->base;
    return SQLITE_OK;
}

static int
evt_close(sqlite3_vtab_cursor* cur)
{
    delete (entity_vtab_cursor*)(cur);
    return SQLITE_OK;
}

static int
evt_eof(sqlite3_vtab_cursor* cur)
{
    auto* vc = (entity_vtab_cursor*)(cur);
    return vc->row_index >= vc->rows.size() ? 1 : 0;
}

static int
evt_next(sqlite3_vtab_cursor* cur)
{
    auto* vc = (entity_vtab_cursor*)(cur);
    vc->row_index++;
    return SQLITE_OK;
}

static int
evt_column(sqlite3_vtab_cursor* cur, sqlite3_context* ctx, int col)
{
    auto* vc = (entity_vtab_cursor*)(cur);
    auto* p_vt = (entity_vtab*)(cur->pVtab);
    const auto& row = vc->rows[vc->row_index];

    switch (col) {
        case ENT_COL_LOG_LINE:
            sqlite3_result_int64(ctx, row.fr_line);
            break;
        case ENT_COL_LOG_TIME: {
            if (p_vt->lss != nullptr) {
                auto cl = content_line_t(row.fr_line);
                uint64_t line_number;
                auto ld = p_vt->lss->find_data(cl, line_number);
                auto* lf = (*ld)->get_file_ptr();
                if (lf != nullptr) {
                    auto ll = lf->begin() + line_number;
                    char time_buf[64];
                    auto tv = ll->get_timeval();
                    sql_strftime(time_buf, sizeof(time_buf), tv);
                    sqlite3_result_text(
                        ctx, time_buf, -1, SQLITE_TRANSIENT);
                    break;
                }
            }
            sqlite3_result_null(ctx);
            break;
        }
        case ENT_COL_LOG_TIME_MSECS: {
            if (p_vt->lss != nullptr) {
                auto cl = content_line_t(row.fr_line);
                uint64_t line_number;
                auto ld = p_vt->lss->find_data(cl, line_number);
                auto* lf = (*ld)->get_file_ptr();
                if (lf != nullptr) {
                    auto ll = lf->begin() + line_number;
                    auto tv = ll->get_timeval();
                    int64_t ms
                        = tv.tv_sec * 1000LL + tv.tv_usec / 1000LL;
                    sqlite3_result_int64(ctx, ms);
                    break;
                }
            }
            sqlite3_result_null(ctx);
            break;
        }
        case ENT_COL_LOG_PATH: {
            if (p_vt->lss != nullptr) {
                auto cl = content_line_t(row.fr_line);
                uint64_t line_number;
                auto ld = p_vt->lss->find_data(cl, line_number);
                auto* lf = (*ld)->get_file_ptr();
                if (lf != nullptr) {
                    auto path = lf->get_filename().string();
                    sqlite3_result_text(ctx,
                                        path.c_str(),
                                        path.size(),
                                        SQLITE_TRANSIENT);
                    break;
                }
            }
            sqlite3_result_null(ctx);
            break;
        }
        case ENT_COL_LOG_FORMAT: {
            if (p_vt->lss != nullptr) {
                auto cl = content_line_t(row.fr_line);
                uint64_t line_number;
                auto ld = p_vt->lss->find_data(cl, line_number);
                auto* lf = (*ld)->get_file_ptr();
                if (lf != nullptr) {
                    auto* fmt = lf->get_format_ptr();
                    if (fmt != nullptr) {
                        auto name = fmt->get_name();
                        sqlite3_result_text(ctx,
                                            name.get(),
                                            name.size(),
                                            SQLITE_TRANSIENT);
                        break;
                    }
                }
            }
            sqlite3_result_null(ctx);
            break;
        }
        case ENT_COL_ENTITY_TYPE: {
            auto type_str = entity_type_to_string(row.fr_type);
            sqlite3_result_text(ctx, type_str, -1, SQLITE_STATIC);
            break;
        }
        case ENT_COL_ENTITY_VALUE:
            sqlite3_result_text(ctx,
                                row.fr_value.c_str(),
                                row.fr_value.size(),
                                SQLITE_TRANSIENT);
            break;
        case ENT_COL_SOURCE_FIELD:
            sqlite3_result_text(ctx,
                                row.fr_source_field.c_str(),
                                row.fr_source_field.size(),
                                SQLITE_TRANSIENT);
            break;
        case ENT_COL_CONFIDENCE:
            sqlite3_result_double(ctx, row.fr_confidence);
            break;
        default:
            sqlite3_result_null(ctx);
            break;
    }

    return SQLITE_OK;
}

static int
evt_rowid(sqlite3_vtab_cursor* cur, sqlite_int64* p_rowid)
{
    auto* vc = (entity_vtab_cursor*)(cur);
    *p_rowid = static_cast<sqlite_int64>(vc->row_index);
    return SQLITE_OK;
}

static int
evt_best_index(sqlite3_vtab* tab, sqlite3_index_info* p_info)
{
    int argv_index = 1;

    for (int i = 0; i < p_info->nConstraint; i++) {
        if (!p_info->aConstraint[i].usable) {
            continue;
        }
        if (p_info->aConstraint[i].op != SQLITE_INDEX_CONSTRAINT_EQ) {
            continue;
        }
        if (p_info->aConstraint[i].iColumn == ENT_COL_ENTITY_TYPE
            || p_info->aConstraint[i].iColumn == ENT_COL_ENTITY_VALUE)
        {
            p_info->aConstraintUsage[i].argvIndex = argv_index++;
            p_info->aConstraintUsage[i].omit = 1;
        }
    }

    p_info->estimatedCost = (argv_index > 1) ? 100.0 : 1000000.0;

    return SQLITE_OK;
}

static int
evt_filter(sqlite3_vtab_cursor* p_vtc,
           int idxNum,
           const char* idxStr,
           int argc,
           sqlite3_value** argv)
{
    auto* vc = (entity_vtab_cursor*)(p_vtc);
    auto* p_vt = (entity_vtab*)(p_vtc->pVtab);

    vc->rows = p_vt->eidx->all_rows();
    vc->row_index = 0;

    // Apply equality filters pushed down from xBestIndex
    if (argc > 0) {
        std::optional<std::string> type_filter;
        std::optional<std::string> value_filter;

        for (int i = 0; i < argc; i++) {
            auto* text = reinterpret_cast<const char*>(
                sqlite3_value_text(argv[i]));
            if (text == nullptr) {
                continue;
            }
            // We assigned argv indices in order of column appearance,
            // but we need to check what was actually bound
            if (i == 0 && argc >= 1) {
                // First constraint
                auto et = string_to_entity_type(text);
                if (et) {
                    type_filter = text;
                } else {
                    value_filter = text;
                }
            }
            if (i == 1 && argc >= 2) {
                value_filter = text;
            }
        }

        if (type_filter || value_filter) {
            std::vector<entity_index::flat_row> filtered;
            for (auto& row : vc->rows) {
                bool match = true;
                if (type_filter
                    && entity_type_to_string(row.fr_type) != *type_filter)
                {
                    match = false;
                }
                if (value_filter && row.fr_value != *value_filter) {
                    match = false;
                }
                if (match) {
                    filtered.emplace_back(std::move(row));
                }
            }
            vc->rows = std::move(filtered);
        }
    }

    return SQLITE_OK;
}

static sqlite3_module entity_vtab_module = {
    0,              /* iVersion */
    evt_create,     /* xCreate */
    evt_create,     /* xConnect */
    evt_best_index, /* xBestIndex */
    evt_disconnect, /* xDisconnect */
    evt_destroy,    /* xDestroy */
    evt_open,       /* xOpen */
    evt_close,      /* xClose */
    evt_filter,     /* xFilter */
    evt_next,       /* xNext */
    evt_eof,        /* xEof */
    evt_column,     /* xColumn */
    evt_rowid,      /* xRowid */
    nullptr,        /* xUpdate */
    nullptr,        /* xBegin */
    nullptr,        /* xSync */
    nullptr,        /* xCommit */
    nullptr,        /* xRollback */
    nullptr,        /* xFindFunction */
};

}  // namespace

static entity_vtab s_entity_vtab_aux;

int
register_entity_vtab(sqlite3* db,
                     entity_index* eidx,
                     logfile_sub_source* lss)
{
    s_entity_vtab_aux.eidx = eidx;
    s_entity_vtab_aux.lss = lss;
    memset(&s_entity_vtab_aux.base, 0, sizeof(sqlite3_vtab));
    s_entity_vtab_aux.db = db;

    auto rc = sqlite3_create_module(
        db, "entity_vtab_impl", &entity_vtab_module, &s_entity_vtab_aux);
    if (rc != SQLITE_OK) {
        return rc;
    }

    auto_mem<char, sqlite3_free> errmsg;
    rc = sqlite3_exec(
        db,
        "CREATE VIRTUAL TABLE IF NOT EXISTS lnav_db.lnav_entities "
        "USING entity_vtab_impl()",
        nullptr,
        nullptr,
        errmsg.out());
    if (rc != SQLITE_OK) {
        log_error("unable to create lnav_entities table: %s", errmsg.in());
    }
    return rc;
}
