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
 * @file entity_graph_vtab_impl.cc
 */

#include "entity_graph_vtab_impl.hh"

#include <cstring>
#include <set>
#include <unordered_map>

#include "base/auto_mem.hh"
#include "base/lnav_log.hh"
#include "config.h"
#include "sql_util.hh"

namespace {

enum {
    EG_COL_ENTITY_A_TYPE,
    EG_COL_ENTITY_A_VALUE,
    EG_COL_ENTITY_B_TYPE,
    EG_COL_ENTITY_B_VALUE,
    EG_COL_CO_OCCURRENCE,
    EG_COL_FIRST_SEEN,
    EG_COL_LAST_SEEN,
    EG_COL_LOG_SOURCES,
};

static const char* const ENTITY_GRAPH_VTAB_CREATE = R"(
-- Exposes co-occurrence relationships between entities across log lines.
CREATE TABLE lnav_db.lnav_entity_graph (
    entity_a_type   TEXT,
    entity_a_value  TEXT,
    entity_b_type   TEXT,
    entity_b_value  TEXT,
    co_occurrence   INTEGER,
    first_seen      TEXT,
    last_seen       TEXT,
    log_sources     TEXT
);
)";

struct graph_vtab {
    sqlite3_vtab base;
    sqlite3* db;
    entity_index* eidx;
    logfile_sub_source* lss;
};

struct graph_row {
    std::string gr_a_type;
    std::string gr_a_value;
    std::string gr_b_type;
    std::string gr_b_value;
    int gr_co_occurrence{0};
    std::string gr_first_seen;
    std::string gr_last_seen;
    std::string gr_log_sources;  // JSON array
};

struct graph_vtab_cursor {
    sqlite3_vtab_cursor base;
    std::vector<graph_row> rows;
    size_t row_index{0};
};

static int
gvt_create(sqlite3* db,
           void* pAux,
           int argc,
           const char* const* argv,
           sqlite3_vtab** pp_vt,
           char** pzErr)
{
    auto* aux = (graph_vtab*)(pAux);

    auto* p_vt
        = (graph_vtab*)(sqlite3_malloc(sizeof(graph_vtab)));
    if (p_vt == nullptr) {
        return SQLITE_NOMEM;
    }

    memset(&p_vt->base, 0, sizeof(sqlite3_vtab));
    p_vt->db = db;
    p_vt->eidx = aux->eidx;
    p_vt->lss = aux->lss;

    *pp_vt = &p_vt->base;

    return sqlite3_declare_vtab(db, ENTITY_GRAPH_VTAB_CREATE);
}

static int
gvt_disconnect(sqlite3_vtab* pVtab)
{
    sqlite3_free(pVtab);
    return SQLITE_OK;
}

static int
gvt_destroy(sqlite3_vtab* pVtab)
{
    sqlite3_free(pVtab);
    return SQLITE_OK;
}

static int
gvt_open(sqlite3_vtab* p_svt, sqlite3_vtab_cursor** pp_cursor)
{
    auto* p_cur = new graph_vtab_cursor();
    p_cur->base.pVtab = p_svt;
    *pp_cursor = &p_cur->base;
    return SQLITE_OK;
}

static int
gvt_close(sqlite3_vtab_cursor* cur)
{
    delete (graph_vtab_cursor*)(cur);
    return SQLITE_OK;
}

static int
gvt_eof(sqlite3_vtab_cursor* cur)
{
    auto* vc = (graph_vtab_cursor*)(cur);
    return vc->row_index >= vc->rows.size() ? 1 : 0;
}

static int
gvt_next(sqlite3_vtab_cursor* cur)
{
    auto* vc = (graph_vtab_cursor*)(cur);
    vc->row_index++;
    return SQLITE_OK;
}

static int
gvt_column(sqlite3_vtab_cursor* cur, sqlite3_context* ctx, int col)
{
    auto* vc = (graph_vtab_cursor*)(cur);
    const auto& row = vc->rows[vc->row_index];

    switch (col) {
        case EG_COL_ENTITY_A_TYPE:
            sqlite3_result_text(ctx,
                                row.gr_a_type.c_str(),
                                row.gr_a_type.size(),
                                SQLITE_TRANSIENT);
            break;
        case EG_COL_ENTITY_A_VALUE:
            sqlite3_result_text(ctx,
                                row.gr_a_value.c_str(),
                                row.gr_a_value.size(),
                                SQLITE_TRANSIENT);
            break;
        case EG_COL_ENTITY_B_TYPE:
            sqlite3_result_text(ctx,
                                row.gr_b_type.c_str(),
                                row.gr_b_type.size(),
                                SQLITE_TRANSIENT);
            break;
        case EG_COL_ENTITY_B_VALUE:
            sqlite3_result_text(ctx,
                                row.gr_b_value.c_str(),
                                row.gr_b_value.size(),
                                SQLITE_TRANSIENT);
            break;
        case EG_COL_CO_OCCURRENCE:
            sqlite3_result_int(ctx, row.gr_co_occurrence);
            break;
        case EG_COL_FIRST_SEEN:
            sqlite3_result_text(ctx,
                                row.gr_first_seen.c_str(),
                                row.gr_first_seen.size(),
                                SQLITE_TRANSIENT);
            break;
        case EG_COL_LAST_SEEN:
            sqlite3_result_text(ctx,
                                row.gr_last_seen.c_str(),
                                row.gr_last_seen.size(),
                                SQLITE_TRANSIENT);
            break;
        case EG_COL_LOG_SOURCES:
            sqlite3_result_text(ctx,
                                row.gr_log_sources.c_str(),
                                row.gr_log_sources.size(),
                                SQLITE_TRANSIENT);
            break;
        default:
            sqlite3_result_null(ctx);
            break;
    }

    return SQLITE_OK;
}

static int
gvt_rowid(sqlite3_vtab_cursor* cur, sqlite_int64* p_rowid)
{
    auto* vc = (graph_vtab_cursor*)(cur);
    *p_rowid = static_cast<sqlite_int64>(vc->row_index);
    return SQLITE_OK;
}

static int
gvt_best_index(sqlite3_vtab* tab, sqlite3_index_info* p_info)
{
    int argv_index = 1;

    for (int i = 0; i < p_info->nConstraint; i++) {
        if (!p_info->aConstraint[i].usable) {
            continue;
        }
        if (p_info->aConstraint[i].op != SQLITE_INDEX_CONSTRAINT_EQ) {
            continue;
        }
        if (p_info->aConstraint[i].iColumn == EG_COL_ENTITY_A_TYPE
            || p_info->aConstraint[i].iColumn == EG_COL_ENTITY_A_VALUE
            || p_info->aConstraint[i].iColumn == EG_COL_ENTITY_B_TYPE)
        {
            p_info->aConstraintUsage[i].argvIndex = argv_index++;
            p_info->aConstraintUsage[i].omit = 1;
        }
    }

    p_info->estimatedCost = (argv_index > 1) ? 500.0 : 5000000.0;

    return SQLITE_OK;
}

/** Build graph rows by iterating all unique entities and their co-occurrences. */
static void
build_graph_rows(graph_vtab* p_vt,
                 graph_vtab_cursor* vc,
                 const std::optional<std::string>& filter_a_type,
                 const std::optional<std::string>& filter_a_value,
                 const std::optional<std::string>& filter_b_type)
{
    auto all = p_vt->eidx->all_rows();

    // Collect unique (type, value) pairs
    using ent_key = std::pair<entity_type_t, std::string>;
    std::set<ent_key> unique_entities;
    for (const auto& row : all) {
        unique_entities.emplace(row.fr_type, row.fr_value);
    }

    std::optional<entity_type_t> b_type_filter;
    if (filter_b_type) {
        b_type_filter = string_to_entity_type(*filter_b_type);
    }

    for (const auto& [etype, evalue] : unique_entities) {
        auto type_str = std::string(entity_type_to_string(etype));

        if (filter_a_type && type_str != *filter_a_type) {
            continue;
        }
        if (filter_a_value && evalue != *filter_a_value) {
            continue;
        }

        auto co_occurrences
            = p_vt->eidx->co_occurring_entities(etype, evalue, b_type_filter);

        for (const auto& co : co_occurrences) {
            graph_row gr;
            gr.gr_a_type = type_str;
            gr.gr_a_value = evalue;
            gr.gr_b_type = entity_type_to_string(co.co_type);
            gr.gr_b_value = co.co_value;
            gr.gr_co_occurrence = co.co_count;

            // Resolve time range and log sources from shared lines
            auto a_lines
                = p_vt->eidx->lines_for_entity(etype, evalue);
            auto b_lines = p_vt->eidx->lines_for_entity(
                co.co_type, co.co_value);

            // Find shared lines
            std::set<std::string> sources;
            std::string first_time;
            std::string last_time;

            size_t ai = 0, bi = 0;
            while (ai < a_lines.size() && bi < b_lines.size()) {
                if (a_lines[ai] == b_lines[bi]) {
                    auto line = a_lines[ai];
                    if (p_vt->lss != nullptr) {
                        auto cl = content_line_t(line);
                        uint64_t line_number;
                        auto ld = p_vt->lss->find_data(cl, line_number);
                        auto* lf = (*ld)->get_file_ptr();
                        if (lf != nullptr) {
                            sources.insert(lf->get_filename().string());
                            auto ll = lf->begin() + line_number;
                            char time_buf[64];
                            auto tv = ll->get_timeval();
                            sql_strftime(
                                time_buf, sizeof(time_buf), tv);
                            std::string ts(time_buf);
                            if (first_time.empty()
                                || ts < first_time)
                            {
                                first_time = ts;
                            }
                            if (last_time.empty() || ts > last_time)
                            {
                                last_time = ts;
                            }
                        }
                    }
                    ai++;
                    bi++;
                } else if (a_lines[ai] < b_lines[bi]) {
                    ai++;
                } else {
                    bi++;
                }
            }

            gr.gr_first_seen = first_time;
            gr.gr_last_seen = last_time;

            // Build JSON array of sources
            gr.gr_log_sources = "[";
            bool first = true;
            for (const auto& src : sources) {
                if (!first) {
                    gr.gr_log_sources += ",";
                }
                gr.gr_log_sources += "\"" + src + "\"";
                first = false;
            }
            gr.gr_log_sources += "]";

            vc->rows.emplace_back(std::move(gr));
        }
    }
}

static int
gvt_filter(sqlite3_vtab_cursor* p_vtc,
           int idxNum,
           const char* idxStr,
           int argc,
           sqlite3_value** argv)
{
    auto* vc = (graph_vtab_cursor*)(p_vtc);
    auto* p_vt = (graph_vtab*)(p_vtc->pVtab);

    vc->rows.clear();
    vc->row_index = 0;

    std::optional<std::string> filter_a_type;
    std::optional<std::string> filter_a_value;
    std::optional<std::string> filter_b_type;

    // Extract filter values (order matches xBestIndex assignment)
    for (int i = 0; i < argc; i++) {
        auto* text
            = reinterpret_cast<const char*>(sqlite3_value_text(argv[i]));
        if (text == nullptr) {
            continue;
        }
        if (i == 0) {
            filter_a_type = text;
        }
        if (i == 1) {
            filter_a_value = text;
        }
        if (i == 2) {
            filter_b_type = text;
        }
    }

    build_graph_rows(p_vt, vc, filter_a_type, filter_a_value, filter_b_type);

    return SQLITE_OK;
}

static sqlite3_module entity_graph_vtab_module = {
    0,              /* iVersion */
    gvt_create,     /* xCreate */
    gvt_create,     /* xConnect */
    gvt_best_index, /* xBestIndex */
    gvt_disconnect, /* xDisconnect */
    gvt_destroy,    /* xDestroy */
    gvt_open,       /* xOpen */
    gvt_close,      /* xClose */
    gvt_filter,     /* xFilter */
    gvt_next,       /* xNext */
    gvt_eof,        /* xEof */
    gvt_column,     /* xColumn */
    gvt_rowid,      /* xRowid */
    nullptr,        /* xUpdate */
    nullptr,        /* xBegin */
    nullptr,        /* xSync */
    nullptr,        /* xCommit */
    nullptr,        /* xRollback */
    nullptr,        /* xFindFunction */
};

}  // namespace

static graph_vtab s_graph_vtab_aux;

int
register_entity_graph_vtab(sqlite3* db,
                           entity_index* eidx,
                           logfile_sub_source* lss)
{
    s_graph_vtab_aux.eidx = eidx;
    s_graph_vtab_aux.lss = lss;
    memset(&s_graph_vtab_aux.base, 0, sizeof(sqlite3_vtab));
    s_graph_vtab_aux.db = db;

    auto rc = sqlite3_create_module(db,
                                    "entity_graph_vtab_impl",
                                    &entity_graph_vtab_module,
                                    &s_graph_vtab_aux);
    if (rc != SQLITE_OK) {
        return rc;
    }

    auto_mem<char, sqlite3_free> errmsg;
    rc = sqlite3_exec(
        db,
        "CREATE VIRTUAL TABLE IF NOT EXISTS lnav_db.lnav_entity_graph "
        "USING entity_graph_vtab_impl()",
        nullptr,
        nullptr,
        errmsg.out());
    if (rc != SQLITE_OK) {
        log_error(
            "unable to create lnav_entity_graph table: %s", errmsg.in());
    }
    return rc;
}
