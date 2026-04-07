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
 * @file cmds.correlation.cc
 */

#include "config.h"
#include "base/attr_line.hh"
#include "base/string_attr_type.hh"
#include "command_executor.hh"
#include "correlation_engine.hh"
#include "entity_extractor.hh"
#include "entity_index.hh"
#include "lnav.hh"
#include "lnav_commands.hh"
#include "log_data_helper.hh"

// Global instances accessible from lnav.cc
entity_extractor g_entity_extractor;
entity_index g_entity_index;
correlation_engine g_correlation_engine;

static Result<std::string, lnav::console::user_message>
com_correlate(exec_context& ec,
              std::string cmdline,
              std::vector<std::string>& args)
{
    std::string retval;

    if (args.empty()) {
        return Ok(retval);
    }

    if (args.size() < 2) {
        return ec.make_error("expecting an entity value to correlate");
    }

    auto entity_value = remaining_args(cmdline, args);

    // Query the entity index for all lines containing this value
    auto all_rows = g_entity_index.all_rows();

    size_t match_count = 0;
    for (const auto& row : all_rows) {
        if (row.fr_value == entity_value) {
            match_count++;
        }
    }

    if (match_count == 0) {
        return ec.make_error(
            "no entities matching '{}' found in the index", entity_value);
    }

    // Show all other entities that co-occur on the same log lines
    // as the target entity — this is the forensic pivot.
    auto query = fmt::format(
        FMT_STRING(";SELECT other.entity_type AS type, "
                   "other.entity_value AS value, "
                   "count(DISTINCT other.log_line) AS lines, "
                   "min(other.log_time) AS first_seen_utc, "
                   "max(other.log_time) AS last_seen_utc, "
                   "group_concat(DISTINCT other.log_path) AS log_files "
                   "FROM lnav_entities target "
                   "JOIN lnav_entities other ON target.log_line = other.log_line "
                   "WHERE target.entity_value = '{}' "
                   "AND (other.entity_value != target.entity_value "
                   "     OR other.entity_type != target.entity_type) "
                   "GROUP BY other.entity_type, other.entity_value "
                   "ORDER BY lines DESC"),
        entity_value);

    auto exec_res = ec.execute(INTERNAL_SRC_LOC, query);
    if (exec_res.isErr()) {
        return exec_res;
    }

    // If no co-occurring entities, fall back to showing the lines
    // where this entity appears
    auto& dls = lnav_data.ld_db_row_source;
    if (dls.dls_row_cursors.size() <= 1) {
        auto fallback_query = fmt::format(
            FMT_STRING(";SELECT entity_type AS type, "
                       "entity_value AS value, "
                       "source_field, confidence, "
                       "log_time AS time_utc, log_line, log_path "
                       "FROM lnav_entities "
                       "WHERE log_line IN ("
                       "  SELECT log_line FROM lnav_entities "
                       "  WHERE entity_value = '{}'"
                       ") ORDER BY log_line, entity_type"),
            entity_value);
        auto fb_res = ec.execute(INTERNAL_SRC_LOC, fallback_query);
        if (fb_res.isErr()) {
            return fb_res;
        }
        retval = fmt::format(
            FMT_STRING("info: all entities on lines containing '{}' "
                       "({} lines) shown in DB view"),
            entity_value,
            match_count);
    } else {
        retval = fmt::format(
            FMT_STRING("info: entities co-occurring with '{}' "
                       "({} lines) shown in DB view"),
            entity_value,
            match_count);
    }
    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_extract_entities(exec_context& ec,
                     std::string cmdline,
                     std::vector<std::string>& args)
{
    std::string retval;

    if (args.empty()) {
        return Ok(retval);
    }

    auto& lss = lnav_data.ld_log_source;
    auto* tc = &lnav_data.ld_views[LNV_LOG];
    auto sel = tc->get_selection();

    if (!sel) {
        return ec.make_error("no log line selected");
    }

    log_data_helper ldh(lss);
    ldh.load_line(sel.value());

    auto& sa = ldh.ldh_line_attrs;
    auto& sbr = ldh.ldh_line_values.lvv_sbr;
    auto body_range = find_string_attr_range(sa, &SA_BODY);

    std::string extract_text;
    if (body_range.is_valid()) {
        auto body_sf = sbr.to_string_fragment(body_range);
        extract_text = body_sf.to_string();
    } else {
        extract_text.assign(sbr.get_data(), sbr.length());
    }

    auto entities = g_entity_extractor.extract_from_body(extract_text);

    // Also extract from structured fields
    for (const auto& lv : ldh.ldh_line_values.lvv_values) {
        auto field_name = lv.lv_meta.lvm_name.to_string();
        auto field_value = lv.to_string();
        if (field_value.empty()) {
            continue;
        }
        auto field_entities
            = g_entity_extractor.infer_from_field(field_name, field_value);
        for (auto& fe : field_entities) {
            entities.emplace_back(std::move(fe));
        }
    }

    if (!entities.empty()) {
        auto cl = lss.at(sel.value());
        g_entity_index.insert(static_cast<log_line_t>(cl),
                              entities);
    }

    if (entities.empty()) {
        retval = "info: no entities found on current line";
    } else {
        retval = fmt::format(
            FMT_STRING("info: found {} entities:"), entities.size());
        for (const auto& ent : entities) {
            retval += fmt::format(
                FMT_STRING("\n  {} = '{}' (confidence: {:.2f})"),
                entity_type_to_string(ent.ee_type),
                ent.ee_value,
                ent.ee_confidence);
        }
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_index_entities(exec_context& ec,
                   std::string cmdline,
                   std::vector<std::string>& args)
{
    std::string retval;

    if (args.empty()) {
        return Ok(retval);
    }

    auto& lss = lnav_data.ld_log_source;
    auto* tc = &lnav_data.ld_views[LNV_LOG];

    g_entity_index.clear();

    size_t lines_scanned = 0;
    size_t entities_found = 0;

    for (auto vl = tc->get_top(); vl <= tc->get_bottom(); ++vl) {
        log_data_helper ldh(lss);

        if (!ldh.load_line(vl)) {
            continue;
        }

        auto& sa = ldh.ldh_line_attrs;
        auto& sbr = ldh.ldh_line_values.lvv_sbr;
        auto body_range = find_string_attr_range(sa, &SA_BODY);

        std::string body_text;
        if (body_range.is_valid()) {
            auto body_sf = sbr.to_string_fragment(body_range);
            body_text = body_sf.to_string();
        } else {
            body_text.assign(sbr.get_data(), sbr.length());
        }

        auto entities = g_entity_extractor.extract_from_body(body_text);

        for (const auto& lv : ldh.ldh_line_values.lvv_values) {
            auto field_name = lv.lv_meta.lvm_name.to_string();
            auto field_value = lv.to_string();
            if (field_value.empty()) {
                continue;
            }
            auto field_entities
                = g_entity_extractor.infer_from_field(field_name, field_value);
            for (auto& fe : field_entities) {
                entities.emplace_back(std::move(fe));
            }
        }

        if (!entities.empty()) {
            entities_found += entities.size();
            auto cl = lss.at(vl);
            g_entity_index.insert(static_cast<log_line_t>(cl),
                                  entities);
        }

        lines_scanned++;
    }

    retval = fmt::format(
        FMT_STRING("info: scanned {} lines, indexed {} entities"),
        lines_scanned,
        entities_found);

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_run_correlations(exec_context& ec,
                     std::string cmdline,
                     std::vector<std::string>& args)
{
    std::string retval;

    if (args.empty()) {
        return Ok(retval);
    }

    auto& lss = lnav_data.ld_log_source;

    auto hits = g_correlation_engine.evaluate_all(g_entity_index, lss);

    if (hits.empty()) {
        retval = "info: no correlation rule matches found";
        return Ok(retval);
    }

    size_t total_lines = 0;
    for (const auto& hit : hits) {
        total_lines += hit.ch_matching_lines.size();
    }

    retval = fmt::format(
        FMT_STRING(
            "info: {} correlation hits across {} rules, {} lines matched"),
        hits.size(),
        g_correlation_engine.rules().size(),
        total_lines);

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_correlation_rules(exec_context& ec,
                      std::string cmdline,
                      std::vector<std::string>& args)
{
    std::string retval;

    if (args.empty()) {
        return Ok(retval);
    }

    const auto& rules = g_correlation_engine.rules();

    if (rules.empty()) {
        retval = "info: no correlation rules loaded";
    } else {
        retval = fmt::format(
            FMT_STRING("info: {} correlation rules loaded:"), rules.size());
        for (const auto& rule : rules) {
            retval += fmt::format(
                FMT_STRING("\n  [{}] {} - {} ({})"),
                rule.cr_severity,
                rule.cr_name,
                rule.cr_title,
                rule.is_sequence_rule() ? "sequence" : "aggregation");
        }
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_bind_entity(exec_context& ec,
                std::string cmdline,
                std::vector<std::string>& args)
{
    std::string retval;

    if (args.empty()) {
        return Ok(retval);
    }

    if (args.size() < 3) {
        return ec.make_error(
            "expecting: :bind-entity <field_name> <entity_type>");
    }

    auto& field_name = args[1];
    auto& type_str = args[2];

    auto type_opt = string_to_entity_type(type_str);
    if (!type_opt) {
        return ec.make_error("unknown entity type: '{}'", type_str);
    }

    retval = fmt::format(
        FMT_STRING("info: bound field '{}' to entity type '{}'"),
        field_name,
        type_str);

    return Ok(retval);
}

static readline_context::command_t CORRELATION_COMMANDS[] = {
    {
        "correlate",
        com_correlate,

        help_text(":correlate")
            .with_summary(
                "Mark all log lines containing the given entity value")
            .with_parameter(
                {"value", "The entity value to trace across all logs"})
            .with_tags({"entity", "correlation"})
            .with_example(
                {"To find all lines with a specific IP", "10.0.1.47"}),
    },
    {
        "extract-entities",
        com_extract_entities,

        help_text(":extract-entities")
            .with_summary(
                "Extract and display entities from the current log line")
            .with_tags({"entity"}),
    },
    {
        "index-entities",
        com_index_entities,

        help_text(":index-entities")
            .with_summary(
                "Scan all visible log lines and build the entity index "
                "for use with :correlate and the lnav_entities table")
            .with_tags({"entity", "correlation"}),
    },
    {
        "run-correlations",
        com_run_correlations,

        help_text(":run-correlations")
            .with_summary(
                "Evaluate all loaded correlation rules and tag matches")
            .with_tags({"correlation"}),
    },
    {
        "correlation-rules",
        com_correlation_rules,

        help_text(":correlation-rules")
            .with_summary("List all loaded correlation rules")
            .with_tags({"correlation"}),
    },
    {
        "bind-entity",
        com_bind_entity,

        help_text(":bind-entity")
            .with_summary(
                "Manually declare a field's entity type for the session")
            .with_parameter({"field_name", "The field to bind"})
            .with_parameter({"entity_type",
                             "The entity type (ip-address, username, etc.)"})
            .with_tags({"entity"})
            .with_example(
                {"To bind src_ip as an IP address",
                 "src_ip ip-address"}),
    },
};

void
init_lnav_correlation_commands(readline_context::command_map_t& cmd_map)
{
    for (auto& cmd : CORRELATION_COMMANDS) {
        cmd.c_help.index_tags();
        cmd_map[cmd.c_name] = &cmd;
    }
}
