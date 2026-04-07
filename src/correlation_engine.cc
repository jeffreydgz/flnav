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
 * @file correlation_engine.cc
 */

#include "correlation_engine.hh"

#include <algorithm>
#include <set>
#include <unordered_set>

#include "base/lnav_log.hh"
#include "config.h"

void
correlation_engine::load_rules(const std::filesystem::path& rules_dir)
{
    auto result = load_correlation_rules_from_dir(rules_dir.string());
    if (result.isOk()) {
        auto rules = result.unwrap();
        for (auto& rule : rules) {
            this->m_rules.emplace_back(std::move(rule));
        }
    } else {
        auto errs = result.unwrapErr();
        for (auto& err : errs) {
            this->m_errors.emplace_back(err.to_attr_line().get_string());
        }
    }
}

void
correlation_engine::load_rule_file(const std::filesystem::path& file)
{
    auto result = load_correlation_rules_from_file(file.string());
    if (result.isOk()) {
        auto rules = result.unwrap();
        for (auto& rule : rules) {
            this->m_rules.emplace_back(std::move(rule));
        }
    } else {
        auto errs = result.unwrapErr();
        for (auto& err : errs) {
            this->m_errors.emplace_back(err.to_attr_line().get_string());
        }
    }
}

const std::vector<correlation_rule>&
correlation_engine::rules() const
{
    return this->m_rules;
}

const std::vector<std::string>&
correlation_engine::last_errors() const
{
    return this->m_errors;
}

void
correlation_engine::clear()
{
    this->m_rules.clear();
    this->m_errors.clear();
}

std::vector<correlation_hit>
correlation_engine::evaluate_all(const entity_index& eidx,
                                 logfile_sub_source& lss)
{
    std::vector<correlation_hit> all_hits;

    for (const auto& rule : this->m_rules) {
        std::vector<correlation_hit> hits;
        if (rule.is_sequence_rule()) {
            hits = this->eval_sequence_rule(rule, eidx, lss);
        } else if (rule.is_aggregation_rule()) {
            hits = this->eval_aggregation_rule(rule, eidx, lss);
        }
        for (auto& hit : hits) {
            all_hits.emplace_back(std::move(hit));
        }
    }

    return all_hits;
}

int64_t
correlation_engine::line_time_ms(logfile_sub_source& lss, log_line_t line)
{
    auto cl = content_line_t(line);
    uint64_t line_number;
    auto ld = lss.find_data(cl, line_number);
    auto* lf = (*ld)->get_file_ptr();
    if (lf != nullptr) {
        auto ll = lf->begin() + line_number;
        auto tv = ll->get_timeval();
        return tv.tv_sec * 1000LL + tv.tv_usec / 1000LL;
    }
    return 0;
}

std::string
correlation_engine::line_body(logfile_sub_source& lss, log_line_t line)
{
    std::string value_out;
    auto cl = content_line_t(line);
    uint64_t line_number;
    auto ld = lss.find_data(cl, line_number);
    auto* lf = (*ld)->get_file_ptr();
    if (lf != nullptr) {
        auto ll = lf->begin() + line_number;
        shared_buffer_ref sbr;
        lf->read_full_message(ll, sbr);
        value_out.assign(sbr.get_data(), sbr.length());
    }
    return value_out;
}

std::string
correlation_engine::line_level(logfile_sub_source& lss, log_line_t line)
{
    auto cl = content_line_t(line);
    uint64_t line_number;
    auto ld = lss.find_data(cl, line_number);
    auto* lf = (*ld)->get_file_ptr();
    if (lf != nullptr) {
        auto ll = lf->begin() + line_number;
        return level_names[ll->get_msg_level()].to_string();
    }
    return "unknown";
}

std::string
correlation_engine::render_comment(
    const std::string& tmpl,
    const std::unordered_map<std::string, std::string>& vars)
{
    std::string result = tmpl;

    for (const auto& [var_name, var_value] : vars) {
        // Replace {$var} and {var} patterns
        std::string pattern1 = "{" + var_name + "}";
        std::string pattern2 = "{$" + var_name.substr(1) + "}";

        size_t pos;
        while ((pos = result.find(pattern1)) != std::string::npos) {
            result.replace(pos, pattern1.size(), var_value);
        }
        if (var_name[0] == '$') {
            while ((pos = result.find(pattern2)) != std::string::npos) {
                result.replace(pos, pattern2.size(), var_value);
            }
        }
    }

    return result;
}

/**
 * Sequence rule evaluation:
 *
 * 1. For each line in chronological order, extract entities
 * 2. For step[0], when body pattern matches and entity bindings are satisfied,
 *    start tracking a new sequence state
 * 3. For subsequent steps, check if the body pattern matches and entity
 *    bindings match the previously bound values
 * 4. Track count thresholds and time windows
 * 5. When final step matches, emit a correlation_hit
 */
std::vector<correlation_hit>
correlation_engine::eval_sequence_rule(const correlation_rule& rule,
                                       const entity_index& eidx,
                                       logfile_sub_source& lss)
{
    std::vector<correlation_hit> hits;

    if (rule.cr_sequence.empty()) {
        return hits;
    }

    // Get all indexed lines sorted by line number (chronological)
    auto all_rows = eidx.all_rows();
    if (all_rows.empty()) {
        return hits;
    }

    // Collect unique lines
    std::vector<log_line_t> all_lines;
    {
        std::set<log_line_t> line_set;
        for (const auto& row : all_rows) {
            line_set.insert(row.fr_line);
        }
        all_lines.assign(line_set.begin(), line_set.end());
    }

    // State machines keyed by serialized binding set
    struct seq_state {
        int current_step{0};
        int match_count{0};
        int64_t window_start_ms{0};
        std::unordered_map<std::string, std::string> bindings;
        std::vector<log_line_t> matched_lines;
    };

    // Key: serialized bindings for step 0
    std::unordered_map<std::string, seq_state> active;

    for (auto line : all_lines) {
        auto body = this->line_body(lss, line);
        auto level = this->line_level(lss, line);
        auto time_ms = this->line_time_ms(lss, line);
        auto line_entities = eidx.entities_for_line(line);

        // Check against each active sequence state
        std::vector<std::string> completed_keys;

        for (auto& [key, state] : active) {
            auto& step = rule.cr_sequence[state.current_step];

            // Check time window
            if (step.cs_window_ms && state.match_count > 0) {
                if (time_ms - state.window_start_ms > *step.cs_window_ms) {
                    // Window expired, reset
                    state.current_step = 0;
                    state.match_count = 0;
                    state.matched_lines.clear();
                    continue;
                }
            }

            if (step.cs_within_after_ms) {
                if (time_ms - state.window_start_ms
                    > *step.cs_within_after_ms)
                {
                    state.current_step = 0;
                    state.match_count = 0;
                    state.matched_lines.clear();
                    continue;
                }
            }

            // Check log level filter
            if (!step.cs_log_levels.empty()) {
                bool level_match = false;
                for (const auto& l : step.cs_log_levels) {
                    if (l == level) {
                        level_match = true;
                        break;
                    }
                }
                if (!level_match) {
                    continue;
                }
            }

            // Check body pattern
            if (step.cs_compiled_pattern) {
                auto sf = string_fragment::from_str(body);
                auto match_res = step.cs_compiled_pattern->find_in(sf);
                if (!match_res.is<lnav::pcre2pp::matcher::found>()) {
                    continue;
                }
            }

            // Check entity bindings
            bool bindings_match = true;
            for (const auto& [etype_str, var_name] : step.cs_entity_bindings)
            {
                auto etype = string_to_entity_type(etype_str);
                if (!etype) {
                    continue;
                }

                bool found = false;
                for (const auto& ref : line_entities) {
                    if (ref.er_type != *etype) {
                        continue;
                    }

                    auto it = state.bindings.find(var_name);
                    if (it != state.bindings.end()) {
                        // Must match previously bound value
                        if (it->second == ref.er_value) {
                            found = true;
                            break;
                        }
                    } else {
                        // New binding
                        state.bindings[var_name] = ref.er_value;
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    bindings_match = false;
                    break;
                }
            }

            if (!bindings_match) {
                continue;
            }

            // Match! Increment count
            state.match_count++;
            state.matched_lines.push_back(line);
            if (state.match_count == 1) {
                state.window_start_ms = time_ms;
            }

            // Check if count threshold is met
            if (state.match_count >= step.cs_count_min) {
                if (!step.cs_count_max
                    || state.match_count <= *step.cs_count_max)
                {
                    // Advance to next step
                    state.current_step++;
                    state.match_count = 0;
                    state.window_start_ms = time_ms;

                    // Check if all steps completed
                    if (state.current_step
                        >= static_cast<int>(rule.cr_sequence.size()))
                    {
                        correlation_hit hit;
                        hit.ch_rule = &rule;
                        hit.ch_matching_lines = state.matched_lines;
                        hit.ch_bound_variables = state.bindings;
                        hit.ch_first_time_ms = this->line_time_ms(
                            lss, state.matched_lines.front());
                        hit.ch_last_time_ms = time_ms;
                        hit.ch_rendered_comment = render_comment(
                            rule.cr_output.comment_template,
                            state.bindings);
                        hits.emplace_back(std::move(hit));
                        completed_keys.push_back(key);
                    }
                }
            }
        }

        // Remove completed sequences
        for (const auto& k : completed_keys) {
            active.erase(k);
        }

        // Check if this line starts a new sequence (step 0)
        auto& step0 = rule.cr_sequence[0];

        // Check log level
        bool level_ok = step0.cs_log_levels.empty();
        if (!level_ok) {
            for (const auto& l : step0.cs_log_levels) {
                if (l == level) {
                    level_ok = true;
                    break;
                }
            }
        }

        if (!level_ok) {
            continue;
        }

        // Check body pattern
        if (step0.cs_compiled_pattern) {
            auto sf = string_fragment::from_str(body);
            auto match_res = step0.cs_compiled_pattern->find_in(sf);
            if (!match_res.is<lnav::pcre2pp::matcher::found>()) {
                continue;
            }
        }

        // Extract entity bindings for step 0
        for (const auto& [etype_str, var_name] : step0.cs_entity_bindings) {
            auto etype = string_to_entity_type(etype_str);
            if (!etype) {
                continue;
            }

            for (const auto& ref : line_entities) {
                if (ref.er_type != *etype) {
                    continue;
                }

                // Create a key from the binding
                std::string state_key
                    = rule.cr_name + ":" + var_name + "=" + ref.er_value;

                if (active.find(state_key) != active.end()) {
                    // Already tracking this entity
                    continue;
                }

                seq_state state;
                state.current_step = 0;
                state.match_count = 1;
                state.window_start_ms = time_ms;
                state.bindings[var_name] = ref.er_value;
                state.matched_lines.push_back(line);

                // Check if step 0 count threshold is already met
                if (state.match_count >= step0.cs_count_min) {
                    state.current_step = 1;
                    state.match_count = 0;

                    if (state.current_step
                        >= static_cast<int>(rule.cr_sequence.size()))
                    {
                        // Single-step rule completed
                        correlation_hit hit;
                        hit.ch_rule = &rule;
                        hit.ch_matching_lines = state.matched_lines;
                        hit.ch_bound_variables = state.bindings;
                        hit.ch_first_time_ms = time_ms;
                        hit.ch_last_time_ms = time_ms;
                        hit.ch_rendered_comment = render_comment(
                            rule.cr_output.comment_template,
                            state.bindings);
                        hits.emplace_back(std::move(hit));
                        continue;
                    }
                }

                active[state_key] = std::move(state);
            }
        }
    }

    return hits;
}

/**
 * Aggregation rule evaluation:
 *
 * 1. Query entity index for all entities of group_by_entity type
 * 2. For each unique value, count distinct co-occurring entities of
 *    count_distinct_entity type
 * 3. If count >= threshold, emit hit
 */
std::vector<correlation_hit>
correlation_engine::eval_aggregation_rule(const correlation_rule& rule,
                                          const entity_index& eidx,
                                          logfile_sub_source& lss)
{
    std::vector<correlation_hit> hits;

    if (!rule.cr_aggregation) {
        return hits;
    }

    const auto& agg = *rule.cr_aggregation;
    auto group_type = string_to_entity_type(agg.ar_group_by_entity);
    auto count_type = string_to_entity_type(agg.ar_count_distinct_entity);

    if (!group_type || !count_type) {
        return hits;
    }

    // Get all entities grouped by the group_by type
    auto all_rows = eidx.all_rows();

    // Collect unique group-by entity values
    std::set<std::string> group_values;
    for (const auto& row : all_rows) {
        if (row.fr_type == *group_type) {
            group_values.insert(row.fr_value);
        }
    }

    for (const auto& group_val : group_values) {
        auto co_entities = eidx.co_occurring_entities(
            *group_type, group_val, count_type);

        // Count distinct values within the time window
        std::set<std::string> distinct_values;
        for (const auto& co : co_entities) {
            distinct_values.insert(co.co_value);
        }

        int distinct_count = static_cast<int>(distinct_values.size());

        if (distinct_count >= agg.ar_threshold_min) {
            if (agg.ar_threshold_max
                && distinct_count > *agg.ar_threshold_max)
            {
                continue;
            }

            // Collect all matching lines
            auto group_lines
                = eidx.lines_for_entity(*group_type, group_val);

            correlation_hit hit;
            hit.ch_rule = &rule;
            hit.ch_matching_lines.assign(
                group_lines.begin(), group_lines.end());

            std::unordered_map<std::string, std::string> vars;
            vars["$" + agg.ar_group_by_entity] = group_val;
            vars["distinct_" + agg.ar_count_distinct_entity + "_count"]
                = std::to_string(distinct_count);
            vars["window"] = std::to_string(agg.ar_window_ms / 1000) + "s";

            hit.ch_bound_variables = vars;

            if (!group_lines.empty()) {
                hit.ch_first_time_ms
                    = this->line_time_ms(lss, group_lines.front());
                hit.ch_last_time_ms
                    = this->line_time_ms(lss, group_lines.back());
            }

            hit.ch_rendered_comment
                = render_comment(rule.cr_output.comment_template, vars);

            hits.emplace_back(std::move(hit));
        }
    }

    return hits;
}
