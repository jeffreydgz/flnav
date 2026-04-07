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
 * @file correlation_rule.cc
 */

#include "correlation_rule.hh"

#include <filesystem>
#include <fstream>
#include <sstream>

#include "base/lnav_log.hh"
#include "config.h"
#include "yajlpp/yajlpp.hh"
#include "yajlpp/yajlpp_def.hh"

std::optional<int64_t>
parse_duration_ms(const std::string& s)
{
    if (s.empty()) {
        return std::nullopt;
    }

    size_t pos = 0;
    int64_t value = 0;

    while (pos < s.size() && std::isdigit(s[pos])) {
        value = value * 10 + (s[pos] - '0');
        pos++;
    }

    if (pos == 0) {
        return std::nullopt;
    }

    std::string unit = s.substr(pos);
    if (unit == "ms") {
        return value;
    }
    if (unit == "s" || unit.empty()) {
        return value * 1000;
    }
    if (unit == "m") {
        return value * 60 * 1000;
    }
    if (unit == "h") {
        return value * 3600 * 1000;
    }
    if (unit == "d") {
        return value * 86400 * 1000;
    }

    return std::nullopt;
}

/**
 * Parse the correlation rules JSON using yajl directly.
 * The format is:
 * {
 *   "correlation_rules": {
 *     "rule_name": { ... },
 *     ...
 *   }
 * }
 */

// Helper to extract a string from a yajl tree node
static std::string
yajl_tree_get_string(yajl_val node, const char* key)
{
    const char* path[] = {key, nullptr};
    auto* val = yajl_tree_get(node, path, yajl_t_string);
    if (val != nullptr) {
        return YAJL_GET_STRING(val);
    }
    return {};
}

static int64_t
yajl_tree_get_int(yajl_val node, const char* key, int64_t dflt = 0)
{
    const char* path[] = {key, nullptr};
    auto* val = yajl_tree_get(node, path, yajl_t_number);
    if (val != nullptr && YAJL_IS_INTEGER(val)) {
        return YAJL_GET_INTEGER(val);
    }
    return dflt;
}

static std::vector<std::string>
yajl_tree_get_string_array(yajl_val node, const char* key)
{
    std::vector<std::string> result;
    const char* path[] = {key, nullptr};
    auto* arr = yajl_tree_get(node, path, yajl_t_array);
    if (arr != nullptr && YAJL_IS_ARRAY(arr)) {
        for (size_t i = 0; i < YAJL_GET_ARRAY(arr)->len; i++) {
            auto* elem = YAJL_GET_ARRAY(arr)->values[i];
            if (YAJL_IS_STRING(elem)) {
                result.emplace_back(YAJL_GET_STRING(elem));
            }
        }
    }
    return result;
}

static std::optional<correlation_step>
parse_step(yajl_val step_node)
{
    if (!YAJL_IS_OBJECT(step_node)) {
        return std::nullopt;
    }

    correlation_step step;
    step.cs_id = yajl_tree_get_string(step_node, "id");
    step.cs_log_levels = yajl_tree_get_string_array(step_node, "log_level");

    // Parse match object
    const char* match_path[] = {"match", nullptr};
    auto* match_node = yajl_tree_get(step_node, match_path, yajl_t_object);
    if (match_node != nullptr) {
        step.cs_log_levels
            = yajl_tree_get_string_array(match_node, "log_level");
        step.cs_body_pattern
            = yajl_tree_get_string(match_node, "body_pattern");

        // Parse entity_bind
        const char* bind_path[] = {"entity_bind", nullptr};
        auto* bind_node
            = yajl_tree_get(match_node, bind_path, yajl_t_object);
        if (bind_node != nullptr && YAJL_IS_OBJECT(bind_node)) {
            auto* obj = YAJL_GET_OBJECT(bind_node);
            for (size_t i = 0; i < obj->len; i++) {
                auto* val = obj->values[i];
                if (YAJL_IS_STRING(val)) {
                    step.cs_entity_bindings[obj->keys[i]]
                        = YAJL_GET_STRING(val);
                }
            }
        }
    }

    // Compile pattern
    if (!step.cs_body_pattern.empty()) {
        auto compile_res = lnav::pcre2pp::code::from(
            string_fragment::from_str(step.cs_body_pattern));
        if (compile_res.isOk()) {
            step.cs_compiled_pattern
                = std::make_shared<lnav::pcre2pp::code>(
                    std::move(compile_res.unwrap()));
        }
    }

    // Parse count
    const char* count_path[] = {"count", nullptr};
    auto* count_node = yajl_tree_get(step_node, count_path, yajl_t_object);
    if (count_node != nullptr) {
        step.cs_count_min
            = static_cast<int>(yajl_tree_get_int(count_node, "min", 1));
        auto max_val = yajl_tree_get_int(count_node, "max", -1);
        if (max_val >= 0) {
            step.cs_count_max = static_cast<int>(max_val);
        }
    }

    // Parse window
    auto window_str = yajl_tree_get_string(step_node, "window");
    if (!window_str.empty()) {
        step.cs_window_ms = parse_duration_ms(window_str);
    }

    auto within_str = yajl_tree_get_string(step_node, "within_after");
    if (!within_str.empty()) {
        step.cs_within_after_ms = parse_duration_ms(within_str);
    }

    return step;
}

static std::optional<aggregation_rule>
parse_aggregation(yajl_val agg_node)
{
    if (!YAJL_IS_OBJECT(agg_node)) {
        return std::nullopt;
    }

    aggregation_rule ar;
    ar.ar_group_by_entity
        = yajl_tree_get_string(agg_node, "group_by_entity");
    ar.ar_count_distinct_entity
        = yajl_tree_get_string(agg_node, "count_distinct_entity");

    const char* thresh_path[] = {"threshold", nullptr};
    auto* thresh_node
        = yajl_tree_get(agg_node, thresh_path, yajl_t_object);
    if (thresh_node != nullptr) {
        ar.ar_threshold_min
            = static_cast<int>(yajl_tree_get_int(thresh_node, "min", 1));
        auto max_val = yajl_tree_get_int(thresh_node, "max", -1);
        if (max_val >= 0) {
            ar.ar_threshold_max = static_cast<int>(max_val);
        }
    }

    auto window_str = yajl_tree_get_string(agg_node, "window");
    if (!window_str.empty()) {
        auto ms = parse_duration_ms(window_str);
        if (ms) {
            ar.ar_window_ms = *ms;
        }
    }

    return ar;
}

static std::optional<correlation_rule>
parse_single_rule(const std::string& name, yajl_val rule_node)
{
    if (!YAJL_IS_OBJECT(rule_node)) {
        return std::nullopt;
    }

    correlation_rule rule;
    rule.cr_name = name;
    rule.cr_title = yajl_tree_get_string(rule_node, "title");
    rule.cr_description = yajl_tree_get_string(rule_node, "description");
    rule.cr_severity = yajl_tree_get_string(rule_node, "severity");
    rule.cr_mitre_attack
        = yajl_tree_get_string_array(rule_node, "mitre_attack");
    rule.cr_tags = yajl_tree_get_string_array(rule_node, "tags");

    // Parse sequence
    const char* seq_path[] = {"sequence", nullptr};
    auto* seq_node = yajl_tree_get(rule_node, seq_path, yajl_t_array);
    if (seq_node != nullptr && YAJL_IS_ARRAY(seq_node)) {
        for (size_t i = 0; i < YAJL_GET_ARRAY(seq_node)->len; i++) {
            auto step = parse_step(YAJL_GET_ARRAY(seq_node)->values[i]);
            if (step) {
                rule.cr_sequence.emplace_back(std::move(*step));
            }
        }
    }

    // Parse aggregation
    const char* agg_path[] = {"aggregation", nullptr};
    auto* agg_node = yajl_tree_get(rule_node, agg_path, yajl_t_object);
    if (agg_node != nullptr) {
        rule.cr_aggregation = parse_aggregation(agg_node);
    }

    // Parse output
    const char* out_path[] = {"output", nullptr};
    auto* out_node = yajl_tree_get(rule_node, out_path, yajl_t_object);
    if (out_node != nullptr) {
        rule.cr_output.tag = yajl_tree_get_string(out_node, "tag");
        rule.cr_output.comment_template
            = yajl_tree_get_string(out_node, "comment_template");
    }

    return rule;
}

Result<std::vector<correlation_rule>,
       std::vector<lnav::console::user_message>>
load_correlation_rules_from_file(const std::string& path)
{
    std::vector<correlation_rule> rules;
    std::vector<lnav::console::user_message> errors;

    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        errors.emplace_back(
            lnav::console::user_message::error(
                attr_line_t("unable to open correlation rules file: ")
                    .append(path))
                .move());
        return Err(std::move(errors));
    }

    std::stringstream ss;
    ss << ifs.rdbuf();
    std::string json_str = ss.str();

    char errbuf[1024];
    auto* root = yajl_tree_parse(
        json_str.c_str(), errbuf, sizeof(errbuf));
    if (root == nullptr) {
        errors.emplace_back(
            lnav::console::user_message::error(
                attr_line_t("JSON parse error in ").append(path))
                .with_reason(errbuf)
                .move());
        return Err(std::move(errors));
    }

    // Navigate to correlation_rules object
    const char* rules_path[] = {"correlation_rules", nullptr};
    auto* rules_node = yajl_tree_get(root, rules_path, yajl_t_object);
    if (rules_node != nullptr && YAJL_IS_OBJECT(rules_node)) {
        auto* obj = YAJL_GET_OBJECT(rules_node);
        for (size_t i = 0; i < obj->len; i++) {
            auto rule = parse_single_rule(obj->keys[i], obj->values[i]);
            if (rule) {
                rules.emplace_back(std::move(*rule));
            }
        }
    }

    yajl_tree_free(root);

    return Ok(std::move(rules));
}

Result<std::vector<correlation_rule>,
       std::vector<lnav::console::user_message>>
load_correlation_rules_from_dir(const std::string& dir_path)
{
    std::vector<correlation_rule> all_rules;
    std::vector<lnav::console::user_message> all_errors;

    namespace fs = std::filesystem;

    if (!fs::exists(dir_path) || !fs::is_directory(dir_path)) {
        return Ok(std::move(all_rules));
    }

    for (const auto& entry : fs::directory_iterator(dir_path)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        auto ext = entry.path().extension().string();
        if (ext != ".json") {
            continue;
        }

        auto result
            = load_correlation_rules_from_file(entry.path().string());
        if (result.isOk()) {
            auto rules = result.unwrap();
            for (auto& rule : rules) {
                all_rules.emplace_back(std::move(rule));
            }
        } else {
            auto errs = result.unwrapErr();
            for (auto& err : errs) {
                all_errors.emplace_back(std::move(err));
            }
        }
    }

    if (!all_errors.empty() && all_rules.empty()) {
        return Err(std::move(all_errors));
    }

    return Ok(std::move(all_rules));
}
