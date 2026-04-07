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
 * @file correlation_rule.hh
 */

#ifndef lnav_correlation_rule_hh
#define lnav_correlation_rule_hh

#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "base/intern_string.hh"
#include "base/lnav.console.hh"
#include "base/result.h"
#include "pcrepp/pcre2pp.hh"

/** A single step in a sequence-based correlation rule. */
struct correlation_step {
    std::string cs_id;
    std::vector<std::string> cs_log_levels;
    std::string cs_body_pattern;
    std::shared_ptr<lnav::pcre2pp::code> cs_compiled_pattern;
    /** Maps entity_type string -> "$variable" name for binding. */
    std::unordered_map<std::string, std::string> cs_entity_bindings;
    int cs_count_min{1};
    std::optional<int> cs_count_max;
    std::optional<int64_t> cs_window_ms;
    std::optional<int64_t> cs_within_after_ms;
};

/** An aggregation-based correlation rule definition. */
struct aggregation_rule {
    std::string ar_group_by_entity;
    std::string ar_count_distinct_entity;
    int ar_threshold_min{1};
    std::optional<int> ar_threshold_max;
    int64_t ar_window_ms{3600000};  // 1 hour default
};

/** A complete correlation rule loaded from JSON. */
struct correlation_rule {
    std::string cr_name;
    std::string cr_title;
    std::string cr_description;
    std::string cr_severity;
    std::vector<std::string> cr_mitre_attack;
    std::vector<std::string> cr_tags;

    /** Sequence-based detection (ordered multi-step). */
    std::vector<correlation_step> cr_sequence;

    /** Aggregation-based detection (count distinct). */
    std::optional<aggregation_rule> cr_aggregation;

    struct {
        std::string tag;
        std::string comment_template;
    } cr_output;

    bool is_sequence_rule() const { return !this->cr_sequence.empty(); }
    bool is_aggregation_rule() const
    {
        return this->cr_aggregation.has_value();
    }
};

/** A correlation hit produced by rule evaluation. */
struct correlation_hit {
    const correlation_rule* ch_rule{nullptr};
    std::vector<int64_t> ch_matching_lines;
    std::unordered_map<std::string, std::string> ch_bound_variables;
    int64_t ch_first_time_ms{0};
    int64_t ch_last_time_ms{0};
    std::string ch_rendered_comment;
};

/**
 * Parse duration strings like "300s", "5m", "1h" into milliseconds.
 */
std::optional<int64_t> parse_duration_ms(const std::string& s);

/**
 * Load correlation rules from a JSON file.
 *
 * @return vector of parsed rules, or error messages.
 */
Result<std::vector<correlation_rule>,
       std::vector<lnav::console::user_message>>
load_correlation_rules_from_file(const std::string& path);

/**
 * Load all .json rule files from a directory.
 */
Result<std::vector<correlation_rule>,
       std::vector<lnav::console::user_message>>
load_correlation_rules_from_dir(const std::string& dir_path);

#endif
