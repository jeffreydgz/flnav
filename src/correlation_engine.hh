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
 * @file correlation_engine.hh
 */

#ifndef lnav_correlation_engine_hh
#define lnav_correlation_engine_hh

#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

#include "correlation_rule.hh"
#include "entity_index.hh"
#include "logfile_sub_source.hh"

/**
 * Evaluates multi-step and aggregation correlation rules against the
 * entity index and log data.
 */
class correlation_engine {
public:
    /** Load rules from a directory of JSON files. */
    void load_rules(const std::filesystem::path& rules_dir);

    /** Load a single rule file. */
    void load_rule_file(const std::filesystem::path& file);

    /** Full evaluation against all indexed data. */
    std::vector<correlation_hit> evaluate_all(
        const entity_index& eidx,
        logfile_sub_source& lss);

    /** Get all loaded rules. */
    const std::vector<correlation_rule>& rules() const;

    /** Get last evaluation errors. */
    const std::vector<std::string>& last_errors() const;

    /** Clear all rules and state. */
    void clear();

private:
    std::vector<correlation_rule> m_rules;
    std::vector<std::string> m_errors;

    /** Evaluate a sequence-based rule. */
    std::vector<correlation_hit> eval_sequence_rule(
        const correlation_rule& rule,
        const entity_index& eidx,
        logfile_sub_source& lss);

    /** Evaluate an aggregation-based rule. */
    std::vector<correlation_hit> eval_aggregation_rule(
        const correlation_rule& rule,
        const entity_index& eidx,
        logfile_sub_source& lss);

    /** Interpolate variables into a comment template. */
    static std::string render_comment(
        const std::string& tmpl,
        const std::unordered_map<std::string, std::string>& vars);

    /** Get timestamp in milliseconds for a log line. */
    static int64_t line_time_ms(logfile_sub_source& lss, log_line_t line);

    /** Get the log body text for a line. */
    static std::string line_body(logfile_sub_source& lss, log_line_t line);

    /** Get the log level string for a line. */
    static std::string line_level(logfile_sub_source& lss, log_line_t line);
};

#endif
