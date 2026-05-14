/**
 * Copyright (c) 2026, Jeffrey Douglas
 *
 * All rights reserved.
 */

#include "session_trace.hh"

#include <algorithm>
#include <cctype>
#include <utility>

#include "data_scanner.hh"
#include "pcrepp/pcre2pp.hh"

namespace lnav::forensics {

static std::string
extract_first_ip(const std::string& line)
{
    auto sf = string_fragment::from_str(line);
    data_scanner ds(sf);
    while (true) {
        auto tok_res = ds.tokenize2();
        if (!tok_res) {
            break;
        }
        if (tok_res->tr_token == DT_IPV4_ADDRESS
            || tok_res->tr_token == DT_IPV6_ADDRESS)
        {
            return tok_res->to_string();
        }
    }
    return {};
}

static std::string
extract_user(const std::string& line)
{
    static const auto re = lnav::pcre2pp::code::from_const(
        R"USER((?i)(?:invalid user\s+|from user\s+|for user\s+|user=|user\s+|for\s+)(?:"([^"]+)"|([^()\s]+)))USER");
    auto md = re.create_match_data();
    auto inp = string_fragment::from_str(line);
    if (re.capture_from(inp).into(md).matches().ignore_error()) {
        for (size_t lpc = 1; lpc <= 2; ++lpc) {
            auto cap = md[lpc];
            if (cap) {
                return cap->to_string();
            }
        }
    }
    return {};
}

bool
session_line_matches_target(const string_fragment& sf,
                            const std::string& line,
                            const std::string& target)
{
    data_scanner ds(sf);
    while (true) {
        auto tok_res = ds.tokenize2();
        if (!tok_res) {
            break;
        }
        if ((tok_res->tr_token == DT_IPV4_ADDRESS
             || tok_res->tr_token == DT_IPV6_ADDRESS)
            && tok_res->to_string() == target)
        {
            return true;
        }
    }

    auto it = std::search(
        line.begin(),
        line.end(),
        target.begin(),
        target.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a))
                == std::tolower(static_cast<unsigned char>(b));
        });
    return it != line.end();
}

void
collect_session_trace_suggestions(const string_fragment& sf,
                                  const std::string& line,
                                  std::set<std::string>& suggestions)
{
    data_scanner ds(sf);
    while (true) {
        auto tok_res = ds.tokenize2();
        if (!tok_res) {
            break;
        }
        if (tok_res->tr_token == DT_IPV4_ADDRESS
            || tok_res->tr_token == DT_IPV6_ADDRESS)
        {
            suggestions.insert(tok_res->to_string());
        }
    }

    static const auto user_re = lnav::pcre2pp::code::from_const(
        R"USER((?i)(?:invalid user\s+|from user\s+|for user\s+|user=|user\s+|for\s+)(?:"([^"]+)"|([^()\s]+)))USER");
    auto md = user_re.create_match_data();
    auto inp = string_fragment::from_str(line);
    while (user_re.capture_from(inp).into(md).matches().ignore_error()) {
        for (size_t lpc = 1; lpc <= 2; ++lpc) {
            auto cap = md[lpc];
            if (cap) {
                auto u = cap->to_string();
                if (u.size() > 1 && u.size() < 64) {
                    suggestions.insert(u);
                }
                break;
            }
        }
        auto last = md[0];
        if (!last) {
            break;
        }
        inp = inp.substr(last->sf_end - inp.sf_begin);
    }
}

std::vector<session_info>
group_session_trace_lines(const std::vector<session_trace_line>& lines,
                          int64_t session_gap_us)
{
    std::vector<session_info> retval;
    if (lines.empty()) {
        return retval;
    }

    static const auto session_open_re = lnav::pcre2pp::code::from_const(
        R"((?i)(?:session opened|connection from|Accepted |new connection|Connected))");
    static const auto session_close_re = lnav::pcre2pp::code::from_const(
        R"((?i)(?:session closed|Disconnected from|Disconnecting|Connection closed|closed connection|Remove session))");

    session_info current;
    current.start_tv = lines[0].tv;
    current.end_tv = lines[0].tv;
    current.local_offset = lines[0].local_offset;

    for (size_t i = 0; i < lines.size(); ++i) {
        const auto& ml = lines[i];

        if (i > 0) {
            auto delta_us
                = (int64_t(ml.tv.tv_sec) - int64_t(current.end_tv.tv_sec))
                      * 1000000LL
                + (int64_t(ml.tv.tv_usec)
                   - int64_t(current.end_tv.tv_usec));

            auto prev_sf = string_fragment::from_str(lines[i - 1].text);
            bool prev_closed
                = session_close_re.find_in(prev_sf)
                      .ignore_error()
                      .has_value();

            auto cur_sf = string_fragment::from_str(ml.text);
            bool cur_opens
                = session_open_re.find_in(cur_sf).ignore_error().has_value();

            bool new_session
                = (prev_closed && cur_opens) || (delta_us > session_gap_us);

            if (new_session) {
                if (!current.source_ip.empty() || !current.user.empty()
                    || !current.line_indices.empty())
                {
                    retval.push_back(std::move(current));
                }
                current = session_info{};
                current.start_tv = ml.tv;
                current.local_offset = ml.local_offset;
            }
        }

        current.end_tv = ml.tv;
        current.line_indices.push_back(i);

        if (current.source_ip.empty()) {
            auto ip = extract_first_ip(ml.text);
            if (!ip.empty()) {
                current.source_ip = ip;
            }
        }
        if (current.user.empty()) {
            auto user = extract_user(ml.text);
            if (!user.empty()) {
                current.user = user;
            }
        }

        auto cur_sf = string_fragment::from_str(ml.text);
        if (session_close_re.find_in(cur_sf).ignore_error()) {
            current.outcome = "closed";
        }
        if (session_open_re.find_in(cur_sf).ignore_error()) {
            if (current.outcome.empty()) {
                current.outcome = "opened";
            }
        }
    }

    if (!current.line_indices.empty()) {
        retval.push_back(std::move(current));
    }

    return retval;
}

session_summary
summarize_session_trace(const std::vector<session_trace_line>& lines,
                        const std::vector<session_info>& sessions)
{
    session_summary retval;
    if (!lines.empty()) {
        retval.total_span = lines.back().tv.tv_sec - lines.front().tv.tv_sec;
    }

    static const auto auth_accept_re = lnav::pcre2pp::code::from_const(
        R"((?i)(?:Accepted |session opened|authenticated|login successful))");
    static const auto auth_fail_re = lnav::pcre2pp::code::from_const(
        R"((?i)(?:Failed |authentication failure|invalid user|failed password|access denied|login failed|permission denied))");

    for (const auto& ml : lines) {
        retval.all_files.insert(ml.filename);

        if (ml.level == log_level_t::LEVEL_ERROR
            || ml.level == log_level_t::LEVEL_CRITICAL
            || ml.level == log_level_t::LEVEL_FATAL)
        {
            retval.level_error += 1;
        } else if (ml.level == log_level_t::LEVEL_WARNING) {
            retval.level_warning += 1;
        }

        auto line_sf = string_fragment::from_str(ml.text);
        if (auth_accept_re.find_in(line_sf).ignore_error().has_value()) {
            retval.auth_accepted += 1;
        }
        if (auth_fail_re.find_in(line_sf).ignore_error().has_value()) {
            retval.auth_failed += 1;
        }

        data_scanner ds(line_sf);
        while (true) {
            auto tok_res = ds.tokenize2();
            if (!tok_res) {
                break;
            }
            if (tok_res->tr_token == DT_IPV4_ADDRESS
                || tok_res->tr_token == DT_IPV6_ADDRESS)
            {
                retval.all_ips.insert(tok_res->to_string());
            }
        }
    }

    for (size_t si = 0; si < sessions.size(); ++si) {
        const auto& sess = sessions[si];

        if (!sess.source_ip.empty()) {
            retval.all_ips.insert(sess.source_ip);
        }
        if (!sess.user.empty()) {
            retval.all_users.insert(sess.user);
        }

        if (sess.outcome == "closed") {
            retval.outcome_closed += 1;
        } else if (sess.outcome == "opened") {
            retval.outcome_opened += 1;
        } else {
            retval.outcome_unknown += 1;
        }

        auto dur = int64_t(sess.end_tv.tv_sec) - int64_t(sess.start_tv.tv_sec);
        if (dur > retval.longest_duration) {
            retval.longest_duration = dur;
            retval.longest_index = si;
        }
    }

    return retval;
}

}  // namespace lnav::forensics
