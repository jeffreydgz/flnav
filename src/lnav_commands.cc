/**
 * Copyright (c) 2007-2022, Timothy Stack
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

#include <fstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "lnav.hh"

#include <fnmatch.h>
#include <sys/stat.h>
#include <termios.h>

#include "base/attr_line.builder.hh"
#include "base/auto_mem.hh"
#include "base/fs_util.hh"
#include "base/humanize.hh"
#include "base/humanize.network.hh"
#include "base/injector.hh"
#include "base/isc.hh"
#include "base/itertools.hh"
#include "base/paths.hh"
#include "base/relative_time.hh"
#include "base/string_util.hh"
#include "bound_tags.hh"
#include "breadcrumb_curses.hh"
#include "CLI/App.hpp"
#include "cmd.parser.hh"
#include "command_executor.hh"
#include "config.h"
#include "curl_looper.hh"
#include "date/tz.h"
#include "data_scanner.hh"
#include "db_sub_source.hh"
#include "field_overlay_source.hh"
#include "hasher.hh"
#include "itertools.similar.hh"
#include "lnav.indexing.hh"
#include "lnav.prompt.hh"
#include "lnav_commands.hh"
#include "lnav_config.hh"
#include "lnav_util.hh"
#include "log.annotate.hh"
#include "log_data_helper.hh"
#include "log_data_table.hh"
#include "log_format_loader.hh"
#include "log_search_table.hh"
#include "log_search_table_fwd.hh"
#include "md4cpp.hh"
#include "ptimec.hh"
#include "readline_callbacks.hh"
#include "readline_highlighters.hh"
#include "scn/scan.h"
#include "service_tags.hh"
#include "session_data.hh"
#include "shlex.hh"
#include "spectro_impls.hh"
#include "sql_util.hh"
#include "sqlite-extension-func.hh"
#include "url_loader.hh"
#include "vtab_module.hh"
#include "yajl/api/yajl_parse.h"
#include "yajlpp/json_op.hh"
#include "yajlpp/yajlpp.hh"

#ifdef HAVE_RUST_DEPS
#    include "lnav_rs_ext.cxx.hh"
#endif

using namespace std::literals::chrono_literals;
using namespace lnav::roles::literals;

constexpr std::chrono::microseconds ZOOM_LEVELS[] = {
    1s,
    30s,
    60s,
    5min,
    15min,
    1h,
    4h,
    8h,
    24h,
    7 * 24h,
    30 * 24h,
    365 * 24h,
};

constexpr std::array<string_fragment, ZOOM_COUNT> lnav_zoom_strings = {
    "1-second"_frag,
    "30-second"_frag,
    "1-minute"_frag,
    "5-minute"_frag,
    "15-minute"_frag,
    "1-hour"_frag,
    "4-hour"_frag,
    "8-hour"_frag,
    "1-day"_frag,
    "1-week"_frag,
    "1-month"_frag,
    "1-year"_frag,
};

inline attr_line_t&
symbol_reducer(const std::string& elem, attr_line_t& accum)
{
    return accum.append("\n   ").append(lnav::roles::symbol(elem));
}

std::string
remaining_args(const std::string& cmdline,
               const std::vector<std::string>& args,
               size_t index)
{
    size_t start_pos = 0;

    require(index > 0);

    if (index >= args.size()) {
        return "";
    }
    for (size_t lpc = 0; lpc < index; lpc++) {
        start_pos += args[lpc].length();
    }

    size_t index_in_cmdline = cmdline.find(args[index], start_pos);

    require(index_in_cmdline != std::string::npos);

    auto retval = cmdline.substr(index_in_cmdline);
    while (!retval.empty() && retval.back() == ' ') {
        retval.pop_back();
    }

    return retval;
}

string_fragment
remaining_args_frag(const std::string& cmdline,
                    const std::vector<std::string>& args,
                    size_t index)
{
    size_t start_pos = 0;

    require(index > 0);

    if (index >= args.size()) {
        return string_fragment{};
    }
    for (size_t lpc = 0; lpc < index; lpc++) {
        start_pos += args[lpc].length();
    }

    size_t index_in_cmdline = cmdline.find(args[index], start_pos);

    require(index_in_cmdline != std::string::npos);

    return string_fragment::from_str_range(
        cmdline, index_in_cmdline, cmdline.size());
}

std::optional<std::string>
find_arg(std::vector<std::string>& args, const std::string& flag)
{
    auto iter = find_if(args.begin(), args.end(), [&flag](const auto elem) {
        return startswith(elem, flag);
    });

    if (iter == args.end()) {
        return std::nullopt;
    }

    auto index = iter->find('=');
    if (index == std::string::npos) {
        return "";
    }

    auto retval = iter->substr(index + 1);

    args.erase(iter);

    return retval;
}

bookmark_vector<vis_line_t>
combined_user_marks(vis_bookmarks& vb)
{
    const auto& bv = vb[&textview_curses::BM_USER];
    const auto& bv_expr = vb[&textview_curses::BM_USER_EXPR];
    bookmark_vector<vis_line_t> retval;

    for (const auto& row : bv.bv_tree) {
        retval.insert_once(row);
    }
    for (const auto& row : bv_expr.bv_tree) {
        retval.insert_once(row);
    }
    return retval;
}

static Result<std::string, lnav::console::user_message>
com_write_debug_log_to(exec_context& ec,
                       std::string cmdline,
                       std::vector<std::string>& args)
{
    if (args.size() < 2) {
        return ec.make_error("expecting a file path");
    }

    if (lnav_log_file.has_value()) {
        return ec.make_error("debug log is already being written to a file");
    }

    std::string retval;
    if (ec.ec_dry_run) {
        return Ok(retval);
    }

    auto fp = fopen(args[1].c_str(), "we");
    if (fp == nullptr) {
        auto um = lnav::console::user_message::error(
                      attr_line_t("unable to open file for write: ")
                          .append(lnav::roles::file(args[1])))
                      .with_errno_reason();
        return Err(um);
    }
    auto fd = fileno(fp);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    log_write_ring_to(fd);
    lnav_log_level = lnav_log_level_t::TRACE;
    lnav_log_file = fp;

    retval = fmt::format(FMT_STRING("info: wrote debug log to -- {}"), args[1]);

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_add_src_path(exec_context& ec,
                 std::string cmdline,
                 std::vector<std::string>& args)
{
    static const intern_string_t SRC = intern_string::lookup("path");
    if (args.size() < 2) {
        return ec.make_error("expecting a path to source code");
    }

#if !defined(HAVE_RUST_DEPS)
    return ec.make_error("source paths are not supported in this build");
#else
    auto pat = trim(remaining_args(cmdline, args));
    std::string retval;

    shlex lexer(pat);
    auto split_args_res = lexer.split(ec.create_resolver());
    if (split_args_res.isErr()) {
        auto split_err = split_args_res.unwrapErr();
        auto um = lnav::console::user_message::error("unable to parse paths")
                      .with_reason(split_err.se_error.te_msg)
                      .with_snippet(lnav::console::snippet::from(
                          SRC, lexer.to_attr_line(split_err.se_error)))
                      .move();

        return Err(um);
    }

    auto split_args = split_args_res.unwrap()
        | lnav::itertools::map([](const auto& elem) { return elem.se_value; });

    for (const auto& path_str : split_args) {
        std::error_code err_co;
        auto path = std::filesystem::canonical(std::filesystem::path(path_str),
                                               err_co);
        if (err_co) {
            auto um = lnav::console::user_message::error(
                          attr_line_t("invalid path: ")
                              .append(lnav::roles::file(path_str)))
                          .with_reason(err_co.message());
            return Err(um);
        }

        if (ec.ec_dry_run) {
            continue;
        }
        auto res = lnav_rs_ext::add_src_root(path.string());
        if (res != nullptr) {
            auto um
                = lnav::console::user_message::error((std::string) res->error);

            return Err(um);
        }
    }
    if (!ec.ec_dry_run) {
        lnav_rs_ext::discover_srcs();
    }
    return Ok(retval);
#endif
}

static Result<std::string, lnav::console::user_message>
com_adjust_log_time(exec_context& ec,
                    std::string cmdline,
                    std::vector<std::string>& args)
{
    std::string retval;

    if (lnav_data.ld_views[LNV_LOG].get_inner_height() == 0) {
        return ec.make_error("no log messages");
    }
    if (args.size() >= 2) {
        auto& lss = lnav_data.ld_log_source;
        struct timeval top_time, time_diff;
        struct timeval new_time = {0, 0};
        content_line_t top_content;
        date_time_scanner dts;
        struct exttm tm;
        struct tm base_tm;

        auto top_line = lnav_data.ld_views[LNV_LOG].get_selection();
        top_content = lss.at(top_line.value_or(0_vl));
        auto lf = lss.find(top_content);

        auto& ll = (*lf)[top_content];

        top_time = ll.get_timeval();
        localtime_r(&top_time.tv_sec, &base_tm);

        dts.set_base_time(top_time.tv_sec, base_tm);
        args[1] = remaining_args(cmdline, args);

        auto parse_res = relative_time::from_str(args[1]);
        if (parse_res.isOk()) {
            new_time = parse_res.unwrap().adjust(top_time).to_timeval();
        } else if (dts.scan(
                       args[1].c_str(), args[1].size(), nullptr, &tm, new_time)
                   != nullptr)
        {
            // nothing to do
        } else {
            return ec.make_error("could not parse timestamp -- {}", args[1]);
        }

        timersub(&new_time, &top_time, &time_diff);
        if (ec.ec_dry_run) {
            char buffer[1024];

            snprintf(
                buffer,
                sizeof(buffer),
                "info: log timestamps will be adjusted by %ld.%06ld seconds",
                time_diff.tv_sec,
                (long) time_diff.tv_usec);

            retval = buffer;
        } else {
            lf->adjust_content_time(top_content, time_diff, false);

            lss.set_force_rebuild();

            retval = "info: adjusted time";
        }
    } else {
        return ec.make_error("expecting new time value");
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_clear_adjusted_log_time(exec_context& ec,
                            std::string cmdline,
                            std::vector<std::string>& args)
{
    if (lnav_data.ld_views[LNV_LOG].get_inner_height() == 0) {
        return ec.make_error("no log messages");
    }

    auto& lss = lnav_data.ld_log_source;
    auto sel_line = lnav_data.ld_views[LNV_LOG].get_selection();
    auto sel_pair = lss.find_line_with_file(sel_line);
    if (sel_pair) {
        auto lf = sel_pair->first;
        lf->clear_time_offset();
        lss.set_force_rebuild();
    }

    return Ok(std::string("info: cleared time offset"));
}

static Result<std::string, lnav::console::user_message>
com_unix_time(exec_context& ec,
              std::string cmdline,
              std::vector<std::string>& args)
{
    std::string retval;

    if (args.size() >= 2) {
        bool parsed = false;
        struct tm log_time;
        time_t u_time;
        size_t millis;
        char* rest;

        u_time = time(nullptr);
        if (localtime_r(&u_time, &log_time) == nullptr) {
            return ec.make_error(
                "invalid epoch time: {} -- {}", u_time, strerror(errno));
        }

        log_time.tm_isdst = -1;

        args[1] = remaining_args(cmdline, args);
        if ((millis = args[1].find('.')) != std::string::npos
            || (millis = args[1].find(',')) != std::string::npos)
        {
            args[1] = args[1].erase(millis, 4);
        }
        if (((rest = strptime(args[1].c_str(), "%b %d %H:%M:%S %Y", &log_time))
                 != nullptr
             && (rest - args[1].c_str()) >= 20)
            || ((rest
                 = strptime(args[1].c_str(), "%Y-%m-%d %H:%M:%S", &log_time))
                    != nullptr
                && (rest - args[1].c_str()) >= 19))
        {
            u_time = mktime(&log_time);
            parsed = true;
        } else if (sscanf(args[1].c_str(), "%ld", &u_time)) {
            if (localtime_r(&u_time, &log_time) == nullptr) {
                return ec.make_error(
                    "invalid epoch time: {} -- {}", args[1], strerror(errno));
            }

            parsed = true;
        }
        if (parsed) {
            char ftime[128];

            strftime(ftime,
                     sizeof(ftime),
                     "%a %b %d %H:%M:%S %Y  %z %Z",
                     localtime_r(&u_time, &log_time));
            retval = fmt::format(FMT_STRING("{} -- {}"), ftime, u_time);
        } else {
            return ec.make_error("invalid unix time -- {}", args[1]);
        }
    } else {
        return ec.make_error("expecting a unix time value");
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_set_file_timezone(exec_context& ec,
                      std::string cmdline,
                      std::vector<std::string>& args)
{
    static const intern_string_t SRC = intern_string::lookup("args");
    std::string retval;

    if (args.size() == 1) {
        return ec.make_error("expecting a timezone name");
    }

    auto* tc = *lnav_data.ld_view_stack.top();
    auto* lss = dynamic_cast<logfile_sub_source*>(tc->get_sub_source());

    if (lss != nullptr) {
        if (lss->text_line_count() == 0) {
            return ec.make_error("no log messages to examine");
        }

        auto line_pair = lss->find_line_with_file(tc->get_selection());
        if (!line_pair) {
            return ec.make_error(FMT_STRING("cannot find line"));
        }

        shlex lexer(cmdline);
        auto split_res = lexer.split(ec.create_resolver());
        if (split_res.isErr()) {
            auto split_err = split_res.unwrapErr();
            auto um = lnav::console::user_message::error(
                          "unable to parse arguments")
                          .with_reason(split_err.se_error.te_msg)
                          .with_snippet(lnav::console::snippet::from(
                              SRC, lexer.to_attr_line(split_err.se_error)))
                          .move();

            return Err(um);
        }

        auto split_args
            = split_res.unwrap() | lnav::itertools::map([](const auto& elem) {
                  return elem.se_value;
              });
        try {
            const auto* tz = date::locate_zone(split_args[1]);
            auto pattern = split_args.size() == 2
                ? line_pair->first->get_filename()
                : std::filesystem::path(split_args[2]);

            if (!ec.ec_dry_run) {
                static auto& safe_options_hier
                    = injector::get<lnav::safe_file_options_hier&>();

                safe::WriteAccess<lnav::safe_file_options_hier> options_hier(
                    safe_options_hier);

                options_hier->foh_generation += 1;
                auto& coll = options_hier->foh_path_to_collection["/"];

                log_info("setting timezone for %s to %s (%s)",
                         pattern.c_str(),
                         args[1].c_str(),
                         tz->name().c_str());
                coll.foc_pattern_to_options[pattern] = lnav::file_options{
                    {intern_string_t{}, source_location{}, tz},
                };

                auto opt_path = lnav::paths::dotlnav() / "file-options.json";
                auto coll_str = coll.to_json();
                lnav::filesystem::write_file(opt_path, coll_str);
            }
        } catch (const std::runtime_error& e) {
            attr_line_t note;

            try {
                note = (date::get_tzdb().zones
                        | lnav::itertools::map(&date::time_zone::name)
                        | lnav::itertools::similar_to(split_args[1])
                        | lnav::itertools::fold(symbol_reducer, attr_line_t{}))
                           .add_header("did you mean one of the following?");
            } catch (const std::runtime_error& e) {
                log_error("unable to get timezones: %s", e.what());
            }
            auto um = lnav::console::user_message::error(
                          attr_line_t()
                              .append_quoted(split_args[1])
                              .append(" is not a valid timezone"))
                          .with_reason(e.what())
                          .with_note(note)
                          .move();
            return Err(um);
        }
    } else {
        return ec.make_error(
            ":set-file-timezone is only supported for the LOG view");
    }

    return Ok(retval);
}

static readline_context::prompt_result_t
com_set_file_timezone_prompt(exec_context& ec, const std::string& cmdline)
{
    auto* tc = *lnav_data.ld_view_stack.top();
    auto* lss = dynamic_cast<logfile_sub_source*>(tc->get_sub_source());

    if (lss == nullptr || lss->text_line_count() == 0) {
        return {};
    }

    shlex lexer(cmdline);
    auto split_res = lexer.split(ec.create_resolver());
    if (split_res.isErr()) {
        return {};
    }

    auto line_pair = lss->find_line_with_file(tc->get_selection());
    if (!line_pair) {
        return {};
    }

    auto elems = split_res.unwrap();
    auto pattern_arg = line_pair->first->get_filename();
    if (elems.size() == 1) {
        try {
            static auto& safe_options_hier
                = injector::get<lnav::safe_file_options_hier&>();

            safe::ReadAccess<lnav::safe_file_options_hier> options_hier(
                safe_options_hier);
            auto file_zone = date::get_tzdb().current_zone()->name();
            auto match_res = options_hier->match(pattern_arg);
            if (match_res) {
                file_zone = match_res->second.fo_default_zone.pp_value->name();
                pattern_arg = lnav::filesystem::escape_path(
                    match_res->first, lnav::filesystem::path_type::pattern);

                auto new_prompt = fmt::format(FMT_STRING("{} {} {}"),
                                              trim(cmdline),
                                              file_zone,
                                              pattern_arg);

                return {new_prompt};
            }

            return {"", file_zone + " "};
        } catch (const std::runtime_error& e) {
            log_error("cannot get timezones: %s", e.what());
        }
    }
    auto arg_path = std::filesystem::path(pattern_arg);
    auto arg_parent = lnav::filesystem::escape_path(arg_path.parent_path());
    if (!endswith(arg_parent, "/")) {
        arg_parent += "/";
    }
    if (elems.size() == 2 && endswith(cmdline, " ")) {
        return {"", arg_parent};
    }
    if (elems.size() == 3 && elems.back().se_value == arg_parent) {
        return {"", arg_path.filename().string()};
    }

    return {};
}

static readline_context::prompt_result_t
com_clear_file_timezone_prompt(exec_context& ec, const std::string& cmdline)
{
    std::string retval;

    auto* tc = *lnav_data.ld_view_stack.top();
    auto* lss = dynamic_cast<logfile_sub_source*>(tc->get_sub_source());

    if (lss != nullptr && lss->text_line_count() > 0) {
        auto line_pair = lss->find_line_with_file(tc->get_selection());
        if (line_pair) {
            try {
                static auto& safe_options_hier
                    = injector::get<lnav::safe_file_options_hier&>();

                safe::ReadAccess<lnav::safe_file_options_hier> options_hier(
                    safe_options_hier);
                auto file_zone = date::get_tzdb().current_zone()->name();
                auto pattern_arg = line_pair->first->get_filename();
                auto match_res
                    = options_hier->match(line_pair->first->get_filename());
                if (match_res) {
                    file_zone
                        = match_res->second.fo_default_zone.pp_value->name();
                    pattern_arg = match_res->first;
                }

                retval = fmt::format(
                    FMT_STRING("{} {}"), trim(cmdline), pattern_arg);
            } catch (const std::runtime_error& e) {
                log_error("cannot get timezones: %s", e.what());
            }
        }
    }

    return {retval};
}

static Result<std::string, lnav::console::user_message>
com_clear_file_timezone(exec_context& ec,
                        std::string cmdline,
                        std::vector<std::string>& args)
{
    std::string retval;

    if (args.size() != 2) {
        return ec.make_error("expecting a single file path or pattern");
    }

    auto* tc = *lnav_data.ld_view_stack.top();
    auto* lss = dynamic_cast<logfile_sub_source*>(tc->get_sub_source());

    if (lss != nullptr) {
        if (!ec.ec_dry_run) {
            static auto& safe_options_hier
                = injector::get<lnav::safe_file_options_hier&>();

            safe::WriteAccess<lnav::safe_file_options_hier> options_hier(
                safe_options_hier);

            options_hier->foh_generation += 1;
            auto& coll = options_hier->foh_path_to_collection["/"];
            const auto iter = coll.foc_pattern_to_options.find(args[1]);

            if (iter == coll.foc_pattern_to_options.end()) {
                return ec.make_error(FMT_STRING("no timezone set for: {}"),
                                     args[1]);
            }

            log_info("clearing timezone for %s", args[1].c_str());
            iter->second.fo_default_zone.pp_value = nullptr;
            if (iter->second.empty()) {
                coll.foc_pattern_to_options.erase(iter);
            }

            auto opt_path = lnav::paths::dotlnav() / "file-options.json";
            auto coll_str = coll.to_json();
            lnav::filesystem::write_file(opt_path, coll_str);
        }
    } else {
        return ec.make_error(
            ":clear-file-timezone is only supported for the LOG view");
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_convert_time_to(exec_context& ec,
                    std::string cmdline,
                    std::vector<std::string>& args)
{
    std::string retval;

    if (args.size() == 1) {
        return ec.make_error("expecting a timezone name");
    }

    const auto* tc = *lnav_data.ld_view_stack.top();
    auto* lss = dynamic_cast<logfile_sub_source*>(tc->get_sub_source());

    if (lss != nullptr) {
        if (lss->text_line_count() == 0) {
            return ec.make_error("no log messages to examine");
        }
        auto sel = tc->get_selection();
        if (!sel) {
            return ec.make_error("no focused message");
        }

        const auto* ll = lss->find_line(lss->at(sel.value()));
        try {
            auto* dst_tz = date::locate_zone(args[1]);
            auto utime = date::local_time<std::chrono::seconds>{
                ll->get_time<std::chrono::seconds>()};
            auto cz_time = lnav::to_sys_time(utime);
            auto dz_time = date::make_zoned(dst_tz, cz_time);
            auto etime = std::chrono::duration_cast<std::chrono::microseconds>(
                dz_time.get_local_time().time_since_epoch());
            etime += ll->get_subsecond_time<std::chrono::milliseconds>();
            char ftime[128];
            sql_strftime(ftime, sizeof(ftime), etime, 'T');
            retval = ftime;

            off_t off = 0;
            exttm tm;
            tm.et_flags |= ETF_ZONE_SET;
            tm.et_gmtoff = dz_time.get_info().offset.count();
            ftime_Z(ftime, off, sizeof(ftime), tm);
            ftime[off] = '\0';
            retval.append(" ");
            retval.append(ftime);
        } catch (const std::runtime_error& e) {
            return ec.make_error(FMT_STRING("Unable to get timezone: {} -- {}"),
                                 args[1],
                                 e.what());
        }
    } else {
        return ec.make_error(
            ":convert-time-to is only supported for the LOG view");
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_current_time(exec_context& ec,
                 std::string cmdline,
                 std::vector<std::string>& args)
{
    char ftime[128];
    struct tm localtm;
    std::string retval;
    time_t u_time;

    memset(&localtm, 0, sizeof(localtm));
    u_time = time(nullptr);
    strftime(ftime,
             sizeof(ftime),
             "%a %b %d %H:%M:%S %Y  %z %Z",
             localtime_r(&u_time, &localtm));
    retval = fmt::format(FMT_STRING("{} -- {}"), ftime, u_time);

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_goto(exec_context& ec, std::string cmdline, std::vector<std::string>& args)
{
    static const char* INTERACTIVE_FMTS[] = {
        "%B %e %H:%M:%S",
        "%b %e %H:%M:%S",
        "%B %e %H:%M",
        "%b %e %H:%M",
        "%B %e %I:%M%p",
        "%b %e %I:%M%p",
        "%B %e %I%p",
        "%b %e %I%p",
        "%B %e",
        "%b %e",
        nullptr,
    };

    std::string retval;

    std::string all_args = trim(remaining_args(cmdline, args));
    auto* tc = *lnav_data.ld_view_stack.top();
    std::optional<vis_line_t> dst_vl;
    auto is_location = false;

    if (startswith(all_args, "#")) {
        auto* ta = dynamic_cast<text_anchors*>(tc->get_sub_source());

        if (ta == nullptr) {
            return ec.make_error("view does not support anchor links");
        }

        dst_vl = ta->row_for_anchor(all_args);
        if (!dst_vl) {
            return ec.make_error("unable to find anchor: {}", all_args);
        }
        is_location = true;
    }

    auto* ttt = dynamic_cast<text_time_translator*>(tc->get_sub_source());
    int line_number, consumed;
    date_time_scanner dts;
    const char* scan_end = nullptr;
    struct timeval tv;
    struct exttm tm;
    float value;
    auto parse_res = relative_time::from_str(all_args);

    if (ttt != nullptr && tc->get_inner_height() > 0_vl) {
        auto top_time_opt
            = ttt->time_for_row(tc->get_selection().value_or(0_vl));

        if (top_time_opt) {
            auto top_time_tv = top_time_opt.value().ri_time;
            struct tm top_tm;

            localtime_r(&top_time_tv.tv_sec, &top_tm);
            dts.set_base_time(top_time_tv.tv_sec, top_tm);
        }
    }

    if (all_args.empty() || dst_vl) {
    } else if (parse_res.isOk()) {
        if (ttt == nullptr) {
            return ec.make_error(
                "relative time values only work in a time-indexed view");
        }
        if (tc->get_inner_height() == 0_vl) {
            return ec.make_error("view is empty");
        }
        auto tv_opt = ttt->time_for_row(tc->get_selection().value_or(0_vl));
        if (!tv_opt) {
            return ec.make_error("cannot get time for the top row");
        }
        tv = tv_opt.value().ri_time;

        vis_line_t vl = tc->get_selection().value_or(0_vl), new_vl;
        bool done = false;
        auto rt = parse_res.unwrap();
        log_info("  goto relative time: %s", rt.to_string().c_str());

        if (rt.is_relative()) {
            injector::get<relative_time&, last_relative_time_tag>() = rt;
        }

        do {
            auto orig_tv = tv;
            auto tm = rt.adjust(tv);

            tv = tm.to_timeval();
            if (tv == orig_tv) {
                break;
            }
            auto new_vl_opt = ttt->row_for_time(tv);
            if (!new_vl_opt) {
                break;
            }

            new_vl = new_vl_opt.value();
            if (new_vl == 0_vl || new_vl != vl || !rt.is_relative()) {
                vl = new_vl;
                done = true;
            }
        } while (!done);

        dst_vl = vl;

#if 0
            if (!ec.ec_dry_run && !rt.is_absolute()
                && lnav_data.ld_rl_view != nullptr)
            {
                lnav_data.ld_rl_view->set_alt_value(HELP_MSG_2(
                    r, R, "to move forward/backward the same amount of time"));
            }
#endif
    } else if ((scan_end
                = dts.scan(all_args.c_str(), all_args.size(), nullptr, &tm, tv))
                   != nullptr
               || (scan_end = dts.scan(all_args.c_str(),
                                       all_args.size(),
                                       INTERACTIVE_FMTS,
                                       &tm,
                                       tv))
                   != nullptr)
    {
        if (ttt == nullptr) {
            return ec.make_error(
                "time values only work in a time-indexed view");
        }

        size_t matched_size = scan_end - all_args.c_str();
        if (matched_size != all_args.size()) {
            auto um = lnav::console::user_message::error(
                          attr_line_t("invalid timestamp: ").append(all_args))
                          .with_reason(
                              attr_line_t("the leading part of the timestamp "
                                          "was matched, however, the trailing "
                                          "text ")
                                  .append_quoted(scan_end)
                                  .append(" was not"))
                          .with_snippets(ec.ec_source)
                          .with_note(
                              attr_line_t("input matched time format ")
                                  .append_quoted(
                                      PTIMEC_FORMATS[dts.dts_fmt_lock].pf_fmt))
                          .with_help(
                              "fix the timestamp or remove the trailing text")
                          .move();

            auto unmatched_size = all_args.size() - matched_size;
            auto& snippet_copy = um.um_snippets.back();
            attr_line_builder alb(snippet_copy.s_content);

            alb.append("\n")
                .append(1 + cmdline.find(all_args), ' ')
                .append(matched_size, ' ');
            {
                auto attr_guard
                    = alb.with_attr(VC_ROLE.value(role_t::VCR_COMMENT));

                alb.append("^");
                if (unmatched_size > 1) {
                    if (unmatched_size > 2) {
                        alb.append(unmatched_size - 2, '-');
                    }
                    alb.append("^");
                }
                alb.append(" unrecognized input");
            }
            return Err(um);
        }

        if (!(tm.et_flags & ETF_DAY_SET)) {
            tm.et_tm.tm_yday = -1;
            tm.et_tm.tm_mday = 1;
        }
        if (!(tm.et_flags & ETF_HOUR_SET)) {
            tm.et_tm.tm_hour = 0;
        }
        if (!(tm.et_flags & ETF_MINUTE_SET)) {
            tm.et_tm.tm_min = 0;
        }
        if (!(tm.et_flags & ETF_SECOND_SET)) {
            tm.et_tm.tm_sec = 0;
        }
        if (!(tm.et_flags & ETF_MICROS_SET) && !(tm.et_flags & ETF_MILLIS_SET))
        {
            tm.et_nsec = 0;
        }
        tv = tm.to_timeval();
        dst_vl = ttt->row_for_time(tv);
    } else if (sscanf(args[1].c_str(), "%f%n", &value, &consumed) == 1) {
        if (args[1][consumed] == '%') {
            if (value < 0) {
                return ec.make_error("negative percentages are not allowed");
            }
            line_number
                = (int) ((double) tc->get_inner_height() * (value / 100.0));
        } else {
            line_number = (int) value;
            if (line_number < 0) {
                log_info("negative goto: %d height=%d",
                         line_number,
                         (int) tc->get_inner_height());
                line_number = tc->get_inner_height() + line_number;
                if (line_number < 0) {
                    line_number = 0;
                }
            }
        }

        dst_vl = vis_line_t(line_number);
    } else {
        auto um = lnav::console::user_message::error(
                      attr_line_t("invalid argument: ").append(args[1]))
                      .with_reason(
                          "expecting line number/percentage, timestamp, or "
                          "relative time")
                      .move();
        ec.add_error_context(um);
        return Err(um);
    }

    dst_vl | [&ec, tc, &retval, is_location](auto new_top) {
        if (ec.ec_dry_run) {
            retval = "info: will move to line " + std::to_string((int) new_top);
        } else {
            tc->get_sub_source()->get_location_history() |
                [new_top](auto lh) { lh->loc_history_append(new_top); };
            tc->set_selection(new_top);
            if (tc->is_selectable() && is_location) {
                tc->set_top(new_top - 2_vl, false);
            }

            retval = "";
        }
    };

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_relative_goto(exec_context& ec,
                  std::string cmdline,
                  std::vector<std::string>& args)
{
    std::string retval = "error: ";

    if (args.empty()) {
    } else if (args.size() > 1) {
        auto* tc = *lnav_data.ld_view_stack.top();
        int line_offset, consumed;
        float value;

        auto sel = tc->get_selection();
        if (!sel) {
            return ec.make_error("no focused message");
        }
        if (sscanf(args[1].c_str(), "%f%n", &value, &consumed) == 1) {
            if (args[1][consumed] == '%') {
                line_offset
                    = (int) ((double) tc->get_inner_height() * (value / 100.0));
            } else {
                line_offset = (int) value;
            }

            auto new_sel = sel.value() + vis_line_t(line_offset);
            if (ec.ec_dry_run) {
                retval = "info: shifting top by " + std::to_string(line_offset)
                    + " lines";
            } else if (new_sel < 0) {
                retval = "";
            } else {
                tc->set_selection(new_sel);

                retval = "";
            }
        } else {
            return ec.make_error("invalid line number -- {}", args[1]);
        }
    } else {
        return ec.make_error("expecting line number/percentage");
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_mark_expr(exec_context& ec,
              std::string cmdline,
              std::vector<std::string>& args)
{
    std::string retval;

    if (args.size() < 2) {
        return ec.make_error("expecting an SQL expression");
    }
    if (*lnav_data.ld_view_stack.top() != &lnav_data.ld_views[LNV_LOG]) {
        return ec.make_error(":mark-expr is only supported for the LOG view");
    }
    auto expr = remaining_args(cmdline, args);
    auto stmt_str = fmt::format(FMT_STRING("SELECT 1 WHERE {}"), expr);

    auto_mem<sqlite3_stmt> stmt(sqlite3_finalize);
#ifdef SQLITE_PREPARE_PERSISTENT
    auto retcode = sqlite3_prepare_v3(lnav_data.ld_db.in(),
                                      stmt_str.c_str(),
                                      stmt_str.size(),
                                      SQLITE_PREPARE_PERSISTENT,
                                      stmt.out(),
                                      nullptr);
#else
    auto retcode = sqlite3_prepare_v2(lnav_data.ld_db.in(),
                                      stmt_str.c_str(),
                                      stmt_str.size(),
                                      stmt.out(),
                                      nullptr);
#endif
    if (retcode != SQLITE_OK) {
        const char* errmsg = sqlite3_errmsg(lnav_data.ld_db);
        auto expr_al
            = attr_line_t(expr)
                  .with_attr_for_all(VC_ROLE.value(role_t::VCR_QUOTED_CODE))
                  .move();
        readline_sql_highlighter(
            expr_al, lnav::sql::dialect::sqlite, std::nullopt);
        auto um = lnav::console::user_message::error(
                      attr_line_t("invalid mark expression: ").append(expr_al))
                      .with_reason(errmsg)
                      .with_snippets(ec.ec_source)
                      .move();

        return Err(um);
    }

    auto& lss = lnav_data.ld_log_source;
    if (ec.ec_dry_run) {
        auto set_res = lss.set_preview_sql_filter(stmt.release());

        if (set_res.isErr()) {
            return Err(set_res.unwrapErr());
        }
        lnav_data.ld_preview_status_source[0].get_description().set_value(
            "Matches are highlighted in the text view"_frag);
        lnav_data.ld_status[LNS_PREVIEW0].set_needs_update();
    } else {
        auto set_res = lss.set_sql_marker(expr, stmt.release());

        if (set_res.isErr()) {
            return Err(set_res.unwrapErr());
        }
        lnav_data.ld_views[LNV_LOG].reload_data();
    }

    return Ok(retval);
}

static readline_context::prompt_result_t
com_mark_expr_prompt(exec_context& ec, const std::string& cmdline)
{
    textview_curses* tc = *lnav_data.ld_view_stack.top();

    if (tc != &lnav_data.ld_views[LNV_LOG]) {
        return {""};
    }

    return {
        fmt::format(FMT_STRING("{} {}"),
                    trim(cmdline),
                    trim(lnav_data.ld_log_source.get_sql_marker_text())),
    };
}

static Result<std::string, lnav::console::user_message>
com_clear_mark_expr(exec_context& ec,
                    std::string cmdline,
                    std::vector<std::string>& args)
{
    std::string retval;

    if (args.empty()) {
    } else {
        if (!ec.ec_dry_run) {
            lnav_data.ld_log_source.set_sql_marker("", nullptr);
        }
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_goto_location(exec_context& ec,
                  std::string cmdline,
                  std::vector<std::string>& args)
{
    std::string retval;

    if (args.empty()) {
    } else if (!ec.ec_dry_run) {
        lnav_data.ld_view_stack.top() | [&args](auto tc) {
            tc->get_sub_source()->get_location_history() |
                [tc, &args](auto lh) {
                    return args[0] == "prev-location"
                        ? lh->loc_history_back(
                              tc->get_selection().value_or(0_vl))
                        : lh->loc_history_forward(
                              tc->get_selection().value_or(0_vl));
                }
                | [tc](auto new_top) { tc->set_selection(new_top); };
        };
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_next_section(exec_context& ec,
                 std::string cmdline,
                 std::vector<std::string>& args)
{
    std::string retval;

    if (args.empty()) {
    } else if (!ec.ec_dry_run) {
        auto* tc = *lnav_data.ld_view_stack.top();
        auto* ta = dynamic_cast<text_anchors*>(tc->get_sub_source());

        if (ta == nullptr) {
            return ec.make_error("view does not support sections");
        }

        auto old_sel = tc->get_selection().value_or(0_vl);
        auto adj_opt
            = ta->adjacent_anchor(old_sel, text_anchors::direction::next);
        if (!adj_opt) {
            return ec.make_error("no next section found");
        }

        tc->get_sub_source()->get_location_history() |
            [old_sel](auto lh) { lh->loc_history_append(old_sel); };
        tc->set_selection(adj_opt.value());
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_prev_section(exec_context& ec,
                 std::string cmdline,
                 std::vector<std::string>& args)
{
    std::string retval;

    if (args.empty()) {
    } else if (!ec.ec_dry_run) {
        auto* tc = *lnav_data.ld_view_stack.top();
        auto* ta = dynamic_cast<text_anchors*>(tc->get_sub_source());

        if (ta == nullptr) {
            return ec.make_error("view does not support sections");
        }

        auto old_sel = tc->get_selection().value_or(0_vl);
        auto adj_opt
            = ta->adjacent_anchor(old_sel, text_anchors::direction::prev);
        if (!adj_opt) {
            return ec.make_error("no previous section found");
        }

        tc->get_sub_source()->get_location_history() |
            [old_sel](auto lh) { lh->loc_history_append(old_sel); };
        tc->set_selection(adj_opt.value());
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_highlight(exec_context& ec,
              std::string cmdline,
              std::vector<std::string>& args)
{
    std::string retval;

    if (args.size() > 1) {
        const static intern_string_t PATTERN_SRC
            = intern_string::lookup("pattern");

        auto* tc = *lnav_data.ld_view_stack.top();
        auto& hm = tc->get_highlights();
        auto re_frag = remaining_args_frag(cmdline, args);
        args[1] = re_frag.to_string();
        if (hm.find({highlight_source_t::INTERACTIVE, args[1]}) != hm.end()) {
            return ec.make_error("highlight already exists -- {}", args[1]);
        }

        auto compile_res = lnav::pcre2pp::code::from(args[1], PCRE2_CASELESS);

        if (compile_res.isErr()) {
            auto ce = compile_res.unwrapErr();
            auto um = lnav::console::to_user_message(PATTERN_SRC, ce);
            return Err(um);
        }
        highlighter hl(compile_res.unwrap().to_shared());
        auto hl_attrs = view_colors::singleton().attrs_for_ident(args[1]);

        if (ec.ec_dry_run) {
            hl_attrs |= text_attrs::style::blink;
        }

        hl.with_attrs(hl_attrs);

        if (ec.ec_dry_run) {
            hm[{highlight_source_t::PREVIEW, "preview"}] = hl;

            lnav_data.ld_preview_status_source[0].get_description().set_value(
                "Matches are highlighted in the view"_frag);
            lnav_data.ld_status[LNS_PREVIEW0].set_needs_update();

            retval = "";
        } else {
            hm[{highlight_source_t::INTERACTIVE, args[1]}] = hl;
            retval = "info: highlight pattern now active";
        }
        tc->reload_data();
    } else {
        return ec.make_error("expecting a regular expression to highlight");
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_highlight_field(exec_context& ec,
                    std::string cmdline,
                    std::vector<std::string>& args)
{
    static auto& vc = view_colors::singleton();

    CLI::App app{"highlight-field"};
    std::string retval;
    std::string field_name;
    std::string fg_color;
    std::string bg_color;
    bool style_bold = false;
    bool style_underline = false;
    bool style_strike = false;
    bool style_blink = false;
    bool style_italic = false;

    app.add_option("--color", fg_color);
    app.add_option("--bg-color", bg_color);
    app.add_flag("--bold", style_bold);
    app.add_flag("--underline", style_underline);
    app.add_flag("--strike", style_strike);
    app.add_flag("--blink", style_blink);
    app.add_flag("--italic", style_italic);
    app.add_option("field", field_name);

    size_t name_index = 1;
    for (; name_index < args.size(); name_index++) {
        if (!startswith(args[name_index], "-")) {
            break;
        }
    }
    if (name_index >= args.size()) {
        return ec.make_error("expecting field name");
    }

    auto pat = name_index + 1 < args.size()
        ? trim(remaining_args(cmdline, args, name_index + 1))
        : std::string(".*");

    std::vector<std::string> cli_args(args.begin() + 1,
                                      args.begin() + name_index + 1);
    std::vector<lnav::console::user_message> errors;

    text_attrs attrs;
    app.parse(cli_args);
    if (!fg_color.empty()) {
        attrs.ta_fg_color = vc.match_color(
            styling::color_unit::from_str(fg_color).unwrapOrElse(
                [&](const auto& msg) {
                    errors.emplace_back(
                        lnav::console::user_message::error(
                            attr_line_t().append_quoted(fg_color).append(
                                " is not a valid color value"))
                            .with_reason(msg));
                    return styling::color_unit::EMPTY;
                }));
    }
    if (!bg_color.empty()) {
        attrs.ta_bg_color = vc.match_color(
            styling::color_unit::from_str(bg_color).unwrapOrElse(
                [&](const auto& msg) {
                    errors.emplace_back(
                        lnav::console::user_message::error(
                            attr_line_t().append_quoted(bg_color).append(
                                " is not a valid background color value"))
                            .with_reason(msg));
                    return styling::color_unit::EMPTY;
                }));
    }
    if (style_bold) {
        attrs |= text_attrs::style::bold;
    }
    if (style_underline) {
        attrs |= text_attrs::style::underline;
    }
    if (style_blink) {
        attrs |= text_attrs::style::blink;
    }
    if (style_strike) {
        attrs |= text_attrs::style::struck;
    }
    if (style_italic) {
        attrs |= text_attrs::style::italic;
    }
    if (!errors.empty()) {
        return Err(errors[0]);
    }
    if (field_name.empty()) {
        return ec.make_error("field name cannot be empty");
    }
    if (attrs.empty()) {
        attrs = vc.attrs_for_ident(pat);
    }

    auto compile_res = lnav::pcre2pp::code::from(pat, PCRE2_CASELESS);

    if (compile_res.isErr()) {
        const static intern_string_t PATTERN_SRC
            = intern_string::lookup("pattern");
        auto ce = compile_res.unwrapErr();
        auto um = lnav::console::to_user_message(PATTERN_SRC, ce);
        return Err(um);
    }

    intern_string_t field_name_i = intern_string::lookup(field_name);

    auto re = compile_res.unwrap().to_shared();
    lnav_data.ld_log_source.lss_highlighters.emplace_back(
        highlighter(re)
            .with_field(field_name_i)
            .with_attrs(attrs)
            .with_preview(ec.ec_dry_run));

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_clear_highlight(exec_context& ec,
                    std::string cmdline,
                    std::vector<std::string>& args)
{
    std::string retval;

    if (args.size() > 1 && args[1][0] != '$') {
        auto* tc = *lnav_data.ld_view_stack.top();
        auto& hm = tc->get_highlights();

        args[1] = remaining_args_frag(cmdline, args).to_string();
        auto hm_iter = hm.find({highlight_source_t::INTERACTIVE, args[1]});
        if (hm_iter == hm.end()) {
            return ec.make_error("highlight does not exist -- {}", args[1]);
        }
        if (ec.ec_dry_run) {
            retval = "";
        } else {
            hm.erase(hm_iter);
            retval = "info: highlight pattern cleared";
            tc->reload_data();
        }
    } else {
        return ec.make_error("expecting highlight expression to clear");
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_clear_highlight_field(exec_context& ec,
                          std::string cmdline,
                          std::vector<std::string>& args)
{
    std::string retval;

    if (args.size() > 1) {
        auto& tc = lnav_data.ld_views[LNV_LOG];
        auto& log_hlv = lnav_data.ld_log_source.lss_highlighters;
        auto new_end
            = std::remove_if(log_hlv.begin(), log_hlv.end(), [&](auto& kv) {
                  return kv.h_field == args[1];
              });
        if (new_end != log_hlv.end()) {
            if (!ec.ec_dry_run) {
                log_hlv.erase(new_end, log_hlv.end());
                tc.reload_data();
                retval = "info: removed field highlight";
            }
            return Ok(retval);
        }

        return ec.make_error("highlight does not exist -- {}", args[1]);
    }
    return ec.make_error("expecting highlighted field to clear");
}

static Result<std::string, lnav::console::user_message>
com_help(exec_context& ec, std::string cmdline, std::vector<std::string>& args)
{
    std::string retval;

    if (!ec.ec_dry_run) {
        ensure_view(&lnav_data.ld_views[LNV_HELP]);
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_filter_expr(exec_context& ec,
                std::string cmdline,
                std::vector<std::string>& args)
{
    std::string retval;

    if (args.size() > 1) {
        textview_curses* tc = *lnav_data.ld_view_stack.top();

        if (tc != &lnav_data.ld_views[LNV_LOG]) {
            return ec.make_error(
                "The :filter-expr command only works in the log view");
        }

        auto expr = remaining_args(cmdline, args);
        args[1] = fmt::format(FMT_STRING("SELECT 1 WHERE {}"), expr);

        auto_mem<sqlite3_stmt> stmt(sqlite3_finalize);
#ifdef SQLITE_PREPARE_PERSISTENT
        auto retcode = sqlite3_prepare_v3(lnav_data.ld_db.in(),
                                          args[1].c_str(),
                                          args[1].size(),
                                          SQLITE_PREPARE_PERSISTENT,
                                          stmt.out(),
                                          nullptr);
#else
        auto retcode = sqlite3_prepare_v2(lnav_data.ld_db.in(),
                                          args[1].c_str(),
                                          args[1].size(),
                                          stmt.out(),
                                          nullptr);
#endif
        if (retcode != SQLITE_OK) {
            const char* errmsg = sqlite3_errmsg(lnav_data.ld_db);
            auto expr_al
                = attr_line_t(expr)
                      .with_attr_for_all(VC_ROLE.value(role_t::VCR_QUOTED_CODE))
                      .move();
            readline_sql_highlighter(
                expr_al, lnav::sql::dialect::sqlite, std::nullopt);
            auto um = lnav::console::user_message::error(
                          attr_line_t("invalid filter expression: ")
                              .append(expr_al))
                          .with_reason(errmsg)
                          .with_snippets(ec.ec_source)
                          .move();

            return Err(um);
        }

        if (ec.ec_dry_run) {
            auto set_res = lnav_data.ld_log_source.set_preview_sql_filter(
                stmt.release());

            if (set_res.isErr()) {
                return Err(set_res.unwrapErr());
            }
            lnav_data.ld_preview_status_source[0].get_description().set_value(
                "Matches are highlighted in the text view"_frag);
            lnav_data.ld_status[LNS_PREVIEW0].set_needs_update();
        } else {
            lnav_data.ld_log_source.set_preview_sql_filter(nullptr);
            auto set_res
                = lnav_data.ld_log_source.set_sql_filter(expr, stmt.release());

            if (set_res.isErr()) {
                return Err(set_res.unwrapErr());
            }
        }
        lnav_data.ld_log_source.text_filters_changed();
        tc->reload_data();
    } else {
        return ec.make_error("expecting an SQL expression");
    }

    return Ok(retval);
}

static readline_context::prompt_result_t
com_filter_expr_prompt(exec_context& ec, const std::string& cmdline)
{
    auto* tc = *lnav_data.ld_view_stack.top();

    if (tc != &lnav_data.ld_views[LNV_LOG]) {
        return {""};
    }

    return {
        fmt::format(FMT_STRING("{} {}"),
                    trim(cmdline),
                    trim(lnav_data.ld_log_source.get_sql_filter_text())),
    };
}

static Result<std::string, lnav::console::user_message>
com_clear_filter_expr(exec_context& ec,
                      std::string cmdline,
                      std::vector<std::string>& args)
{
    std::string retval;

    if (!ec.ec_dry_run) {
        lnav_data.ld_log_source.set_sql_filter("", nullptr);
        lnav_data.ld_log_source.text_filters_changed();
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_enable_word_wrap(exec_context& ec,
                     std::string cmdline,
                     std::vector<std::string>& args)
{
    std::string retval;

    if (!ec.ec_dry_run) {
        lnav_data.ld_views[LNV_LOG].set_word_wrap(true);
        lnav_data.ld_views[LNV_TEXT].set_word_wrap(true);
        lnav_data.ld_views[LNV_PRETTY].set_word_wrap(true);
        retval = "info: enabled word-wrap";
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_disable_word_wrap(exec_context& ec,
                      std::string cmdline,
                      std::vector<std::string>& args)
{
    std::string retval;

    if (!ec.ec_dry_run) {
        lnav_data.ld_views[LNV_LOG].set_word_wrap(false);
        lnav_data.ld_views[LNV_TEXT].set_word_wrap(false);
        lnav_data.ld_views[LNV_PRETTY].set_word_wrap(false);
        retval = "info: disabled word-wrap";
    }

    return Ok(retval);
}

static std::set<std::string> custom_logline_tables;

static Result<std::string, lnav::console::user_message>
com_create_logline_table(exec_context& ec,
                         std::string cmdline,
                         std::vector<std::string>& args)
{
    auto* vtab_manager = injector::get<log_vtab_manager*>();
    std::string retval;

    if (args.size() == 2) {
        auto& log_view = lnav_data.ld_views[LNV_LOG];

        if (log_view.get_inner_height() == 0) {
            return ec.make_error("no log data available");
        }
        auto vl = log_view.get_selection();
        if (!vl) {
            return ec.make_error("no focused line");
        }
        auto cl = lnav_data.ld_log_source.at_base(vl.value());
        auto ldt
            = std::make_shared<log_data_table>(lnav_data.ld_log_source,
                                               *vtab_manager,
                                               cl,
                                               intern_string::lookup(args[1]));
        ldt->vi_provenance = log_vtab_impl::provenance_t::user;
        if (ec.ec_dry_run) {
            attr_line_t al(ldt->get_table_statement());

            lnav_data.ld_preview_status_source[0].get_description().set_value(
                "The following table will be created:"_frag);
            lnav_data.ld_status[LNS_PREVIEW0].set_needs_update();
            lnav_data.ld_preview_view[0].set_sub_source(
                &lnav_data.ld_preview_source[0]);
            lnav_data.ld_preview_source[0].replace_with(al).set_text_format(
                text_format_t::TF_SQL);

            return Ok(std::string());
        }

        auto errmsg = vtab_manager->register_vtab(ldt);
        if (errmsg.empty()) {
            custom_logline_tables.insert(args[1]);
#if 0
                    if (lnav_data.ld_rl_view != NULL) {
                        lnav_data.ld_rl_view->add_possibility(
                            ln_mode_t::COMMAND, "custom-table", args[1]);
                    }
#endif
            retval = "info: created new log table -- " + args[1];
        } else {
            return ec.make_error("unable to create table -- {}", errmsg);
        }
    } else {
        return ec.make_error("expecting a table name");
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_delete_logline_table(exec_context& ec,
                         std::string cmdline,
                         std::vector<std::string>& args)
{
    auto* vtab_manager = injector::get<log_vtab_manager*>();
    std::string retval;

    if (args.size() == 2) {
        if (custom_logline_tables.find(args[1]) == custom_logline_tables.end())
        {
            return ec.make_error("unknown logline table -- {}", args[1]);
        }

        if (ec.ec_dry_run) {
            return Ok(std::string());
        }

        std::string rc = vtab_manager->unregister_vtab(args[1]);

        if (rc.empty()) {
#if 0
            if (lnav_data.ld_rl_view != NULL) {
                lnav_data.ld_rl_view->rem_possibility(
                    ln_mode_t::COMMAND, "custom-table", args[1]);
            }
#endif
            retval = "info: deleted logline table";
        } else {
            return ec.make_error("{}", rc);
        }
    } else {
        return ec.make_error("expecting a table name");
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_create_search_table(exec_context& ec,
                        std::string cmdline,
                        std::vector<std::string>& args)
{
    auto* vtab_manager = injector::get<log_vtab_manager*>();
    std::string retval;

    if (args.size() >= 2) {
        const static intern_string_t PATTERN_SRC
            = intern_string::lookup("pattern");
        string_fragment regex_frag;
        std::string regex;

        if (args.size() >= 3) {
            regex_frag = remaining_args_frag(cmdline, args, 2);
            regex = regex_frag.to_string();
        } else {
            regex = lnav_data.ld_views[LNV_LOG].get_current_search();
        }

        auto compile_res = lnav::pcre2pp::code::from(
            regex, log_search_table_ns::PATTERN_OPTIONS);

        if (compile_res.isErr()) {
            auto re_err = compile_res.unwrapErr();
            auto um = lnav::console::to_user_message(PATTERN_SRC, re_err)
                          .with_snippets(ec.ec_source);
            return Err(um);
        }

        auto re = compile_res.unwrap().to_shared();
        auto tab_name = intern_string::lookup(args[1]);
        auto lst = std::make_shared<log_search_table>(re, tab_name);
        if (ec.ec_dry_run) {
            auto* tc = &lnav_data.ld_views[LNV_LOG];
            auto& hm = tc->get_highlights();
            highlighter hl(re);

            hl.with_role(role_t::VCR_INFO);
            hl.with_attrs(text_attrs::with_blink());

            hm[{highlight_source_t::PREVIEW, "preview"}] = hl;
            tc->reload_data();

            attr_line_t al(lst->get_table_statement());

            lnav_data.ld_preview_status_source[0].get_description().set_value(
                "The following table will be created:"_frag);
            lnav_data.ld_status[LNS_PREVIEW0].set_needs_update();

            lnav_data.ld_preview_view[0].set_sub_source(
                &lnav_data.ld_preview_source[0]);
            lnav_data.ld_preview_source[0].replace_with(al).set_text_format(
                text_format_t::TF_SQL);

            return Ok(std::string());
        }

        lst->vi_provenance = log_vtab_impl::provenance_t::user;
        auto existing = vtab_manager->lookup_impl(tab_name);
        if (existing != nullptr) {
            if (existing->vi_provenance != log_vtab_impl::provenance_t::user) {
                return ec.make_error(
                    FMT_STRING("a table with the name '{}' already exists"),
                    tab_name->to_string_fragment());
            }
            vtab_manager->unregister_vtab(tab_name->to_string_fragment());
        }

        auto errmsg = vtab_manager->register_vtab(lst);
        if (errmsg.empty()) {
            retval = "info: created new search table -- " + args[1];
        } else {
            return ec.make_error("unable to create table -- {}", errmsg);
        }
    } else {
        return ec.make_error("expecting a table name");
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_delete_search_table(exec_context& ec,
                        std::string cmdline,
                        std::vector<std::string>& args)
{
    auto* vtab_manager = injector::get<log_vtab_manager*>();
    std::string retval;

    if (args.size() < 2) {
        return ec.make_error("expecting a table name");
    }
    for (auto lpc = size_t{1}; lpc < args.size(); lpc++) {
        auto& table_name = args[lpc];
        auto tab = vtab_manager->lookup_impl(table_name);
        if (tab == nullptr
            || dynamic_cast<log_search_table*>(tab.get()) == nullptr
            || tab->vi_provenance != log_vtab_impl::provenance_t::user)
        {
            return ec.make_error("unknown search table -- {}", table_name);
        }

        if (ec.ec_dry_run) {
            continue;
        }

        auto rc = vtab_manager->unregister_vtab(args[1]);
        if (rc.empty()) {
            retval = "info: deleted search table";
        } else {
            return ec.make_error("{}", rc);
        }
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_session(exec_context& ec,
            std::string cmdline,
            std::vector<std::string>& args)
{
    std::string retval;

    if (ec.ec_dry_run) {
        retval = "";
    } else if (args.size() >= 2) {
        /* XXX put these in a map */
        if (args[1] != "highlight" && args[1] != "enable-word-wrap"
            && args[1] != "disable-word-wrap" && args[1] != "filter-in"
            && args[1] != "filter-out" && args[1] != "enable-filter"
            && args[1] != "disable-filter")
        {
            return ec.make_error(
                "only the highlight, filter, and word-wrap commands are "
                "supported");
        }
        if (getenv("HOME") == NULL) {
            return ec.make_error("the HOME environment variable is not set");
        }
        auto saved_cmd = trim(remaining_args(cmdline, args));
        auto old_file_name = lnav::paths::dotlnav() / "session";
        auto new_file_name = lnav::paths::dotlnav() / "session.tmp";

        std::ifstream session_file(old_file_name.string());
        std::ofstream new_session_file(new_file_name.string());

        if (!new_session_file) {
            return ec.make_error("cannot write to session file");
        } else {
            bool added = false;
            std::string line;

            if (session_file.is_open()) {
                while (getline(session_file, line)) {
                    if (line == saved_cmd) {
                        added = true;
                        break;
                    }
                    new_session_file << line << std::endl;
                }
            }
            if (!added) {
                new_session_file << saved_cmd << std::endl;

                log_perror(
                    rename(new_file_name.c_str(), old_file_name.c_str()));
            } else {
                log_perror(remove(new_file_name.c_str()));
            }

            retval = "info: session file saved";
        }
    } else {
        return ec.make_error("expecting a command to save to the session file");
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_file_visibility(exec_context& ec,
                    std::string cmdline,
                    std::vector<std::string>& args)
{
    static const intern_string_t SRC = intern_string::lookup("path");
    bool only_this_file = false;
    bool make_visible;
    std::string retval;

    if (args[0] == "show-file") {
        make_visible = true;
    } else if (args[0] == "show-only-this-file") {
        make_visible = true;
        only_this_file = true;
    } else {
        make_visible = false;
    }

    if (args.size() == 1 || only_this_file) {
        auto* tc = *lnav_data.ld_view_stack.top();
        std::shared_ptr<logfile> lf;

        if (tc == &lnav_data.ld_views[LNV_TEXT]) {
            const auto& tss = lnav_data.ld_text_source;

            if (tss.empty()) {
                return ec.make_error("no text files are opened");
            }
            lf = tss.current_file();
        } else if (tc == &lnav_data.ld_views[LNV_LOG]) {
            if (tc->get_inner_height() == 0) {
                return ec.make_error("no log files loaded");
            }
            auto& lss = lnav_data.ld_log_source;
            auto vl = tc->get_selection().value_or(0_vl);
            auto cl = lss.at(vl);
            lf = lss.find(cl);
        } else {
            return ec.make_error(
                ":{} must be run in the log or text file views", args[0]);
        }

        if (!ec.ec_dry_run) {
            if (only_this_file) {
                for (const auto& ld : lnav_data.ld_log_source) {
                    ld->set_visibility(false);
                    ld->get_file_ptr()->set_indexing(false);
                }
            }
            lf->set_indexing(make_visible);
            lnav_data.ld_log_source.find_data(lf) |
                [make_visible](auto ld) { ld->set_visibility(make_visible); };
            tc->get_sub_source()->text_filters_changed();
        }
        retval = fmt::format(FMT_STRING("info: {} file -- {}"),
                             make_visible ? "showing" : "hiding",
                             lf->get_filename());
    } else {
        auto* top_tc = *lnav_data.ld_view_stack.top();
        int text_file_count = 0, log_file_count = 0;
        auto lexer = shlex(cmdline);

        auto split_args_res = lexer.split(ec.create_resolver());
        if (split_args_res.isErr()) {
            auto split_err = split_args_res.unwrapErr();
            auto um = lnav::console::user_message::error(
                          "unable to parse file name")
                          .with_reason(split_err.se_error.te_msg)
                          .with_snippet(lnav::console::snippet::from(
                              SRC, lexer.to_attr_line(split_err.se_error)))
                          .move();

            return Err(um);
        }

        auto args = split_args_res.unwrap()
            | lnav::itertools::map(
                        [](const auto& elem) { return elem.se_value; });
        args.erase(args.begin());

        for (const auto& lf : lnav_data.ld_active_files.fc_files) {
            if (lf.get() == nullptr) {
                continue;
            }

            auto ld_opt = lnav_data.ld_log_source.find_data(lf);

            if (!ld_opt || ld_opt.value()->ld_visible == make_visible) {
                continue;
            }

            auto find_iter
                = find_if(args.begin(), args.end(), [&lf](const auto& arg) {
                      return fnmatch(arg.c_str(), lf->get_filename().c_str(), 0)
                          == 0;
                  });

            if (find_iter == args.end()) {
                continue;
            }

            if (!ec.ec_dry_run) {
                ld_opt | [make_visible](auto ld) {
                    ld->get_file_ptr()->set_indexing(make_visible);
                    ld->set_visibility(make_visible);
                };
            }
            if (lf->get_format() != nullptr) {
                log_file_count += 1;
            } else {
                text_file_count += 1;
            }
        }
        if (!ec.ec_dry_run && log_file_count > 0) {
            lnav_data.ld_views[LNV_LOG]
                .get_sub_source()
                ->text_filters_changed();
            if (top_tc == &lnav_data.ld_views[LNV_TIMELINE]) {
                lnav_data.ld_views[LNV_TIMELINE]
                    .get_sub_source()
                    ->text_filters_changed();
            }
        }
        if (!ec.ec_dry_run && text_file_count > 0) {
            lnav_data.ld_views[LNV_TEXT]
                .get_sub_source()
                ->text_filters_changed();
        }
        retval = fmt::format(
            FMT_STRING("info: {} {:L} log files and {:L} text files"),
            make_visible ? "showing" : "hiding",
            log_file_count,
            text_file_count);
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_summarize(exec_context& ec,
              std::string cmdline,
              std::vector<std::string>& args)
{
    std::string retval;

    if (!setup_logline_table(ec)) {
        return ec.make_error("no log data available");
    }
    if (args.size() == 1) {
        return ec.make_error("no columns specified");
    }
    auto_mem<char, sqlite3_free> query_frag;
    std::vector<std::string> other_columns;
    std::vector<std::string> num_columns;
    const auto& top_source = ec.ec_source.back();
    sql_progress_guard progress_guard(sql_progress,
                                      sql_progress_finished,
                                      top_source.s_location,
                                      top_source.s_content,
                                      true);
    auto_mem<sqlite3_stmt> stmt(sqlite3_finalize);
    int retcode;
    std::string query;

    query = "SELECT ";
    for (size_t lpc = 1; lpc < args.size(); lpc++) {
        if (lpc > 1)
            query += ", ";
        query += args[lpc];
    }
    query += " FROM logline ";

    retcode = sqlite3_prepare_v2(
        lnav_data.ld_db.in(), query.c_str(), -1, stmt.out(), nullptr);
    if (retcode != SQLITE_OK) {
        const char* errmsg = sqlite3_errmsg(lnav_data.ld_db);

        return ec.make_error("{}", errmsg);
    }

    switch (sqlite3_step(stmt.in())) {
        case SQLITE_OK:
        case SQLITE_DONE: {
            return ec.make_error("no data");
        } break;
        case SQLITE_ROW:
            break;
        default: {
            const char* errmsg;

            errmsg = sqlite3_errmsg(lnav_data.ld_db);
            return ec.make_error("{}", errmsg);
        } break;
    }

    if (ec.ec_dry_run) {
        return Ok(std::string());
    }

    for (int lpc = 0; lpc < sqlite3_column_count(stmt.in()); lpc++) {
        switch (sqlite3_column_type(stmt.in(), lpc)) {
            case SQLITE_INTEGER:
            case SQLITE_FLOAT:
                num_columns.push_back(args[lpc + 1]);
                break;
            default:
                other_columns.push_back(args[lpc + 1]);
                break;
        }
    }

    query = "SELECT";
    for (auto iter = other_columns.begin(); iter != other_columns.end(); ++iter)
    {
        if (iter != other_columns.begin()) {
            query += ",";
        }
        query_frag
            = sqlite3_mprintf(" %s as \"c_%s\", count(*) as \"count_%s\"",
                              iter->c_str(),
                              iter->c_str(),
                              iter->c_str());
        query += query_frag;
    }

    if (!other_columns.empty() && !num_columns.empty()) {
        query += ", ";
    }

    for (auto iter = num_columns.begin(); iter != num_columns.end(); ++iter) {
        if (iter != num_columns.begin()) {
            query += ",";
        }
        query_frag = sqlite3_mprintf(
            " sum(\"%s\"), "
            " min(\"%s\"), "
            " avg(\"%s\"), "
            " median(\"%s\"), "
            " stddev(\"%s\"), "
            " max(\"%s\") ",
            iter->c_str(),
            iter->c_str(),
            iter->c_str(),
            iter->c_str(),
            iter->c_str(),
            iter->c_str());
        query += query_frag;
    }

    query
        += (" FROM logline "
            "WHERE (logline.log_part is null or "
            "startswith(logline.log_part, '.') = 0) ");

    for (auto iter = other_columns.begin(); iter != other_columns.end(); ++iter)
    {
        if (iter == other_columns.begin()) {
            query += " GROUP BY ";
        } else {
            query += ",";
        }
        query_frag = sqlite3_mprintf(" \"c_%s\"", iter->c_str());
        query += query_frag;
    }

    for (auto iter = other_columns.begin(); iter != other_columns.end(); ++iter)
    {
        if (iter == other_columns.begin()) {
            query += " ORDER BY ";
        } else {
            query += ",";
        }
        query_frag = sqlite3_mprintf(
            " \"count_%s\" desc, \"c_%s\" collate "
            "naturalnocase asc",
            iter->c_str(),
            iter->c_str());
        query += query_frag;
    }
    log_debug("query %s", query.c_str());

    auto& dls = *ec.ec_label_source_stack.back();

    dls.clear();
    retcode = sqlite3_prepare_v2(
        lnav_data.ld_db.in(), query.c_str(), -1, stmt.out(), nullptr);

    if (retcode != SQLITE_OK) {
        const char* errmsg = sqlite3_errmsg(lnav_data.ld_db);

        return ec.make_error("{}", errmsg);
    } else if (stmt == nullptr) {
        retval = "";
    } else {
        bool done = false;

        ec.ec_sql_callback(ec, stmt.in());
        while (!done) {
            retcode = sqlite3_step(stmt.in());

            switch (retcode) {
                case SQLITE_OK:
                case SQLITE_DONE:
                    done = true;
                    break;

                case SQLITE_ROW:
                    ec.ec_sql_callback(ec, stmt.in());
                    break;

                default: {
                    const char* errmsg;

                    errmsg = sqlite3_errmsg(lnav_data.ld_db);
                    return ec.make_error("{}", errmsg);
                }
            }
        }

        if (retcode == SQLITE_DONE) {
            lnav_data.ld_views[LNV_LOG].reload_data();
            lnav_data.ld_views[LNV_DB].reload_data();
            lnav_data.ld_views[LNV_DB].set_left(0);

            if (dls.dls_row_cursors.size() > 0) {
                ensure_view(&lnav_data.ld_views[LNV_DB]);
            }
        }

        lnav_data.ld_bottom_source.update_loading(0, 0);
        lnav_data.ld_status[LNS_BOTTOM].set_needs_update();
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_add_test(exec_context& ec,
             std::string cmdline,
             std::vector<std::string>& args)
{
    std::string retval;

    if (args.size() > 1) {
        return ec.make_error("not expecting any arguments");
    }
    if (!ec.ec_dry_run) {
        auto* tc = *lnav_data.ld_view_stack.top();

        auto& bv = tc->get_bookmarks()[&textview_curses::BM_USER];
        for (auto iter = bv.bv_tree.begin(); iter != bv.bv_tree.end(); ++iter) {
            auto_mem<FILE> file(fclose);
            char path[PATH_MAX];
            std::string line;

            tc->grep_value_for_line(*iter, line);

            line.insert(0, 13, ' ');

            snprintf(path,
                     sizeof(path),
                     "%s/test/log-samples/sample-%s.txt",
                     getenv("LNAV_SRC"),
                     hasher().update(line).to_string().c_str());

            if ((file = fopen(path, "w")) == nullptr) {
                perror("fopen failed");
            } else {
                fprintf(file, "%s\n", line.c_str());
            }
        }
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_switch_to_view(exec_context& ec,
                   std::string cmdline,
                   std::vector<std::string>& args)
{
    std::string retval;

    if (args.size() > 1) {
        auto view_index_opt = view_from_string(args[1].c_str());
        if (!view_index_opt) {
            return ec.make_error("invalid view name -- {}", args[1]);
        }
        if (!ec.ec_dry_run) {
            auto* tc = &lnav_data.ld_views[view_index_opt.value()];
            if (args[0] == "switch-to-view") {
                ensure_view(tc);
            } else {
                toggle_view(tc);
            }
        }
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_toggle_filtering(exec_context& ec,
                     std::string cmdline,
                     std::vector<std::string>& args)
{
    std::string retval;

    if (!ec.ec_dry_run) {
        auto* tc = *lnav_data.ld_view_stack.top();
        auto* tss = tc->get_sub_source();

        tss->toggle_apply_filters();
        lnav_data.ld_filter_status_source.update_filtered(tss);
        lnav_data.ld_status[LNS_FILTER].set_needs_update();
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_zoom_to(exec_context& ec,
            std::string cmdline,
            std::vector<std::string>& args)
{
    std::string retval;
    std::optional<int> zoom_level;

    if (args.size() == 1) {
        auto um = lnav::console::user_message::error("expecting a zoom level")
                      .with_snippets(ec.ec_source)
                      .with_help(attr_line_t("available levels: ")
                                     .join(lnav_zoom_strings, ", "))
                      .move();
        return Err(um);
    }

    for (size_t lpc = 0; lpc < lnav_zoom_strings.size() && !zoom_level; lpc++) {
        if (lnav_zoom_strings[lpc].iequal(args[1])) {
            zoom_level = lpc;
        }
    }

    if (!zoom_level) {
        auto um = lnav::console::user_message::error(
                      attr_line_t("invalid zoom level: ")
                          .append(lnav::roles::symbol(args[1])))
                      .with_snippets(ec.ec_source)
                      .with_help(attr_line_t("available levels: ")
                                     .join(lnav_zoom_strings, ", "))
                      .move();
        return Err(um);
    }
    if (!ec.ec_dry_run) {
        auto& ss = *lnav_data.ld_spectro_source;
        timeval old_time;

        lnav_data.ld_zoom_level = zoom_level.value();

        auto& hist_view = lnav_data.ld_views[LNV_HISTOGRAM];

        if (hist_view.get_inner_height() > 0) {
            auto old_time_opt = lnav_data.ld_hist_source2.time_for_row(
                lnav_data.ld_views[LNV_HISTOGRAM].get_top());
            if (old_time_opt) {
                old_time = old_time_opt.value().ri_time;
                rebuild_hist();
                lnav_data.ld_hist_source2.row_for_time(old_time) |
                    [](auto new_top) {
                        lnav_data.ld_views[LNV_HISTOGRAM].set_top(new_top);
                    };
            }
        }

        auto& spectro_view = lnav_data.ld_views[LNV_SPECTRO];

        if (spectro_view.get_inner_height() > 0) {
            auto old_time_opt = lnav_data.ld_spectro_source->time_for_row(
                lnav_data.ld_views[LNV_SPECTRO].get_selection().value_or(0_vl));
            ss.ss_granularity = ZOOM_LEVELS[lnav_data.ld_zoom_level];
            ss.invalidate();
            spectro_view.reload_data();
            if (old_time_opt) {
                lnav_data.ld_spectro_source->row_for_time(
                    old_time_opt.value().ri_time)
                    |
                    [](auto new_top) {
                        lnav_data.ld_views[LNV_SPECTRO].set_selection(new_top);
                    };
            }
        }

        lnav_data.ld_view_stack.set_needs_update();

        retval = fmt::format(FMT_STRING("info: set zoom-level to {}"),
                             lnav_zoom_strings[zoom_level.value()]);
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_reset_session(exec_context& ec,
                  std::string cmdline,
                  std::vector<std::string>& args)
{
    if (!ec.ec_dry_run) {
        reset_session();
        lnav_data.ld_views[LNV_LOG].reload_data();
    }

    return Ok(std::string());
}

static Result<std::string, lnav::console::user_message>
com_load_session(exec_context& ec,
                 std::string cmdline,
                 std::vector<std::string>& args)
{
    if (!ec.ec_dry_run) {
        load_session();
        lnav::session::apply_view_commands();
        lnav::session::restore_view_states();
        load_time_bookmarks();
        lnav_data.ld_views[LNV_LOG].reload_data();
    }

    return Ok(std::string());
}

static Result<std::string, lnav::console::user_message>
com_save_session(exec_context& ec,
                 std::string cmdline,
                 std::vector<std::string>& args)
{
    if (!ec.ec_dry_run) {
        save_session();
    }

    return Ok(std::string());
}

static Result<std::string, lnav::console::user_message>
com_set_min_log_level(exec_context& ec,
                      std::string cmdline,
                      std::vector<std::string>& args)
{
    std::string retval;

    if (args.size() == 2) {
        auto& lss = lnav_data.ld_log_source;
        auto new_level = string2level(args[1].c_str(), args[1].size(), false);
        if (ec.ec_dry_run) {
            lss.tss_preview_min_log_level = new_level;
            retval = fmt::format(
                FMT_STRING("info: previewing with min log level -- {}"),
                level_names[new_level]);
        } else {
            lss.set_min_log_level(new_level);
            retval = fmt::format(
                FMT_STRING("info: minimum log level is now -- {}"),
                level_names[new_level]);
        }
    } else {
        return ec.make_error("expecting a log level name");
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_hide_unmarked(exec_context& ec,
                  std::string cmdline,
                  std::vector<std::string>& args)
{
    std::string retval = "info: hid unmarked lines";

    if (ec.ec_dry_run) {
        retval = "";
    } else {
        auto* tc = *lnav_data.ld_view_stack.top();
        const auto& bv = tc->get_bookmarks()[&textview_curses::BM_USER];
        const auto& bv_expr
            = tc->get_bookmarks()[&textview_curses::BM_USER_EXPR];

        if (bv.empty() && bv_expr.empty()) {
            return ec.make_error("no lines have been marked");
        } else {
            lnav_data.ld_log_source.set_marked_only(true);
        }
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_show_unmarked(exec_context& ec,
                  std::string cmdline,
                  std::vector<std::string>& args)
{
    std::string retval = "info: showing unmarked lines";

    if (ec.ec_dry_run) {
        retval = "";
    } else {
        lnav_data.ld_log_source.set_marked_only(false);
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_shexec(exec_context& ec,
           std::string cmdline,
           std::vector<std::string>& args)
{
    if (!ec.ec_dry_run) {
        log_perror(system(cmdline.substr(args[0].size()).c_str()));
    }

    return Ok(std::string());
}

static Result<std::string, lnav::console::user_message>
com_poll_now(exec_context& ec,
             std::string cmdline,
             std::vector<std::string>& args)
{
    if (!ec.ec_dry_run) {
        isc::to<curl_looper&, services::curl_streamer_t>().send_and_wait(
            [](auto& clooper) { clooper.process_all(); });
    }

    return Ok(std::string());
}

static Result<std::string, lnav::console::user_message>
com_test_comment(exec_context& ec,
                 std::string cmdline,
                 std::vector<std::string>& args)
{
    return Ok(std::string());
}

static Result<std::string, lnav::console::user_message>
com_redraw(exec_context& ec,
           std::string cmdline,
           std::vector<std::string>& args)
{
    if (ec.ec_dry_run) {
    } else if (ec.ec_ui_callbacks.uc_redraw) {
        ec.ec_ui_callbacks.uc_redraw();
    }

    return Ok(std::string());
}

static auto CONFIG_HELP
    = help_text(":config")
          .with_summary("Read or write a configuration option")
          .with_parameter(
              help_text{"option", "The path to the option to read or write"}
                  .with_format(help_parameter_format_t::HPF_CONFIG_PATH))
          .with_parameter(
              help_text("value",
                        "The value to write.  If not given, the "
                        "current value is returned")
                  .optional()
                  .with_format(help_parameter_format_t::HPF_CONFIG_VALUE))
          .with_example({"To read the configuration of the "
                         "'/ui/clock-format' option",
                         "/ui/clock-format"})
          .with_example({"To set the '/ui/dim-text' option to 'false'",
                         "/ui/dim-text false"})
          .with_tags({"configuration"});

static Result<std::string, lnav::console::user_message>
com_config(exec_context& ec,
           std::string cmdline,
           std::vector<std::string>& args)
{
    static auto& prompt = lnav::prompt::get();

    std::string retval;

    if (args.size() > 1) {
        static const intern_string_t INPUT_SRC = intern_string::lookup("input");

        auto cmdline_sf = string_fragment::from_str(cmdline);
        auto parse_res = lnav::command::parse_for_call(
            ec,
            cmdline_sf.split_pair(string_fragment::tag1{' '})->second,
            CONFIG_HELP);
        if (parse_res.isErr()) {
            return Err(parse_res.unwrapErr());
        }
        auto parsed_args = parse_res.unwrap();

        log_debug("config dry run %zu %d",
                  args.size(),
                  prompt.p_editor.tc_popup.is_visible());
        if (ec.ec_dry_run && args.size() == 2
            && prompt.p_editor.tc_popup.is_visible())
        {
            prompt.p_editor.tc_popup.map_top_row(
                [&parsed_args](const attr_line_t& al) {
                    auto sub_opt = get_string_attr(al.al_attrs,
                                                   lnav::prompt::SUBST_TEXT);
                    if (sub_opt) {
                        auto sub = sub_opt->get();

                        log_debug("doing dry run with popup value");
                        auto& value_arg = parsed_args.p_args["value"];
                        value_arg.a_help = &CONFIG_HELP.ht_parameters[1];
                        value_arg.a_values.emplace_back(
                            shlex::split_element_t{{}, sub});
                    } else {
                        log_debug("completion does not have attr");
                    }
                });
        }

        yajlpp_parse_context ypc(INPUT_SRC, &lnav_config_handlers);
        std::vector<lnav::console::user_message> errors, errors_ignored;
        const auto& option = parsed_args.p_args["option"].a_values[0].se_value;

        lnav_config = rollback_lnav_config;
        ypc.set_path(option)
            .with_obj(lnav_config)
            .with_error_reporter([&errors](const auto& ypc, auto msg) {
                if (msg.um_level == lnav::console::user_message::level::error) {
                    errors.push_back(msg);
                }
            });
        ypc.ypc_active_paths[option] = 0;
        ypc.update_callbacks();

        const auto* jph = ypc.ypc_current_handler;

        if (jph == nullptr && !ypc.ypc_handler_stack.empty()) {
            jph = ypc.ypc_handler_stack.back();
        }

        if (jph != nullptr) {
            yajlpp_gen gen;
            yajlpp_gen_context ygc(gen, lnav_config_handlers);
            yajl_gen_config(gen, yajl_gen_beautify, 1);
            ygc.with_context(ypc);

            if (ypc.ypc_current_handler == nullptr) {
                ygc.gen();
            } else {
                jph->gen(ygc, gen);
            }

            auto old_value = gen.to_string_fragment().to_string();
            const auto& option_value = parsed_args.p_args["value"];

            if (option_value.a_values.empty()
                || ypc.ypc_current_handler == nullptr)
            {
                lnav_config = rollback_lnav_config;
                reload_config(errors);

                if (ec.ec_dry_run) {
                    attr_line_t al(old_value);

                    lnav_data.ld_preview_view[0].set_sub_source(
                        &lnav_data.ld_preview_source[0]);
                    lnav_data.ld_preview_source[0]
                        .replace_with(al)
                        .set_text_format(detect_text_format(old_value))
                        .truncate_to(10);
                    lnav_data.ld_preview_status_source[0]
                        .get_description()
                        .set_value("Value of option: %s", option.c_str());
                    lnav_data.ld_status[LNS_PREVIEW0].set_needs_update();

                    auto help_text = fmt::format(
                        FMT_STRING(
                            ANSI_BOLD("{}") " " ANSI_UNDERLINE("{}") " -- {}"),
                        jph->jph_property.c_str(),
                        jph->jph_synopsis,
                        jph->jph_description);

                    retval = help_text;
                } else {
                    retval = fmt::format(
                        FMT_STRING("{} = {}"), option, trim(old_value));
                }
            } else if (lnav_data.ld_flags.is_set<lnav_flags::secure_mode>()
                       && !startswith(option, "/ui/"))
            {
                return ec.make_error(":config {} -- unavailable in secure mode",
                                     option);
            } else {
                const auto& value = option_value.a_values[0].se_value;
                bool changed = false;

                if (ec.ec_dry_run) {
                    char help_text[1024];

                    snprintf(help_text,
                             sizeof(help_text),
                             ANSI_BOLD("%s %s") " -- %s",
                             jph->jph_property.c_str(),
                             jph->jph_synopsis,
                             jph->jph_description);

                    retval = help_text;
                }

                if (ypc.ypc_current_handler->jph_callbacks.yajl_string) {
                    yajl_string_props_t props{};
                    ypc.ypc_callbacks.yajl_string(
                        &ypc,
                        (const unsigned char*) value.c_str(),
                        value.size(),
                        &props);
                    changed = true;
                } else if (ypc.ypc_current_handler->jph_callbacks.yajl_integer)
                {
                    auto scan_res = scn::scan_value<int64_t>(value);
                    if (!scan_res || !scan_res->range().empty()) {
                        return ec.make_error("expecting an integer, found: {}",
                                             value);
                    }
                    ypc.ypc_callbacks.yajl_integer(&ypc, scan_res->value());
                    changed = true;
                } else if (ypc.ypc_current_handler->jph_callbacks.yajl_boolean)
                {
                    bool bvalue = false;

                    if (strcasecmp(value.c_str(), "true") == 0) {
                        bvalue = true;
                    }
                    ypc.ypc_callbacks.yajl_boolean(&ypc, bvalue);
                    changed = true;
                } else {
                    return ec.make_error("unhandled type");
                }

                while (!errors.empty()) {
                    if (errors.back().um_level
                        == lnav::console::user_message::level::error)
                    {
                        break;
                    }
                    errors.pop_back();
                }

                if (!errors.empty()) {
                    return Err(errors.back());
                }

                if (changed) {
                    intern_string_t path = intern_string::lookup(option);

                    lnav_config_locations[path]
                        = ec.ec_source.back().s_location;
                    reload_config(errors);

                    while (!errors.empty()) {
                        if (errors.back().um_level
                            == lnav::console::user_message::level::error)
                        {
                            break;
                        }
                        errors.pop_back();
                    }

                    if (!errors.empty()) {
                        lnav_config = rollback_lnav_config;
                        reload_config(errors_ignored);
                        return Err(errors.back());
                    }
                    if (!ec.ec_dry_run) {
                        retval = "info: changed config option -- " + option;
                        rollback_lnav_config = lnav_config;
                        if (!lnav_data.ld_flags
                                 .is_set<lnav_flags::secure_mode>())
                        {
                            save_config();
                        }
                    }
                }
            }
        } else {
            return ec.make_error("unknown configuration option -- {}", option);
        }
    } else {
        return ec.make_error(
            "expecting a configuration option to read or write");
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_reset_config(exec_context& ec,
                 std::string cmdline,
                 std::vector<std::string>& args)
{
    std::string retval;

    if (args.size() == 1) {
        return ec.make_error("expecting a configuration option to reset");
    }
    static const auto INPUT_SRC = intern_string::lookup("input");

    yajlpp_parse_context ypc(INPUT_SRC, &lnav_config_handlers);
    std::string option = args[1];

    while (!option.empty() && option.back() == '/') {
        option.pop_back();
    }
    lnav_config = rollback_lnav_config;
    ypc.set_path(option).with_obj(lnav_config);
    ypc.ypc_active_paths[option] = 0;
    ypc.update_callbacks();

    if (option == "*"
        || (ypc.ypc_current_handler != nullptr
            || !ypc.ypc_handler_stack.empty()))
    {
        if (!ec.ec_dry_run) {
            reset_config(option);
            rollback_lnav_config = lnav_config;
            if (!lnav_data.ld_flags.is_set<lnav_flags::secure_mode>()) {
                save_config();
            }
        }
        if (option == "*") {
            retval = "info: reset all options";
        } else {
            retval = "info: reset option -- " + option;
        }
    } else {
        return ec.make_error("unknown configuration option -- {}", option);
    }

    return Ok(retval);
}

// Background-prebuild support: when set, com_ssh_stats builds the report
// without flipping into the SSH view, so pressing `0` later switches
// instantly with no rebuild.  s_ssh_stats_cached_lines tracks the line
// count the cached report was built for; if the log grows or shrinks the
// next interactive (or prebuild) call will rebuild.
static bool s_ssh_stats_prebuild_mode = false;
static size_t s_ssh_stats_cached_lines = 0;

static Result<std::string, lnav::console::user_message>
com_ssh_stats(exec_context& ec,
              std::string cmdline,
              std::vector<std::string>& args)
{
    if (args.empty()) {
        return Ok(std::string());
    }
    if (ec.ec_dry_run) {
        return Ok(std::string());
    }

    const bool prebuild = s_ssh_stats_prebuild_mode;

    // If the SSH stats view is already showing, just dismiss it.
    // (In prebuild mode we never toggle.)
    if (!prebuild
        && *lnav_data.ld_view_stack.top()
            == &lnav_data.ld_views[LNV_SSH_STATS])
    {
        toggle_view(&lnav_data.ld_views[LNV_SSH_STATS]);
        return Ok(std::string());
    }

    auto& lss = lnav_data.ld_log_source;
    const size_t line_count = lss.text_line_count();

    // Fast path: report is already cached for the current log content.
    // For interactive calls, just switch into the prebuilt view.
    // For prebuild calls, nothing to do.
    if (s_ssh_stats_cached_lines == line_count && line_count > 0) {
        if (!prebuild) {
            ensure_view(&lnav_data.ld_views[LNV_SSH_STATS]);
        }
        return Ok(std::string());
    }

    // Background color for IOC-matched rows (Nord dark: #2e3440)
    static const auto IOC_BG = VC_BACKGROUND.value(
        styling::color_unit::from_rgb(rgb_color{0x2e, 0x34, 0x40}));

    auto is_ioc_ip = [](const std::string& ip) -> bool {
        return !lnav_data.ld_ioc_ips.empty()
            && lnav_data.ld_ioc_ips.count(ip) > 0;
    };

    // Flow key: (src_ip, dest_host, outcome, auth_source)
    using FlowKey = std::tuple<std::string, std::string, std::string, std::string>;
    struct FlowRecord {
        std::map<std::string, size_t> user_counts;
        size_t count = 0;
    };
    std::map<FlowKey, FlowRecord> flows;
    std::set<std::string> unique_sources;
    size_t total_ssh_events = 0;

    // SSH event type counters
    size_t ev_accepted{0}, ev_failed_pw{0}, ev_failed_pk{0};
    size_t ev_invalid_user{0}, ev_too_many{0};
    size_t ev_disconnected{0}, ev_closed_preauth{0};
    size_t ev_client_disc{0}, ev_closed{0}, ev_new_conn{0};

    // IP frequency map
    std::map<std::string, size_t> ip_counts;

    // --- Helpers ---

    // First whitespace-delimited word after a literal marker in a line
    auto extract_word_after
        = [](const std::string& line, const std::string& marker) -> std::string {
        auto pos = line.find(marker);
        if (pos == std::string::npos) {
            return {};
        }
        pos += marker.size();
        while (pos < line.size() && line[pos] == ' ') {
            ++pos;
        }
        auto end = line.find(' ', pos);
        return line.substr(pos,
                           end == std::string::npos ? std::string::npos
                                                    : end - pos);
    };

    // Strip a matching pair of surrounding single or double quotes
    auto strip_quotes = [](std::string s) -> std::string {
        if (s.size() >= 2
            && ((s.front() == '\'' && s.back() == '\'')
                || (s.front() == '"' && s.back() == '"')))
        {
            return s.substr(1, s.size() - 2);
        }
        return s;
    };

    // Extract the syslog hostname by finding the word immediately before
    // "sshd[" or "sshd:".  This works regardless of the timestamp format
    // (BSD "Mon DD HH:MM:SS host", ISO "YYYY-MM-DDTHH:MM:SS host", etc.)
    auto extract_syslog_host
        = [](const std::string& line) -> std::string {
        size_t sshd_pos = line.find("sshd[");
        if (sshd_pos == std::string::npos) {
            sshd_pos = line.find("sshd:");
        }
        if (sshd_pos == 0 || sshd_pos == std::string::npos) {
            return {};
        }
        // Back up past any spaces before "sshd"
        size_t end = sshd_pos - 1;
        while (end > 0 && line[end] == ' ') {
            --end;
        }
        // Find start of the word
        size_t start = line.rfind(' ', end);
        start = (start == std::string::npos) ? 0 : start + 1;
        return line.substr(start, end - start + 1);
    };

    // Identify authentication source from a log line.
    // Checks sshd "Accepted <method>" first, then PAM module names.
    // Coverage:
    //   password              → local /etc/shadow
    //   publickey             → SSH public key
    //   gssapi-with-mic/keyex → Kerberos/GSSAPI
    //   keyboard-interactive  → falls through to PAM module detection
    //   hostbased             → host-based trust
    //   pam_sss               → SSSD (FreeIPA / LDAP / Active Directory via SSSD)
    //   pam_krb5              → MIT/Heimdal Kerberos via PAM
    //   pam_winbind           → Samba Winbind (Windows AD)
    //   pam_google_authenticator / pam_duo / pam_oath / pam_yubico → MFA/OTP
    //   pam_fprintd           → biometric (fingerprint)
    //   pam_radius_auth       → RADIUS (network auth server)
    //   pam_ldap              → legacy direct LDAP (nss_ldap era)
    //   pam_pkcs11            → smartcard / PIV token
    auto detect_auth_source = [](const std::string& line) -> std::string {
        // SSH method from "Accepted <method> for ..." — most reliable
        {
            auto pos = line.find("Accepted ");
            if (pos != std::string::npos) {
                pos += 9;
                auto end  = line.find(' ', pos);
                auto meth = line.substr(
                    pos, end == std::string::npos ? std::string::npos : end - pos);
                if (meth == "password")                        return "local (/etc/shadow)";
                if (meth == "publickey")                       return "public key";
                if (meth == "gssapi-with-mic"
                    || meth == "gssapi-keyex")                 return "Kerberos/GSSAPI";
                if (meth == "hostbased")                       return "host-based";
                if (meth == "none")                            return "none (no auth)";
                // keyboard-interactive: fall through to PAM detection below
            }
        }
        // PAM module detection (keyboard-interactive and explicit PAM log lines)
        if (line.find("pam_sss")                  != std::string::npos) return "SSSD (LDAP/AD/IPA)";
        if (line.find("pam_krb5")                 != std::string::npos) return "Kerberos (pam_krb5)";
        if (line.find("pam_winbind")              != std::string::npos) return "Winbind/AD";
        if (line.find("pam_google_authenticator") != std::string::npos) return "MFA/Google Auth";
        if (line.find("pam_duo")                  != std::string::npos) return "MFA/Duo";
        if (line.find("pam_oath")                 != std::string::npos) return "MFA/OTP";
        if (line.find("pam_yubico")               != std::string::npos) return "MFA/YubiKey";
        if (line.find("pam_fprintd")              != std::string::npos) return "Biometric";
        if (line.find("pam_radius")               != std::string::npos) return "RADIUS";
        if (line.find("pam_pkcs11")               != std::string::npos) return "Smartcard/PIV";
        if (line.find("pam_ldap")                 != std::string::npos) return "LDAP";
        if (line.find("keyboard-interactive")     != std::string::npos) return "PAM (interactive)";
        return "";
    };

    // Count UTF-8 code points — equals visual terminal width for BMP characters
    auto vlen = [](const std::string& s) -> int {
        int w = 0;
        for (unsigned char c : s) {
            if ((c & 0xC0u) != 0x80u) {
                ++w;
            }
        }
        return w;
    };

    // Return true if the string resembles an IP address (contains '.' or ':')
    // Used to reject words like "user", "invalid", etc. that are not IPs.
    auto is_ip = [](const std::string& s) -> bool {
        if (s.empty()) return false;
        return s.find('.') != std::string::npos
            || s.find(':') != std::string::npos;
    };

    // Emit one SSH event into the flow map
    auto emit_flow = [&](const std::string& src_ip,
                         const std::string& host,
                         const std::string& outcome,
                         const std::string& auth_source,
                         const std::string& user)
    {
        FlowKey key{src_ip, host, outcome, auth_source};
        auto& rec = flows[key];
        rec.count++;
        if (!user.empty()) {
            rec.user_counts[user]++;
        }
        if (!src_ip.empty()) {
            unique_sources.insert(src_ip);
        }
        ++total_ssh_events;
    };

    // Show the panel immediately with a placeholder so the user sees it's working,
    // and kick off the Pac-Man animation in the bottom bar right away.
    // (Skipped during background prebuild — we don't want to switch views.)
    if (!prebuild) {
        attr_line_t placeholder;
        placeholder.append(" Computing SSH Traffic Flow Map"_h1);
        lnav_data.ld_ssh_stats_source.replace_with(placeholder);
        lnav_data.ld_views[LNV_SSH_STATS].reload_data();
        ensure_view(&lnav_data.ld_views[LNV_SSH_STATS]);
        lnav_data.ld_bottom_source.update_loading(0, line_count, "SSH Stats");
        lnav_data.ld_status[LNS_BOTTOM].set_needs_update();
        lnav_data.ld_status_refresher(lnav::func::op_type::blocking);
    }

    // --- Scan log lines ---
    static const auto& ui_timer = ui_periodic_timer::singleton();
    sig_atomic_t ssh_progress_counter = 0;
    for (size_t vl_idx = 0; vl_idx < line_count; ++vl_idx) {
        if (ui_timer.time_to_update(ssh_progress_counter)) {
            lnav_data.ld_bottom_source.update_loading(vl_idx, line_count, "SSH Stats");
            lnav_data.ld_status[LNS_BOTTOM].set_needs_update();
            lnav_data.ld_status_refresher(lnav::func::op_type::blocking);
        }
        auto cl = lss.at(vis_line_t(vl_idx));
        auto line_opt = lss.find_line_with_file(cl);
        if (!line_opt) {
            continue;
        }
        auto& [lf, ll_iter] = *line_opt;
        auto read_res = lf->read_line(ll_iter);
        if (read_res.isErr()) {
            continue;
        }
        auto sbr      = read_res.unwrap();
        auto sf       = sbr.to_string_fragment();
        auto line_str = sf.to_string();

        // IP address extraction via data_scanner (all lines)
        data_scanner ds(sf);
        while (true) {
            auto tok_res = ds.tokenize2();
            if (!tok_res) {
                break;
            }
            if (tok_res->tr_token == DT_IPV4_ADDRESS
                || tok_res->tr_token == DT_IPV6_ADDRESS)
            {
                ip_counts[tok_res->to_string()]++;
            } else if (tok_res->tr_token == DT_QUOTED_STRING) {
                auto inner_sf = tok_res->inner_string_fragment();
                data_scanner inner_ds(inner_sf, false);
                auto inner_tok = inner_ds.tokenize2();
                if (inner_tok
                    && (inner_tok->tr_token == DT_IPV4_ADDRESS
                        || inner_tok->tr_token == DT_IPV6_ADDRESS)
                    && inner_tok->tr_capture.length() == inner_sf.length())
                {
                    ip_counts[inner_tok->to_string()]++;
                }
            }
        }

        auto host = extract_syslog_host(line_str);

        // Generic source-IP extraction: covers "... from <ip> ..." patterns.
        // Validated with is_ip() to reject words like "user" or "invalid" that
        // follow " from " in "Disconnected from user ..." or similar phrases.
        auto raw_ip = extract_word_after(line_str, " from ");
        if (raw_ip.empty()) {
            raw_ip = extract_word_after(line_str, "Connection from ");
        }
        if (raw_ip.empty()
            && line_str.find("Connection closed by") != std::string::npos)
        {
            auto after_by = extract_word_after(line_str, " by ");
            if (after_by != "invalid") {
                raw_ip = after_by;
            } else {
                auto utmp = extract_word_after(line_str, "invalid user ");
                raw_ip   = extract_word_after(line_str, utmp + " ");
            }
        }
        raw_ip = strip_quotes(raw_ip);
        auto src_ip = is_ip(raw_ip) ? raw_ip : std::string{};

        auto auth = detect_auth_source(line_str);

        // Classify and emit
        if (line_str.find("Accepted ") != std::string::npos) {
            ++ev_accepted;
            auto user = extract_word_after(line_str, " for ");
            emit_flow(src_ip, host, "\xE2\x9C\x93 Accepted", auth, user);

        } else if (line_str.find("Disconnecting: Too many") != std::string::npos
                   || line_str.find("Too many authentication failures")
                          != std::string::npos)
        {
            ++ev_too_many;
            auto user = extract_word_after(line_str, " for ");
            emit_flow(src_ip, host, "\xE2\x9C\x97 Too many failures", auth, user);

        } else if (line_str.find("Failed password")  != std::string::npos
                   || line_str.find("Failed publickey") != std::string::npos
                   || line_str.find("Failed keyboard")  != std::string::npos)
        {
            if (line_str.find("Failed publickey") != std::string::npos) {
                ++ev_failed_pk;
            } else {
                ++ev_failed_pw;
            }
            auto user_raw = extract_word_after(line_str, "Failed password for ");
            if (user_raw.empty()) {
                user_raw = extract_word_after(line_str, "Failed publickey for ");
            }
            if (user_raw.empty()) {
                user_raw
                    = extract_word_after(line_str, "Failed keyboard-interactive for ");
            }
            auto user = (user_raw == "invalid")
                ? extract_word_after(line_str, "invalid user ")
                : user_raw;
            emit_flow(src_ip, host, "\xE2\x9C\x97 Failed auth", auth, user);

        } else if (line_str.find("Invalid user ") != std::string::npos) {
            ++ev_invalid_user;
            auto user = extract_word_after(line_str, "Invalid user ");
            emit_flow(src_ip, host, "\xE2\x9C\x97 Invalid user", auth, user);

        } else if (line_str.find("authenticating user ") != std::string::npos) {
            // Modern OpenSSH (8+) preauth close patterns:
            //   "Connection closed by authenticating user <u> <ip> port <p> [preauth]"
            //   "Disconnected from authenticating user <u> <ip> port <p> [preauth]"
            ++ev_closed_preauth;
            auto user    = extract_word_after(line_str, "authenticating user ");
            auto auth_ip = extract_word_after(line_str,
                                              "authenticating user " + user + " ");
            auto ip = is_ip(auth_ip) ? auth_ip : src_ip;
            emit_flow(ip, host, "\xE2\x8A\x98 Closed (preauth)", auth, user);

        } else if (line_str.find("Disconnected from user ") != std::string::npos) {
            ++ev_disconnected;
            // Pattern: "Disconnected from user <user> <ip> port <port>"
            // Generic src_ip extraction yields "user" (not an IP) so we
            // extract the IP explicitly from after the username.
            auto user   = extract_word_after(line_str, "Disconnected from user ");
            auto disc_ip = extract_word_after(line_str,
                                              "Disconnected from user " + user + " ");
            auto ip = is_ip(disc_ip) ? disc_ip : src_ip;
            emit_flow(ip, host, "\xE2\x8A\x98 Disconnected", auth, user);

        } else if (line_str.find("Disconnected from") != std::string::npos) {
            ++ev_disconnected;
            emit_flow(src_ip, host, "\xE2\x8A\x98 Disconnected", auth, "");

        } else if ((line_str.find("Received disconnect from") != std::string::npos
                    || line_str.find("Connection closed by") != std::string::npos)
                   && line_str.find("[preauth]") != std::string::npos)
        {
            ++ev_closed_preauth;
            emit_flow(src_ip, host, "\xE2\x8A\x98 Closed (preauth)", auth, "");

        } else if (line_str.find("Received disconnect from") != std::string::npos) {
            ++ev_client_disc;
            auto user = extract_word_after(line_str, "disconnected by user ");
            emit_flow(src_ip, host, "\xE2\x8A\x98 Client disconnect", auth, user);

        } else if (line_str.find("Connection closed by") != std::string::npos) {
            ++ev_closed;
            auto user = extract_word_after(line_str, "closed by invalid user ");
            emit_flow(src_ip, host, "\xE2\x8A\x98 Closed", auth, user);

        } else if (line_str.find("Connection from ") != std::string::npos
                   || line_str.find("connection from ") != std::string::npos)
        {
            ++ev_new_conn;
            emit_flow(src_ip, host, "\xE2\x86\x92 Connection", auth, "");

        } else {
            continue;
        }
    }
    lnav_data.ld_bottom_source.update_loading(0, 0);

    // Sort flows by source IP, then by outcome, then by dest host
    std::vector<std::pair<FlowKey, size_t>> sorted_flows;
    sorted_flows.reserve(flows.size());
    for (auto& [key, rec] : flows) {
        sorted_flows.emplace_back(key, rec.count);
    }
    std::sort(sorted_flows.begin(),
              sorted_flows.end(),
              [](const auto& a, const auto& b) {
                  return a.first < b.first;
              });

    // Returns true for RFC-1918, loopback, link-local, and IPv6 ULA/loopback
    auto is_private_ip = [](const std::string& ip) -> bool {
        // IPv6 loopback / ULA / link-local
        if (ip.find(':') != std::string::npos) {
            if (ip == "::1") return true;
            // fe80::/10  (link-local)
            if (ip.size() >= 4
                && (ip.substr(0, 4) == "fe80" || ip.substr(0, 4) == "FE80"))
                return true;
            // fc00::/7  (unique local: fc** and fd**)
            if (ip.size() >= 2) {
                auto pfx = ip.substr(0, 2);
                if (pfx == "fc" || pfx == "fd" || pfx == "FC" || pfx == "FD")
                    return true;
            }
            return false;
        }
        // Parse dotted-decimal IPv4
        unsigned a = 0, b = 0, c = 0, d = 0;
        if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4)
            return false;
        if (a == 10) return true;                            // 10.0.0.0/8
        if (a == 127) return true;                           // 127.0.0.0/8
        if (a == 172 && b >= 16 && b <= 31) return true;    // 172.16.0.0/12
        if (a == 192 && b == 168) return true;               // 192.168.0.0/16
        if (a == 169 && b == 254) return true;               // 169.254.0.0/16
        return false;
    };

    // Sort IPs by count descending, split into private and public
    std::vector<std::pair<size_t, std::string>> private_ips, public_ips;
    for (auto& [ip, cnt] : ip_counts) {
        if (is_private_ip(ip))
            private_ips.emplace_back(cnt, ip);
        else
            public_ips.emplace_back(cnt, ip);
    }
    auto ip_cmp = [](const auto& a, const auto& b) { return a.first > b.first; };
    std::sort(private_ips.begin(), private_ips.end(), ip_cmp);
    std::sort(public_ips.begin(), public_ips.end(), ip_cmp);

    // --- Build report ---
    attr_line_t report;

    // Repeat a multi-byte UTF-8 character n times
    auto rep = [](const char* ch, size_t n) {
        std::string s;
        s.reserve(n * 3);
        for (size_t i = 0; i < n; ++i) {
            s += ch;
        }
        return s;
    };

    // Pad string to `target` visual columns (right-fills with spaces)
    auto padr = [&vlen](const std::string& s, int target) {
        return std::string(std::max(0, target - vlen(s)), ' ');
    };

    // Column visual widths:
    //   IP=18, fixed "  SSH →  "=9, Dest=15, gap=2,
    //   Outcome=22, gap=2, User=22, gap=2, Auth=22, gap=2, Count=6, gap=2, Pct="%"=1
    // Total content width (after 2-space indent):
    //   18+9+15+2+22+2+22+2+22+2+6+2+1 = 125
    // So BAR/THIN = "  " + 125 chars
    const int CONTENT_W = 125;
    const std::string BAR  = "  " + rep("\xE2\x95\x90", CONTENT_W); // ═
    const std::string THIN = "  " + rep("\xE2\x94\x80", CONTENT_W); // ─

    // Visual column start of the User field (used for continuation rows):
    //   indent(2) + IP(18) + "  SSH →  "(9) + Dest(15) + gap(2) + Outcome(22) + gap(2) = 70
    const int USER_COL = 70;

    // ── Section 1: SSH Traffic Flow Map ──────────────────────────────────────
    report.append(BAR + "\n");
    report.append("  SSH TRAFFIC FLOW MAP\n"_h1);
    report.append(BAR + "\n");
    report.append("  Total SSH events : ")
        .append(lnav::roles::number(fmt::to_string(total_ssh_events)))
        .append("\n");
    report.append("  Unique sources   : ")
        .append(lnav::roles::number(fmt::to_string(unique_sources.size())))
        .append("\n");
    report.append(BAR + "\n");

    if (flows.empty()) {
        report.append("  (no SSH events found in loaded logs)\n"_comment);
    } else {
        // Header row
        auto hdr_ip  = std::string("Source IP");
        auto hdr_dst = std::string("Destination");
        auto hdr_out = std::string("Outcome");
        auto hdr_usr = std::string("User(s)");
        auto hdr_ath = std::string("Auth source");
        report.append("  ")
            .append(hdr_ip).append(padr(hdr_ip, 18))
            .append("  SSH \xE2\x86\x92  ")
            .append(hdr_dst).append(padr(hdr_dst, 15))
            .append("  ")
            .append(hdr_out).append(padr(hdr_out, 22))
            .append("  ")
            .append(hdr_usr).append(padr(hdr_usr, 22))
            .append("  ")
            .append(hdr_ath).append(padr(hdr_ath, 22))
            .append("  ")
            .appendf(FMT_STRING("{:>6}  {}\n"), "Count", "%");
        // Separator: exactly CONTENT_W chars wide
        report.append(THIN + "\n");

        // Data rows
        for (const auto& [key, cnt] : sorted_flows) {
            const auto& [src_ip, dest_host, outcome, auth_source] = key;
            auto& rec = flows[key];

            // Sort users by frequency descending
            std::vector<std::pair<size_t, std::string>> su;
            su.reserve(rec.user_counts.size());
            for (auto& [u, c] : rec.user_counts) {
                su.emplace_back(c, u);
            }
            std::sort(su.begin(), su.end(), [](const auto& a, const auto& b) {
                return a.first > b.first;
            });

            auto first_user = su.empty() ? std::string("\xE2\x80\x94")  // —
                                         : su[0].second;
            auto src_d  = src_ip.empty()     ? "\xE2\x80\x94" : src_ip;
            auto dst_d  = dest_host.empty()  ? "\xE2\x80\x94" : dest_host;
            auto auth_d = auth_source.empty()? "\xE2\x80\x94" : auth_source;
            auto cnt_str = fmt::to_string(cnt);
            auto pct_str = fmt::format(
                FMT_STRING("{:.1f}%"),
                total_ssh_events > 0 ? (100.0 * cnt / total_ssh_events) : 0.0);

            // Main row — first user inline
            attr_line_t row_line;
            row_line.append("  ")
                .append(lnav::roles::identifier(src_d))
                .append(padr(src_d, 18))
                .append("  SSH \xE2\x86\x92  ")
                .append(lnav::roles::identifier(dst_d))
                .append(padr(dst_d, 15))
                .append("  ")
                .append(outcome)
                .append(padr(outcome, 22))
                .append("  ")
                .append(lnav::roles::identifier(first_user))
                .append(padr(first_user, 22))
                .append("  ")
                .append(auth_d)
                .append(padr(auth_d, 22))
                .append("  ")
                .append(std::string(std::max(0, 6 - (int)cnt_str.size()), ' '))
                .append(lnav::roles::number(cnt_str))
                .append("  ")
                .append(pct_str)
                .append("\n");
            if (is_ioc_ip(src_ip)) {
                row_line.with_attr_for_all(IOC_BG);
            }
            report.append(row_line);

            // Continuation rows — remaining users, aligned to USER_COL
            for (size_t i = 1; i < su.size(); ++i) {
                report.append(std::string(USER_COL, ' '))
                    .append(lnav::roles::identifier(su[i].second))
                    .append("\n");
            }
        }
    }

    // ── Section 2: SSH Event Summary ─────────────────────────────────────────
    report.append("\n").append(BAR + "\n");
    report.append("  SSH EVENT SUMMARY\n"_h1);
    report.append(BAR + "\n");

    auto add_stat = [&](const char* label, size_t count) {
        report.appendf(FMT_STRING("  {:<40}"), label)
            .append(lnav::roles::number(fmt::to_string(count)))
            .append("\n");
    };
    add_stat("Successful authentications :", ev_accepted);
    add_stat("Failed password attempts   :", ev_failed_pw);
    add_stat("Failed publickey attempts  :", ev_failed_pk);
    add_stat("Invalid user attempts      :", ev_invalid_user);
    add_stat("Too many auth failures     :", ev_too_many);
    add_stat("Disconnections             :", ev_disconnected);
    add_stat("Closed (preauth)           :", ev_closed_preauth);
    add_stat("Client disconnects         :", ev_client_disc);
    add_stat("Connection closed          :", ev_closed);
    add_stat("New connections            :", ev_new_conn);

    // ── Section 3: IP Address Frequency ──────────────────────────────────────
    {
        size_t total_unique = private_ips.size() + public_ips.size();
        report.append("\n").append(BAR + "\n");
        report.append("  IP ADDRESSES  ("_h1)
            .append(lnav::roles::number(fmt::to_string(total_unique)))
            .append(" unique)\n"_h1);
        report.append(BAR + "\n");

        if (!lnav_data.ld_ioc_ips.empty()) {
            size_t ioc_hits = 0;
            for (const auto& [ip, cnt] : ip_counts) {
                if (lnav_data.ld_ioc_ips.count(ip)) {
                    ++ioc_hits;
                }
            }
            report.append("  IOC matches      : ")
                .append(lnav::roles::number(fmt::to_string(ioc_hits)))
                .append(" / ")
                .append(lnav::roles::number(fmt::to_string(lnav_data.ld_ioc_ips.size())))
                .append(" IPs from IOC file\n");
            report.append(BAR + "\n");
        }

        if (total_unique == 0) {
            report.append("  (no IP addresses found in loaded logs)\n"_comment);
        } else {
            // Column header + separator shared by both sub-sections
            auto emit_ip_group
                = [&](const std::vector<std::pair<size_t, std::string>>& group,
                       const std::pair<string_fragment, role_t>& label)
            {
                report.append("  ").append(label).append("\n");
                report.appendf(FMT_STRING("  {:<45} {}\n"), "Address", "Count");
                report.append("  " + rep("\xE2\x94\x80", 51) + "\n");
                for (const auto& [cnt, ip] : group) {
                    auto cnt_str = fmt::to_string(cnt);
                    attr_line_t ip_line;
                    ip_line.append("  ")
                        .append(lnav::roles::identifier(ip))
                        .append(padr(ip, 45))
                        .append(" ")
                        .append(lnav::roles::number(cnt_str))
                        .append("\n");
                    if (is_ioc_ip(ip)) {
                        ip_line.with_attr_for_all(IOC_BG);
                    }
                    report.append(ip_line);
                }
            };

            if (!public_ips.empty()) {
                emit_ip_group(public_ips, "PUBLIC IPs"_h2);
            }
            if (!private_ips.empty()) {
                if (!public_ips.empty()) report.append("\n");
                emit_ip_group(private_ips, "PRIVATE IPs"_h2);
            }
        }
    }

    lnav_data.ld_ssh_stats_source.replace_with(report);
    lnav_data.ld_views[LNV_SSH_STATS].reload_data();
    s_ssh_stats_cached_lines = line_count;

    return Ok(std::string());
}

// Public entry point for background SSH-stats prebuild.  Called from
// rebuild_indexes_repeatedly() once the log content has settled.  No-op
// when the report is already cached for the current line count, when
// there are no log lines yet, when a scan is interruptible, or when
// re-entered.
void
prewarm_ssh_stats()
{
    if (s_ssh_stats_prebuild_mode) {
        return;
    }
    auto& lss = lnav_data.ld_log_source;
    const size_t line_count = lss.text_line_count();
    if (line_count == 0 || line_count == s_ssh_stats_cached_lines) {
        return;
    }
    auto top = lnav_data.ld_view_stack.top();
    if (top && *top == &lnav_data.ld_views[LNV_SSH_STATS]) {
        // User is currently viewing it; the next interactive call will rebuild.
        return;
    }
    s_ssh_stats_prebuild_mode = true;
    std::vector<std::string> args = {"ssh-stats"};
    auto res = com_ssh_stats(lnav_data.ld_exec_context, "ssh-stats", args);
    s_ssh_stats_prebuild_mode = false;
    if (res.isErr()) {
        log_warning("ssh-stats prebuild failed");
    }
}

// ---------------------------------------------------------------------------
// Shared helpers for :session-trace and :log-gaps
// ---------------------------------------------------------------------------

static std::string
forensic_format_tv(const timeval& tv, time_t local_offset = 0)
{
    bool normalize = lnav_data.ld_log_source.get_normalize_timestamps();
    char buf[64];
    struct tm tm;
    if (normalize) {
        time_t true_utc = tv.tv_sec - local_offset;
        gmtime_r(&true_utc, &tm);
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
    } else {
        gmtime_r(&tv.tv_sec, &tm);
        strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm);
    }
    return std::string(buf) + fmt::format(FMT_STRING(".{:06d}"), tv.tv_usec);
}

static std::string
forensic_format_duration(int64_t secs)
{
    if (secs >= 3600) {
        return fmt::format(FMT_STRING("{}h {:02d}m {:02d}s"),
                           secs / 3600, (secs % 3600) / 60, secs % 60);
    }
    if (secs >= 60) {
        return fmt::format(FMT_STRING("{}m {:02d}s"), secs / 60, secs % 60);
    }
    return fmt::format(FMT_STRING("{}s"), secs);
}

// --- session-trace cached state ---
struct st_trace_line {
    timeval tv;
    time_t local_offset{0};
    std::string filename;
    std::string text;
    log_level_t level{log_level_t::LEVEL_UNKNOWN};
};

struct st_session_info {
    timeval start_tv;
    timeval end_tv;
    time_t local_offset{0};
    std::string source_ip;
    std::string user;
    std::string outcome;
    std::vector<size_t> line_indices;
};

static std::string s_session_trace_target;
static std::vector<st_trace_line> s_session_trace_lines;
static std::vector<st_session_info> s_session_trace_sessions;

static void
rebuild_session_trace_report()
{
    if (s_session_trace_target.empty() && s_session_trace_sessions.empty()) {
        return;
    }

    std::vector<attr_line_t> lines;
    std::vector<vis_line_t> session_header_lines;

    // Helper: push a plain text line
    auto push_line = [&lines](const std::string& text) {
        lines.emplace_back(text);
    };

    // Helper: push a log line with SA_LEVEL + token-level coloring
    auto push_log_line = [&lines](const std::string& text, log_level_t level) {
        auto& vc = view_colors::singleton();
        attr_line_t al(text);
        al.al_attrs.emplace_back(
            line_range{0, -1},
            SA_LEVEL.value(static_cast<int64_t>(level)));

        // Find the start of the original log text (after "| ")
        auto pipe_pos = text.find(" | ");
        if (pipe_pos != std::string::npos) {
            auto body_start = (int) (pipe_pos + 3);
            auto body_sf = string_fragment::from_str_range(
                text, body_start, text.size());
            data_scanner ds(body_sf);
            while (true) {
                auto tok_res = ds.tokenize2();
                if (!tok_res) {
                    break;
                }
                auto token_lr = line_range{
                    tok_res->tr_capture.c_begin,
                    tok_res->tr_capture.c_end};
                switch (tok_res->tr_token) {
                    case DT_IPV4_ADDRESS:
                    case DT_IPV6_ADDRESS:
                    case DT_MAC_ADDRESS:
                    case DT_UUID:
                    case DT_URL:
                    case DT_PATH:
                    case DT_EMAIL:
                    case DT_WORD:
                    case DT_ID:
                    case DT_CONSTANT: {
                        auto ident_attrs = vc.attrs_for_ident(
                            &text[tok_res->tr_capture.c_begin],
                            tok_res->tr_capture.length());
                        al.al_attrs.emplace_back(
                            token_lr, VC_STYLE.value(ident_attrs));
                        break;
                    }
                    case DT_NUMBER:
                    case DT_HEX_NUMBER:
                    case DT_OCTAL_NUMBER:
                        al.al_attrs.emplace_back(
                            token_lr,
                            VC_ROLE.value(role_t::VCR_NUMBER));
                        break;
                    case DT_QUOTED_STRING:
                        al.al_attrs.emplace_back(
                            token_lr,
                            VC_ROLE.value(role_t::VCR_STRING));
                        break;
                    default:
                        break;
                }
            }
        }

        lines.emplace_back(std::move(al));
    };

    push_line(fmt::format(
        FMT_STRING(" Session Trace: {} ({} sessions, {} matching lines)"),
        s_session_trace_target,
        s_session_trace_sessions.size(),
        s_session_trace_lines.size()));

    // --- Forensic Summary ---
    if (!s_session_trace_sessions.empty()) {
        // Gather aggregated data across all sessions and lines
        std::set<std::string> all_files;
        std::set<std::string> all_ips;
        std::set<std::string> all_users;
        size_t auth_accepted = 0;
        size_t auth_failed = 0;
        size_t outcome_closed = 0;
        size_t outcome_opened = 0;
        size_t outcome_unknown = 0;
        size_t level_error = 0;
        size_t level_warning = 0;
        int64_t longest_dur = -1;
        size_t longest_idx = 0;

        static const auto auth_accept_re
            = lnav::pcre2pp::code::from_const(
                R"((?i)(?:Accepted |session opened|authenticated|login successful))");
        static const auto auth_fail_re
            = lnav::pcre2pp::code::from_const(
                R"((?i)(?:Failed |authentication failure|invalid user|failed password|access denied|login failed|permission denied))");

        for (auto& ml : s_session_trace_lines) {
            all_files.insert(ml.filename);

            if (ml.level == log_level_t::LEVEL_ERROR
                || ml.level == log_level_t::LEVEL_CRITICAL
                || ml.level == log_level_t::LEVEL_FATAL)
            {
                ++level_error;
            } else if (ml.level == log_level_t::LEVEL_WARNING) {
                ++level_warning;
            }

            auto line_sf = string_fragment::from_str(ml.text);
            if (auth_accept_re.find_in(line_sf).ignore_error().has_value()) {
                ++auth_accepted;
            }
            if (auth_fail_re.find_in(line_sf).ignore_error().has_value()) {
                ++auth_failed;
            }
        }

        for (size_t si = 0; si < s_session_trace_sessions.size(); ++si) {
            auto& sess = s_session_trace_sessions[si];

            if (!sess.source_ip.empty()) {
                all_ips.insert(sess.source_ip);
            }
            if (!sess.user.empty()) {
                all_users.insert(sess.user);
            }

            if (sess.outcome == "closed") {
                ++outcome_closed;
            } else if (sess.outcome == "opened") {
                ++outcome_opened;
            } else {
                ++outcome_unknown;
            }

            int64_t dur = sess.end_tv.tv_sec - sess.start_tv.tv_sec;
            if (dur > longest_dur) {
                longest_dur = dur;
                longest_idx = si;
            }
        }

        // Also scan all lines for IPs not captured in session metadata
        {
            auto extract_all_ips
                = [](const std::string& line,
                     std::set<std::string>& out) {
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
                              out.insert(tok_res->to_string());
                          }
                      }
                  };
            for (auto& ml : s_session_trace_lines) {
                extract_all_ips(ml.text, all_ips);
            }
        }

        // First/last timestamps
        auto& first_line = s_session_trace_lines.front();
        auto& last_line = s_session_trace_lines.back();
        int64_t total_span = last_line.tv.tv_sec - first_line.tv.tv_sec;

        push_line("");
        session_header_lines.push_back(
            vis_line_t(static_cast<int>(lines.size())));
        push_line("── Summary ──");
        push_line(fmt::format(
            FMT_STRING("  First Seen: {}"),
            forensic_format_tv(first_line.tv, first_line.local_offset)));
        push_line(fmt::format(
            FMT_STRING("  Last Seen:  {}"),
            forensic_format_tv(last_line.tv, last_line.local_offset)));
        push_line(fmt::format(
            FMT_STRING("  Time Span:  {}"),
            forensic_format_duration(total_span)));

        // Log files
        {
            std::string files_str;
            for (auto& f : all_files) {
                if (!files_str.empty()) {
                    files_str += ", ";
                }
                files_str += f;
            }
            push_line(fmt::format(
                FMT_STRING("  Log Files:  {}"), files_str));
        }

        // IPs seen
        if (!all_ips.empty()) {
            std::string ips_str;
            for (auto& ip : all_ips) {
                if (!ips_str.empty()) {
                    ips_str += ", ";
                }
                ips_str += ip;
            }
            push_line(fmt::format(
                FMT_STRING("  IPs Seen:   {}"), ips_str));
        }

        // Users seen
        if (!all_users.empty()) {
            std::string users_str;
            for (auto& u : all_users) {
                if (!users_str.empty()) {
                    users_str += ", ";
                }
                users_str += u;
            }
            push_line(fmt::format(
                FMT_STRING("  Users Seen: {}"), users_str));
        }

        // Auth counts
        if (auth_accepted > 0 || auth_failed > 0) {
            push_line(fmt::format(
                FMT_STRING("  Auth:       {} accepted, {} failed"),
                auth_accepted, auth_failed));
        }

        // Outcomes
        {
            std::string outcome_str;
            if (outcome_closed > 0) {
                outcome_str += fmt::format(
                    FMT_STRING("{} closed"), outcome_closed);
            }
            if (outcome_opened > 0) {
                if (!outcome_str.empty()) {
                    outcome_str += ", ";
                }
                outcome_str += fmt::format(
                    FMT_STRING("{} opened"), outcome_opened);
            }
            if (outcome_unknown > 0) {
                if (!outcome_str.empty()) {
                    outcome_str += ", ";
                }
                outcome_str += fmt::format(
                    FMT_STRING("{} unknown"), outcome_unknown);
            }
            push_line(fmt::format(
                FMT_STRING("  Outcomes:   {}"), outcome_str));
        }

        // Error/warning counts
        if (level_error > 0 || level_warning > 0) {
            std::string err_str;
            if (level_error > 0) {
                err_str += fmt::format(
                    FMT_STRING("{} error"), level_error);
            }
            if (level_warning > 0) {
                if (!err_str.empty()) {
                    err_str += ", ";
                }
                err_str += fmt::format(
                    FMT_STRING("{} warning"), level_warning);
            }
            push_line(fmt::format(
                FMT_STRING("  Errors:     {}"), err_str));
        }

        // Longest session (only when 2+ sessions)
        if (s_session_trace_sessions.size() > 1 && longest_dur >= 0) {
            push_line(fmt::format(
                FMT_STRING("  Longest:    {} (Session {})"),
                forensic_format_duration(longest_dur),
                longest_idx + 1));
        }
    }

    for (size_t si = 0; si < s_session_trace_sessions.size(); ++si) {
        auto& sess = s_session_trace_sessions[si];

        int64_t duration_sec = sess.end_tv.tv_sec - sess.start_tv.tv_sec;
        int hours = static_cast<int>(duration_sec / 3600);
        int mins = static_cast<int>((duration_sec % 3600) / 60);
        int secs = static_cast<int>(duration_sec % 60);

        push_line("");
        session_header_lines.push_back(
            vis_line_t(static_cast<int>(lines.size())));
        push_line(
            fmt::format(FMT_STRING("── Session {} ──"), si + 1));
        push_line(
            fmt::format(FMT_STRING("  Start:    {}"),
                        forensic_format_tv(sess.start_tv, sess.local_offset)));
        push_line(
            fmt::format(FMT_STRING("  End:      {}"),
                        forensic_format_tv(sess.end_tv, sess.local_offset)));
        push_line(
            fmt::format(FMT_STRING("  Duration: {:02d}:{:02d}:{:02d}"),
                        hours, mins, secs));
        if (!sess.source_ip.empty()) {
            push_line(
                fmt::format(FMT_STRING("  Source:   {}"), sess.source_ip));
        }
        if (!sess.user.empty()) {
            push_line(
                fmt::format(FMT_STRING("  User:     {}"), sess.user));
        }
        push_line(
            fmt::format(FMT_STRING("  Outcome:  {}"),
                        sess.outcome.empty() ? "unknown" : sess.outcome));
        push_line(
            fmt::format(FMT_STRING("  Lines:    {}"),
                        sess.line_indices.size()));
        push_line("");

        for (auto idx : sess.line_indices) {
            auto& ml = s_session_trace_lines[idx];
            push_log_line(
                fmt::format(FMT_STRING("  [{}] {} | {}"),
                            forensic_format_tv(ml.tv, ml.local_offset),
                            ml.filename,
                            ml.text),
                ml.level);
        }
    }

    auto& st_view = lnav_data.ld_views[LNV_SESSION_TRACE];
    auto saved_top = st_view.get_top();
    lnav_data.ld_session_trace_source.replace_with(lines)
        .set_text_format(text_format_t::TF_PLAINTEXT);
    st_view.reload_data();
    st_view.set_top(saved_top);

    // Set BM_SEARCH bookmarks on session headers so n/N jumps between them
    auto& bm = lnav_data.ld_views[LNV_SESSION_TRACE].get_bookmarks();
    bm[&textview_curses::BM_SEARCH].clear();
    for (auto vl : session_header_lines) {
        bm[&textview_curses::BM_SEARCH].insert_once(vl);
    }
}

// --- log-gaps cached state ---
struct lg_gap_record {
    std::string filename;
    timeval gap_start;
    timeval gap_end;
    time_t local_offset{0};
    int64_t duration_secs;
    bool other_files_active;
    std::string severity;
};

static int64_t s_log_gaps_threshold_secs = 0;
static size_t s_log_gaps_file_count = 0;
static std::vector<lg_gap_record> s_log_gaps_records;

static void
rebuild_log_gaps_report()
{
    if (s_log_gaps_threshold_secs == 0 && s_log_gaps_records.empty()) {
        return;
    }

    attr_line_t report;
    std::vector<vis_line_t> gap_row_lines;

    report.append(fmt::format(
        FMT_STRING(" Log Gap Analysis (threshold: {}, {} files, {} gaps found)"),
        forensic_format_duration(s_log_gaps_threshold_secs),
        s_log_gaps_file_count,
        s_log_gaps_records.size()));
    report.append("\n");

    auto current_line = [&report]() -> vis_line_t {
        auto count = std::count(report.al_string.begin(),
                                report.al_string.end(), '\n');
        return vis_line_t(static_cast<int>(count));
    };

    if (s_log_gaps_records.empty()) {
        report.append("\n  No gaps exceeding the threshold were found.\n");
    } else {
        size_t suspicious_count = 0;
        for (auto& g : s_log_gaps_records) {
            if (g.severity == "suspicious") {
                ++suspicious_count;
            }
        }
        if (suspicious_count > 0) {
            report.append(fmt::format(
                FMT_STRING("\n  {} SUSPICIOUS gaps (other files have "
                           "entries during gap)\n"),
                suspicious_count));
        }

        report.append("\n");
        report.append(fmt::format(
            FMT_STRING("  {:<25s} {:<28s} {:<28s} {:<15s} {:<8s} {:<10s}"),
            "FILE", "GAP START", "GAP END", "DURATION",
            "XREF", "SEVERITY"));
        report.append("\n");
        report.append(
            fmt::format(FMT_STRING("  {:-<25s} {:-<28s} {:-<28s} "
                                   "{:-<15s} {:-<8s} {:-<10s}"),
                        "", "", "", "", "", ""));
        report.append("\n");

        for (auto& g : s_log_gaps_records) {
            auto fname = g.filename;
            if (fname.size() > 24) {
                fname = "..." + fname.substr(fname.size() - 21);
            }
            gap_row_lines.push_back(current_line());
            report.append(fmt::format(
                FMT_STRING(
                    "  {:<25s} {:<28s} {:<28s} {:<15s} {:<8s} {:<10s}"),
                fname,
                forensic_format_tv(g.gap_start, g.local_offset),
                forensic_format_tv(g.gap_end, g.local_offset),
                forensic_format_duration(g.duration_secs),
                g.other_files_active ? "YES" : "no",
                g.severity));
            report.append("\n");
        }
    }

    auto& lg_view = lnav_data.ld_views[LNV_LOG_GAPS];
    auto saved_top = lg_view.get_top();
    lnav_data.ld_log_gaps_source.replace_with(report);
    lg_view.reload_data();
    lg_view.set_top(saved_top);

    // Set BM_SEARCH bookmarks on gap rows so n/N jumps between them
    auto& bm = lg_view.get_bookmarks();
    bm[&textview_curses::BM_SEARCH].clear();
    for (auto vl : gap_row_lines) {
        bm[&textview_curses::BM_SEARCH].insert_once(vl);
    }
}

void
refresh_forensic_views()
{
    rebuild_session_trace_report();
    rebuild_log_gaps_report();
}

// ---------------------------------------------------------------------------
// :session-trace <actor> [<actor2> ...]
// ---------------------------------------------------------------------------

// Helper: check if a log line matches a single target (IP or username)
static bool
st_line_matches_target(const string_fragment& sf,
                       const std::string& line_str,
                       const std::string& target)
{
    // Check via data_scanner for exact IP matches
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
    }

    // Freetext match (case-insensitive) for usernames
    auto it = std::search(
        line_str.begin(), line_str.end(),
        target.begin(), target.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a))
                == std::tolower(static_cast<unsigned char>(b));
        });
    return it != line_str.end();
}

static Result<std::string, lnav::console::user_message>
com_session_trace(exec_context& ec,
                  std::string cmdline,
                  std::vector<std::string>& args)
{
    std::string retval;

    if (args.empty()) {
        // Tab-completion: gather IPs and usernames from the log
        auto& lss = lnav_data.ld_log_source;
        const size_t line_count = lss.text_line_count();
        std::set<std::string> suggestions;
        const size_t max_scan = std::min<size_t>(line_count, 50000);

        for (size_t vl_idx = 0; vl_idx < max_scan; ++vl_idx) {
            auto cl = lss.at(vis_line_t(vl_idx));
            auto line_opt = lss.find_line_with_file(cl);
            if (!line_opt) {
                continue;
            }
            auto& [lf, ll_iter] = *line_opt;
            auto read_res = lf->read_line(ll_iter);
            if (read_res.isErr()) {
                continue;
            }
            auto sbr = read_res.unwrap();
            auto sf = sbr.to_string_fragment();

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

            // Extract "user <name>" patterns
            auto line_str = sf.to_string();
            static const auto user_re
                = lnav::pcre2pp::code::from_const(
                    R"((?:user[= ]|User |for )(\S+))");
            auto md = user_re.create_match_data();
            auto inp = string_fragment::from_str(line_str);
            while (user_re.capture_from(inp)
                       .into(md)
                       .matches()
                       .ignore_error())
            {
                auto cap = md[1];
                if (cap) {
                    auto u = cap->to_string();
                    if (u.size() > 1 && u.size() < 64) {
                        suggestions.insert(u);
                    }
                }
                auto last = md[0];
                if (last) {
                    inp = inp.substr(
                        last->sf_end - inp.sf_begin);
                } else {
                    break;
                }
            }
        }

        for (const auto& s : suggestions) {
            args.emplace_back(s);
        }
        return Ok(retval);
    }

    if (args.size() < 2) {
        return ec.make_error(
            "expecting an IP address and/or username");
    }

    if (ec.ec_dry_run) {
        return Ok(std::string());
    }

    // Toggle off if already showing
    if (*lnav_data.ld_view_stack.top()
        == &lnav_data.ld_views[LNV_SESSION_TRACE])
    {
        toggle_view(&lnav_data.ld_views[LNV_SESSION_TRACE]);
        return Ok(std::string());
    }

    // Collect all targets from the arguments (args[1..N])
    std::vector<std::string> targets;
    for (size_t ti = 1; ti < args.size(); ++ti) {
        targets.push_back(args[ti]);
    }

    // Build display string for all targets
    std::string target_display;
    for (size_t ti = 0; ti < targets.size(); ++ti) {
        if (ti > 0) {
            target_display += " + ";
        }
        target_display += targets[ti];
    }

    auto& lss = lnav_data.ld_log_source;
    const size_t line_count = lss.text_line_count();

    // Default session inactivity timeout: 30 minutes
    static constexpr int64_t SESSION_GAP_US = 30LL * 60 * 1000000;

    s_session_trace_target = target_display;
    s_session_trace_lines.clear();
    s_session_trace_sessions.clear();
    auto& matching_lines = s_session_trace_lines;

    // Show placeholder
    {
        attr_line_t placeholder;
        placeholder.append(
            fmt::format(FMT_STRING(" Session Trace: {}"), target_display));
        lnav_data.ld_session_trace_source.replace_with(placeholder)
            .set_text_format(text_format_t::TF_PLAINTEXT);
        lnav_data.ld_views[LNV_SESSION_TRACE].reload_data();
        ensure_view(&lnav_data.ld_views[LNV_SESSION_TRACE]);
        lnav_data.ld_bottom_source.update_loading(
            0, line_count, "Session Trace");
        lnav_data.ld_status[LNS_BOTTOM].set_needs_update();
        lnav_data.ld_status_refresher(lnav::func::op_type::blocking);
    }

    // Scan all log lines for matches
    static const auto& ui_timer = ui_periodic_timer::singleton();
    sig_atomic_t progress_counter = 0;

    for (size_t vl_idx = 0; vl_idx < line_count; ++vl_idx) {
        if (ui_timer.time_to_update(progress_counter)) {
            lnav_data.ld_bottom_source.update_loading(
                vl_idx, line_count, "Session Trace");
            lnav_data.ld_status[LNS_BOTTOM].set_needs_update();
            lnav_data.ld_status_refresher(lnav::func::op_type::blocking);
        }

        auto cl = lss.at(vis_line_t(vl_idx));
        auto line_opt = lss.find_line_with_file(cl);
        if (!line_opt) {
            continue;
        }
        auto& [lf, ll_iter] = *line_opt;
        auto read_res = lf->read_line(ll_iter);
        if (read_res.isErr()) {
            continue;
        }
        auto sbr = read_res.unwrap();
        auto sf = sbr.to_string_fragment();
        auto line_str = sf.to_string();

        // A line matches if it contains ANY of the specified targets
        bool matched = false;
        for (const auto& target : targets) {
            if (st_line_matches_target(sf, line_str, target)) {
                matched = true;
                break;
            }
        }

        if (matched) {
            time_t local_off = 0;
            auto* fmt = lf->get_format_ptr();
            if (fmt != nullptr) {
                local_off = fmt->lf_date_time.dts_local_offset_cache;
            }
            matching_lines.push_back({
                ll_iter->get_timeval(),
                local_off,
                lf->get_filename().filename().string(),
                line_str,
                ll_iter->get_msg_level(),
            });
        }
    }

    lnav_data.ld_bottom_source.update_loading(0, 0);

    if (matching_lines.empty()) {
        lnav_data.ld_session_trace_source
            .replace_with(attr_line_t().append(fmt::format(
                FMT_STRING("No log lines found matching '{}'"),
                target_display)))
            .set_text_format(text_format_t::TF_PLAINTEXT);
        lnav_data.ld_views[LNV_SESSION_TRACE].reload_data();
        return Ok(std::string());
    }

    // Sort by time
    std::sort(matching_lines.begin(), matching_lines.end(),
              [](const st_trace_line& a, const st_trace_line& b) {
                  return timercmp(&a.tv, &b.tv, <);
              });

    // Session boundary keywords
    static const auto session_open_re
        = lnav::pcre2pp::code::from_const(
            R"((?i)(?:session opened|connection from|Accepted |new connection|Connected))");
    static const auto session_close_re
        = lnav::pcre2pp::code::from_const(
            R"((?i)(?:session closed|Disconnected from|Disconnecting|Connection closed|closed connection|Remove session))");

    // Group lines into sessions
    auto& sessions = s_session_trace_sessions;
    st_session_info current;
    current.start_tv = matching_lines[0].tv;
    current.end_tv = matching_lines[0].tv;
    current.local_offset = matching_lines[0].local_offset;
    current.line_indices.push_back(0);
    bool in_session = false;

    // Helper to extract first IP from a line
    auto extract_ip = [](const std::string& line) -> std::string {
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
    };

    // Helper to extract user from a line
    auto extract_user = [](const std::string& line) -> std::string {
        static const auto re
            = lnav::pcre2pp::code::from_const(
                R"((?:user[= ]|User |for )(\S+))");
        auto md = re.create_match_data();
        auto inp = string_fragment::from_str(line);
        if (re.capture_from(inp).into(md).matches().ignore_error()) {
            auto cap = md[1];
            if (cap) {
                return cap->to_string();
            }
        }
        return {};
    };

    for (size_t i = 0; i < matching_lines.size(); ++i) {
        auto& ml = matching_lines[i];

        if (i > 0) {
            // Check for session boundary or timeout
            int64_t delta_us
                = (int64_t(ml.tv.tv_sec) - int64_t(current.end_tv.tv_sec))
                      * 1000000LL
                + (int64_t(ml.tv.tv_usec) - int64_t(current.end_tv.tv_usec));

            // Check if previous line was a close event
            bool prev_closed = false;
            if (i > 0) {
                auto prev_sf = string_fragment::from_str(
                    matching_lines[i - 1].text);
                prev_closed
                    = session_close_re.find_in(prev_sf)
                          .ignore_error()
                          .has_value();
            }

            // Check if current line is an open event
            auto cur_sf = string_fragment::from_str(ml.text);
            bool cur_opens
                = session_open_re.find_in(cur_sf)
                      .ignore_error()
                      .has_value();

            bool new_session
                = (prev_closed && cur_opens) || (delta_us > SESSION_GAP_US);

            if (new_session) {
                // Finalize current session
                if (!current.source_ip.empty() || !current.user.empty()
                    || !current.line_indices.empty())
                {
                    sessions.push_back(std::move(current));
                }
                current = st_session_info{};
                current.start_tv = ml.tv;
                current.local_offset = ml.local_offset;
            }
        }

        current.end_tv = ml.tv;
        current.line_indices.push_back(i);

        // Try to extract IP and user from this line
        if (current.source_ip.empty()) {
            auto ip = extract_ip(ml.text);
            if (!ip.empty()) {
                current.source_ip = ip;
            }
        }
        if (current.user.empty()) {
            auto u = extract_user(ml.text);
            if (!u.empty()) {
                current.user = u;
            }
        }

        // Detect outcome
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
    // Push last session
    if (!current.line_indices.empty()) {
        sessions.push_back(std::move(current));
    }

    rebuild_session_trace_report();

    return Ok(std::string());
}

// ---------------------------------------------------------------------------
// :log-gaps [threshold]
// ---------------------------------------------------------------------------
static Result<std::string, lnav::console::user_message>
com_log_gaps(exec_context& ec,
             std::string cmdline,
             std::vector<std::string>& args)
{
    std::string retval;

    if (args.empty()) {
        return Ok(retval);
    }

    if (ec.ec_dry_run) {
        return Ok(std::string());
    }

    // Toggle off if already showing
    if (*lnav_data.ld_view_stack.top()
        == &lnav_data.ld_views[LNV_LOG_GAPS])
    {
        toggle_view(&lnav_data.ld_views[LNV_LOG_GAPS]);
        return Ok(std::string());
    }

    // Parse threshold (default 5 minutes = 300 seconds)
    int64_t threshold_secs = 300;
    if (args.size() >= 2) {
        auto arg = args[1];
        // Support formats: "10m", "600", "1h", "30s"
        int64_t val = 0;
        size_t pos = 0;
        try {
            val = std::stoll(arg, &pos);
        } catch (...) {
            return ec.make_error(
                "invalid threshold '{}' — use a number with optional "
                "suffix (s/m/h)",
                arg);
        }
        if (pos < arg.size()) {
            char suffix = arg[pos];
            switch (suffix) {
                case 's':
                case 'S':
                    threshold_secs = val;
                    break;
                case 'm':
                case 'M':
                    threshold_secs = val * 60;
                    break;
                case 'h':
                case 'H':
                    threshold_secs = val * 3600;
                    break;
                default:
                    return ec.make_error(
                        "unknown suffix '{}' — use s, m, or h", suffix);
            }
        } else {
            // If suffix looks like minutes (small number), treat as minutes
            // Otherwise treat as seconds for consistency
            if (arg.find('m') != std::string::npos
                || arg.find('M') != std::string::npos)
            {
                threshold_secs = val * 60;
            } else {
                // Bare number: if <= 120, treat as minutes; else seconds
                if (val <= 120) {
                    threshold_secs = val * 60;
                } else {
                    threshold_secs = val;
                }
            }
        }
    }

    // Show placeholder
    {
        attr_line_t placeholder;
        placeholder.append(fmt::format(
            FMT_STRING(" Analyzing Log Gaps (threshold: {}s)"),
            threshold_secs));
        lnav_data.ld_log_gaps_source.replace_with(placeholder);
        lnav_data.ld_views[LNV_LOG_GAPS].reload_data();
        ensure_view(&lnav_data.ld_views[LNV_LOG_GAPS]);
        lnav_data.ld_bottom_source.update_loading(0, 1, "Log Gaps");
        lnav_data.ld_status[LNS_BOTTOM].set_needs_update();
        lnav_data.ld_status_refresher(lnav::func::op_type::blocking);
    }

    s_log_gaps_records.clear();
    s_log_gaps_threshold_secs = threshold_secs;
    auto& all_gaps = s_log_gaps_records;

    // Collect per-file line timestamps
    struct file_info {
        std::string filename;
        std::vector<timeval> timestamps;
        time_t local_offset{0};
    };
    std::vector<file_info> files;

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

        file_info fi;
        fi.filename = lf->get_filename().filename().string();
        auto* fmt = lf->get_format_ptr();
        if (fmt != nullptr) {
            fi.local_offset = fmt->lf_date_time.dts_local_offset_cache;
        }
        fi.timestamps.reserve(lf->size());
        for (auto ll = lf->cbegin(); ll != lf->cend(); ++ll) {
            fi.timestamps.push_back(ll->get_timeval());
        }
        files.push_back(std::move(fi));
    }

    // For each file, find gaps exceeding threshold
    for (size_t fi_idx = 0; fi_idx < files.size(); ++fi_idx) {
        auto& fi = files[fi_idx];
        for (size_t li = 1; li < fi.timestamps.size(); ++li) {
            auto& prev_tv = fi.timestamps[li - 1];
            auto& cur_tv = fi.timestamps[li];

            int64_t delta = (int64_t(cur_tv.tv_sec) - int64_t(prev_tv.tv_sec));
            if (delta < threshold_secs) {
                continue;
            }

            // Check if other files have entries during this gap
            bool others_active = false;
            for (size_t oi = 0; oi < files.size(); ++oi) {
                if (oi == fi_idx) {
                    continue;
                }
                auto& other = files[oi];
                // Binary search for any timestamp in [prev_tv, cur_tv]
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

            all_gaps.push_back({
                fi.filename,
                prev_tv,
                cur_tv,
                fi.local_offset,
                delta,
                others_active,
                others_active ? "suspicious" : "normal",
            });
        }
    }

    lnav_data.ld_bottom_source.update_loading(0, 0);

    // Sort by severity (suspicious first), then by duration descending
    std::sort(all_gaps.begin(), all_gaps.end(),
              [](const lg_gap_record& a, const lg_gap_record& b) {
                  if (a.severity != b.severity) {
                      return a.severity > b.severity;  // "suspicious" > "normal"
                  }
                  return a.duration_secs > b.duration_secs;
              });

    s_log_gaps_file_count = files.size();
    rebuild_log_gaps_report();

    return Ok(std::string());
}

static Result<std::string, lnav::console::user_message>
com_spectrogram(exec_context& ec,
                std::string cmdline,
                std::vector<std::string>& args)
{
    std::string retval;

    if (ec.ec_dry_run) {
        retval = "";
    } else if (args.size() == 2) {
        auto colname = remaining_args(cmdline, args);
        auto& ss = *lnav_data.ld_spectro_source;
        bool found = false;

        ss.ss_granularity = ZOOM_LEVELS[lnav_data.ld_zoom_level];
        if (ss.ss_value_source != nullptr) {
            delete std::exchange(ss.ss_value_source, nullptr);
        }
        ss.invalidate();

        if (*lnav_data.ld_view_stack.top() == &lnav_data.ld_views[LNV_DB]) {
            auto dsvs = std::make_unique<db_spectro_value_source>(colname);

            if (dsvs->dsvs_error_msg) {
                return Err(
                    dsvs->dsvs_error_msg.value().with_snippets(ec.ec_source));
            }
            ss.ss_value_source = dsvs.release();
            found = true;
        } else {
            auto lsvs = std::make_unique<log_spectro_value_source>(
                intern_string::lookup(colname));

            if (!lsvs->lsvs_found) {
                return ec.make_error("unknown numeric message field -- {}",
                                     colname);
            }
            ss.ss_value_source = lsvs.release();
            found = true;
        }

        if (found) {
            lnav_data.ld_views[LNV_SPECTRO].reload_data();
            ss.text_selection_changed(lnav_data.ld_views[LNV_SPECTRO]);
            ensure_view(&lnav_data.ld_views[LNV_SPECTRO]);

#if 0
            if (lnav_data.ld_rl_view != nullptr) {
                lnav_data.ld_rl_view->set_alt_value(
                    HELP_MSG_2(z, Z, "to zoom in/out"));
            }
#endif

            retval = "info: visualizing field -- " + colname;
        }
    } else {
        return ec.make_error("expecting a message field name");
    }

    return Ok(retval);
}

static Result<std::string, lnav::console::user_message>
com_quit(exec_context& ec, std::string cmdline, std::vector<std::string>& args)
{
    if (!ec.ec_dry_run) {
        lnav_data.ld_looping = false;
    }
    return Ok(std::string());
}

static void
breadcrumb_prompt(std::vector<std::string>& args)
{
    set_view_mode(ln_mode_t::BREADCRUMBS);
}

static void
command_prompt(std::vector<std::string>& args)
{
    static auto& prompt = lnav::prompt::get();
    auto* tc = *lnav_data.ld_view_stack.top();

    rollback_lnav_config = lnav_config;
    lnav_data.ld_doc_status_source.set_title("Command Help"_frag);
    lnav_data.ld_doc_status_source.set_description(
        " See " ANSI_BOLD("https://docs.lnav.org/en/latest/"
                          "commands.html") " for more details");

    set_view_mode(ln_mode_t::COMMAND);
    lnav_data.ld_exec_context.ec_top_line = tc->get_selection().value_or(0_vl);
    prompt.focus_for(
        *tc, prompt.p_editor, lnav::prompt::context_t::cmd, ':', args);

    rl_set_help();
}

static void
script_prompt(std::vector<std::string>& args)
{
    static auto& prompt = lnav::prompt::get();

    auto* tc = *lnav_data.ld_view_stack.top();

    set_view_mode(ln_mode_t::EXEC);

    lnav_data.ld_exec_context.ec_top_line = tc->get_selection().value_or(0_vl);
    prompt.focus_for(
        *tc, prompt.p_editor, lnav::prompt::context_t::script, '|', args);
    lnav_data.ld_bottom_source.set_prompt(
        "Enter a script to execute: (Press " ANSI_BOLD("Esc") " to abort)");
    lnav_data.ld_status[LNS_BOTTOM].set_needs_update();
}

static void
search_prompt(std::vector<std::string>& args)
{
    static auto& prompt = lnav::prompt::get();

    auto* tc = *lnav_data.ld_view_stack.top();

    log_debug("search prompt");
    set_view_mode(ln_mode_t::SEARCH);
    lnav_data.ld_exec_context.ec_top_line = tc->get_selection().value_or(0_vl);
    lnav_data.ld_search_start_line = tc->get_selection().value_or(0_vl);
    prompt.focus_for(
        *tc, prompt.p_editor, lnav::prompt::context_t::search, '/', args);
    lnav_data.ld_doc_status_source.set_title("Syntax Help"_frag);
    lnav_data.ld_doc_status_source.set_description("");
    rl_set_help();
    lnav_data.ld_bottom_source.set_prompt(
        "Search for:  "
        "(Press " ANSI_BOLD("CTRL+J") " to jump to a previous hit and "
        ANSI_BOLD("Esc") " to abort)");
    lnav_data.ld_status[LNS_BOTTOM].set_needs_update();
}

static void
search_filters_prompt(std::vector<std::string>& args)
{
    static auto& prompt = lnav::prompt::get();

    set_view_mode(ln_mode_t::SEARCH_FILTERS);
    auto* tc = get_textview_for_mode(lnav_data.ld_mode);
    lnav_data.ld_filter_view.reload_data();
    prompt.focus_for(
        *tc, prompt.p_editor, lnav::prompt::context_t::search, '/', args);
    lnav_data.ld_bottom_source.set_prompt(
        "Search for:  "
        "(Press " ANSI_BOLD("CTRL+J") " to jump to a previous hit and "
        ANSI_BOLD("Esc") " to abort)");
    lnav_data.ld_status[LNS_BOTTOM].set_needs_update();
}

static void
search_files_prompt(std::vector<std::string>& args)
{
    static auto& prompt = lnav::prompt::get();

    set_view_mode(ln_mode_t::SEARCH_FILES);
    auto* tc = get_textview_for_mode(lnav_data.ld_mode);
    prompt.focus_for(
        *tc, prompt.p_editor, lnav::prompt::context_t::search, '/', args);
    lnav_data.ld_bottom_source.set_prompt(
        "Search for:  "
        "(Press " ANSI_BOLD("CTRL+J") " to jump to a previous hit and "
        ANSI_BOLD("Esc") " to abort)");
    lnav_data.ld_status[LNS_BOTTOM].set_needs_update();
}

static void
search_spectro_details_prompt(std::vector<std::string>& args)
{
    static auto& prompt = lnav::prompt::get();

    set_view_mode(ln_mode_t::SEARCH_SPECTRO_DETAILS);
    auto* tc = get_textview_for_mode(lnav_data.ld_mode);
    prompt.focus_for(
        *tc, prompt.p_editor, lnav::prompt::context_t::search, '/', args);

    lnav_data.ld_bottom_source.set_prompt(
        "Search for:  "
        "(Press " ANSI_BOLD("CTRL+J") " to jump to a previous hit and "
        ANSI_BOLD("Esc") " to abort)");
    lnav_data.ld_status[LNS_BOTTOM].set_needs_update();
}

static void
sql_prompt(std::vector<std::string>& args)
{
    static auto& prompt = lnav::prompt::get();

    auto* tc = *lnav_data.ld_view_stack.top();
    auto& log_view = lnav_data.ld_views[LNV_LOG];

    lnav_data.ld_exec_context.ec_top_line = tc->get_selection().value_or(0_vl);

    set_view_mode(ln_mode_t::SQL);
    setup_logline_table(lnav_data.ld_exec_context);
    prompt.focus_for(
        *tc, prompt.p_editor, lnav::prompt::context_t::sql, ';', args);

    lnav_data.ld_doc_status_source.set_title("Query Help"_frag);
    lnav_data.ld_doc_status_source.set_description(
        "See " ANSI_BOLD("https://docs.lnav.org/en/latest/"
                         "sqlext.html") " for more details");
    rl_set_help();
    lnav_data.ld_bottom_source.update_loading(0, 0);
    lnav_data.ld_status[LNS_BOTTOM].set_needs_update();

    auto* fos = (field_overlay_source*) log_view.get_overlay_source();
    fos->fos_contexts.top().c_show = true;
    tc->set_sync_selection_and_top(true);
    tc->reload_data();
    tc->set_overlay_selection(3_vl);
    lnav_data.ld_bottom_source.set_prompt(
        "Enter an SQL query: (Press " ANSI_BOLD(
            "CTRL+L") " for multi-line mode and " ANSI_BOLD("Esc") " to "
                                                                   "abort)");
}

static void
user_prompt(std::vector<std::string>& args)
{
    static auto& prompt = lnav::prompt::get();

    auto* tc = *lnav_data.ld_view_stack.top();
    lnav_data.ld_exec_context.ec_top_line = tc->get_selection().value_or(0_vl);

    set_view_mode(ln_mode_t::USER);
    setup_logline_table(lnav_data.ld_exec_context);
    prompt.focus_for(
        *tc, prompt.p_editor, lnav::prompt::context_t::cmd, '\0', args);

    lnav_data.ld_bottom_source.update_loading(0, 0);
    lnav_data.ld_status[LNS_BOTTOM].set_needs_update();
}

static Result<std::string, lnav::console::user_message>
com_prompt(exec_context& ec,
           std::string cmdline,
           std::vector<std::string>& args)
{
    static auto& prompt = lnav::prompt::get();
    static const std::map<std::string,
                          std::function<void(std::vector<std::string>&)>>
        PROMPT_TYPES = {
            {"breadcrumb", breadcrumb_prompt},
            {"command", command_prompt},
            {"script", script_prompt},
            {"search", search_prompt},
            {"search-filters", search_filters_prompt},
            {"search-files", search_files_prompt},
            {"search-spectro-details", search_spectro_details_prompt},
            {"sql", sql_prompt},
            {"user", user_prompt},
        };

    if (!ec.ec_dry_run) {
        static const intern_string_t SRC = intern_string::lookup("flags");

        auto lexer = shlex(cmdline);
        auto split_args_res = lexer.split(ec.create_resolver());
        if (split_args_res.isErr()) {
            auto split_err = split_args_res.unwrapErr();
            auto um
                = lnav::console::user_message::error("unable to parse prompt")
                      .with_reason(split_err.se_error.te_msg)
                      .with_snippet(lnav::console::snippet::from(
                          SRC, lexer.to_attr_line(split_err.se_error)))
                      .move();

            return Err(um);
        }

        auto split_args = split_args_res.unwrap()
            | lnav::itertools::map(
                              [](const auto& elem) { return elem.se_value; });

        auto alt_flag
            = std::find(split_args.begin(), split_args.end(), "--alt");
        prompt.p_alt_mode = alt_flag != split_args.end();
        if (prompt.p_alt_mode) {
            split_args.erase(alt_flag);
        }

        auto prompter = PROMPT_TYPES.find(split_args[1]);

        if (prompter == PROMPT_TYPES.end()) {
            return ec.make_error("Unknown prompt type: {}", split_args[1]);
        }

        prompter->second(split_args);
    }
    return Ok(std::string());
}

readline_context::command_t STD_COMMANDS[] = {
    {
        "prompt",
        com_prompt,

        help_text(":prompt")
            .with_summary("Open the given prompt")
            .with_parameter(
                help_text{"type", "The type of prompt"}.with_enum_values({
                    "breadcrumb"_frag,
                    "command"_frag,
                    "script"_frag,
                    "search"_frag,
                    "sql"_frag,
                }))
            .with_parameter(help_text("--alt",
                                      "Perform the alternate action "
                                      "for this prompt by default")
                                .with_format(help_parameter_format_t::HPF_NONE)
                                .optional())
            .with_parameter(
                help_text("prompt", "The prompt to display").optional())
            .with_parameter(
                help_text("initial-value",
                          "The initial value to fill in for the prompt")
                    .optional())
            .with_example({
                "To open the command prompt with 'filter-in' already filled in",
                "command : 'filter-in '",
            })
            .with_example({
                "To ask the user a question",
                "user 'Are you sure? '",
            }),
    },
    {
        "add-source-path",
        com_add_src_path,
        help_text(":add-source-path")
            .with_summary(
                "Add a path to the source code that generated log messages.  "
                "Adding source allows lnav to more accurately extract values "
                "from log messages")
            .with_parameter(
                help_text("path")
                    .with_summary("The path to the source code to index")
                    .with_format(help_parameter_format_t::HPF_DIRECTORY)
                    .one_or_more()),
    },

    {
        "adjust-log-time",
        com_adjust_log_time,

        help_text(":adjust-log-time")
            .with_summary(
                "Change the timestamps of the focused file to be relative "
                "to the given date")
            .with_parameter(
                help_text("timestamp",
                          "The new timestamp for the focused line in the view")
                    .with_format(help_parameter_format_t::HPF_ADJUSTED_TIME))
            .with_example({"To set the focused timestamp to a given date",
                           "2017-01-02T05:33:00"})
            .with_example({"To set the focused timestamp back an hour", "-1h"})
            .with_opposites({"clear-adjusted-log-time"}),
    },
    {
        "clear-adjusted-log-time",
        com_clear_adjusted_log_time,

        help_text(":clear-adjusted-log-time")
            .with_summary(
                "Clear the adjusted time for the focused line in the view")
            .with_opposites({":adjust-log-time"}),
    },

    {
        "unix-time",
        com_unix_time,

        help_text(":unix-time")
            .with_summary("Convert epoch time to a human-readable form")
            .with_parameter(
                help_text("seconds", "The epoch timestamp to convert")
                    .with_format(help_parameter_format_t::HPF_INTEGER))
            .with_example(
                {"To convert the epoch time 1490191111", "1490191111"}),
    },
    {
        "convert-time-to",
        com_convert_time_to,
        help_text(":convert-time-to")
            .with_summary("Convert the focused timestamp to the "
                          "given timezone")
            .with_parameter(
                help_text("zone", "The timezone name")
                    .with_format(help_parameter_format_t::HPF_TIMEZONE)),
    },
    {
        "set-file-timezone",
        com_set_file_timezone,
        help_text(":set-file-timezone")
            .with_summary("Set the timezone to use for log messages that do "
                          "not include a timezone.  The timezone is applied "
                          "to "
                          "the focused file or the given glob pattern.")
            .with_parameter(help_text{"zone", "The timezone name"}.with_format(
                help_parameter_format_t::HPF_TIMEZONE))
            .with_parameter(help_text{"pattern",
                                      "The glob pattern to match against "
                                      "files that should use this timezone"}
                                .optional())
            .with_tags({"file-options"}),
        com_set_file_timezone_prompt,
    },
    {
        "clear-file-timezone",
        com_clear_file_timezone,
        help_text(":clear-file-timezone")
            .with_summary("Clear the timezone setting for the "
                          "focused file or "
                          "the given glob pattern.")
            .with_parameter(
                help_text{"pattern",
                          "The glob pattern to match against files "
                          "that should no longer use this timezone"}
                    .with_format(help_parameter_format_t::HPF_FILE_WITH_ZONE))
            .with_tags({"file-options"}),
        com_clear_file_timezone_prompt,
    },
    {"current-time",
     com_current_time,

     help_text(":current-time")
         .with_summary("Print the current time in human-readable form and "
                       "seconds since the epoch")},
    {
        "goto",
        com_goto,

        help_text(":goto")
            .with_summary("Go to the given location in the top view")
            .with_parameter(
                help_text("line#|N%|timestamp|#anchor",
                          "A line number, percent into the file, timestamp, "
                          "or an anchor in a text file")
                    .with_format(help_parameter_format_t::HPF_LOCATION))
            .with_examples(
                {{"To go to line 22", "22"},
                 {"To go to the line 75% of the way into the view", "75%"},
                 {"To go to the first message on the first day of "
                  "2017",
                  "2017-01-01"},
                 {"To go to the Screenshots section", "#screenshots"}})
            .with_tags({"navigation"}),
    },
    {
        "relative-goto",
        com_relative_goto,
        help_text(":relative-goto")
            .with_summary(
                "Move the current view up or down by the given amount")
            .with_parameter(
                {"line-count|N%", "The amount to move the view by."})
            .with_examples({
                {"To move 22 lines down in the view", "+22"},
                {"To move 10 percent back in the view", "-10%"},
            })
            .with_tags({"navigation"}),
    },

    {
        "mark-expr",
        com_mark_expr,

        help_text(":mark-expr")
            .with_summary("Set the bookmark expression")
            .with_parameter(
                help_text("expr",
                          "The SQL expression to evaluate for each "
                          "log message.  "
                          "The message values can be accessed "
                          "using column names "
                          "prefixed with a colon")
                    .with_format(help_parameter_format_t::HPF_SQL_EXPR))
            .with_opposites({"clear-mark-expr"})
            .with_tags({"bookmarks"})
            .with_example({"To mark lines from 'dhclient' that "
                           "mention 'eth0'",
                           ":log_procname = 'dhclient' AND "
                           ":log_body LIKE '%eth0%'"}),

        com_mark_expr_prompt,
    },
    {"clear-mark-expr",
     com_clear_mark_expr,

     help_text(":clear-mark-expr")
         .with_summary("Clear the mark expression")
         .with_opposites({"mark-expr"})
         .with_tags({"bookmarks"})},
    {"next-location",
     com_goto_location,

     help_text(":next-location")
         .with_summary("Move to the next position in the location history")
         .with_tags({"navigation"})},
    {"prev-location",
     com_goto_location,

     help_text(":prev-location")
         .with_summary("Move to the previous position in the "
                       "location history")
         .with_tags({"navigation"})},

    {
        "next-section",
        com_next_section,

        help_text(":next-section")
            .with_summary("Move to the next section in the document")
            .with_tags({"navigation"}),
    },
    {
        "prev-section",
        com_prev_section,

        help_text(":prev-section")
            .with_summary("Move to the previous section in the document")
            .with_tags({"navigation"}),
    },

    {
        "help",
        com_help,

        help_text(":help").with_summary("Open the help text view"),
    },
    {
        "hide-unmarked-lines",
        com_hide_unmarked,

        help_text(":hide-unmarked-lines")
            .with_summary("Hide lines that have not been bookmarked")
            .with_tags({"filtering", "bookmarks"}),
    },
    {
        "show-unmarked-lines",
        com_show_unmarked,

        help_text(":show-unmarked-lines")
            .with_summary("Show lines that have not been bookmarked")
            .with_opposites({"show-unmarked-lines"})
            .with_tags({"filtering", "bookmarks"}),
    },
    {
        "highlight",
        com_highlight,

        help_text(":highlight")
            .with_summary("Add coloring to log messages fragments "
                          "that match the "
                          "given regular expression")
            .with_parameter(
                help_text("pattern", "The regular expression to match")
                    .with_format(help_parameter_format_t::HPF_REGEX))
            .with_tags({"display"})
            .with_opposites({"clear-highlight"})
            .with_example({"To highlight numbers with three or more digits",
                           R"(\d{3,})"}),
    },
    {
        "highlight-field",
        com_highlight_field,

        help_text(":highlight-field")
            .with_summary("Highlight a field that matches the given pattern")
            .with_parameter(
                help_text("--color", "The foreground color to apply")
                    .with_format(help_parameter_format_t::HPF_STRING)
                    .optional())
            .with_parameter(help_text("--bold", "Make the text bold")
                                .with_format(help_parameter_format_t::HPF_NONE)
                                .optional())
            .with_parameter(help_text("--underline", "Underline the text")
                                .with_format(help_parameter_format_t::HPF_NONE)
                                .optional())
            .with_parameter(help_text("--italic", "Italicize the text")
                                .with_format(help_parameter_format_t::HPF_NONE)
                                .optional())
            .with_parameter(help_text("--strike", "Strikethrough the text")
                                .with_format(help_parameter_format_t::HPF_NONE)
                                .optional())
            .with_parameter(help_text("--blink", "Make the text blink")
                                .with_format(help_parameter_format_t::HPF_NONE)
                                .optional())
            .with_parameter(
                help_text("field", "The name of the field to highlight")
                    .with_format(help_parameter_format_t::HPF_FORMAT_FIELD))
            .with_parameter(
                help_text("pattern", "The regular expression to match")
                    .with_format(help_parameter_format_t::HPF_REGEX)
                    .optional())
            .with_tags({"display"})
            .with_opposites({"clear-highlight-field"})
            .with_example({"To color status values that start with '2' green",
                           R"(--color=green sc_status ^2.*)"}),
    },
    {
        "clear-highlight-field",
        com_clear_highlight_field,

        help_text(":clear-highlight-field")
            .with_summary("Remove a field highlight")
            .with_parameter(
                help_text("field", "The name of highlighted field")
                    .with_format(
                        help_parameter_format_t::HPF_HIGHLIGHTED_FIELD))
            .with_tags({"display"})
            .with_opposites({"highlight-field"})
            .with_example({"To clear the highlights for the 'sc_status' field",
                           "sc_status"}),
    },
    {
        "clear-highlight",
        com_clear_highlight,

        help_text(":clear-highlight")
            .with_summary(
                "Remove a previously set highlight regular expression")
            .with_parameter(
                help_text("pattern",
                          "The regular expression previously used "
                          "with :highlight")
                    .with_format(help_parameter_format_t::HPF_HIGHLIGHTS))
            .with_tags({"display"})
            .with_opposites({"highlight"})
            .with_example(
                {"To clear the highlight with the pattern 'foobar'", "foobar"}),
    },
    {
        "filter-expr",
        com_filter_expr,

        help_text(":filter-expr")
            .with_summary("Set the filter expression")
            .with_parameter(
                help_text("expr",
                          "The SQL expression to evaluate for each "
                          "log message.  "
                          "The message values can be accessed "
                          "using column names "
                          "prefixed with a colon")
                    .with_format(help_parameter_format_t::HPF_SQL_EXPR))
            .with_opposites({"clear-filter-expr"})
            .with_tags({"filtering"})
            .with_example({"To set a filter expression that matched syslog "
                           "messages from 'syslogd'",
                           ":log_procname = 'syslogd'"})
            .with_example(
                {"To set a filter expression that matches log "
                 "messages where 'id' is followed by a number and contains the "
                 "string 'foo'",
                 ":log_body REGEXP 'id\\d+' AND :log_body REGEXP 'foo'"}),

        com_filter_expr_prompt,
    },
    {"clear-filter-expr",
     com_clear_filter_expr,

     help_text(":clear-filter-expr")
         .with_summary("Clear the filter expression")
         .with_opposites({"filter-expr"})
         .with_tags({"filtering"})},
    {"enable-word-wrap",
     com_enable_word_wrap,

     help_text(":enable-word-wrap")
         .with_summary("Enable word-wrapping for the current view")
         .with_tags({"display"})},
    {"disable-word-wrap",
     com_disable_word_wrap,

     help_text(":disable-word-wrap")
         .with_summary("Disable word-wrapping for the current view")
         .with_opposites({"enable-word-wrap"})
         .with_tags({"display"})},
    {"create-logline-table",
     com_create_logline_table,

     help_text(":create-logline-table")
         .with_summary("Create an SQL table using the focused line of "
                       "the log view "
                       "as a template")
         .with_parameter(help_text("table-name", "The name for the new table"))
         .with_tags({"vtables", "sql"})
         .with_example({"To create a logline-style table named "
                        "'task_durations'",
                        "task_durations"})},
    {"delete-logline-table",
     com_delete_logline_table,

     help_text(":delete-logline-table")
         .with_summary("Delete a table created with create-logline-table")
         .with_parameter(
             help_text("table-name", "The name of the table to delete")
                 .with_format(help_parameter_format_t::HPF_LOGLINE_TABLE))
         .with_opposites({"delete-logline-table"})
         .with_tags({"vtables", "sql"})
         .with_example({"To delete the logline-style table named "
                        "'task_durations'",
                        "task_durations"})},
    {"create-search-table",
     com_create_search_table,

     help_text(":create-search-table")
         .with_summary("Create an SQL table based on a regex search")
         .with_parameter(
             help_text("table-name", "The name of the table to create"))
         .with_parameter(
             help_text("pattern",
                       "The regular expression used to capture the table "
                       "columns.  "
                       "If not given, the current search pattern is "
                       "used.")
                 .optional()
                 .with_format(help_parameter_format_t::HPF_REGEX))
         .with_tags({"vtables", "sql"})
         .with_example({"To create a table named 'task_durations' that "
                        "matches log "
                        "messages with the pattern "
                        "'duration=(?<duration>\\d+)'",
                        R"(task_durations duration=(?<duration>\d+))"})},
    {"delete-search-table",
     com_delete_search_table,

     help_text(":delete-search-table")
         .with_summary("Delete a search table")
         .with_parameter(
             help_text("table-name", "The name of the table to delete")
                 .one_or_more()
                 .with_format(help_parameter_format_t::HPF_SEARCH_TABLE))
         .with_opposites({"create-search-table"})
         .with_tags({"vtables", "sql"})
         .with_example({"To delete the search table named 'task_durations'",
                        "task_durations"})},
    {
        "hide-file",
        com_file_visibility,

        help_text(":hide-file")
            .with_summary("Hide the given file(s) and skip indexing until it "
                          "is shown again.  If no path is given, the current "
                          "file in the view is hidden")
            .with_parameter(
                help_text{"path",
                          "A path or glob pattern that "
                          "specifies the files to hide"}
                    .with_format(help_parameter_format_t::HPF_VISIBLE_FILES)
                    .zero_or_more())
            .with_opposites({"show-file"}),
    },
    {
        "show-file",
        com_file_visibility,

        help_text(":show-file")
            .with_summary("Show the given file(s) and resume indexing.")
            .with_parameter(
                help_text{"path",
                          "The path or glob pattern that "
                          "specifies the files to show"}
                    .with_format(help_parameter_format_t::HPF_HIDDEN_FILES)
                    .zero_or_more())
            .with_opposites({"hide-file"}),
    },
    {
        "show-only-this-file",
        com_file_visibility,

        help_text(":show-only-this-file")
            .with_summary("Show only the file for the focused line in the view")
            .with_opposites({"hide-file"}),
    },
    {"session",
     com_session,

     help_text(":session")
         .with_summary("Add the given command to the session file "
                       "(~/.lnav/session)")
         .with_parameter(help_text("lnav-command", "The lnav command to save."))
         .with_example({"To add the command ':highlight foobar' to "
                        "the session file",
                        ":highlight foobar"})},
    {
        "summarize",
        com_summarize,

        help_text(":summarize")
            .with_summary("Execute a SQL query that computes the "
                          "characteristics "
                          "of the values in the given column")
            .with_parameter(
                help_text("column-name", "The name of the column to analyze.")
                    .with_format(help_parameter_format_t::HPF_FORMAT_FIELD))
            .with_example({"To get a summary of the sc_bytes column in the "
                           "access_log table",
                           "sc_bytes"}),
    },
    {"switch-to-view",
     com_switch_to_view,

     help_text(":switch-to-view")
         .with_summary("Switch to the given view")
         .with_parameter(
             help_text("view-name", "The name of the view to switch to.")
                 .with_enum_values(lnav_view_strings))
         .with_example({"To switch to the 'schema' view", "schema"})},
    {"toggle-view",
     com_switch_to_view,

     help_text(":toggle-view")
         .with_summary("Switch to the given view or, if it is "
                       "already displayed, "
                       "switch to the previous view")
         .with_parameter(
             help_text("view-name",
                       "The name of the view to toggle the display of.")
                 .with_enum_values(lnav_view_strings))
         .with_example({"To switch to the 'schema' view if it is "
                        "not displayed "
                        "or switch back to the previous view",
                        "schema"})},
    {"toggle-filtering",
     com_toggle_filtering,

     help_text(":toggle-filtering")
         .with_summary("Toggle the filtering flag for the current view")
         .with_tags({"filtering"})},
    {"reset-session",
     com_reset_session,

     help_text(":reset-session")
         .with_summary("Reset the session state, clearing all filters, "
                       "highlights, and bookmarks")},
    {"load-session",
     com_load_session,

     help_text(":load-session").with_summary("Load the latest session state")},
    {"save-session",
     com_save_session,

     help_text(":save-session")
         .with_summary("Save the current state as a session")},
    {
        "set-min-log-level",
        com_set_min_log_level,

        help_text(":set-min-log-level")
            .with_summary(
                "Set the minimum log level to display in the log view")
            .with_parameter(help_text("log-level", "The new minimum log level")
                                .with_enum_values(level_names))
            .with_example(
                {"To set the minimum log level displayed to error", "error"}),
    },
    {"redraw",
     com_redraw,

     help_text(":redraw").with_summary("Do a full redraw of the screen")},
    {
        "zoom-to",
        com_zoom_to,

        help_text(":zoom-to")
            .with_summary("Zoom the histogram view to the given level")
            .with_parameter(help_text("zoom-level", "The zoom level")
                                .with_enum_values(lnav_zoom_strings))
            .with_example({"To set the zoom level to '1-week'", "1-week"}),
    },
    {
        "config",
        com_config,
        CONFIG_HELP,
    },
    {"reset-config",
     com_reset_config,

     help_text(":reset-config")
         .with_summary("Reset the configuration option to its default value")
         .with_parameter(
             help_text("option", "The path to the option to reset")
                 .with_format(help_parameter_format_t::HPF_CONFIG_PATH))
         .with_example({"To reset the '/ui/clock-format' option back to the "
                        "builtin default",
                        "/ui/clock-format"})
         .with_tags({"configuration"})},
    {
        "ssh-stats",
        com_ssh_stats,

        help_text(":ssh-stats")
            .with_summary(
                "Toggle a panel showing SSH event statistics and IP address "
                "frequency counts extracted from the loaded logs")
            .with_tags({"display"}),
    },
    {
        "session-trace",
        com_session_trace,

        help_text(":session-trace")
            .with_summary(
                "Extract and reconstruct a single actor's session from all "
                "loaded log files, grouping by connect/disconnect boundaries "
                "or inactivity timeout")
            .with_parameter(
                {"actor",
                 "One or more IP addresses and/or usernames to trace "
                 "across all logs (e.g. 192.168.1.1 admin)"})
            .with_tags({"forensics"}),
    },
    {
        "log-gaps",
        com_log_gaps,

        help_text(":log-gaps")
            .with_summary(
                "Detect periods where logging stopped or was potentially "
                "tampered with by finding gaps in each file's timeline "
                "and cross-referencing with other loaded files")
            .with_parameter(
                help_text(
                    "threshold",
                    "Gap threshold with optional suffix s/m/h (default 5m)")
                    .optional())
            .with_tags({"forensics"}),
    },
    {
        "spectrogram",
        com_spectrogram,

        help_text(":spectrogram")
            .with_summary(
                "Visualize the given message field or database column "
                "using a spectrogram")
            .with_parameter(
                help_text("field-name",
                          "The name of the numeric field to visualize.")
                    .with_format(help_parameter_format_t::HPF_NUMERIC_FIELD))
            .with_example({"To visualize the sc_bytes field in the "
                           "access_log format",
                           "sc_bytes"}),
    },
    {
        "quit",
        com_quit,

        help_text(":quit").with_summary("Quit lnav"),
    },
    {
        "write-debug-log-to",
        com_write_debug_log_to,
        help_text(":write-debug-log-to")
            .with_summary(
                "Write lnav's internal debug log to the given path.  This can "
                "be useful if the `-d` flag was not passed on the command line")
            .with_parameter(
                help_text("path", "The destination path for the debug log")
                    .with_format(help_parameter_format_t::HPF_LOCAL_FILENAME)),
    },
};

static Result<std::string, lnav::console::user_message>
com_crash(exec_context& ec, std::string cmdline, std::vector<std::string>& args)
{
    if (args.empty()) {
    } else if (!ec.ec_dry_run) {
        int* nums = nullptr;

        return ec.make_error(FMT_STRING("oops... {}"), nums[0]);
    }
    return Ok(std::string());
}

void
init_lnav_commands(readline_context::command_map_t& cmd_map)
{
    for (auto& cmd : STD_COMMANDS) {
        cmd.c_help.index_tags();
        cmd_map[cmd.c_name] = &cmd;
    }
    cmd_map["q"_frag] = cmd_map["q!"_frag] = cmd_map["quit"_frag];

    if (getenv("LNAV_SRC") != nullptr) {
        static readline_context::command_t add_test(com_add_test);

        cmd_map["add-test"_frag] = &add_test;
    }
    if (getenv("lnav_test") != nullptr) {
        static readline_context::command_t shexec(com_shexec),
            poll_now(com_poll_now), test_comment(com_test_comment),
            crasher(com_crash);

        cmd_map["shexec"_frag] = &shexec;
        cmd_map["poll-now"_frag] = &poll_now;
        cmd_map["test-comment"_frag] = &test_comment;
        cmd_map["crash"_frag] = &crasher;
    }
}
