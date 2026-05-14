/**
 * Copyright (c) 2026, Jeffrey Douglas
 *
 * All rights reserved.
 */

#include "ssh_stats_vtab.hh"

#include <algorithm>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "ioc_matcher.hh"
#include "lnav.hh"
#include "sql_help.hh"
#include "ssh_stats.hh"
#include "vtab_module.hh"
#include "vtab_module_json.hh"
#include "yajl/api/yajl_gen.h"
#include "yajlpp/yajlpp.hh"

namespace {

struct ssh_flow_export_row {
    std::string source_ip;
    std::string destination;
    std::string outcome;
    std::string auth_source;
    std::string top_user;
    std::vector<std::pair<std::string, size_t>> user_counts;
    size_t event_count{0};
    double event_percent{0.0};
    bool ioc_match{false};
};

struct ssh_ip_export_row {
    std::string address;
    std::string scope;
    size_t event_count{0};
    bool ioc_match{false};
};

static std::vector<std::pair<std::string, size_t>>
sorted_user_counts(const std::map<std::string, size_t>& user_counts)
{
    std::vector<std::pair<std::string, size_t>> retval;

    retval.reserve(user_counts.size());
    for (const auto& [user, count] : user_counts) {
        retval.emplace_back(user, count);
    }
    std::sort(retval.begin(), retval.end(), [](const auto& a, const auto& b) {
        if (a.second != b.second) {
            return a.second > b.second;
        }
        return a.first < b.first;
    });

    return retval;
}

static std::vector<ssh_flow_export_row>
build_flow_rows(const lnav::forensics::ssh_flow_stats& stats)
{
    std::vector<ssh_flow_export_row> retval;
    auto sorted_flows = lnav::forensics::sorted_ssh_flows(stats);

    retval.reserve(sorted_flows.size());
    for (const auto& [key, count] : sorted_flows) {
        const auto& [src_ip, dest_host, outcome, auth_source] = key;
        const auto& rec = stats.flows.at(key);
        auto users = sorted_user_counts(rec.user_counts);

        ssh_flow_export_row row;
        row.source_ip = src_ip;
        row.destination = dest_host;
        row.outcome = outcome;
        row.auth_source = auth_source;
        row.user_counts = std::move(users);
        if (!row.user_counts.empty()) {
            row.top_user = row.user_counts[0].first;
        }
        row.event_count = count;
        row.event_percent = stats.total_ssh_events == 0
            ? 0.0
            : (100.0 * static_cast<double>(count)
               / static_cast<double>(stats.total_ssh_events));
        row.ioc_match = lnav_data.ld_ioc_matcher.matches(src_ip);
        retval.emplace_back(std::move(row));
    }

    return retval;
}

static std::vector<ssh_ip_export_row>
build_ip_rows(const lnav::forensics::ssh_flow_stats& stats)
{
    std::vector<ssh_ip_export_row> retval;

    retval.reserve(stats.ip_counts.size());
    for (const auto& [ip, count] : stats.ip_counts) {
        ssh_ip_export_row row;
        row.address = ip;
        row.scope = lnav::forensics::is_private_ip(ip) ? "private" : "public";
        row.event_count = count;
        row.ioc_match = lnav_data.ld_ioc_matcher.matches(ip);
        retval.emplace_back(std::move(row));
    }

    std::sort(retval.begin(), retval.end(), [](const auto& a, const auto& b) {
        if (a.scope != b.scope) {
            return a.scope < b.scope;
        }
        if (a.event_count != b.event_count) {
            return a.event_count > b.event_count;
        }
        return a.address < b.address;
    });

    return retval;
}

static json_string
user_counts_to_json(const std::vector<std::pair<std::string, size_t>>& users)
{
    yajlpp_gen gen;
    {
        yajlpp_map root(gen);
        for (const auto& [user, count] : users) {
            root.gen(user);
            root.gen(count);
        }
    }
    return json_string(gen);
}

static void
gen_nullable_string(yajlpp_generator& gen, const std::string& value)
{
    if (value.empty()) {
        gen();
    } else {
        gen(value);
    }
}

static void
gen_user_counts(yajlpp_generator& gen,
                const std::vector<std::pair<std::string, size_t>>& users)
{
    yajlpp_map users_obj(gen.yg_handle);
    for (const auto& [user, count] : users) {
        users_obj.gen(user);
        users_obj.gen(count);
    }
}

static json_string
ssh_stats_to_json(const lnav::forensics::ssh_flow_stats& stats)
{
    auto flow_rows = build_flow_rows(stats);
    auto ip_rows = build_ip_rows(stats);
    yajlpp_gen gen;
    yajl_gen_config(gen, yajl_gen_beautify, false);

    {
        yajlpp_map root(gen);

        root.gen("summary");
        {
            yajlpp_map summary(gen);
            summary.gen("total_ssh_events");
            summary.gen(stats.total_ssh_events);
            summary.gen("unique_sources");
            summary.gen(stats.unique_sources.size());
            summary.gen("counters");
            {
                yajlpp_map counters(gen);
                counters.gen("accepted");
                counters.gen(stats.counters.accepted);
                counters.gen("failed_password");
                counters.gen(stats.counters.failed_password);
                counters.gen("failed_publickey");
                counters.gen(stats.counters.failed_publickey);
                counters.gen("failed_keyboard_interactive");
                counters.gen(stats.counters.failed_keyboard_interactive);
                counters.gen("failed_pam");
                counters.gen(stats.counters.failed_pam);
                counters.gen("invalid_user");
                counters.gen(stats.counters.invalid_user);
                counters.gen("too_many_auth_failures");
                counters.gen(stats.counters.too_many_auth_failures);
                counters.gen("disconnected");
                counters.gen(stats.counters.disconnected);
                counters.gen("closed_preauth");
                counters.gen(stats.counters.closed_preauth);
                counters.gen("client_disconnect");
                counters.gen(stats.counters.client_disconnect);
                counters.gen("closed");
                counters.gen(stats.counters.closed);
                counters.gen("new_connection");
                counters.gen(stats.counters.new_connection);
            }
        }

        root.gen("ioc");
        {
            yajlpp_map ioc(gen);
            ioc.gen("entries_loaded");
            ioc.gen(lnav_data.ld_ioc_matcher.entry_count());
            ioc.gen("exact_ips");
            ioc.gen(lnav_data.ld_ioc_matcher.exact_ips());
            ioc.gen("cidrs");
            ioc.gen(lnav_data.ld_ioc_matcher.cidr_labels());
        }

        root.gen("flows");
        {
            yajlpp_array flows(gen);
            for (const auto& row : flow_rows) {
                yajlpp_map flow(gen);
                flow.gen("source_ip");
                gen_nullable_string(flow.gen, row.source_ip);
                flow.gen("destination");
                gen_nullable_string(flow.gen, row.destination);
                flow.gen("outcome");
                flow.gen(row.outcome);
                flow.gen("auth_source");
                gen_nullable_string(flow.gen, row.auth_source);
                flow.gen("top_user");
                gen_nullable_string(flow.gen, row.top_user);
                flow.gen("user_counts");
                gen_user_counts(flow.gen, row.user_counts);
                flow.gen("event_count");
                flow.gen(row.event_count);
                flow.gen("event_percent");
                flow.gen(row.event_percent);
                flow.gen("ioc_match");
                flow.gen(row.ioc_match);
            }
        }

        root.gen("ip_counts");
        {
            yajlpp_array ips(gen);
            for (const auto& row : ip_rows) {
                yajlpp_map ip(gen);
                ip.gen("address");
                ip.gen(row.address);
                ip.gen("scope");
                ip.gen(row.scope);
                ip.gen("event_count");
                ip.gen(row.event_count);
                ip.gen("ioc_match");
                ip.gen(row.ioc_match);
            }
        }
    }

    return json_string(gen);
}

static void
sql_ssh_stats_json(sqlite3_context* ctx, int argc, sqlite3_value** argv)
{
    if (argc != 0) {
        sqlite3_result_error(ctx, "ssh_stats_json() expects no arguments", -1);
        return;
    }

    auto stats = lnav::forensics::collect_ssh_stats(lnav_data.ld_log_source);
    to_sqlite(ctx, ssh_stats_to_json(stats));
}

enum {
    SS_COL_SOURCE_IP,
    SS_COL_DESTINATION,
    SS_COL_OUTCOME,
    SS_COL_AUTH_SOURCE,
    SS_COL_TOP_USER,
    SS_COL_USER_COUNTS,
    SS_COL_EVENT_COUNT,
    SS_COL_EVENT_PERCENT,
    SS_COL_IOC_MATCH,
};

struct ssh_stats_vtab {
    static constexpr const char* NAME = "ssh_stats";
    static constexpr const char* CREATE_STMT = R"(
-- The ssh_stats table exposes the same flow rows used by the :ssh-stats view
CREATE TABLE ssh_stats (
    source_ip text,
    destination text,
    outcome text,
    auth_source text,
    top_user text,
    user_counts text,
    event_count integer,
    event_percent real,
    ioc_match integer
);
)";

    struct cursor {
        sqlite3_vtab_cursor base;
        sqlite3_int64 c_rowid{0};
        std::vector<ssh_flow_export_row> c_rows;

        cursor(sqlite3_vtab* vt) : base({vt}) {}

        int reset()
        {
            this->c_rowid = 0;
            auto stats
                = lnav::forensics::collect_ssh_stats(lnav_data.ld_log_source);
            this->c_rows = build_flow_rows(stats);
            return SQLITE_OK;
        }

        int next()
        {
            this->c_rowid += 1;
            return SQLITE_OK;
        }

        int eof() { return this->c_rowid >= (int64_t) this->c_rows.size(); }

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
        auto emit_string = [ctx](const std::string& value) {
            if (value.empty()) {
                sqlite3_result_null(ctx);
            } else {
                sqlite3_result_text(
                    ctx, value.c_str(), value.length(), SQLITE_TRANSIENT);
            }
        };

        switch (col) {
            case SS_COL_SOURCE_IP:
                emit_string(row.source_ip);
                break;
            case SS_COL_DESTINATION:
                emit_string(row.destination);
                break;
            case SS_COL_OUTCOME:
                emit_string(row.outcome);
                break;
            case SS_COL_AUTH_SOURCE:
                emit_string(row.auth_source);
                break;
            case SS_COL_TOP_USER:
                emit_string(row.top_user);
                break;
            case SS_COL_USER_COUNTS:
                to_sqlite(ctx, user_counts_to_json(row.user_counts));
                break;
            case SS_COL_EVENT_COUNT:
                sqlite3_result_int64(ctx, row.event_count);
                break;
            case SS_COL_EVENT_PERCENT:
                sqlite3_result_double(ctx, row.event_percent);
                break;
            case SS_COL_IOC_MATCH:
                sqlite3_result_int(ctx, row.ioc_match ? 1 : 0);
                break;
        }

        return SQLITE_OK;
    }
};

enum {
    SSIP_COL_ADDRESS,
    SSIP_COL_SCOPE,
    SSIP_COL_EVENT_COUNT,
    SSIP_COL_IOC_MATCH,
};

struct ssh_stats_ip_counts_vtab {
    static constexpr const char* NAME = "ssh_stats_ip_counts";
    static constexpr const char* CREATE_STMT = R"(
-- The ssh_stats_ip_counts table exposes IP frequency rows from :ssh-stats
CREATE TABLE ssh_stats_ip_counts (
    address text,
    scope text,
    event_count integer,
    ioc_match integer
);
)";

    struct cursor {
        sqlite3_vtab_cursor base;
        sqlite3_int64 c_rowid{0};
        std::vector<ssh_ip_export_row> c_rows;

        cursor(sqlite3_vtab* vt) : base({vt}) {}

        int reset()
        {
            this->c_rowid = 0;
            auto stats
                = lnav::forensics::collect_ssh_stats(lnav_data.ld_log_source);
            this->c_rows = build_ip_rows(stats);
            return SQLITE_OK;
        }

        int next()
        {
            this->c_rowid += 1;
            return SQLITE_OK;
        }

        int eof() { return this->c_rowid >= (int64_t) this->c_rows.size(); }

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
        switch (col) {
            case SSIP_COL_ADDRESS:
                sqlite3_result_text(
                    ctx, row.address.c_str(), row.address.length(), SQLITE_TRANSIENT);
                break;
            case SSIP_COL_SCOPE:
                sqlite3_result_text(
                    ctx, row.scope.c_str(), row.scope.length(), SQLITE_TRANSIENT);
                break;
            case SSIP_COL_EVENT_COUNT:
                sqlite3_result_int64(ctx, row.event_count);
                break;
            case SSIP_COL_IOC_MATCH:
                sqlite3_result_int(ctx, row.ioc_match ? 1 : 0);
                break;
        }
        return SQLITE_OK;
    }
};

enum {
    SSSUM_COL_METRIC,
    SSSUM_COL_VALUE,
};

struct ssh_summary_row {
    std::string metric;
    size_t value{0};
};

static std::vector<ssh_summary_row>
build_summary_rows(const lnav::forensics::ssh_flow_stats& stats)
{
    return {
        {"total_ssh_events", stats.total_ssh_events},
        {"unique_sources", stats.unique_sources.size()},
        {"accepted", stats.counters.accepted},
        {"failed_password", stats.counters.failed_password},
        {"failed_publickey", stats.counters.failed_publickey},
        {"failed_keyboard_interactive",
         stats.counters.failed_keyboard_interactive},
        {"failed_pam", stats.counters.failed_pam},
        {"invalid_user", stats.counters.invalid_user},
        {"too_many_auth_failures", stats.counters.too_many_auth_failures},
        {"disconnected", stats.counters.disconnected},
        {"closed_preauth", stats.counters.closed_preauth},
        {"client_disconnect", stats.counters.client_disconnect},
        {"closed", stats.counters.closed},
        {"new_connection", stats.counters.new_connection},
    };
}

struct ssh_stats_summary_vtab {
    static constexpr const char* NAME = "ssh_stats_summary";
    static constexpr const char* CREATE_STMT = R"(
-- The ssh_stats_summary table exposes event counters from :ssh-stats
CREATE TABLE ssh_stats_summary (
    metric text,
    value integer
);
)";

    struct cursor {
        sqlite3_vtab_cursor base;
        sqlite3_int64 c_rowid{0};
        std::vector<ssh_summary_row> c_rows;

        cursor(sqlite3_vtab* vt) : base({vt}) {}

        int reset()
        {
            this->c_rowid = 0;
            auto stats
                = lnav::forensics::collect_ssh_stats(lnav_data.ld_log_source);
            this->c_rows = build_summary_rows(stats);
            return SQLITE_OK;
        }

        int next()
        {
            this->c_rowid += 1;
            return SQLITE_OK;
        }

        int eof() { return this->c_rowid >= (int64_t) this->c_rows.size(); }

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
        switch (col) {
            case SSSUM_COL_METRIC:
                sqlite3_result_text(
                    ctx, row.metric.c_str(), row.metric.length(), SQLITE_TRANSIENT);
                break;
            case SSSUM_COL_VALUE:
                sqlite3_result_int64(ctx, row.value);
                break;
        }
        return SQLITE_OK;
    }
};

}  // namespace

int
register_ssh_stats_vtabs(sqlite3* db)
{
    static vtab_module<tvt_no_update<ssh_stats_vtab>> SSH_STATS_MODULE;
    static vtab_module<tvt_no_update<ssh_stats_ip_counts_vtab>>
        SSH_STATS_IP_COUNTS_MODULE;
    static vtab_module<tvt_no_update<ssh_stats_summary_vtab>>
        SSH_STATS_SUMMARY_MODULE;
    static help_text ssh_stats_help
        = help_text("ssh_stats",
                    "A table-valued function that exposes SSH flow rows from "
                    "the current log view.")
              .sql_table_valued_function()
              .with_result({"source_ip", "The SSH source IP address."})
              .with_result({"destination", "The destination host."})
              .with_result({"outcome", "The SSH event outcome."})
              .with_result({"auth_source", "The detected auth source."})
              .with_result({"top_user", "The most frequent user for the flow."})
              .with_result({"user_counts", "A JSON object of user counts."})
              .with_result({"event_count", "The number of events in the flow."})
              .with_result({"event_percent", "The percent of all SSH events."})
              .with_result({"ioc_match",
                            "1 if the source IP matches a loaded IOC entry."})
              .with_tags({"forensics"})
              .with_example({
                  "To list SSH flow rows",
                  "SELECT source_ip, destination, outcome, event_count FROM "
                  "ssh_stats",
              });
    static help_text ssh_stats_ip_help
        = help_text("ssh_stats_ip_counts",
                    "A table-valued function that exposes IP frequency rows "
                    "from the current SSH stats.")
              .sql_table_valued_function()
              .with_result({"address", "The IP address."})
              .with_result({"scope", "'public' or 'private'."})
              .with_result({"event_count", "The number of sightings."})
              .with_result({"ioc_match",
                            "1 if the address matches a loaded IOC entry."})
              .with_tags({"forensics"})
              .with_example({
                  "To list IOC-matched source addresses",
                  "SELECT * FROM ssh_stats_ip_counts WHERE ioc_match = 1",
              });
    static help_text ssh_stats_summary_help
        = help_text("ssh_stats_summary",
                    "A table-valued function that exposes SSH event counters "
                    "from the current log view.")
              .sql_table_valued_function()
              .with_result({"metric", "The counter name."})
              .with_result({"value", "The counter value."})
              .with_tags({"forensics"})
              .with_example({
                  "To list SSH event counters",
                  "SELECT * FROM ssh_stats_summary",
              });
    static help_text ssh_stats_json_help
        = help_text("ssh_stats_json",
                    "Return the current SSH stats as a structured JSON "
                    "document.")
              .sql_function()
              .with_result({"summary", "The event counters."})
              .with_result({"ioc", "The loaded IOC entry metadata."})
              .with_result({"flows", "The SSH flow rows."})
              .with_result({"ip_counts", "The IP frequency rows."})
              .with_tags({"forensics"})
              .with_example({
                  "To export the current SSH stats as JSON",
                  "SELECT ssh_stats_json()",
              });

    auto rc = SSH_STATS_MODULE.create(db, "ssh_stats");
    ensure(rc == SQLITE_OK);
    rc = SSH_STATS_IP_COUNTS_MODULE.create(db, "ssh_stats_ip_counts");
    ensure(rc == SQLITE_OK);
    rc = SSH_STATS_SUMMARY_MODULE.create(db, "ssh_stats_summary");
    ensure(rc == SQLITE_OK);

    auto json_flags = SQLITE_UTF8;
#ifdef SQLITE_RESULT_SUBTYPE
    json_flags |= SQLITE_RESULT_SUBTYPE;
#endif

    rc = sqlite3_create_function_v2(db,
                                    "ssh_stats_json",
                                    0,
                                    json_flags,
                                    nullptr,
                                    sql_ssh_stats_json,
                                    nullptr,
                                    nullptr,
                                    nullptr);
    ensure(rc == SQLITE_OK);

    sqlite_function_help.insert(std::make_pair("ssh_stats", &ssh_stats_help));
    sqlite_function_help.insert(
        std::make_pair("ssh_stats_ip_counts", &ssh_stats_ip_help));
    sqlite_function_help.insert(
        std::make_pair("ssh_stats_summary", &ssh_stats_summary_help));
    sqlite_function_help.insert(
        std::make_pair("ssh_stats_json", &ssh_stats_json_help));
    ssh_stats_help.index_tags();
    ssh_stats_ip_help.index_tags();
    ssh_stats_summary_help.index_tags();
    ssh_stats_json_help.index_tags();

    return rc;
}
