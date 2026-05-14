/**
 * Copyright (c) 2026, Jeffrey Douglas
 *
 * All rights reserved.
 */

#include "ssh_flow.hh"

#include <arpa/inet.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <optional>
#include <utility>

#include "data_scanner.hh"

namespace lnav::forensics {

static std::string
trim_copy(std::string s)
{
    auto is_space = [](unsigned char ch) { return std::isspace(ch) != 0; };

    while (!s.empty() && is_space(static_cast<unsigned char>(s.front()))) {
        s.erase(s.begin());
    }
    while (!s.empty() && is_space(static_cast<unsigned char>(s.back()))) {
        s.pop_back();
    }
    return s;
}

static bool
starts_with(const std::string& s, const char* prefix)
{
    return s.rfind(prefix, 0) == 0;
}

static bool
contains_ci(const std::string& haystack, const char* needle)
{
    const auto needle_len = strlen(needle);

    if (needle_len == 0) {
        return true;
    }

    return std::search(
               haystack.begin(),
               haystack.end(),
               needle,
               needle + needle_len,
               [](unsigned char ch, unsigned char pat_ch) {
                   return std::tolower(ch) == std::tolower(pat_ch);
               })
        != haystack.end();
}

static std::string
strip_wrappers(std::string s)
{
    s = trim_copy(std::move(s));

    bool changed;
    do {
        changed = false;
        if (s.size() >= 2
            && ((s.front() == '\'' && s.back() == '\'')
                || (s.front() == '"' && s.back() == '"')
                || (s.front() == '[' && s.back() == ']')
                || (s.front() == '(' && s.back() == ')')))
        {
            s = trim_copy(s.substr(1, s.size() - 2));
            changed = true;
        }
    } while (changed);

    while (!s.empty() && (s.back() == ',' || s.back() == ';')) {
        s.pop_back();
    }

    return trim_copy(std::move(s));
}

static std::optional<std::string>
normalize_ip_address(std::string candidate)
{
    candidate = strip_wrappers(std::move(candidate));
    if (candidate.empty()) {
        return std::nullopt;
    }

    in_addr addr4;
    if (inet_pton(AF_INET, candidate.c_str(), &addr4) == 1) {
        char buf[INET_ADDRSTRLEN];
        if (inet_ntop(AF_INET, &addr4, buf, sizeof(buf)) != nullptr) {
            return std::string(buf);
        }
    }

    in6_addr addr6;
    if (inet_pton(AF_INET6, candidate.c_str(), &addr6) == 1) {
        char buf[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &addr6, buf, sizeof(buf)) != nullptr) {
            return std::string(buf);
        }
    }

    return std::nullopt;
}

static std::optional<std::string>
first_ip_in_text(const std::string& text)
{
    auto sf = string_fragment::from_str(text);
    data_scanner ds(sf);

    while (true) {
        auto tok_res = ds.tokenize2();
        if (!tok_res) {
            break;
        }
        if (tok_res->tr_token == DT_IPV4_ADDRESS
            || tok_res->tr_token == DT_IPV6_ADDRESS)
        {
            auto norm_ip = normalize_ip_address(tok_res->to_string());
            if (norm_ip) {
                return norm_ip;
            }
        } else if (tok_res->tr_token == DT_QUOTED_STRING) {
            auto inner_sf = tok_res->inner_string_fragment();
            data_scanner inner_ds(inner_sf, false);
            auto inner_tok = inner_ds.tokenize2();
            if (inner_tok
                && (inner_tok->tr_token == DT_IPV4_ADDRESS
                    || inner_tok->tr_token == DT_IPV6_ADDRESS)
                && inner_tok->tr_capture.length() == inner_sf.length())
            {
                auto norm_ip = normalize_ip_address(inner_tok->to_string());
                if (norm_ip) {
                    return norm_ip;
                }
            }
        }
    }

    std::string token;
    auto flush_token = [&token]() -> std::optional<std::string> {
        if (token.empty()) {
            return std::nullopt;
        }
        auto retval = normalize_ip_address(token);
        token.clear();
        return retval;
    };
    for (auto ch : text) {
        if (std::isspace(static_cast<unsigned char>(ch)) || ch == ','
            || ch == ';')
        {
            auto ip = flush_token();
            if (ip) {
                return ip;
            }
        } else {
            token.push_back(ch);
        }
    }
    return flush_token();
}

static std::optional<std::string>
first_ip_after(const std::string& line, const std::string& marker)
{
    auto pos = line.find(marker);
    if (pos == std::string::npos) {
        return std::nullopt;
    }
    return first_ip_in_text(line.substr(pos + marker.size()));
}

static std::string
extract_source_ip(const std::string& line)
{
    static const char* const MARKERS[] = {
        " rhost=",
        " from ",
        "Connection from ",
        "Received disconnect from ",
        "Disconnected from ",
        " by ",
    };

    for (const auto* marker : MARKERS) {
        auto ip = first_ip_after(line, marker);
        if (ip) {
            return ip.value();
        }
    }

    return first_ip_in_text(line).value_or(std::string{});
}

static std::string
clean_user_value(std::string value)
{
    value = trim_copy(std::move(value));

    static const char* const PREFIXES[] = {
        "invalid user ",
        "authenticating user ",
        "user ",
    };

    bool stripped;
    do {
        stripped = false;
        for (const auto* prefix : PREFIXES) {
            if (starts_with(value, prefix)) {
                value = trim_copy(value.substr(strlen(prefix)));
                stripped = true;
                break;
            }
        }
    } while (stripped);

    value = strip_wrappers(std::move(value));

    auto paren = value.find('(');
    if (paren != std::string::npos) {
        value.resize(paren);
    }
    while (!value.empty() && (value.back() == ',' || value.back() == ';')) {
        value.pop_back();
    }
    return trim_copy(std::move(value));
}

static std::string
extract_quoted_or_word(std::string text)
{
    text = trim_copy(std::move(text));
    if (text.empty()) {
        return {};
    }

    if (text.front() == '\'' || text.front() == '"') {
        auto quote = text.front();
        auto end = text.find(quote, 1);
        if (end != std::string::npos) {
            return clean_user_value(text.substr(0, end + 1));
        }
    }

    auto end = text.find_first_of(" \t\r\n,;");
    return clean_user_value(text.substr(
        0, end == std::string::npos ? std::string::npos : end));
}

static std::string
extract_user_word_after(const std::string& line, const std::string& marker)
{
    auto pos = line.find(marker);
    if (pos == std::string::npos) {
        return {};
    }
    return extract_quoted_or_word(line.substr(pos + marker.size()));
}

static std::string
extract_user_after(const std::string& line, const std::string& marker)
{
    auto pos = line.find(marker);
    if (pos == std::string::npos) {
        return {};
    }

    auto rest = trim_copy(line.substr(pos + marker.size()));
    if (rest.empty()) {
        return {};
    }

    if (rest.front() == '\'' || rest.front() == '"') {
        auto quote = rest.front();
        auto end = rest.find(quote, 1);
        if (end != std::string::npos) {
            return clean_user_value(rest.substr(0, end + 1));
        }
    }

    size_t end = rest.size();
    static const char* const END_MARKERS[] = {
        " from ",
        " rhost=",
        " port ",
        " ssh2",
        " [",
        ": ",
    };
    for (const auto* end_marker : END_MARKERS) {
        auto end_pos = rest.find(end_marker);
        if (end_pos != std::string::npos) {
            end = std::min(end, end_pos);
        }
    }
    return clean_user_value(rest.substr(0, end));
}

static std::string
extract_user_value(const std::string& line)
{
    auto user = extract_user_after(line, "user=");
    if (!user.empty()) {
        return user;
    }
    user = extract_user_after(line, " for ");
    if (!user.empty()) {
        return user;
    }
    return extract_user_after(line, " user ");
}

static std::string
extract_syslog_host(const std::string& line)
{
    size_t sshd_pos = line.find("sshd[");
    if (sshd_pos == std::string::npos) {
        sshd_pos = line.find("sshd:");
    }
    if (sshd_pos == 0 || sshd_pos == std::string::npos) {
        return {};
    }

    size_t end = sshd_pos - 1;
    while (end > 0 && line[end] == ' ') {
        --end;
    }
    size_t start = line.rfind(' ', end);
    start = (start == std::string::npos) ? 0 : start + 1;
    return line.substr(start, end - start + 1);
}

static std::string
detect_auth_source(const std::string& line)
{
    auto pos = line.find("Accepted ");
    if (pos != std::string::npos) {
        pos += 9;
        auto end = line.find(' ', pos);
        auto meth = line.substr(
            pos, end == std::string::npos ? std::string::npos : end - pos);
        if (meth == "password") {
            return "local (/etc/shadow)";
        }
        if (meth == "publickey") {
            return "public key";
        }
        if (meth == "gssapi-with-mic" || meth == "gssapi-keyex") {
            return "Kerberos/GSSAPI";
        }
        if (meth == "hostbased") {
            return "host-based";
        }
        if (meth == "none") {
            return "none (no auth)";
        }
    }

    if (line.find("pam_sss") != std::string::npos) {
        return "SSSD (LDAP/AD/IPA)";
    }
    if (line.find("pam_krb5") != std::string::npos) {
        return "Kerberos (pam_krb5)";
    }
    if (line.find("pam_winbind") != std::string::npos) {
        return "Winbind/AD";
    }
    if (line.find("pam_google_authenticator") != std::string::npos) {
        return "MFA/Google Auth";
    }
    if (line.find("pam_duo") != std::string::npos) {
        return "MFA/Duo";
    }
    if (line.find("pam_oath") != std::string::npos) {
        return "MFA/OTP";
    }
    if (line.find("pam_yubico") != std::string::npos) {
        return "MFA/YubiKey";
    }
    if (line.find("pam_fprintd") != std::string::npos) {
        return "Biometric";
    }
    if (line.find("pam_radius") != std::string::npos) {
        return "RADIUS";
    }
    if (line.find("pam_pkcs11") != std::string::npos) {
        return "Smartcard/PIV";
    }
    if (line.find("pam_ldap") != std::string::npos) {
        return "LDAP";
    }
    if (line.find("keyboard-interactive") != std::string::npos) {
        return "PAM (interactive)";
    }
    return "";
}

static void
emit_flow(ssh_flow_stats& stats,
          const std::string& src_ip,
          const std::string& host,
          const std::string& outcome,
          const std::string& auth_source,
          const std::string& user)
{
    ssh_flow_key key{src_ip, host, outcome, auth_source};
    auto& rec = stats.flows[key];
    rec.count += 1;
    if (!user.empty()) {
        rec.user_counts[user] += 1;
    }
    if (!src_ip.empty()) {
        stats.unique_sources.insert(src_ip);
    }
    stats.total_ssh_events += 1;
}

static std::set<std::string>
count_ip_tokens(const string_fragment& sf, ssh_flow_stats& stats)
{
    std::set<std::string> ips_seen;
    data_scanner ds(sf);

    while (true) {
        auto tok_res = ds.tokenize2();
        if (!tok_res) {
            break;
        }

        std::optional<std::string> ip_str;
        if (tok_res->tr_token == DT_IPV4_ADDRESS
            || tok_res->tr_token == DT_IPV6_ADDRESS)
        {
            ip_str = normalize_ip_address(tok_res->to_string());
        } else if (tok_res->tr_token == DT_QUOTED_STRING) {
            auto inner_sf = tok_res->inner_string_fragment();
            data_scanner inner_ds(inner_sf, false);
            auto inner_tok = inner_ds.tokenize2();
            if (inner_tok
                && (inner_tok->tr_token == DT_IPV4_ADDRESS
                    || inner_tok->tr_token == DT_IPV6_ADDRESS)
                && inner_tok->tr_capture.length() == inner_sf.length())
            {
                ip_str = normalize_ip_address(inner_tok->to_string());
            }
        }

        if (ip_str) {
            stats.ip_counts[ip_str.value()] += 1;
            stats.unique_sources.insert(ip_str.value());
            ips_seen.insert(ip_str.value());
        }
    }

    return ips_seen;
}

void
scan_ssh_line(const string_fragment& sf,
              const std::string& line,
              ssh_flow_stats& stats)
{
    auto ips_seen = count_ip_tokens(sf, stats);

    auto host = extract_syslog_host(line);
    auto src_ip = extract_source_ip(line);
    if (!src_ip.empty() && ips_seen.count(src_ip) == 0) {
        stats.ip_counts[src_ip] += 1;
        stats.unique_sources.insert(src_ip);
    }

    auto auth = detect_auth_source(line);

    if (line.find("Accepted ") != std::string::npos) {
        stats.counters.accepted += 1;
        auto user = extract_user_after(line, " for ");
        emit_flow(stats, src_ip, host, "\xE2\x9C\x93 Accepted", auth, user);
    } else if (!auth.empty()
               && (contains_ci(line, "authentication success")
                   || contains_ci(line, "successful duo login")))
    {
        stats.counters.accepted += 1;
        auto user = extract_user_value(line);
        emit_flow(stats, src_ip, host, "\xE2\x9C\x93 Accepted", auth, user);
    } else if (!auth.empty() && contains_ci(line, "authentication failure")) {
        stats.counters.failed_pam += 1;
        auto user = extract_user_value(line);
        emit_flow(stats, src_ip, host, "\xE2\x9C\x97 Failed auth", auth, user);
    } else if (line.find("Disconnecting: Too many") != std::string::npos
               || line.find("Too many authentication failures")
                   != std::string::npos)
    {
        stats.counters.too_many_auth_failures += 1;
        auto user = extract_user_after(line, " for ");
        emit_flow(
            stats, src_ip, host, "\xE2\x9C\x97 Too many failures", auth, user);
    } else if (line.find("Failed password") != std::string::npos
               || line.find("Failed publickey") != std::string::npos
               || line.find("Failed keyboard") != std::string::npos)
    {
        if (line.find("Failed publickey") != std::string::npos) {
            stats.counters.failed_publickey += 1;
        } else if (line.find("Failed keyboard") != std::string::npos) {
            stats.counters.failed_keyboard_interactive += 1;
        } else {
            stats.counters.failed_password += 1;
        }
        auto user_raw = extract_user_after(line, "Failed password for ");
        if (user_raw.empty()) {
            user_raw = extract_user_after(line, "Failed publickey for ");
        }
        if (user_raw.empty()) {
            user_raw
                = extract_user_after(line, "Failed keyboard-interactive/pam for ");
        }
        if (user_raw.empty()) {
            user_raw
                = extract_user_after(line, "Failed keyboard-interactive for ");
        }
        emit_flow(
            stats, src_ip, host, "\xE2\x9C\x97 Failed auth", auth, user_raw);
    } else if (line.find("Invalid user ") != std::string::npos) {
        stats.counters.invalid_user += 1;
        auto user = extract_user_after(line, "Invalid user ");
        emit_flow(stats, src_ip, host, "\xE2\x9C\x97 Invalid user", auth, user);
    } else if (line.find("authenticating user ") != std::string::npos) {
        stats.counters.closed_preauth += 1;
        auto user = extract_user_word_after(line, "authenticating user ");
        emit_flow(
            stats, src_ip, host, "\xE2\x8A\x98 Closed (preauth)", auth, user);
    } else if (line.find("Disconnected from user ") != std::string::npos) {
        stats.counters.disconnected += 1;
        auto user = extract_user_word_after(line, "Disconnected from user ");
        emit_flow(stats, src_ip, host, "\xE2\x8A\x98 Disconnected", auth, user);
    } else if (line.find("Disconnected from") != std::string::npos) {
        stats.counters.disconnected += 1;
        emit_flow(stats, src_ip, host, "\xE2\x8A\x98 Disconnected", auth, "");
    } else if ((line.find("Received disconnect from") != std::string::npos
                || line.find("Connection closed by") != std::string::npos)
               && line.find("[preauth]") != std::string::npos)
    {
        stats.counters.closed_preauth += 1;
        auto user = extract_user_word_after(line, "invalid user ");
        emit_flow(
            stats, src_ip, host, "\xE2\x8A\x98 Closed (preauth)", auth, user);
    } else if (line.find("Received disconnect from") != std::string::npos) {
        stats.counters.client_disconnect += 1;
        auto user = extract_user_after(line, "disconnected by user ");
        emit_flow(
            stats, src_ip, host, "\xE2\x8A\x98 Client disconnect", auth, user);
    } else if (line.find("Connection closed by") != std::string::npos) {
        stats.counters.closed += 1;
        auto user = extract_user_word_after(line, "closed by invalid user ");
        emit_flow(stats, src_ip, host, "\xE2\x8A\x98 Closed", auth, user);
    } else if (line.find("Connection from ") != std::string::npos
               || line.find("connection from ") != std::string::npos)
    {
        stats.counters.new_connection += 1;
        emit_flow(stats, src_ip, host, "\xE2\x86\x92 Connection", auth, "");
    }
}

std::vector<std::pair<ssh_flow_key, size_t>>
sorted_ssh_flows(const ssh_flow_stats& stats)
{
    std::vector<std::pair<ssh_flow_key, size_t>> retval;
    retval.reserve(stats.flows.size());
    for (const auto& [key, rec] : stats.flows) {
        retval.emplace_back(key, rec.count);
    }
    std::sort(retval.begin(), retval.end(), [](const auto& a, const auto& b) {
        return a.first < b.first;
    });
    return retval;
}

bool
is_private_ip(const std::string& ip)
{
    if (ip.find(':') != std::string::npos) {
        if (ip == "::1") {
            return true;
        }
        if (ip.size() >= 4
            && (ip.substr(0, 4) == "fe80" || ip.substr(0, 4) == "FE80"))
        {
            return true;
        }
        if (ip.size() >= 2) {
            auto pfx = ip.substr(0, 2);
            if (pfx == "fc" || pfx == "fd" || pfx == "FC" || pfx == "FD") {
                return true;
            }
        }
        return false;
    }

    unsigned a = 0, b = 0, c = 0, d = 0;
    if (sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return false;
    }
    if (a == 10) {
        return true;
    }
    if (a == 127) {
        return true;
    }
    if (a == 172 && b >= 16 && b <= 31) {
        return true;
    }
    if (a == 192 && b == 168) {
        return true;
    }
    if (a == 169 && b == 254) {
        return true;
    }
    return false;
}

}  // namespace lnav::forensics
