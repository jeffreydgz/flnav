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
 * @file entity_extractor.cc
 */

#include "entity_extractor.hh"

#include <algorithm>
#include <cstring>

#include "config.h"

static const struct {
    const char* name;
    entity_type_t type;
} ENTITY_TYPE_NAMES[] = {
    {"ip-address", entity_type_t::IP_ADDRESS},
    {"username", entity_type_t::USERNAME},
    {"hostname", entity_type_t::HOSTNAME},
    {"pid", entity_type_t::PID},
    {"session-id", entity_type_t::SESSION_ID},
    {"file-path", entity_type_t::FILE_PATH},
    {"hash-md5", entity_type_t::HASH_MD5},
    {"hash-sha1", entity_type_t::HASH_SHA1},
    {"hash-sha256", entity_type_t::HASH_SHA256},
    {"hash", entity_type_t::HASH_SHA256},
    {"email", entity_type_t::EMAIL},
    {"url", entity_type_t::URL},
    {"port", entity_type_t::PORT},
    {"mac-address", entity_type_t::MAC_ADDRESS},
};

const char*
entity_type_to_string(entity_type_t type)
{
    switch (type) {
        case entity_type_t::IP_ADDRESS:
            return "ip-address";
        case entity_type_t::USERNAME:
            return "username";
        case entity_type_t::HOSTNAME:
            return "hostname";
        case entity_type_t::PID:
            return "pid";
        case entity_type_t::SESSION_ID:
            return "session-id";
        case entity_type_t::FILE_PATH:
            return "file-path";
        case entity_type_t::HASH_MD5:
            return "hash-md5";
        case entity_type_t::HASH_SHA1:
            return "hash-sha1";
        case entity_type_t::HASH_SHA256:
            return "hash-sha256";
        case entity_type_t::EMAIL:
            return "email";
        case entity_type_t::URL:
            return "url";
        case entity_type_t::PORT:
            return "port";
        case entity_type_t::MAC_ADDRESS:
            return "mac-address";
        case entity_type_t::UNKNOWN:
        default:
            return "unknown";
    }
}

std::optional<entity_type_t>
string_to_entity_type(const std::string& s)
{
    for (const auto& entry : ENTITY_TYPE_NAMES) {
        if (s == entry.name) {
            return entry.type;
        }
    }
    return std::nullopt;
}

struct pattern_def {
    entity_type_t type;
    const char* pattern;
    float base_confidence;
    char quick_check;
};

static const pattern_def PATTERNS[] = {
    // IPv4 address
    {entity_type_t::IP_ADDRESS,
     R"(\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b)",
     0.85f,
     '.'},

    // IPv6 address (simplified — common forms, require 4+ groups to
    // avoid matching timestamps like "10:03:00")
    {entity_type_t::IP_ADDRESS,
     R"(\b((?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4})\b)",
     0.80f,
     ':'},

    // MAC address
    {entity_type_t::MAC_ADDRESS,
     R"(\b((?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\b)",
     0.90f,
     ':'},

    // Email address
    {entity_type_t::EMAIL,
     R"(\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b)",
     0.90f,
     '@'},

    // URL (http/https/ftp)
    {entity_type_t::URL,
     R"(\b((?:https?|ftp)://[^\s<>\"\')]+))",
     0.95f,
     '/'},

    // File path (Unix)
    {entity_type_t::FILE_PATH,
     R"((?:^|\s)(\/(?:[a-zA-Z0-9._\-]+\/)*[a-zA-Z0-9._\-]+))",
     0.70f,
     '/'},

    // SHA-256 hash (64 hex chars)
    {entity_type_t::HASH_SHA256,
     R"(\b([a-fA-F0-9]{64})\b)",
     0.90f,
     0},

    // SHA-1 hash (40 hex chars)
    {entity_type_t::HASH_SHA1,
     R"(\b([a-fA-F0-9]{40})\b)",
     0.85f,
     0},

    // MD5 hash (32 hex chars)
    {entity_type_t::HASH_MD5,
     R"(\b([a-fA-F0-9]{32})\b)",
     0.80f,
     0},

    // Session/request ID (high-entropy alphanumeric, 16+ chars)
    {entity_type_t::SESSION_ID,
     R"(\b([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})\b)",
     0.95f,
     '-'},

    // Hostname (FQDN)
    {entity_type_t::HOSTNAME,
     R"(\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){2,}[a-zA-Z]{2,})\b)",
     0.60f,
     '.'},
};

entity_extractor::entity_extractor()
{
    for (const auto& pd : PATTERNS) {
        auto compile_res = lnav::pcre2pp::code::from(
            string_fragment::from_c_str(pd.pattern));
        if (compile_res.isOk()) {
            pattern_entry pe;
            pe.pe_type = pd.type;
            pe.pe_code = std::make_shared<lnav::pcre2pp::code>(
                std::move(compile_res.unwrap()));
            pe.pe_base_confidence = pd.base_confidence;
            pe.pe_quick_check_char = pd.quick_check;
            this->m_patterns.emplace_back(std::move(pe));
        }
    }
}

bool
entity_extractor::quick_check(const std::string& text,
                               const pattern_entry& pe) const
{
    if (pe.pe_quick_check_char == 0) {
        return true;
    }
    return text.find(pe.pe_quick_check_char) != std::string::npos;
}

std::vector<extracted_entity>
entity_extractor::extract_from_body(const std::string& log_body) const
{
    std::vector<extracted_entity> results;

    if (log_body.empty()) {
        return results;
    }

    auto body_sf = string_fragment::from_str(log_body);

    for (const auto& pe : this->m_patterns) {
        if (!this->quick_check(log_body, pe)) {
            continue;
        }

        auto md = pe.pe_code->create_match_data();
        auto remaining = body_sf;

        while (remaining.is_valid() && !remaining.empty()) {
            auto match_res
                = pe.pe_code->capture_from(remaining).into(md).matches();
            if (match_res.is<lnav::pcre2pp::matcher::not_found>()
                || match_res.is<lnav::pcre2pp::matcher::error>())
            {
                break;
            }

            auto cap = md[1];
            if (!cap) {
                cap = md[0];
            }
            if (cap) {
                extracted_entity ent;
                ent.ee_type = pe.pe_type;
                ent.ee_value = cap->to_string();
                ent.ee_source_field = "log_body";
                ent.ee_start_offset
                    = static_cast<int>(cap->sf_begin - body_sf.sf_begin);
                ent.ee_end_offset
                    = static_cast<int>(cap->sf_end - body_sf.sf_begin);
                ent.ee_confidence = pe.pe_base_confidence;
                results.emplace_back(std::move(ent));
            }

            remaining = md.remaining();
        }
    }

    // Remove overlapping matches — prefer longer matches and higher confidence
    std::sort(results.begin(),
              results.end(),
              [](const extracted_entity& a, const extracted_entity& b) {
                  if (a.ee_start_offset != b.ee_start_offset) {
                      return a.ee_start_offset < b.ee_start_offset;
                  }
                  int len_a = a.ee_end_offset - a.ee_start_offset;
                  int len_b = b.ee_end_offset - b.ee_start_offset;
                  if (len_a != len_b) {
                      return len_a > len_b;
                  }
                  return a.ee_confidence > b.ee_confidence;
              });

    std::vector<extracted_entity> deduped;
    int last_end = -1;
    for (auto& ent : results) {
        if (ent.ee_start_offset >= last_end) {
            last_end = ent.ee_end_offset;
            deduped.emplace_back(std::move(ent));
        }
    }

    return deduped;
}

std::optional<extracted_entity>
entity_extractor::extract_from_field(const std::string& field_name,
                                     const std::string& field_value,
                                     entity_type_t declared_type) const
{
    if (field_value.empty()) {
        return std::nullopt;
    }

    // For declared types, validate the value matches the expected pattern
    for (const auto& pe : this->m_patterns) {
        if (pe.pe_type != declared_type) {
            continue;
        }

        auto sf = string_fragment::from_str(field_value);
        auto match_res = pe.pe_code->find_in(sf);
        if (match_res.is<lnav::pcre2pp::matcher::found>()) {
            extracted_entity ent;
            ent.ee_type = declared_type;
            ent.ee_value = field_value;
            ent.ee_source_field = field_name;
            ent.ee_start_offset = 0;
            ent.ee_end_offset = static_cast<int>(field_value.size());
            ent.ee_confidence = 1.0f;
            return ent;
        }
    }

    // Even if no pattern matched, trust the declared type
    extracted_entity ent;
    ent.ee_type = declared_type;
    ent.ee_value = field_value;
    ent.ee_source_field = field_name;
    ent.ee_start_offset = 0;
    ent.ee_end_offset = static_cast<int>(field_value.size());
    ent.ee_confidence = 0.90f;
    return ent;
}

entity_type_t
entity_extractor::guess_type_from_field_name(const std::string& name) const
{
    // Convert to lowercase for matching
    std::string lower;
    lower.reserve(name.size());
    for (auto c : name) {
        lower.push_back(static_cast<char>(tolower(c)));
    }

    if (lower.find("ip") != std::string::npos
        || lower.find("addr") != std::string::npos
        || lower == "src" || lower == "dst" || lower == "source"
        || lower == "destination" || lower == "remote" || lower == "client"
        || lower == "server")
    {
        return entity_type_t::IP_ADDRESS;
    }
    if (lower.find("user") != std::string::npos
        || lower.find("login") != std::string::npos
        || lower.find("account") != std::string::npos
        || lower == "uid" || lower == "owner" || lower == "author")
    {
        return entity_type_t::USERNAME;
    }
    if (lower.find("host") != std::string::npos
        || lower.find("fqdn") != std::string::npos
        || lower.find("server_name") != std::string::npos)
    {
        return entity_type_t::HOSTNAME;
    }
    if (lower == "pid" || lower == "process_id" || lower == "ppid") {
        return entity_type_t::PID;
    }
    if (lower.find("session") != std::string::npos
        || lower.find("request_id") != std::string::npos
        || lower.find("req_id") != std::string::npos
        || lower.find("trace_id") != std::string::npos
        || lower.find("correlation_id") != std::string::npos
        || lower.find("txn_id") != std::string::npos
        || lower.find("op_id") != std::string::npos)
    {
        return entity_type_t::SESSION_ID;
    }
    if (lower.find("path") != std::string::npos
        || lower.find("file") != std::string::npos
        || lower.find("dir") != std::string::npos)
    {
        return entity_type_t::FILE_PATH;
    }
    if (lower.find("hash") != std::string::npos
        || lower.find("digest") != std::string::npos
        || lower.find("checksum") != std::string::npos
        || lower == "md5" || lower == "sha1" || lower == "sha256")
    {
        return entity_type_t::HASH_SHA256;
    }
    if (lower.find("email") != std::string::npos
        || lower.find("mail") != std::string::npos)
    {
        return entity_type_t::EMAIL;
    }
    if (lower.find("url") != std::string::npos
        || lower.find("uri") != std::string::npos
        || lower.find("href") != std::string::npos)
    {
        return entity_type_t::URL;
    }
    if (lower == "port" || lower == "src_port" || lower == "dst_port"
        || lower == "sport" || lower == "dport")
    {
        return entity_type_t::PORT;
    }
    if (lower.find("mac") != std::string::npos) {
        return entity_type_t::MAC_ADDRESS;
    }

    return entity_type_t::UNKNOWN;
}

std::vector<extracted_entity>
entity_extractor::infer_from_field(const std::string& field_name,
                                   const std::string& field_value) const
{
    std::vector<extracted_entity> results;

    if (field_value.empty()) {
        return results;
    }

    auto guessed = this->guess_type_from_field_name(field_name);

    // Try pattern matching against the value
    auto sf = string_fragment::from_str(field_value);
    for (const auto& pe : this->m_patterns) {
        if (!this->quick_check(field_value, pe)) {
            continue;
        }

        auto match_res = pe.pe_code->find_in(sf);
        if (match_res.is<lnav::pcre2pp::matcher::found>()) {
            extracted_entity ent;
            ent.ee_type = pe.pe_type;
            ent.ee_value = field_value;
            ent.ee_source_field = field_name;
            ent.ee_start_offset = 0;
            ent.ee_end_offset = static_cast<int>(field_value.size());
            ent.ee_confidence = pe.pe_base_confidence;

            // Boost confidence if field name heuristic agrees
            if (guessed == pe.pe_type) {
                ent.ee_confidence
                    = std::min(1.0f, ent.ee_confidence + 0.10f);
            }
            results.emplace_back(std::move(ent));
            return results;  // first match wins for field values
        }
    }

    // If field name strongly suggests a type but no pattern matched,
    // still record with lower confidence for non-pattern types
    if (guessed == entity_type_t::USERNAME
        || guessed == entity_type_t::PID
        || guessed == entity_type_t::SESSION_ID
        || guessed == entity_type_t::PORT)
    {
        extracted_entity ent;
        ent.ee_type = guessed;
        ent.ee_value = field_value;
        ent.ee_source_field = field_name;
        ent.ee_start_offset = 0;
        ent.ee_end_offset = static_cast<int>(field_value.size());
        ent.ee_confidence = 0.60f;
        results.emplace_back(std::move(ent));
    }

    return results;
}
