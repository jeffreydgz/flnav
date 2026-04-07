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
 * @file entity_sql_funcs.cc
 */

#include "entity_sql_funcs.hh"

#include <string>

#include "config.h"
#include "entity_extractor.hh"
#include "vtab_module.hh"

/**
 * SQL function: extract_entity_types(text)
 *
 * Returns a JSON array of entities extracted from the given text.
 * Each element is an object with type, value, start, end, confidence.
 */
static std::string
sql_extract_entity_types(string_fragment text)
{
    static entity_extractor s_extractor;

    auto entities = s_extractor.extract_from_body(text.to_string());

    std::string json = "[";
    bool first = true;
    for (const auto& ent : entities) {
        if (!first) {
            json += ",";
        }
        json += "{";
        json += "\"entity_type\":\"";
        json += entity_type_to_string(ent.ee_type);
        json += "\",\"entity_value\":\"";
        // Escape quotes in value
        for (char c : ent.ee_value) {
            if (c == '"') {
                json += "\\\"";
            } else if (c == '\\') {
                json += "\\\\";
            } else {
                json += c;
            }
        }
        json += "\",\"start_offset\":";
        json += std::to_string(ent.ee_start_offset);
        json += ",\"end_offset\":";
        json += std::to_string(ent.ee_end_offset);
        json += ",\"confidence\":";
        json += std::to_string(ent.ee_confidence);
        json += "}";
        first = false;
    }
    json += "]";

    return json;
}

/**
 * SQL function: entity_count(text)
 *
 * Returns the number of entities detected in the given text.
 */
static int64_t
sql_entity_count(string_fragment text)
{
    static entity_extractor s_extractor;

    auto entities = s_extractor.extract_from_body(text.to_string());
    return static_cast<int64_t>(entities.size());
}

/**
 * SQL function: has_entity(text, entity_type)
 *
 * Returns 1 if the text contains an entity of the given type, 0 otherwise.
 */
static int64_t
sql_has_entity(string_fragment text, string_fragment type_str)
{
    static entity_extractor s_extractor;

    auto type_opt = string_to_entity_type(type_str.to_string());
    if (!type_opt) {
        return 0;
    }

    auto entities = s_extractor.extract_from_body(text.to_string());
    for (const auto& ent : entities) {
        if (ent.ee_type == *type_opt) {
            return 1;
        }
    }
    return 0;
}

/**
 * SQL function: entity_value(text, entity_type)
 *
 * Returns the first entity value of the given type found in text,
 * or NULL if not found.
 */
static std::optional<std::string>
sql_entity_value(string_fragment text, string_fragment type_str)
{
    static entity_extractor s_extractor;

    auto type_opt = string_to_entity_type(type_str.to_string());
    if (!type_opt) {
        return std::nullopt;
    }

    auto entities = s_extractor.extract_from_body(text.to_string());
    for (const auto& ent : entities) {
        if (ent.ee_type == *type_opt) {
            return ent.ee_value;
        }
    }
    return std::nullopt;
}

int
entity_extension_functions(struct FuncDef** basic_funcs,
                           struct FuncDefAgg** agg_funcs)
{
    static struct FuncDef entity_funcs[] = {
        sqlite_func_adapter<decltype(&sql_extract_entity_types),
                            sql_extract_entity_types>::
            builder(
                help_text("extract_entities",
                          "Extract semantic entities (IPs, usernames, hashes, "
                          "etc.) from text")
                    .sql_function()
                    .with_parameter(
                        {"text", "The text to extract entities from"})
                    .with_tags({"entity", "security"})
                    .with_example({
                        "To extract entities from a log message",
                        "SELECT extract_entities('Failed login from "
                        "192.168.1.1 user admin')",
                    })),

        sqlite_func_adapter<decltype(&sql_entity_count), sql_entity_count>::
            builder(
                help_text("entity_count",
                          "Count the number of entities in text")
                    .sql_function()
                    .with_parameter(
                        {"text", "The text to scan for entities"})
                    .with_tags({"entity", "security"})
                    .with_example({
                        "To count entities in a log line",
                        "SELECT entity_count('Connection from 10.0.1.1 "
                        "to server.example.com')",
                    })),

        sqlite_func_adapter<decltype(&sql_has_entity), sql_has_entity>::
            builder(
                help_text("has_entity",
                          "Check if text contains an entity of the given type")
                    .sql_function()
                    .with_parameter(
                        {"text", "The text to scan"})
                    .with_parameter(
                        {"entity_type",
                         "The entity type to look for (e.g., 'ip-address', "
                         "'email')"})
                    .with_tags({"entity", "security"})
                    .with_example({
                        "To check for IP addresses",
                        "SELECT has_entity('Login from 10.0.0.1', "
                        "'ip-address')",
                    })),

        sqlite_func_adapter<decltype(&sql_entity_value), sql_entity_value>::
            builder(
                help_text("entity_value",
                          "Extract the first entity of the given type from "
                          "text")
                    .sql_function()
                    .with_parameter(
                        {"text", "The text to scan"})
                    .with_parameter(
                        {"entity_type",
                         "The entity type to extract (e.g., 'ip-address', "
                         "'username')"})
                    .with_tags({"entity", "security"})
                    .with_example({
                        "To extract the first IP address",
                        "SELECT entity_value('Login from 10.0.0.1', "
                        "'ip-address')",
                    })),

        {nullptr},
    };

    *basic_funcs = entity_funcs;

    return SQLITE_OK;
}
