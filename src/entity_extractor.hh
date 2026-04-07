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
 * @file entity_extractor.hh
 */

#ifndef lnav_entity_extractor_hh
#define lnav_entity_extractor_hh

#include <optional>
#include <string>
#include <vector>

#include "base/intern_string.hh"
#include "pcrepp/pcre2pp.hh"

/** Semantic entity types that can be extracted from log lines. */
enum class entity_type_t : int {
    IP_ADDRESS = 0,
    USERNAME,
    HOSTNAME,
    PID,
    SESSION_ID,
    FILE_PATH,
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA256,
    EMAIL,
    URL,
    PORT,
    MAC_ADDRESS,
    UNKNOWN,

    ET__MAX
};

/** Convert entity_type_t to its string representation used in SQL/JSON. */
const char* entity_type_to_string(entity_type_t type);

/** Parse a string (from JSON "entity-type" field) to entity_type_t. */
std::optional<entity_type_t> string_to_entity_type(const std::string& s);

/** A single extracted entity from a log line. */
struct extracted_entity {
    entity_type_t ee_type;
    std::string ee_value;
    std::string ee_source_field;
    int ee_start_offset{0};
    int ee_end_offset{0};
    float ee_confidence{0.0f};
};

/**
 * Extracts typed semantic entities from log lines using PCRE2 regex patterns
 * and field-name heuristics.
 *
 * Thread-safety: the compiled patterns are immutable after construction.
 * Match data is allocated per-call.
 */
class entity_extractor {
public:
    entity_extractor();

    /**
     * Extract entities from raw log body text using heuristic regex patterns.
     * All patterns are run; non-overlapping matches are returned (longest wins).
     */
    std::vector<extracted_entity> extract_from_body(
        const std::string& log_body) const;

    /**
     * Extract entity from a named field with a declared entity-type.
     * Returns confidence 1.0 if the value validates against the type.
     */
    std::optional<extracted_entity> extract_from_field(
        const std::string& field_name,
        const std::string& field_value,
        entity_type_t declared_type) const;

    /**
     * Infer entity type from an untyped field using name heuristics and
     * value pattern matching.
     */
    std::vector<extracted_entity> infer_from_field(
        const std::string& field_name,
        const std::string& field_value) const;

private:
    struct pattern_entry {
        entity_type_t pe_type;
        std::shared_ptr<lnav::pcre2pp::code> pe_code;
        float pe_base_confidence;
        char pe_quick_check_char;  // skip regex if char absent; 0 = no check
    };

    std::vector<pattern_entry> m_patterns;

    entity_type_t guess_type_from_field_name(const std::string& name) const;

    bool quick_check(const std::string& text,
                     const pattern_entry& pe) const;
};

#endif
