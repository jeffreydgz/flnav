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
 * @file entity_index.hh
 */

#ifndef lnav_entity_index_hh
#define lnav_entity_index_hh

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "entity_extractor.hh"

using log_line_t = int64_t;

/** Reference to an entity on a specific log line. */
struct entity_ref {
    entity_type_t er_type;
    std::string er_value;
    std::string er_source_field;
    float er_confidence;
};

/**
 * In-memory index of all extracted entities, supporting fast lookup by
 * entity value and by log line number.
 *
 * Thread safety: concurrent reads are safe; writes must be serialized
 * (caller holds m_mutex or ensures single-writer).
 */
class entity_index {
public:
    /** Insert entities for a given log line. */
    void insert(log_line_t line,
                const std::vector<extracted_entity>& entities);

    /** All lines containing a specific entity. */
    std::vector<log_line_t> lines_for_entity(
        entity_type_t type,
        const std::string& value) const;

    /** All entities on a specific line. */
    std::vector<entity_ref> entities_for_line(log_line_t line) const;

    /** Co-occurrence: entities sharing log lines with the given entity. */
    struct co_occurrence {
        entity_type_t co_type;
        std::string co_value;
        int co_count{0};
    };

    std::vector<co_occurrence> co_occurring_entities(
        entity_type_t type,
        const std::string& value,
        std::optional<entity_type_t> filter_type = std::nullopt) const;

    size_t total_entities() const;
    size_t unique_entity_values() const;

    /** Total number of indexed lines. */
    size_t indexed_line_count() const;

    void clear();

    /** Iteration support for virtual tables. */
    struct flat_row {
        log_line_t fr_line;
        entity_type_t fr_type;
        std::string fr_value;
        std::string fr_source_field;
        float fr_confidence;
    };

    /** Materialize all rows for vtab scanning. */
    std::vector<flat_row> all_rows() const;

private:
    using entity_key = std::pair<entity_type_t, std::string>;

    struct entity_key_hash {
        size_t operator()(const entity_key& k) const;
    };

    /** Intern pool for entity values to reduce memory usage. */
    std::unordered_set<std::string> m_string_pool;

    const std::string& intern(const std::string& s);

    /** (type, value) -> sorted line numbers */
    std::unordered_map<entity_key, std::vector<log_line_t>, entity_key_hash>
        m_value_index;

    /** line -> entities on that line */
    std::unordered_map<log_line_t, std::vector<entity_ref>> m_line_index;

    mutable std::mutex m_mutex;
};

#endif
