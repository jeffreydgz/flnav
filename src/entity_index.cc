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
 * @file entity_index.cc
 */

#include "entity_index.hh"

#include <algorithm>

#include "config.h"

size_t
entity_index::entity_key_hash::operator()(const entity_key& k) const
{
    auto h1 = std::hash<int>{}(static_cast<int>(k.first));
    auto h2 = std::hash<std::string>{}(k.second);
    return h1 ^ (h2 << 1);
}

const std::string&
entity_index::intern(const std::string& s)
{
    auto it = this->m_string_pool.find(s);
    if (it != this->m_string_pool.end()) {
        return *it;
    }
    return *this->m_string_pool.insert(s).first;
}

void
entity_index::insert(log_line_t line,
                     const std::vector<extracted_entity>& entities)
{
    std::lock_guard<std::mutex> lock(this->m_mutex);

    auto& line_ents = this->m_line_index[line];

    for (const auto& ent : entities) {
        const auto& interned_value = this->intern(ent.ee_value);
        const auto& interned_field = this->intern(ent.ee_source_field);

        entity_key key{ent.ee_type, interned_value};
        auto& lines_vec = this->m_value_index[key];

        // Maintain sorted order
        auto insert_pos
            = std::lower_bound(lines_vec.begin(), lines_vec.end(), line);
        if (insert_pos == lines_vec.end() || *insert_pos != line) {
            lines_vec.insert(insert_pos, line);
        }

        entity_ref ref;
        ref.er_type = ent.ee_type;
        ref.er_value = interned_value;
        ref.er_source_field = interned_field;
        ref.er_confidence = ent.ee_confidence;
        line_ents.emplace_back(std::move(ref));
    }
}

std::vector<log_line_t>
entity_index::lines_for_entity(entity_type_t type,
                               const std::string& value) const
{
    std::lock_guard<std::mutex> lock(this->m_mutex);

    entity_key key{type, value};
    auto it = this->m_value_index.find(key);
    if (it != this->m_value_index.end()) {
        return it->second;
    }
    return {};
}

std::vector<entity_ref>
entity_index::entities_for_line(log_line_t line) const
{
    std::lock_guard<std::mutex> lock(this->m_mutex);

    auto it = this->m_line_index.find(line);
    if (it != this->m_line_index.end()) {
        return it->second;
    }
    return {};
}

std::vector<entity_index::co_occurrence>
entity_index::co_occurring_entities(
    entity_type_t type,
    const std::string& value,
    std::optional<entity_type_t> filter_type) const
{
    std::lock_guard<std::mutex> lock(this->m_mutex);

    entity_key key{type, value};
    auto it = this->m_value_index.find(key);
    if (it == this->m_value_index.end()) {
        return {};
    }

    // Count co-occurrences across all lines containing this entity
    std::unordered_map<entity_key, int, entity_key_hash> counts;

    for (auto line : it->second) {
        auto line_it = this->m_line_index.find(line);
        if (line_it == this->m_line_index.end()) {
            continue;
        }
        for (const auto& ref : line_it->second) {
            if (ref.er_type == type && ref.er_value == value) {
                continue;  // skip self
            }
            if (filter_type && ref.er_type != *filter_type) {
                continue;
            }
            entity_key co_key{ref.er_type, ref.er_value};
            counts[co_key]++;
        }
    }

    std::vector<co_occurrence> results;
    results.reserve(counts.size());
    for (const auto& [co_key, count] : counts) {
        co_occurrence co;
        co.co_type = co_key.first;
        co.co_value = co_key.second;
        co.co_count = count;
        results.emplace_back(std::move(co));
    }

    std::sort(results.begin(),
              results.end(),
              [](const co_occurrence& a, const co_occurrence& b) {
                  return a.co_count > b.co_count;
              });

    return results;
}

size_t
entity_index::total_entities() const
{
    std::lock_guard<std::mutex> lock(this->m_mutex);

    size_t total = 0;
    for (const auto& [key, lines] : this->m_value_index) {
        total += lines.size();
    }
    return total;
}

size_t
entity_index::unique_entity_values() const
{
    std::lock_guard<std::mutex> lock(this->m_mutex);
    return this->m_value_index.size();
}

size_t
entity_index::indexed_line_count() const
{
    std::lock_guard<std::mutex> lock(this->m_mutex);
    return this->m_line_index.size();
}

void
entity_index::clear()
{
    std::lock_guard<std::mutex> lock(this->m_mutex);
    this->m_value_index.clear();
    this->m_line_index.clear();
    this->m_string_pool.clear();
}

std::vector<entity_index::flat_row>
entity_index::all_rows() const
{
    std::lock_guard<std::mutex> lock(this->m_mutex);

    std::vector<flat_row> rows;

    for (const auto& [line, refs] : this->m_line_index) {
        for (const auto& ref : refs) {
            flat_row row;
            row.fr_line = line;
            row.fr_type = ref.er_type;
            row.fr_value = ref.er_value;
            row.fr_source_field = ref.er_source_field;
            row.fr_confidence = ref.er_confidence;
            rows.emplace_back(std::move(row));
        }
    }

    std::sort(rows.begin(),
              rows.end(),
              [](const flat_row& a, const flat_row& b) {
                  return a.fr_line < b.fr_line;
              });

    return rows;
}
