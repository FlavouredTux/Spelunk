#pragma once

// A speculative emitter buffer and the LineMap hits recorded while producing
// it. Hits stay relative to `text_` until the chunk is appended; abandoning a
// chunk abandons its provenance as well.

#include <cstddef>
#include <functional>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#include <spelunk/decompile/emit_options.hpp>

namespace spelunk::emit {

class RenderChunk final {
public:
    RenderChunk(const RenderChunk&) = delete;
    RenderChunk& operator=(const RenderChunk&) = delete;
    RenderChunk(RenderChunk&&) noexcept = default;
    RenderChunk& operator=(RenderChunk&&) noexcept = default;

    template <typename Renderer>
    [[nodiscard]] static RenderChunk
    capture(LineMap* line_map, Renderer&& renderer) {
        RenderChunk chunk(line_map);
        const std::size_t first_hit = line_map ? line_map->hits.size() : 0;
        try {
            std::invoke(std::forward<Renderer>(renderer), chunk.text_);
            chunk.capture_hits(first_hit);
        } catch (...) {
            if (line_map) line_map->hits.resize(first_hit);
            throw;
        }
        return chunk;
    }

    [[nodiscard]] const std::string& text() const noexcept { return text_; }
    [[nodiscard]] std::string& text() noexcept { return text_; }

    void swap(RenderChunk& other) noexcept {
        text_.swap(other.text_);
        hits_.swap(other.hits_);
        std::swap(line_map_, other.line_map_);
    }

    void discard() noexcept {
        text_.clear();
        hits_.clear();
        line_map_ = nullptr;
    }

    void append_to(std::string& output) && {
        const std::size_t base = output.size();
        output += text_;
        rebase(base);
        if (line_map_) {
            line_map_->hits.insert(
                line_map_->hits.end(),
                std::make_move_iterator(hits_.begin()),
                std::make_move_iterator(hits_.end()));
        }
        discard();
    }

private:
    explicit RenderChunk(LineMap* line_map) noexcept : line_map_(line_map) {}

    void capture_hits(std::size_t first_hit) {
        if (!line_map_) return;
        auto& recorded = line_map_->hits;
        hits_.insert(hits_.end(),
                     std::make_move_iterator(recorded.begin() +
                                             static_cast<std::ptrdiff_t>(first_hit)),
                     std::make_move_iterator(recorded.end()));
        recorded.resize(first_hit);
    }

    void rebase(std::size_t base) noexcept {
        for (LineMap::Hit& hit : hits_) hit.byte_offset += base;
    }

    LineMap* line_map_ = nullptr;
    std::string text_;
    std::vector<LineMap::Hit> hits_;
};

}  // namespace spelunk::emit
