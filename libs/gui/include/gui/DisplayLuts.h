/*
 * Copyright (C) 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include <android-base/unique_fd.h>
#include <binder/Parcel.h>
#include <binder/Parcelable.h>
#include <cutils/ashmem.h>
#include <sys/mman.h>
#include <algorithm>
#include <optional>
#include <ostream>
#include <vector>

namespace android::gui {

struct DisplayLuts : public Parcelable {
public:
    struct Entry : public Parcelable {
        Entry() {};
        Entry(int32_t lutDimension, int32_t lutSize, int32_t lutSamplingKey)
              : dimension(lutDimension), size(lutSize), samplingKey(lutSamplingKey) {}
        int32_t dimension;
        int32_t size;
        int32_t samplingKey;

        status_t writeToParcel(android::Parcel* parcel) const override;
        status_t readFromParcel(const android::Parcel* parcel) override;
        size_t getElementsNeededPerChannel() const;
    };

    DisplayLuts() {}

    DisplayLuts(base::unique_fd lutfd, std::vector<int32_t> lutoffsets,
                std::vector<int32_t> lutdimensions, std::vector<int32_t> lutsizes,
                std::vector<int32_t> lutsamplingKeys)
          : offsets(std::move(lutoffsets)), fd(std::move(lutfd)) {
        lutProperties.reserve(offsets.size());
        for (size_t i = 0; i < offsets.size(); i++) {
            Entry entry{lutdimensions[i], lutsizes[i], lutsamplingKeys[i]};
            lutProperties.emplace_back(entry);
        }
    }

    status_t writeToParcel(android::Parcel* parcel) const override;
    status_t readFromParcel(const android::Parcel* parcel) override;

    bool isValid() const;
    void dump(std::string& out) const;
    size_t getMaxEndOffset() const;

    const base::unique_fd& getLutFileDescriptor() const { return fd; }

    std::vector<Entry> lutProperties;
    std::vector<int32_t> offsets;

private:
    base::unique_fd fd;
}; // struct DisplayLuts

namespace {
// A newline character followed by N*4 spaces.
static inline constexpr std::string IndentedNewline(uint8_t indent) {
    return "\n" + std::string(static_cast<size_t>(indent * 4), ' ');
}
} // namespace

static inline void PrintTo(const std::vector<int32_t>& offsets, ::std::ostream* os,
                           const uint8_t currentIndent = 0) {
    *os << IndentedNewline(currentIndent) << ".offsets = {";
    for (size_t i = 0; i < offsets.size(); i++) {
        *os << offsets[i];
        if (i != offsets.size() - 1) {
            *os << ", ";
        }
    }
    *os << "}";
}

static inline void PrintTo(const std::vector<DisplayLuts::Entry>& entries, ::std::ostream* os,
                           const uint8_t currentIndent = 0) {
    const std::string outerNewline = IndentedNewline(currentIndent);
    const std::string innerNewline = IndentedNewline(currentIndent + 1);
    *os << outerNewline << ".lutProperties = [";
    for (auto& [dimension, size, samplingKey] : entries) {
        *os << innerNewline << "Entry{"
            << "dimension: " << dimension << ", size: " << size << ", samplingKey: " << samplingKey
            << "}";
    }
    *os << outerNewline << "]";
}

static constexpr size_t kMaxPrintCount = 100;

static inline void PrintTo(const std::vector<float>& buffer, size_t offset, int32_t dimension,
                           size_t size, ::std::ostream* os, const uint8_t currentIndent = 0) {
    size_t range = std::min(size, kMaxPrintCount);
    *os << "[";
    if (dimension == 1) {
        for (size_t i = 0; i < range; i++) {
            *os << buffer[offset + i];
            if (i != range - 1) {
                *os << ", ";
            }
        }
        *os << "]";
    } else {
        const std::string newline = IndentedNewline(currentIndent + 1);
        *os << newline << "{R channel:";
        for (size_t i = 0; i < range; i++) {
            *os << buffer[offset + i];
            if (i != range - 1) {
                *os << ", ";
            }
        }
        *os << "}";
        *os << newline << "{G channel:";
        for (size_t i = 0; i < range; i++) {
            *os << buffer[offset + size + i];
            if (i != range - 1) {
                *os << ", ";
            }
        }
        *os << "}";
        *os << newline << "{B channel:";
        for (size_t i = 0; i < range; i++) {
            *os << buffer[offset + 2 * size + i];
            if (i != range - 1) {
                *os << ", ";
            }
        }
        *os << "}";
        *os << IndentedNewline(currentIndent) << "]";
    }
}

static inline void PrintTo(const std::shared_ptr<DisplayLuts>& luts, ::std::ostream* os,
                           const uint8_t currentIndent = 0) {
    const std::string newline = IndentedNewline(currentIndent + 1);
    *os << "gui::DisplayLuts {";
    auto& fd = luts->getLutFileDescriptor();
    *os << newline << ".pfd = " << fd.get();
    if (fd.ok()) {
        PrintTo(luts->offsets, os);
        PrintTo(luts->lutProperties, os);
        // decode luts
        int32_t fullLength = luts->offsets[luts->offsets.size() - 1];
        if (luts->lutProperties[luts->offsets.size() - 1].dimension == 1) {
            fullLength += luts->lutProperties[luts->offsets.size() - 1].size;
        } else {
            fullLength += (luts->lutProperties[luts->offsets.size() - 1].size *
                           luts->lutProperties[luts->offsets.size() - 1].size *
                           luts->lutProperties[luts->offsets.size() - 1].size * 3);
        }
        size_t bufferSize = static_cast<size_t>(fullLength) * sizeof(float);
        float* ptr = (float*)mmap(NULL, bufferSize, PROT_READ, MAP_SHARED, fd.get(), 0);
        if (ptr == MAP_FAILED) {
            *os << newline << ".bufferdata cannot mmap!";
            return;
        }
        std::vector<float> buffers(ptr, ptr + fullLength);
        munmap(ptr, bufferSize);

        *os << newline << ".bufferdata = ";
        for (size_t i = 0; i < luts->offsets.size(); i++) {
            PrintTo(buffers, static_cast<size_t>(luts->offsets[i]),
                    luts->lutProperties[i].dimension,
                    static_cast<size_t>(luts->lutProperties[i].size), os);
        }
    }
    *os << IndentedNewline(currentIndent) << "}";
}

} // namespace android::gui
