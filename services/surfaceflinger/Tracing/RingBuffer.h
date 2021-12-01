/*
 * Copyright 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <android-base/file.h>
#include <android-base/stringprintf.h>

#include <log/log.h>
#include <utils/Errors.h>
#include <utils/Timers.h>
#include <utils/Trace.h>
#include <chrono>
#include <queue>

namespace android {

class SurfaceFlinger;

template <typename FileProto, typename EntryProto>
class RingBuffer {
public:
    size_t size() const { return mSizeInBytes; }
    size_t used() const { return mUsedInBytes; }
    size_t frameCount() const { return mStorage.size(); }
    void setSize(size_t newSize) { mSizeInBytes = newSize; }
    EntryProto& front() { return mStorage.front(); }
    const EntryProto& front() const { return mStorage.front(); }
    const EntryProto& back() const { return mStorage.back(); }

    void reset() {
        // use the swap trick to make sure memory is released
        std::deque<EntryProto>().swap(mStorage);
        mUsedInBytes = 0U;
    }

    void writeToProto(FileProto& fileProto) {
        fileProto.mutable_entry()->Reserve(static_cast<int>(mStorage.size()) +
                                           fileProto.entry().size());
        for (const EntryProto& entry : mStorage) {
            EntryProto* entryProto = fileProto.add_entry();
            *entryProto = entry;
        }
    }

    status_t writeToFile(FileProto& fileProto, std::string filename) {
        ATRACE_CALL();
        writeToProto(fileProto);
        std::string output;
        if (!fileProto.SerializeToString(&output)) {
            ALOGE("Could not serialize proto.");
            return UNKNOWN_ERROR;
        }

        // -rw-r--r--
        const mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
        if (!android::base::WriteStringToFile(output, filename, mode, getuid(), getgid(), true)) {
            ALOGE("Could not save the proto file.");
            return PERMISSION_DENIED;
        }
        return NO_ERROR;
    }

    std::vector<EntryProto> emplace(EntryProto&& proto) {
        std::vector<EntryProto> replacedEntries;
        size_t protoSize = static_cast<size_t>(proto.ByteSize());
        while (mUsedInBytes + protoSize > mSizeInBytes) {
            if (mStorage.empty()) {
                return {};
            }
            mUsedInBytes -= static_cast<size_t>(mStorage.front().ByteSize());
            replacedEntries.emplace_back(mStorage.front());
            mStorage.pop_front();
        }
        mUsedInBytes += protoSize;
        mStorage.emplace_back();
        mStorage.back().Swap(&proto);
        return replacedEntries;
    }

    void dump(std::string& result) const {
        std::chrono::milliseconds duration(0);
        if (frameCount() > 0) {
            duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::nanoseconds(systemTime() - front().elapsed_realtime_nanos()));
        }
        const int64_t durationCount = duration.count();
        base::StringAppendF(&result,
                            "  number of entries: %zu (%.2fMB / %.2fMB) duration: %" PRIi64 "ms\n",
                            frameCount(), float(used()) / (1024.f * 1024.f),
                            float(size()) / (1024.f * 1024.f), durationCount);
    }

private:
    size_t mUsedInBytes = 0U;
    size_t mSizeInBytes = 0U;
    std::deque<EntryProto> mStorage;
};

} // namespace android
