/*
 * Copyright 2017 The Android Open Source Project
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
#undef LOG_TAG
#define LOG_TAG "SurfaceTracing"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "SurfaceTracing.h"

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <log/log.h>
#include <utils/SystemClock.h>
#include <utils/Trace.h>

namespace android {

void SurfaceTracing::LayersTraceBuffer::reset(size_t newSize) {
    // use the swap trick to make sure memory is released
    std::queue<LayersTraceProto>().swap(mStorage);
    mSizeInBytes = newSize;
    mUsedInBytes = 0U;
}

void SurfaceTracing::LayersTraceBuffer::emplace(LayersTraceProto&& proto) {
    auto protoSize = proto.ByteSize();
    while (mUsedInBytes + protoSize > mSizeInBytes) {
        if (mStorage.empty()) {
            return;
        }
        mUsedInBytes -= mStorage.front().ByteSize();
        mStorage.pop();
    }
    mUsedInBytes += protoSize;
    mStorage.emplace();
    mStorage.back().Swap(&proto);
}

void SurfaceTracing::LayersTraceBuffer::flush(LayersTraceFileProto* fileProto) {
    fileProto->mutable_entry()->Reserve(mStorage.size());

    while (!mStorage.empty()) {
        auto entry = fileProto->add_entry();
        entry->Swap(&mStorage.front());
        mStorage.pop();
    }
}

void SurfaceTracing::enable(size_t bufferSizeInByte) {
    std::lock_guard<std::mutex> protoGuard(mTraceMutex);

    if (mEnabled) {
        return;
    }
    mEnabled = true;
    mBuffer.reset(bufferSizeInByte);
}

status_t SurfaceTracing::disable() {
    std::lock_guard<std::mutex> protoGuard(mTraceMutex);

    if (!mEnabled) {
        return NO_ERROR;
    }
    mEnabled = false;
    status_t err(writeProtoFileLocked());
    ALOGE_IF(err == PERMISSION_DENIED, "Could not save the proto file! Permission denied");
    ALOGE_IF(err == NOT_ENOUGH_DATA, "Could not save the proto file! There are missing fields");
    mBuffer.reset(0);
    return err;
}

bool SurfaceTracing::isEnabled() const {
    std::lock_guard<std::mutex> protoGuard(mTraceMutex);
    return mEnabled;
}

void SurfaceTracing::traceLayers(const char* where, LayersProto layers) {
    std::lock_guard<std::mutex> protoGuard(mTraceMutex);
    if (!mEnabled) {
        return;
    }

    LayersTraceProto entry;
    entry.set_elapsed_realtime_nanos(elapsedRealtimeNano());
    entry.set_where(where);
    entry.mutable_layers()->Swap(&layers);

    mBuffer.emplace(std::move(entry));
}

status_t SurfaceTracing::writeProtoFileLocked() {
    ATRACE_CALL();

    LayersTraceFileProto fileProto;
    std::string output;

    fileProto.set_magic_number(uint64_t(LayersTraceFileProto_MagicNumber_MAGIC_NUMBER_H) << 32 |
                               LayersTraceFileProto_MagicNumber_MAGIC_NUMBER_L);
    mBuffer.flush(&fileProto);

    if (!fileProto.SerializeToString(&output)) {
        return PERMISSION_DENIED;
    }
    if (!android::base::WriteStringToFile(output, kDefaultFileName, true)) {
        return PERMISSION_DENIED;
    }

    return NO_ERROR;
}

void SurfaceTracing::dump(std::string& result) const {
    std::lock_guard<std::mutex> protoGuard(mTraceMutex);

    base::StringAppendF(&result, "Tracing state: %s\n", mEnabled ? "enabled" : "disabled");
    base::StringAppendF(&result, "  number of entries: %zu (%.2fMB / %.2fMB)\n",
                        mBuffer.frameCount(), float(mBuffer.used()) / float(1_MB),
                        float(mBuffer.size()) / float(1_MB));
}

} // namespace android
