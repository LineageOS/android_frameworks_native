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
#include <SurfaceFlinger.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <log/log.h>
#include <utils/SystemClock.h>
#include <utils/Trace.h>

namespace android {

void SurfaceTracing::mainLoop() {
    bool enabled = true;
    // Upon activation, logs the first frame
    traceLayers("tracing.enable");
    do {
        std::unique_lock<std::mutex> sfLock(mFlinger.mDrawingStateLock);
        mConditionalVariable.wait(sfLock);
        LayersTraceProto entry = traceLayersLocked(mWhere);
        sfLock.unlock();
        {
            std::scoped_lock bufferLock(mTraceLock);
            mBuffer.emplace(std::move(entry));
            if (mWriteToFile) {
                writeProtoFileLocked();
                mWriteToFile = false;
            }

            enabled = mEnabled;
        }
    } while (enabled);
}

void SurfaceTracing::traceLayers(const char* where) {
    std::unique_lock<std::mutex> sfLock(mFlinger.mDrawingStateLock);
    LayersTraceProto entry = traceLayersLocked(where);
    sfLock.unlock();
    std::scoped_lock bufferLock(mTraceLock);
    mBuffer.emplace(std::move(entry));
}

void SurfaceTracing::notify(const char* where) {
    std::lock_guard<std::mutex> sfLock(mFlinger.mDrawingStateLock);
    mWhere = where;
    mConditionalVariable.notify_one();
}

void SurfaceTracing::writeToFileAsync() {
    std::lock_guard<std::mutex> bufferLock(mTraceLock);
    mWriteToFile = true;
    mConditionalVariable.notify_one();
}

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

void SurfaceTracing::enable() {
    std::lock_guard<std::mutex> bufferLock(mTraceLock);

    if (mEnabled) {
        return;
    }

    mBuffer.reset(mBufferSize);
    mEnabled = true;
    mThread = std::thread(&SurfaceTracing::mainLoop, this);
}

status_t SurfaceTracing::writeToFile() {
    mThread.join();
    return mLastErr;
}

bool SurfaceTracing::disable() {
    std::lock_guard<std::mutex> bufferLock(mTraceLock);

    if (!mEnabled) {
        return false;
    }

    mEnabled = false;
    mWriteToFile = true;
    mConditionalVariable.notify_all();
    return true;
}

bool SurfaceTracing::isEnabled() const {
    std::lock_guard<std::mutex> bufferLock(mTraceLock);
    return mEnabled;
}

void SurfaceTracing::setBufferSize(size_t bufferSizeInByte) {
    std::lock_guard<std::mutex> bufferLock(mTraceLock);
    mBufferSize = bufferSizeInByte;
    mBuffer.setSize(bufferSizeInByte);
}

LayersTraceProto SurfaceTracing::traceLayersLocked(const char* where) {
    ATRACE_CALL();

    LayersTraceProto entry;
    entry.set_elapsed_realtime_nanos(elapsedRealtimeNano());
    entry.set_where(where);
    LayersProto layers(mFlinger.dumpProtoInfo(LayerVector::StateSet::Drawing));
    entry.mutable_layers()->Swap(&layers);

    return entry;
}

void SurfaceTracing::writeProtoFileLocked() {
    ATRACE_CALL();

    LayersTraceFileProto fileProto;
    std::string output;

    fileProto.set_magic_number(uint64_t(LayersTraceFileProto_MagicNumber_MAGIC_NUMBER_H) << 32 |
                               LayersTraceFileProto_MagicNumber_MAGIC_NUMBER_L);
    mBuffer.flush(&fileProto);
    mBuffer.reset(mBufferSize);

    if (!fileProto.SerializeToString(&output)) {
        ALOGE("Could not save the proto file! Permission denied");
        mLastErr = PERMISSION_DENIED;
    }
    if (!android::base::WriteStringToFile(output, kDefaultFileName, S_IRWXU | S_IRGRP, getuid(),
                                          getgid(), true)) {
        ALOGE("Could not save the proto file! There are missing fields");
        mLastErr = PERMISSION_DENIED;
    }

    mLastErr = NO_ERROR;
}

void SurfaceTracing::dump(std::string& result) const {
    std::lock_guard<std::mutex> bufferLock(mTraceLock);

    base::StringAppendF(&result, "Tracing state: %s\n", mEnabled ? "enabled" : "disabled");
    base::StringAppendF(&result, "  number of entries: %zu (%.2fMB / %.2fMB)\n",
                        mBuffer.frameCount(), float(mBuffer.used()) / float(1_MB),
                        float(mBuffer.size()) / float(1_MB));
}

} // namespace android
