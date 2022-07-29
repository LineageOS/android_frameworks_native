/*
 * Copyright 2022 The Android Open Source Project
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
#include <gui/BufferQueueConsumer.h>
#include <gui/BufferQueueCore.h>
#include <gui/BufferQueueProducer.h>
#include <gui/LayerMetadata.h>
#include <gui/OccupancyTracker.h>
#include <gui/StreamSplitter.h>
#include <gui/Surface.h>
#include <gui/SurfaceControl.h>
#include <gui/view/Surface.h>
#include <libgui_fuzzer_utils.h>
#include "android/view/LayerMetadataKey.h"

using namespace android;

constexpr int32_t kMaxBytes = 256;
constexpr int32_t kMatrixSize = 4;
constexpr int32_t kLayerMetadataKeyCount = 8;

constexpr uint32_t kMetadataKey[] = {
        (uint32_t)view::LayerMetadataKey::METADATA_OWNER_UID,
        (uint32_t)view::LayerMetadataKey::METADATA_WINDOW_TYPE,
        (uint32_t)view::LayerMetadataKey::METADATA_TASK_ID,
        (uint32_t)view::LayerMetadataKey::METADATA_MOUSE_CURSOR,
        (uint32_t)view::LayerMetadataKey::METADATA_ACCESSIBILITY_ID,
        (uint32_t)view::LayerMetadataKey::METADATA_OWNER_PID,
        (uint32_t)view::LayerMetadataKey::METADATA_DEQUEUE_TIME,
        (uint32_t)view::LayerMetadataKey::METADATA_GAME_MODE,
};

class ParcelableFuzzer {
public:
    ParcelableFuzzer(const uint8_t* data, size_t size) : mFdp(data, size){};
    void process();

private:
    void invokeStreamSplitter();
    void invokeOccupancyTracker();
    void invokeLayerDebugInfo();
    void invokeLayerMetadata();
    void invokeViewSurface();

    FuzzedDataProvider mFdp;
};

void ParcelableFuzzer::invokeViewSurface() {
    view::Surface surface;
    surface.name = String16((mFdp.ConsumeRandomLengthString(kMaxBytes)).c_str());
    Parcel parcel;
    surface.writeToParcel(&parcel);
    parcel.setDataPosition(0);
    surface.readFromParcel(&parcel);
    bool nameAlreadyWritten = mFdp.ConsumeBool();
    surface.writeToParcel(&parcel, nameAlreadyWritten);
    parcel.setDataPosition(0);
    surface.readFromParcel(&parcel, mFdp.ConsumeBool());
}

void ParcelableFuzzer::invokeLayerMetadata() {
    std::unordered_map<uint32_t, std::vector<uint8_t>> map;
    for (size_t idx = 0; idx < kLayerMetadataKeyCount; ++idx) {
        std::vector<uint8_t> data;
        for (size_t idx1 = 0; idx1 < mFdp.ConsumeIntegral<uint32_t>(); ++idx1) {
            data.push_back(mFdp.ConsumeIntegral<uint8_t>());
        }
        map[kMetadataKey[idx]] = data;
    }
    LayerMetadata metadata(map);
    uint32_t key = mFdp.PickValueInArray(kMetadataKey);
    metadata.setInt32(key, mFdp.ConsumeIntegral<int32_t>());
    metadata.itemToString(key, (mFdp.ConsumeRandomLengthString(kMaxBytes)).c_str());

    Parcel parcel;
    metadata.writeToParcel(&parcel);
    parcel.setDataPosition(0);
    metadata.readFromParcel(&parcel);
}

void ParcelableFuzzer::invokeLayerDebugInfo() {
    gui::LayerDebugInfo info;
    info.mName = mFdp.ConsumeRandomLengthString(kMaxBytes);
    info.mParentName = mFdp.ConsumeRandomLengthString(kMaxBytes);
    info.mType = mFdp.ConsumeRandomLengthString(kMaxBytes);
    info.mLayerStack = mFdp.ConsumeIntegral<uint32_t>();
    info.mX = mFdp.ConsumeFloatingPoint<float>();
    info.mY = mFdp.ConsumeFloatingPoint<float>();
    info.mZ = mFdp.ConsumeIntegral<uint32_t>();
    info.mWidth = mFdp.ConsumeIntegral<int32_t>();
    info.mHeight = mFdp.ConsumeIntegral<int32_t>();
    info.mActiveBufferWidth = mFdp.ConsumeIntegral<int32_t>();
    info.mActiveBufferHeight = mFdp.ConsumeIntegral<int32_t>();
    info.mActiveBufferStride = mFdp.ConsumeIntegral<int32_t>();
    info.mActiveBufferFormat = mFdp.ConsumeIntegral<int32_t>();
    info.mNumQueuedFrames = mFdp.ConsumeIntegral<int32_t>();

    info.mFlags = mFdp.ConsumeIntegral<uint32_t>();
    info.mPixelFormat = mFdp.ConsumeIntegral<int32_t>();
    info.mTransparentRegion = Region(getRect(&mFdp));
    info.mVisibleRegion = Region(getRect(&mFdp));
    info.mSurfaceDamageRegion = Region(getRect(&mFdp));
    info.mCrop = getRect(&mFdp);
    info.mDataSpace = static_cast<android_dataspace>(mFdp.PickValueInArray(kDataspaces));
    info.mColor = half4(mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>(),
                        mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>());
    for (size_t idx = 0; idx < kMatrixSize; ++idx) {
        info.mMatrix[idx / 2][idx % 2] = mFdp.ConsumeFloatingPoint<float>();
    }
    info.mIsOpaque = mFdp.ConsumeBool();
    info.mContentDirty = mFdp.ConsumeBool();
    info.mStretchEffect.width = mFdp.ConsumeFloatingPoint<float>();
    info.mStretchEffect.height = mFdp.ConsumeFloatingPoint<float>();
    info.mStretchEffect.vectorX = mFdp.ConsumeFloatingPoint<float>();
    info.mStretchEffect.vectorY = mFdp.ConsumeFloatingPoint<float>();
    info.mStretchEffect.maxAmountX = mFdp.ConsumeFloatingPoint<float>();
    info.mStretchEffect.maxAmountY = mFdp.ConsumeFloatingPoint<float>();
    info.mStretchEffect.mappedChildBounds =
            FloatRect(mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>(),
                      mFdp.ConsumeFloatingPoint<float>(), mFdp.ConsumeFloatingPoint<float>());

    Parcel parcel;
    info.writeToParcel(&parcel);
    parcel.setDataPosition(0);
    info.readFromParcel(&parcel);
}

void ParcelableFuzzer::invokeOccupancyTracker() {
    nsecs_t totalTime = mFdp.ConsumeIntegral<uint32_t>();
    size_t numFrames = mFdp.ConsumeIntegral<size_t>();
    float occupancyAverage = mFdp.ConsumeFloatingPoint<float>();
    OccupancyTracker::Segment segment(totalTime, numFrames, occupancyAverage,
                                      mFdp.ConsumeBool() /*usedThirdBuffer*/);
    Parcel parcel;
    segment.writeToParcel(&parcel);
    parcel.setDataPosition(0);
    segment.readFromParcel(&parcel);
}

void ParcelableFuzzer::invokeStreamSplitter() {
    sp<IGraphicBufferProducer> producer;
    sp<IGraphicBufferConsumer> consumer;
    BufferQueue::createBufferQueue(&producer, &consumer);
    sp<StreamSplitter> splitter;
    StreamSplitter::createSplitter(consumer, &splitter);
    splitter->addOutput(producer);
    std::string name = mFdp.ConsumeRandomLengthString(kMaxBytes);
    splitter->setName(String8(name.c_str()));
}

void ParcelableFuzzer::process() {
    invokeStreamSplitter();
    invokeOccupancyTracker();
    invokeLayerDebugInfo();
    invokeLayerMetadata();
    invokeViewSurface();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ParcelableFuzzer libGuiFuzzer(data, size);
    libGuiFuzzer.process();
    return 0;
}
