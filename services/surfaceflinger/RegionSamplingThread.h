/*
 * Copyright 2019 The Android Open Source Project
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

#include <condition_variable>
#include <mutex>
#include <thread>
#include <unordered_map>

#include <android-base/thread_annotations.h>
#include <binder/IBinder.h>
#include <ui/Rect.h>
#include <utils/StrongPointer.h>

namespace android {

class GraphicBuffer;
class IRegionSamplingListener;
class Layer;
class SurfaceFlinger;

class RegionSamplingThread : public IBinder::DeathRecipient {
public:
    explicit RegionSamplingThread(SurfaceFlinger& flinger);
    ~RegionSamplingThread();

    void addListener(const Rect& samplingArea, const sp<IBinder>& stopLayerHandle,
                     const sp<IRegionSamplingListener>& listener);
    void removeListener(const sp<IRegionSamplingListener>& listener);
    void sampleNow();

    struct Descriptor {
        Rect area = Rect::EMPTY_RECT;
        wp<Layer> stopLayer;
        sp<IRegionSamplingListener> listener;
    };

    struct WpHash {
        size_t operator()(const wp<IBinder>& p) const {
            return std::hash<IBinder*>()(p.unsafe_get());
        }
    };

private:
    void binderDied(const wp<IBinder>& who) override;

    void captureSample() REQUIRES(mMutex);
    void threadMain();

    SurfaceFlinger& mFlinger;

    std::mutex mThreadMutex;
    std::thread mThread GUARDED_BY(mThreadMutex);

    std::mutex mMutex;
    std::condition_variable_any mCondition;
    bool mRunning GUARDED_BY(mMutex) = true;
    bool mSampleRequested GUARDED_BY(mMutex) = false;

    std::unordered_map<wp<IBinder>, Descriptor, WpHash> mDescriptors GUARDED_BY(mMutex);
};

} // namespace android
