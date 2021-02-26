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

#undef LOG_TAG
#define LOG_TAG "FpsReporter"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "FpsReporter.h"

#include "Layer.h"

namespace android {

FpsReporter::FpsReporter(frametimeline::FrameTimeline& frameTimeline)
      : mFrameTimeline(frameTimeline) {}

void FpsReporter::dispatchLayerFps() const {
    std::vector<TrackedListener> localListeners;
    {
        std::scoped_lock lock(mMutex);
        if (mListeners.empty()) {
            return;
        }

        std::transform(mListeners.begin(), mListeners.end(), std::back_inserter(localListeners),
                       [](const std::pair<wp<IBinder>, TrackedListener>& entry) {
                           return entry.second;
                       });
    }

    for (const auto& listener : localListeners) {
        sp<Layer> promotedLayer = listener.layer.promote();
        if (promotedLayer != nullptr) {
            std::unordered_set<int32_t> layerIds;

            promotedLayer->traverse(LayerVector::StateSet::Drawing,
                                    [&](Layer* layer) { layerIds.insert(layer->getSequence()); });

            listener.listener->onFpsReported(mFrameTimeline.computeFps(layerIds));
        }
    }
}

void FpsReporter::binderDied(const wp<IBinder>& who) {
    std::scoped_lock lock(mMutex);
    mListeners.erase(who);
}

void FpsReporter::addListener(const sp<gui::IFpsListener>& listener, const wp<Layer>& layer) {
    sp<IBinder> asBinder = IInterface::asBinder(listener);
    asBinder->linkToDeath(this);
    std::lock_guard lock(mMutex);
    mListeners.emplace(wp<IBinder>(asBinder), TrackedListener{listener, layer});
}

void FpsReporter::removeListener(const sp<gui::IFpsListener>& listener) {
    std::lock_guard lock(mMutex);
    mListeners.erase(wp<IBinder>(IInterface::asBinder(listener)));
}

} // namespace android