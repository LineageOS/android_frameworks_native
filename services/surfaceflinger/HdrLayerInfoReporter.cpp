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
#define LOG_TAG "HdrLayerInfoReporter"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include <android-base/stringprintf.h>
#include <inttypes.h>
#include <utils/Trace.h>

#include "HdrLayerInfoReporter.h"

namespace android {

using base::StringAppendF;

void HdrLayerInfoReporter::dispatchHdrLayerInfo(const HdrLayerInfo& info) {
    ATRACE_CALL();
    if (mHdrInfoHistory.size() == 0 || mHdrInfoHistory.back().info != info) {
        mHdrInfoHistory.next() = EventHistoryEntry{info};
    }

    std::vector<sp<gui::IHdrLayerInfoListener>> toInvoke;
    {
        std::scoped_lock lock(mMutex);
        toInvoke.reserve(mListeners.size());
        for (auto& [key, it] : mListeners) {
            if (it.lastInfo != info) {
                it.lastInfo = info;
                toInvoke.push_back(it.listener);
            }
        }
    }

    for (const auto& listener : toInvoke) {
        ATRACE_NAME("invoking onHdrLayerInfoChanged");
        listener->onHdrLayerInfoChanged(info.numberOfHdrLayers, info.maxW, info.maxH, info.flags,
                                        info.maxDesiredHdrSdrRatio);
    }
}

void HdrLayerInfoReporter::binderDied(const wp<IBinder>& who) {
    std::scoped_lock lock(mMutex);
    mListeners.erase(who);
}

void HdrLayerInfoReporter::addListener(const sp<gui::IHdrLayerInfoListener>& listener) {
    sp<IBinder> asBinder = IInterface::asBinder(listener);
    asBinder->linkToDeath(sp<DeathRecipient>::fromExisting(this));
    std::lock_guard lock(mMutex);
    mListeners.emplace(wp<IBinder>(asBinder), TrackedListener{listener, HdrLayerInfo{}});
}

void HdrLayerInfoReporter::removeListener(const sp<gui::IHdrLayerInfoListener>& listener) {
    std::lock_guard lock(mMutex);
    mListeners.erase(wp<IBinder>(IInterface::asBinder(listener)));
}

void HdrLayerInfoReporter::dump(std::string& result) const {
    for (size_t i = 0; i < mHdrInfoHistory.size(); i++) {
        const auto& event = mHdrInfoHistory[i];
        const auto& info = event.info;
        StringAppendF(&result,
                      "%" PRId64 ": numHdrLayers(%d), size(%dx%d), flags(%X), desiredRatio(%.2f)\n",
                      event.timestamp, info.numberOfHdrLayers, info.maxW, info.maxH, info.flags,
                      info.maxDesiredHdrSdrRatio);
    }
}

} // namespace android