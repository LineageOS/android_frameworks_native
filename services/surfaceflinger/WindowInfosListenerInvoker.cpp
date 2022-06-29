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

#include <ftl/small_vector.h>
#include <gui/ISurfaceComposer.h>

#include "SurfaceFlinger.h"
#include "WindowInfosListenerInvoker.h"

namespace android {

using gui::DisplayInfo;
using gui::IWindowInfosListener;
using gui::WindowInfo;

struct WindowInfosListenerInvoker::WindowInfosReportedListener
      : gui::BnWindowInfosReportedListener {
    explicit WindowInfosReportedListener(WindowInfosListenerInvoker& invoker) : mInvoker(invoker) {}

    binder::Status onWindowInfosReported() override {
        mInvoker.windowInfosReported();
        return binder::Status::ok();
    }

    WindowInfosListenerInvoker& mInvoker;
};

WindowInfosListenerInvoker::WindowInfosListenerInvoker(SurfaceFlinger& flinger)
      : mFlinger(flinger),
        mWindowInfosReportedListener(sp<WindowInfosReportedListener>::make(*this)) {}

void WindowInfosListenerInvoker::addWindowInfosListener(sp<IWindowInfosListener> listener) {
    sp<IBinder> asBinder = IInterface::asBinder(listener);
    asBinder->linkToDeath(this);

    std::scoped_lock lock(mListenersMutex);
    mWindowInfosListeners.try_emplace(asBinder, std::move(listener));
}

void WindowInfosListenerInvoker::removeWindowInfosListener(
        const sp<IWindowInfosListener>& listener) {
    sp<IBinder> asBinder = IInterface::asBinder(listener);

    std::scoped_lock lock(mListenersMutex);
    asBinder->unlinkToDeath(this);
    mWindowInfosListeners.erase(asBinder);
}

void WindowInfosListenerInvoker::binderDied(const wp<IBinder>& who) {
    std::scoped_lock lock(mListenersMutex);
    mWindowInfosListeners.erase(who);
}

void WindowInfosListenerInvoker::windowInfosChanged(const std::vector<WindowInfo>& windowInfos,
                                                    const std::vector<DisplayInfo>& displayInfos,
                                                    bool shouldSync) {
    ftl::SmallVector<const sp<IWindowInfosListener>, kStaticCapacity> windowInfosListeners;
    {
        std::scoped_lock lock(mListenersMutex);
        for (const auto& [_, listener] : mWindowInfosListeners) {
            windowInfosListeners.push_back(listener);
        }
    }

    mCallbacksPending = windowInfosListeners.size();

    for (const auto& listener : windowInfosListeners) {
        listener->onWindowInfosChanged(windowInfos, displayInfos,
                                       shouldSync ? mWindowInfosReportedListener : nullptr);
    }
}

void WindowInfosListenerInvoker::windowInfosReported() {
    mCallbacksPending--;
    if (mCallbacksPending == 0) {
        mFlinger.windowInfosReported();
    }
}

} // namespace android
