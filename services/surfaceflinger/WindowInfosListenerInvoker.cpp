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

#include "WindowInfosListenerInvoker.h"

namespace android {

using gui::DisplayInfo;
using gui::IWindowInfosListener;
using gui::WindowInfo;

struct WindowInfosListenerInvoker::WindowInfosReportedListener : gui::BnWindowInfosReportedListener,
                                                                 DeathRecipient {
    explicit WindowInfosReportedListener(
            size_t callbackCount,
            const std::unordered_set<sp<gui::IWindowInfosReportedListener>,
                                     SpHash<gui::IWindowInfosReportedListener>>&
                    windowInfosReportedListeners)
          : mCallbacksPending(callbackCount),
            mWindowInfosReportedListeners(windowInfosReportedListeners) {}

    binder::Status onWindowInfosReported() override {
        // TODO(b/222421815) There could potentially be callbacks that we don't need to wait for
        // before calling the WindowInfosReportedListeners coming from InputWindowCommands. Filter
        // the list of callbacks down to those from system server.
        if (--mCallbacksPending == 0) {
            for (const auto& listener : mWindowInfosReportedListeners) {
                sp<IBinder> asBinder = IInterface::asBinder(listener);
                if (asBinder->isBinderAlive()) {
                    listener->onWindowInfosReported();
                }
            }
        }
        return binder::Status::ok();
    }

    void binderDied(const wp<IBinder>&) { onWindowInfosReported(); }

private:
    std::atomic<size_t> mCallbacksPending;
    std::unordered_set<sp<gui::IWindowInfosReportedListener>,
                       SpHash<gui::IWindowInfosReportedListener>>
            mWindowInfosReportedListeners;
};

void WindowInfosListenerInvoker::addWindowInfosListener(sp<IWindowInfosListener> listener) {
    sp<IBinder> asBinder = IInterface::asBinder(listener);
    asBinder->linkToDeath(sp<DeathRecipient>::fromExisting(this));

    std::scoped_lock lock(mListenersMutex);
    mWindowInfosListeners.try_emplace(asBinder, std::move(listener));
}

void WindowInfosListenerInvoker::removeWindowInfosListener(
        const sp<IWindowInfosListener>& listener) {
    sp<IBinder> asBinder = IInterface::asBinder(listener);

    std::scoped_lock lock(mListenersMutex);
    asBinder->unlinkToDeath(sp<DeathRecipient>::fromExisting(this));
    mWindowInfosListeners.erase(asBinder);
}

void WindowInfosListenerInvoker::binderDied(const wp<IBinder>& who) {
    std::scoped_lock lock(mListenersMutex);
    mWindowInfosListeners.erase(who);
}

void WindowInfosListenerInvoker::windowInfosChanged(
        const std::vector<WindowInfo>& windowInfos, const std::vector<DisplayInfo>& displayInfos,
        const std::unordered_set<sp<gui::IWindowInfosReportedListener>,
                                 SpHash<gui::IWindowInfosReportedListener>>&
                windowInfosReportedListeners) {
    ftl::SmallVector<const sp<IWindowInfosListener>, kStaticCapacity> windowInfosListeners;
    {
        std::scoped_lock lock(mListenersMutex);
        for (const auto& [_, listener] : mWindowInfosListeners) {
            windowInfosListeners.push_back(listener);
        }
    }

    auto windowInfosReportedListener = windowInfosReportedListeners.empty()
            ? nullptr
            : sp<WindowInfosReportedListener>::make(windowInfosListeners.size(),
                                                    windowInfosReportedListeners);
    for (const auto& listener : windowInfosListeners) {
        sp<IBinder> asBinder = IInterface::asBinder(listener);

        // linkToDeath is used here to ensure that the windowInfosReportedListeners
        // are called even if one of the windowInfosListeners dies before
        // calling onWindowInfosReported.
        if (windowInfosReportedListener) {
            asBinder->linkToDeath(windowInfosReportedListener);
        }

        auto status = listener->onWindowInfosChanged(windowInfos, displayInfos,
                                                     windowInfosReportedListener);
        if (windowInfosReportedListener && !status.isOk()) {
            windowInfosReportedListener->onWindowInfosReported();
        }
    }
}

} // namespace android
