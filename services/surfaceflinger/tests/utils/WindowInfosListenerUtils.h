/*
 * Copyright 2023 The Android Open Source Project
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

#include <android-base/properties.h>
#include <gtest/gtest.h>
#include <gui/SurfaceComposerClient.h>
#include <private/android_filesystem_config.h>
#include <cstdint>
#include <future>

namespace android {

using base::HwTimeoutMultiplier;
using gui::DisplayInfo;
using gui::WindowInfo;

using WindowInfosPredicate = std::function<bool(const std::vector<WindowInfo>&)>;

class WindowInfosListenerUtils {
public:
    WindowInfosListenerUtils() { mClient = sp<SurfaceComposerClient>::make(); }

    bool waitForWindowInfosPredicate(const WindowInfosPredicate& predicate) {
        std::promise<void> promise;
        auto listener = sp<WindowInfosListener>::make(std::move(predicate), promise);
        mClient->addWindowInfosListener(listener);
        auto future = promise.get_future();
        bool satisfied = future.wait_for(std::chrono::seconds{5 * HwTimeoutMultiplier()}) ==
                std::future_status::ready;
        mClient->removeWindowInfosListener(listener);
        return satisfied;
    }

    static const WindowInfo* findMatchingWindowInfo(const WindowInfo& targetWindowInfo,
                                                    const std::vector<WindowInfo>& windowInfos) {
        for (const WindowInfo& windowInfo : windowInfos) {
            if (windowInfo.token == targetWindowInfo.token) {
                return &windowInfo;
            }
        }
        return nullptr;
    }

private:
    struct WindowInfosListener : public gui::WindowInfosListener {
    public:
        WindowInfosListener(WindowInfosPredicate predicate, std::promise<void>& promise)
              : mPredicate(std::move(predicate)), mPromise(promise) {}

        void onWindowInfosChanged(const gui::WindowInfosUpdate& update) override {
            if (mPredicate(update.windowInfos)) {
                mPromise.set_value();
            }
        }

    private:
        WindowInfosPredicate mPredicate;
        std::promise<void>& mPromise;
    };

    sp<SurfaceComposerClient> mClient;
};

} // namespace android
