/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <android/native_window.h>
#include <gtest/gtest.h>
#include <gui/SurfaceComposerClient.h>
#include "android-base/stringprintf.h"
#include "utils/Errors.h"

namespace android {

namespace {
status_t runShellCommand(const std::string& cmd, std::string& result) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return UNKNOWN_ERROR;
    }

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        result += buffer;
    }

    pclose(pipe);
    return OK;
}
} // namespace

using android::hardware::graphics::common::V1_1::BufferUsage;

class WaitForCompletedCallback {
public:
    WaitForCompletedCallback() = default;
    ~WaitForCompletedCallback() = default;

    static void transactionCompletedCallback(void* callbackContext, nsecs_t /* latchTime */,
                                             const sp<Fence>& /* presentFence */,
                                             const std::vector<SurfaceControlStats>& /* stats */) {
        ASSERT_NE(callbackContext, nullptr) << "failed to get callback context";
        WaitForCompletedCallback* context = static_cast<WaitForCompletedCallback*>(callbackContext);
        context->notify();
    }

    void wait() {
        std::unique_lock lock(mMutex);
        cv.wait(lock, [this] { return mCallbackReceived; });
    }

    void notify() {
        std::unique_lock lock(mMutex);
        mCallbackReceived = true;
        cv.notify_one();
    }

private:
    std::mutex mMutex;
    std::condition_variable cv;
    bool mCallbackReceived = false;
};

TEST(Dumpsys, listLayers) {
    sp<SurfaceComposerClient> client = sp<SurfaceComposerClient>::make();
    ASSERT_EQ(NO_ERROR, client->initCheck());
    auto newLayer =
            client->createSurface(String8("MY_TEST_LAYER"), 100, 100, PIXEL_FORMAT_RGBA_8888, 0);
    std::string layersAsString;
    EXPECT_EQ(OK, runShellCommand("dumpsys SurfaceFlinger --list", layersAsString));
    EXPECT_NE(strstr(layersAsString.c_str(), ""), nullptr);
}

TEST(Dumpsys, stats) {
    sp<SurfaceComposerClient> client = sp<SurfaceComposerClient>::make();
    ASSERT_EQ(NO_ERROR, client->initCheck());
    auto newLayer =
            client->createSurface(String8("MY_TEST_LAYER"), 100, 100, PIXEL_FORMAT_RGBA_8888, 0);
    uint64_t usageFlags = BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN |
            BufferUsage::COMPOSER_OVERLAY | BufferUsage::GPU_TEXTURE;

    sp<GraphicBuffer> buffer =
            sp<GraphicBuffer>::make(1u, 1u, PIXEL_FORMAT_RGBA_8888, 1u, usageFlags, "test");

    WaitForCompletedCallback callback;
    SurfaceComposerClient::Transaction()
            .setBuffer(newLayer, buffer)
            .addTransactionCompletedCallback(WaitForCompletedCallback::transactionCompletedCallback,
                                             &callback)
            .apply();
    callback.wait();
    std::string stats;
    std::string layerName = base::StringPrintf("MY_TEST_LAYER#%d", newLayer->getLayerId());
    EXPECT_EQ(OK, runShellCommand("dumpsys SurfaceFlinger --latency " + layerName, stats));
    EXPECT_NE(std::string(""), stats);
    EXPECT_EQ(OK, runShellCommand("dumpsys SurfaceFlinger --latency-clear " + layerName, stats));
}

} // namespace android
