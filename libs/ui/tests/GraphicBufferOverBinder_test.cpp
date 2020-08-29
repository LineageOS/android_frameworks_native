/*
 * Copyright (C) 2019 The Android Open Source Project
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

#define LOG_TAG "GraphicBufferOverBinder_test"

#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/ProcessState.h>
#include <gtest/gtest.h>
#include <gui/BufferQueue.h>
#include <gui/IGraphicBufferConsumer.h>
#include <gui/IGraphicBufferProducer.h>
#include <ui/GraphicBuffer.h>
#include <utils/Log.h>

namespace android {

constexpr uint32_t kTestWidth = 1024;
constexpr uint32_t kTestHeight = 1;
constexpr uint32_t kTestFormat = HAL_PIXEL_FORMAT_BLOB;
constexpr uint32_t kTestLayerCount = 1;
constexpr uint64_t kTestUsage = GraphicBuffer::USAGE_SW_WRITE_OFTEN;
static const String16 kTestServiceName = String16("GraphicBufferOverBinderTestService");
enum GraphicBufferOverBinderTestServiceCode {
    GRAPHIC_BUFFER = IBinder::FIRST_CALL_TRANSACTION,
};

class GraphicBufferOverBinderTestService : public BBinder {
public:
    GraphicBufferOverBinderTestService() {
        // GraphicBuffer
        mGraphicBuffer = new GraphicBuffer(kTestWidth, kTestHeight, kTestFormat, kTestLayerCount,
                                           kTestUsage);
    }

    ~GraphicBufferOverBinderTestService() = default;

    virtual status_t onTransact(uint32_t code, const Parcel& /*data*/, Parcel* reply,
                                uint32_t /*flags*/ = 0) {
        switch (code) {
            case GRAPHIC_BUFFER: {
                return reply->write(*mGraphicBuffer);
            }
            default:
                return UNKNOWN_TRANSACTION;
        };
    }

protected:
    sp<GraphicBuffer> mGraphicBuffer;
};

static int runBinderServer() {
    ProcessState::self()->startThreadPool();

    sp<IServiceManager> sm = defaultServiceManager();
    sp<GraphicBufferOverBinderTestService> service = new GraphicBufferOverBinderTestService;
    sm->addService(kTestServiceName, service, false);

    ALOGI("Binder server running...");

    while (true) {
        int stat, retval;
        retval = wait(&stat);
        if (retval == -1 && errno == ECHILD) {
            break;
        }
    }

    ALOGI("Binder server exiting...");
    return 0;
}

class GraphicBufferOverBinderTest : public ::testing::TestWithParam<uint32_t> {
protected:
    virtual void SetUp() {
        mService = defaultServiceManager()->getService(kTestServiceName);
        if (mService == nullptr) {
            ALOGE("Failed to connect to the test service.");
            return;
        }

        ALOGI("Binder service is ready for client.");
    }

    status_t GetGraphicBuffer(sp<GraphicBuffer>* outBuf, uint32_t opCode) {
        Parcel data;
        Parcel reply;
        status_t error = mService->transact(opCode, data, &reply);
        if (error != NO_ERROR) {
            ALOGE("Failed to get graphic buffer over binder, error=%d.", error);
            return error;
        }

        *outBuf = new GraphicBuffer();
        return reply.read(**outBuf);
    }

private:
    sp<IBinder> mService;
};

TEST_F(GraphicBufferOverBinderTest, SendGraphicBufferOverBinder) {
    sp<GraphicBuffer> gb;
    EXPECT_EQ(GetGraphicBuffer(&gb, GRAPHIC_BUFFER), OK);
    EXPECT_NE(gb, nullptr);
    void* vaddr;
    EXPECT_EQ(gb->lock(kTestUsage, &vaddr), OK);
    EXPECT_EQ(gb->unlock(), OK);
}

} // namespace android

int main(int argc, char** argv) {
    pid_t pid = fork();
    if (pid == 0) {
        android::ProcessState::self()->startThreadPool();
        ::testing::InitGoogleTest(&argc, argv);
        return RUN_ALL_TESTS();

    } else {
        ALOGI("Test process pid: %d.", pid);
        return android::runBinderServer();
    }
}
