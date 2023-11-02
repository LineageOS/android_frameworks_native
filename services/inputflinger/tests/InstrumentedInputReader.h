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

#pragma once

#include <memory>
#include <queue>
#include <string>

#include <InputDevice.h>
#include <InputReader.h>
#include <gtest/gtest.h>
#include <utils/StrongPointer.h>

namespace android {

class InstrumentedInputReader : public InputReader {
public:
    InstrumentedInputReader(std::shared_ptr<EventHubInterface> eventHub,
                            const sp<InputReaderPolicyInterface>& policy,
                            InputListenerInterface& listener);
    virtual ~InstrumentedInputReader() {}

    void pushNextDevice(std::shared_ptr<InputDevice> device);

    std::shared_ptr<InputDevice> newDevice(int32_t deviceId, const std::string& name,
                                           const std::string& location = "");

    // Make the protected loopOnce method accessible to tests.
    using InputReader::loopOnce;

protected:
    virtual std::shared_ptr<InputDevice> createDeviceLocked(
            nsecs_t when, int32_t eventHubId, const InputDeviceIdentifier& identifier);

    class FakeInputReaderContext : public ContextImpl {
    public:
        FakeInputReaderContext(InputReader* reader)
              : ContextImpl(reader),
                mGlobalMetaState(0),
                mUpdateGlobalMetaStateWasCalled(false),
                mGeneration(1) {}

        virtual ~FakeInputReaderContext() {}

        void assertUpdateGlobalMetaStateWasCalled() {
            ASSERT_TRUE(mUpdateGlobalMetaStateWasCalled)
                    << "Expected updateGlobalMetaState() to have been called.";
            mUpdateGlobalMetaStateWasCalled = false;
        }

        void setGlobalMetaState(int32_t state) { mGlobalMetaState = state; }

        uint32_t getGeneration() { return mGeneration; }

        void updateGlobalMetaState() override {
            mUpdateGlobalMetaStateWasCalled = true;
            ContextImpl::updateGlobalMetaState();
        }

        int32_t getGlobalMetaState() override {
            return mGlobalMetaState | ContextImpl::getGlobalMetaState();
        }

        int32_t bumpGeneration() override {
            mGeneration = ContextImpl::bumpGeneration();
            return mGeneration;
        }

        void requestTimeoutAtTime(nsecs_t when) override { mRequestedTimeout = when; }

        void assertTimeoutWasRequested(nsecs_t when) {
            ASSERT_TRUE(mRequestedTimeout) << "Expected timeout at time " << when
                                           << " but there was no timeout requested.";
            ASSERT_EQ(when, *mRequestedTimeout);
            mRequestedTimeout.reset();
        }

        void assertTimeoutWasNotRequested() {
            ASSERT_FALSE(mRequestedTimeout) << "Expected no timeout to have been requested,"
                                               " but one was requested at time "
                                            << *mRequestedTimeout;
        }

        void getExternalStylusDevices(std::vector<InputDeviceInfo>& outDevices) override {
            outDevices = mExternalStylusDevices;
        }

        void setExternalStylusDevices(std::vector<InputDeviceInfo>&& devices) {
            mExternalStylusDevices = devices;
        }

        void setPreventingTouchpadTaps(bool prevent) override { mPreventingTouchpadTaps = prevent; }
        bool isPreventingTouchpadTaps() override { return mPreventingTouchpadTaps; }

        void setLastKeyDownTimestamp(nsecs_t when) override { mLastKeyDownTimestamp = when; };
        nsecs_t getLastKeyDownTimestamp() override { return mLastKeyDownTimestamp; };

    private:
        int32_t mGlobalMetaState;
        bool mUpdateGlobalMetaStateWasCalled;
        int32_t mGeneration;
        std::optional<nsecs_t> mRequestedTimeout;
        std::vector<InputDeviceInfo> mExternalStylusDevices;
        bool mPreventingTouchpadTaps{false};
        nsecs_t mLastKeyDownTimestamp;
    } mFakeContext;

    friend class InputReaderTest;

public:
    FakeInputReaderContext* getContext() { return &mFakeContext; }

private:
    std::queue<std::shared_ptr<InputDevice>> mNextDevices;
};

} // namespace android
