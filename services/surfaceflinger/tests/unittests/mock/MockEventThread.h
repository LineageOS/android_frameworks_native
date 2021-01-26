/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <gmock/gmock.h>

#include "Scheduler/EventThread.h"

namespace android::mock {

class EventThread : public android::EventThread {
public:
    EventThread();
    ~EventThread() override;

    MOCK_CONST_METHOD2(createEventConnection,
                       sp<EventThreadConnection>(ResyncCallback,
                                                 ISurfaceComposer::EventRegistrationFlags));
    MOCK_METHOD0(onScreenReleased, void());
    MOCK_METHOD0(onScreenAcquired, void());
    MOCK_METHOD2(onHotplugReceived, void(PhysicalDisplayId, bool));
    MOCK_METHOD3(onConfigChanged, void(PhysicalDisplayId, DisplayModeId, nsecs_t));
    MOCK_METHOD2(onFrameRateOverridesChanged,
                 void(PhysicalDisplayId, std::vector<FrameRateOverride>));
    MOCK_CONST_METHOD1(dump, void(std::string&));
    MOCK_METHOD2(setDuration,
                 void(std::chrono::nanoseconds workDuration,
                      std::chrono::nanoseconds readyDuration));
    MOCK_METHOD1(registerDisplayEventConnection,
                 status_t(const sp<android::EventThreadConnection> &));
    MOCK_METHOD2(setVsyncRate, void(uint32_t, const sp<android::EventThreadConnection> &));
    MOCK_METHOD1(requestNextVsync, void(const sp<android::EventThreadConnection> &));
    MOCK_METHOD1(requestLatestConfig, void(const sp<android::EventThreadConnection> &));
    MOCK_METHOD1(pauseVsyncCallback, void(bool));
    MOCK_METHOD0(getEventThreadConnectionCount, size_t());
};

} // namespace android::mock
