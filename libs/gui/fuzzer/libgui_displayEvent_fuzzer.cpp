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

#include <android/gui/ISurfaceComposer.h>

#include <libgui_fuzzer_utils.h>

using namespace android;

constexpr gui::ISurfaceComposer::VsyncSource kVsyncSource[] = {
        gui::ISurfaceComposer::VsyncSource::eVsyncSourceApp,
        gui::ISurfaceComposer::VsyncSource::eVsyncSourceSurfaceFlinger,
};

constexpr gui::ISurfaceComposer::EventRegistration kEventRegistration[] = {
        gui::ISurfaceComposer::EventRegistration::modeChanged,
        gui::ISurfaceComposer::EventRegistration::frameRateOverride,
};

constexpr uint32_t kDisplayEvent[] = {
        DisplayEventReceiver::DISPLAY_EVENT_NULL,
        DisplayEventReceiver::DISPLAY_EVENT_VSYNC,
        DisplayEventReceiver::DISPLAY_EVENT_HOTPLUG,
        DisplayEventReceiver::DISPLAY_EVENT_MODE_CHANGE,
        DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE,
        DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE_FLUSH,
};

constexpr int32_t kEvents[] = {
        Looper::EVENT_INPUT,  Looper::EVENT_OUTPUT,  Looper::EVENT_ERROR,
        Looper::EVENT_HANGUP, Looper::EVENT_INVALID,
};

DisplayEventReceiver::Event buildDisplayEvent(FuzzedDataProvider* fdp, uint32_t type,
                                              DisplayEventReceiver::Event event) {
    switch (type) {
        case DisplayEventReceiver::DISPLAY_EVENT_VSYNC: {
            event.vsync.count = fdp->ConsumeIntegral<uint32_t>();
            event.vsync.vsyncData.frameInterval = fdp->ConsumeIntegral<uint64_t>();
            event.vsync.vsyncData.preferredFrameTimelineIndex = fdp->ConsumeIntegral<uint32_t>();
            for (size_t idx = 0; idx < gui::VsyncEventData::kFrameTimelinesCapacity; ++idx) {
                event.vsync.vsyncData.frameTimelines[idx].vsyncId = fdp->ConsumeIntegral<int64_t>();
                event.vsync.vsyncData.frameTimelines[idx].deadlineTimestamp =
                        fdp->ConsumeIntegral<uint64_t>();
                event.vsync.vsyncData.frameTimelines[idx].expectedPresentationTime =
                        fdp->ConsumeIntegral<uint64_t>();
            }
            break;

        }
        case DisplayEventReceiver::DISPLAY_EVENT_HOTPLUG: {
            event.hotplug = DisplayEventReceiver::Event::Hotplug{fdp->ConsumeBool() /*connected*/};
            break;
        }
        case DisplayEventReceiver::DISPLAY_EVENT_MODE_CHANGE: {
            event.modeChange =
                    DisplayEventReceiver::Event::ModeChange{fdp->ConsumeIntegral<int32_t>(),
                                                            fdp->ConsumeIntegral<int64_t>()};
            break;
        }
        case DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE:
        case DisplayEventReceiver::DISPLAY_EVENT_FRAME_RATE_OVERRIDE_FLUSH: {
            event.frameRateOverride =
                    DisplayEventReceiver::Event::FrameRateOverride{fdp->ConsumeIntegral<uint32_t>(),
                                                                   fdp->ConsumeFloatingPoint<
                                                                           float>()};
            break;
        }
    }
    return event;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    sp<Looper> looper;
    sp<FakeDisplayEventDispatcher> dispatcher(
            new FakeDisplayEventDispatcher(looper, fdp.PickValueInArray(kVsyncSource),
                                           fdp.PickValueInArray(kEventRegistration)));

    dispatcher->initialize();
    DisplayEventReceiver::Event event;
    uint32_t type = fdp.PickValueInArray(kDisplayEvent);
    PhysicalDisplayId displayId;
    event.header =
            DisplayEventReceiver::Event::Header{type, displayId, fdp.ConsumeIntegral<int64_t>()};
    event = buildDisplayEvent(&fdp, type, event);

    dispatcher->injectEvent(event);
    dispatcher->handleEvent(0, fdp.PickValueInArray(kEvents), nullptr);
    return 0;
}
