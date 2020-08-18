/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <gui/IScreenCaptureListener.h>
#include <gui/LayerState.h>

namespace android {

namespace { // Anonymous

enum class Tag : uint32_t {
    ON_SCREEN_CAPTURE_COMPLETE = IBinder::FIRST_CALL_TRANSACTION,
    LAST = ON_SCREEN_CAPTURE_COMPLETE,
};

} // Anonymous namespace

class BpScreenCaptureListener : public SafeBpInterface<IScreenCaptureListener> {
public:
    explicit BpScreenCaptureListener(const sp<IBinder>& impl)
          : SafeBpInterface<IScreenCaptureListener>(impl, "BpScreenCaptureListener") {}

    ~BpScreenCaptureListener() override;

    status_t onScreenCaptureComplete(const ScreenCaptureResults& captureResults) override {
        Parcel data, reply;
        data.writeInterfaceToken(IScreenCaptureListener::getInterfaceDescriptor());

        SAFE_PARCEL(captureResults.write, data);
        return remote()->transact(static_cast<uint32_t>(Tag::ON_SCREEN_CAPTURE_COMPLETE), data,
                                  &reply, IBinder::FLAG_ONEWAY);
    }
};

// Out-of-line virtual method definitions to trigger vtable emission in this translation unit (see
// clang warning -Wweak-vtables)
BpScreenCaptureListener::~BpScreenCaptureListener() = default;

IMPLEMENT_META_INTERFACE(ScreenCaptureListener, "android.gui.IScreenCaptureListener");

status_t BnScreenCaptureListener::onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                                             uint32_t flags) {
    auto tag = static_cast<Tag>(code);
    switch (tag) {
        case Tag::ON_SCREEN_CAPTURE_COMPLETE: {
            CHECK_INTERFACE(IScreenCaptureListener, data, reply);
            ScreenCaptureResults captureResults;
            SAFE_PARCEL(captureResults.read, data);
            return onScreenCaptureComplete(captureResults);
        }
        default: {
            return BBinder::onTransact(code, data, reply, flags);
        }
    }
}

} // namespace android