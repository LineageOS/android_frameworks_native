//
// Copyright (C) 2019 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#pragma once

#include <android/frameworks/automotive/display/1.0/IAutomotiveDisplayProxyService.h>
#include <gui/ISurfaceComposer.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <ui/DisplayConfig.h>
#include <ui/DisplayState.h>

namespace android {
namespace frameworks {
namespace automotive {
namespace display {
namespace V1_0 {
namespace implementation {

using ::android::hardware::Return;
using ::android::sp;
using ::android::hardware::graphics::bufferqueue::V2_0::IGraphicBufferProducer;

class AutomotiveDisplayProxyService : public IAutomotiveDisplayProxyService {
public:
    Return<sp<IGraphicBufferProducer>> getIGraphicBufferProducer() override;
    Return<bool> showWindow() override;
    Return<bool> hideWindow() override;
    Return<void> getDisplayInfo(getDisplayInfo_cb _info_cb) override {
        HwDisplayConfig cfg;
        cfg.setToExternal((uint8_t*)&mDpyConfig, sizeof(DisplayConfig));

        HwDisplayState state;
        state.setToExternal((uint8_t*)&mDpyState, sizeof(DisplayState));

       _info_cb(cfg, state);
        return hardware::Void();
    }

private:
    sp<android::Surface> mSurface;
    sp<android::SurfaceComposerClient> mSurfaceComposerClient;
    sp<android::SurfaceControl> mSurfaceControl;
    DisplayConfig mDpyConfig;
    ui::DisplayState mDpyState;
};
}  // namespace implementation
}  // namespace V1_0
}  // namespace display
}  // namespace automotive
}  // namespace frameworks
}  // namespace android

