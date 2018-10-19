/*
 * Copyright 2019 The Android Open Source Project
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

#include <cinttypes>

#include <compositionengine/CompositionEngine.h>
#include <compositionengine/DisplayCreationArgs.h>
#include <compositionengine/impl/Display.h>

#include "DisplayHardware/HWComposer.h"

namespace android::compositionengine::impl {

std::shared_ptr<compositionengine::Display> createDisplay(
        const compositionengine::CompositionEngine& compositionEngine,
        compositionengine::DisplayCreationArgs&& args) {
    return std::make_shared<Display>(compositionEngine, std::move(args));
}

Display::Display(const CompositionEngine& compositionEngine, DisplayCreationArgs&& args)
      : mCompositionEngine(compositionEngine),
        mIsSecure(args.isSecure),
        mIsVirtual(args.isVirtual),
        mId(args.displayId) {}

Display::~Display() = default;

const std::optional<DisplayId>& Display::getId() const {
    return mId;
}

bool Display::isSecure() const {
    return mIsSecure;
}

bool Display::isVirtual() const {
    return mIsVirtual;
}

void Display::disconnect() {
    if (!mId) {
        return;
    }

    auto& hwc = mCompositionEngine.getHwComposer();
    hwc.disconnectDisplay(*mId);
    mId.reset();
}

} // namespace android::compositionengine::impl
