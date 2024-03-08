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

#include "FrameRateOverrideMappings.h"
#include <common/FlagManager.h>

namespace android::scheduler {
using FrameRateOverride = DisplayEventReceiver::Event::FrameRateOverride;

std::optional<Fps> FrameRateOverrideMappings::getFrameRateOverrideForUid(
        uid_t uid, bool supportsFrameRateOverrideByContent) const {
    std::lock_guard lock(mFrameRateOverridesLock);

    {
        const auto iter = mFrameRateOverridesFromBackdoor.find(uid);
        if (iter != mFrameRateOverridesFromBackdoor.end()) {
            return iter->second;
        }
    }

    if (!FlagManager::getInstance().game_default_frame_rate()) {
        const auto iter = mFrameRateOverridesFromGameManager.find(uid);
        if (iter != mFrameRateOverridesFromGameManager.end()) {
            return iter->second;
        }
    }

    if (!supportsFrameRateOverrideByContent) {
        return std::nullopt;
    }

    {
        const auto iter = mFrameRateOverridesByContent.find(uid);
        if (iter != mFrameRateOverridesByContent.end()) {
            return iter->second;
        }
    }

    return std::nullopt;
}

std::vector<FrameRateOverride> FrameRateOverrideMappings::getAllFrameRateOverrides(
        bool supportsFrameRateOverrideByContent) {
    std::lock_guard lock(mFrameRateOverridesLock);

    std::vector<FrameRateOverride> overrides;
    overrides.reserve(maxOverridesCount());

    for (const auto& [uid, frameRate] : mFrameRateOverridesFromBackdoor) {
        overrides.emplace_back(FrameRateOverride{uid, frameRate.getValue()});
    }

    if (!FlagManager::getInstance().game_default_frame_rate()) {
        for (const auto& [uid, frameRate] : mFrameRateOverridesFromGameManager) {
            if (std::find_if(overrides.begin(), overrides.end(),
                             [uid = uid](auto i) { return i.uid == uid; }) == overrides.end()) {
                overrides.emplace_back(FrameRateOverride{uid, frameRate.getValue()});
            }
        }
    }

    if (!supportsFrameRateOverrideByContent) {
        return overrides;
    }

    for (const auto& [uid, frameRate] : mFrameRateOverridesByContent) {
        if (std::find_if(overrides.begin(), overrides.end(),
                         [uid = uid](auto i) { return i.uid == uid; }) == overrides.end()) {
            overrides.emplace_back(FrameRateOverride{uid, frameRate.getValue()});
        }
    }

    return overrides;
}

void FrameRateOverrideMappings::dump(utils::Dumper& dumper) const {
    using namespace std::string_view_literals;

    std::lock_guard lock(mFrameRateOverridesLock);

    const bool hasOverrides = maxOverridesCount() > 0;
    dumper.dump("FrameRateOverrides"sv, hasOverrides ? ""sv : "none"sv);

    if (!hasOverrides) return;

    dump(dumper, "setFrameRate"sv, mFrameRateOverridesByContent);
    if (!FlagManager::getInstance().game_default_frame_rate()) {
        dump(dumper, "GameManager"sv, mFrameRateOverridesFromGameManager);
    }
    dump(dumper, "Backdoor"sv, mFrameRateOverridesFromBackdoor);
}

void FrameRateOverrideMappings::dump(utils::Dumper& dumper, std::string_view name,
                                     const UidToFrameRateOverride& overrides) const {
    if (overrides.empty()) return;

    utils::Dumper::Indent indent(dumper);
    dumper.dump(name);
    {
        utils::Dumper::Indent indent(dumper);
        for (const auto& [uid, frameRate] : overrides) {
            using namespace std::string_view_literals;
            dumper.dump("(uid, frameRate)"sv, uid, frameRate);
        }
    }
}

bool FrameRateOverrideMappings::updateFrameRateOverridesByContent(
        const UidToFrameRateOverride& frameRateOverrides) {
    std::lock_guard lock(mFrameRateOverridesLock);
    if (!std::equal(mFrameRateOverridesByContent.begin(), mFrameRateOverridesByContent.end(),
                    frameRateOverrides.begin(), frameRateOverrides.end(),
                    [](const auto& lhs, const auto& rhs) {
                        return lhs.first == rhs.first && isApproxEqual(lhs.second, rhs.second);
                    })) {
        mFrameRateOverridesByContent = frameRateOverrides;
        return true;
    }
    return false;
}

void FrameRateOverrideMappings::setGameModeRefreshRateForUid(FrameRateOverride frameRateOverride) {
    std::lock_guard lock(mFrameRateOverridesLock);
    if (frameRateOverride.frameRateHz != 0.f) {
        mFrameRateOverridesFromGameManager[frameRateOverride.uid] =
                Fps::fromValue(frameRateOverride.frameRateHz);
    } else {
        mFrameRateOverridesFromGameManager.erase(frameRateOverride.uid);
    }
}

void FrameRateOverrideMappings::setPreferredRefreshRateForUid(FrameRateOverride frameRateOverride) {
    std::lock_guard lock(mFrameRateOverridesLock);
    if (frameRateOverride.frameRateHz != 0.f) {
        mFrameRateOverridesFromBackdoor[frameRateOverride.uid] =
                Fps::fromValue(frameRateOverride.frameRateHz);
    } else {
        mFrameRateOverridesFromBackdoor.erase(frameRateOverride.uid);
    }
}
} // namespace android::scheduler
