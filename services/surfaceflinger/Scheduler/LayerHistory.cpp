/*
 * Copyright 2020 The Android Open Source Project
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

#undef LOG_TAG
#define LOG_TAG "LayerHistory"
#define ATRACE_TAG ATRACE_TAG_GRAPHICS

#include "LayerHistory.h"

#include <android-base/stringprintf.h>
#include <cutils/properties.h>
#include <gui/TraceUtils.h>
#include <utils/Log.h>
#include <utils/Timers.h>

#include <algorithm>
#include <cmath>
#include <string>
#include <utility>

#include <common/FlagManager.h>
#include "../Layer.h"
#include "EventThread.h"
#include "LayerInfo.h"

namespace android::scheduler {

namespace {

bool isLayerActive(const LayerInfo& info, nsecs_t threshold) {
    if (FlagManager::getInstance().misc1() && !info.isVisible()) {
        return false;
    }

    // Layers with an explicit frame rate or frame rate category are kept active,
    // but ignore NoVote.
    if (info.getSetFrameRateVote().isValid() && !info.getSetFrameRateVote().isNoVote()) {
        return true;
    }

    // Make all front buffered layers active
    if (FlagManager::getInstance().vrr_config() && info.isFrontBuffered() && info.isVisible()) {
        return true;
    }

    return info.isVisible() && info.getLastUpdatedTime() >= threshold;
}

bool traceEnabled() {
    return property_get_bool("debug.sf.layer_history_trace", false);
}

bool useFrameRatePriority() {
    char value[PROPERTY_VALUE_MAX];
    property_get("debug.sf.use_frame_rate_priority", value, "1");
    return atoi(value);
}

void trace(const LayerInfo& info, LayerHistory::LayerVoteType type, int fps) {
    const auto traceType = [&](LayerHistory::LayerVoteType checkedType, int value) {
        ATRACE_INT(info.getTraceTag(checkedType), type == checkedType ? value : 0);
    };

    traceType(LayerHistory::LayerVoteType::NoVote, 1);
    traceType(LayerHistory::LayerVoteType::Heuristic, fps);
    traceType(LayerHistory::LayerVoteType::ExplicitDefault, fps);
    traceType(LayerHistory::LayerVoteType::ExplicitExactOrMultiple, fps);
    traceType(LayerHistory::LayerVoteType::ExplicitExact, fps);
    traceType(LayerHistory::LayerVoteType::Min, 1);
    traceType(LayerHistory::LayerVoteType::Max, 1);
    traceType(LayerHistory::LayerVoteType::ExplicitCategory, 1);

    ALOGD("%s: %s @ %d Hz", __FUNCTION__, info.getName().c_str(), fps);
}

LayerHistory::LayerVoteType getVoteType(FrameRateCompatibility compatibility,
                                        bool contentDetectionEnabled) {
    LayerHistory::LayerVoteType voteType;
    if (!contentDetectionEnabled || compatibility == FrameRateCompatibility::NoVote) {
        voteType = LayerHistory::LayerVoteType::NoVote;
    } else if (compatibility == FrameRateCompatibility::Min) {
        voteType = LayerHistory::LayerVoteType::Min;
    } else {
        voteType = LayerHistory::LayerVoteType::Heuristic;
    }
    return voteType;
}

} // namespace

LayerHistory::LayerHistory()
      : mTraceEnabled(traceEnabled()), mUseFrameRatePriority(useFrameRatePriority()) {
    LayerInfo::setTraceEnabled(mTraceEnabled);
}

LayerHistory::~LayerHistory() = default;

void LayerHistory::registerLayer(Layer* layer, bool contentDetectionEnabled) {
    std::lock_guard lock(mLock);
    LOG_ALWAYS_FATAL_IF(findLayer(layer->getSequence()).first != LayerStatus::NotFound,
                        "%s already registered", layer->getName().c_str());
    LayerVoteType type =
            getVoteType(layer->getDefaultFrameRateCompatibility(), contentDetectionEnabled);
    auto info = std::make_unique<LayerInfo>(layer->getName(), layer->getOwnerUid(), type);

    // The layer can be placed on either map, it is assumed that partitionLayers() will be called
    // to correct them.
    mInactiveLayerInfos.insert({layer->getSequence(), std::make_pair(layer, std::move(info))});
}

void LayerHistory::deregisterLayer(Layer* layer) {
    std::lock_guard lock(mLock);
    if (!mActiveLayerInfos.erase(layer->getSequence())) {
        if (!mInactiveLayerInfos.erase(layer->getSequence())) {
            LOG_ALWAYS_FATAL("%s: unknown layer %p", __FUNCTION__, layer);
        }
    }
}

void LayerHistory::record(int32_t id, const LayerProps& layerProps, nsecs_t presentTime,
                          nsecs_t now, LayerUpdateType updateType) {
    std::lock_guard lock(mLock);
    auto [found, layerPair] = findLayer(id);
    if (found == LayerStatus::NotFound) {
        // Offscreen layer
        ALOGV("%s: %d not registered", __func__, id);
        return;
    }

    const auto& info = layerPair->second;
    info->setLastPresentTime(presentTime, now, updateType, mModeChangePending, layerProps);

    // Activate layer if inactive.
    if (found == LayerStatus::LayerInInactiveMap) {
        mActiveLayerInfos.insert(
                {id, std::make_pair(layerPair->first, std::move(layerPair->second))});
        mInactiveLayerInfos.erase(id);
    }
}

void LayerHistory::setDefaultFrameRateCompatibility(int32_t id,
                                                    FrameRateCompatibility frameRateCompatibility,
                                                    bool contentDetectionEnabled) {
    std::lock_guard lock(mLock);

    auto [found, layerPair] = findLayer(id);
    if (found == LayerStatus::NotFound) {
        // Offscreen layer
        ALOGV("%s: %d not registered", __func__, id);
        return;
    }

    const auto& info = layerPair->second;
    info->setDefaultLayerVote(getVoteType(frameRateCompatibility, contentDetectionEnabled));
}

void LayerHistory::setLayerProperties(int32_t id, const LayerProps& properties) {
    std::lock_guard lock(mLock);

    auto [found, layerPair] = findLayer(id);
    if (found == LayerStatus::NotFound) {
        // Offscreen layer
        ALOGV("%s: %d not registered", __func__, id);
        return;
    }

    const auto& info = layerPair->second;
    info->setProperties(properties);

    // Activate layer if inactive and visible.
    if (found == LayerStatus::LayerInInactiveMap && info->isVisible()) {
        mActiveLayerInfos.insert(
                {id, std::make_pair(layerPair->first, std::move(layerPair->second))});
        mInactiveLayerInfos.erase(id);
    }
}

auto LayerHistory::summarize(const RefreshRateSelector& selector, nsecs_t now) -> Summary {
    ATRACE_CALL();
    Summary summary;

    std::lock_guard lock(mLock);

    partitionLayers(now);

    for (const auto& [key, value] : mActiveLayerInfos) {
        auto& info = value.second;
        const auto frameRateSelectionPriority = info->getFrameRateSelectionPriority();
        const auto layerFocused = Layer::isLayerFocusedBasedOnPriority(frameRateSelectionPriority);
        ALOGV("%s has priority: %d %s focused", info->getName().c_str(), frameRateSelectionPriority,
              layerFocused ? "" : "not");

        ATRACE_FORMAT("%s", info->getName().c_str());
        const auto votes = info->getRefreshRateVote(selector, now);
        for (LayerInfo::LayerVote vote : votes) {
            if (vote.isNoVote()) {
                continue;
            }

            // Compute the layer's position on the screen
            const Rect bounds = Rect(info->getBounds());
            const ui::Transform transform = info->getTransform();
            constexpr bool roundOutwards = true;
            Rect transformed = transform.transform(bounds, roundOutwards);

            const float layerArea = transformed.getWidth() * transformed.getHeight();
            float weight = mDisplayArea ? layerArea / mDisplayArea : 0.0f;
            const std::string categoryString = vote.category == FrameRateCategory::Default
                    ? ""
                    : base::StringPrintf("category=%s", ftl::enum_string(vote.category).c_str());
            ATRACE_FORMAT_INSTANT("%s %s %s (%.2f)", ftl::enum_string(vote.type).c_str(),
                                  to_string(vote.fps).c_str(), categoryString.c_str(), weight);
            summary.push_back({info->getName(), info->getOwnerUid(), vote.type, vote.fps,
                               vote.seamlessness, vote.category, vote.categorySmoothSwitchOnly,
                               weight, layerFocused});

            if (CC_UNLIKELY(mTraceEnabled)) {
                trace(*info, vote.type, vote.fps.getIntValue());
            }
        }
    }

    return summary;
}

void LayerHistory::partitionLayers(nsecs_t now) {
    ATRACE_CALL();
    const nsecs_t threshold = getActiveLayerThreshold(now);

    // iterate over inactive map
    LayerInfos::iterator it = mInactiveLayerInfos.begin();
    while (it != mInactiveLayerInfos.end()) {
        auto& [layerUnsafe, info] = it->second;
        if (isLayerActive(*info, threshold)) {
            // move this to the active map

            mActiveLayerInfos.insert({it->first, std::move(it->second)});
            it = mInactiveLayerInfos.erase(it);
        } else {
            if (CC_UNLIKELY(mTraceEnabled)) {
                trace(*info, LayerVoteType::NoVote, 0);
            }
            info->onLayerInactive(now);
            it++;
        }
    }

    // iterate over active map
    it = mActiveLayerInfos.begin();
    while (it != mActiveLayerInfos.end()) {
        auto& [layerUnsafe, info] = it->second;
        if (isLayerActive(*info, threshold)) {
            // Set layer vote if set
            const auto frameRate = info->getSetFrameRateVote();

            const auto voteType = [&]() {
                switch (frameRate.vote.type) {
                    case Layer::FrameRateCompatibility::Default:
                        return LayerVoteType::ExplicitDefault;
                    case Layer::FrameRateCompatibility::Min:
                        return LayerVoteType::Min;
                    case Layer::FrameRateCompatibility::ExactOrMultiple:
                        return LayerVoteType::ExplicitExactOrMultiple;
                    case Layer::FrameRateCompatibility::NoVote:
                        return LayerVoteType::NoVote;
                    case Layer::FrameRateCompatibility::Exact:
                        return LayerVoteType::ExplicitExact;
                    case Layer::FrameRateCompatibility::Gte:
                        return LayerVoteType::ExplicitGte;
                }
            }();

            if (FlagManager::getInstance().game_default_frame_rate()) {
                // Determine the layer frame rate considering the following priorities:
                // 1. Game mode intervention frame rate override
                // 2. setFrameRate vote
                // 3. Game default frame rate override

                const auto& [gameModeFrameRateOverride, gameDefaultFrameRateOverride] =
                        getGameFrameRateOverrideLocked(info->getOwnerUid());

                const auto gameFrameRateOverrideVoteType =
                        info->isVisible() ? LayerVoteType::ExplicitDefault : LayerVoteType::NoVote;

                const auto setFrameRateVoteType =
                        info->isVisible() ? voteType : LayerVoteType::NoVote;

                if (gameModeFrameRateOverride.isValid()) {
                    info->setLayerVote({gameFrameRateOverrideVoteType, gameModeFrameRateOverride});
                    ATRACE_FORMAT_INSTANT("GameModeFrameRateOverride");
                    if (CC_UNLIKELY(mTraceEnabled)) {
                        trace(*info, gameFrameRateOverrideVoteType,
                              gameModeFrameRateOverride.getIntValue());
                    }
                } else if (frameRate.isValid()) {
                    info->setLayerVote({setFrameRateVoteType, frameRate.vote.rate,
                                        frameRate.vote.seamlessness, frameRate.category});
                    if (CC_UNLIKELY(mTraceEnabled)) {
                        trace(*info, gameFrameRateOverrideVoteType,
                              frameRate.vote.rate.getIntValue());
                    }
                } else if (gameDefaultFrameRateOverride.isValid()) {
                    info->setLayerVote(
                            {gameFrameRateOverrideVoteType, gameDefaultFrameRateOverride});
                    ATRACE_FORMAT_INSTANT("GameDefaultFrameRateOverride");
                    if (CC_UNLIKELY(mTraceEnabled)) {
                        trace(*info, gameFrameRateOverrideVoteType,
                              gameDefaultFrameRateOverride.getIntValue());
                    }
                } else {
                    info->resetLayerVote();
                }
            } else {
                if (frameRate.isValid()) {
                    const auto type = info->isVisible() ? voteType : LayerVoteType::NoVote;
                    info->setLayerVote({type, frameRate.vote.rate, frameRate.vote.seamlessness,
                                        frameRate.category});
                } else {
                    info->resetLayerVote();
                }
            }

            it++;
        } else {
            if (CC_UNLIKELY(mTraceEnabled)) {
                trace(*info, LayerVoteType::NoVote, 0);
            }
            info->onLayerInactive(now);
            // move this to the inactive map
            mInactiveLayerInfos.insert({it->first, std::move(it->second)});
            it = mActiveLayerInfos.erase(it);
        }
    }
}

void LayerHistory::clear() {
    std::lock_guard lock(mLock);
    for (const auto& [key, value] : mActiveLayerInfos) {
        value.second->clearHistory(systemTime());
    }
}

std::string LayerHistory::dump() const {
    std::lock_guard lock(mLock);
    return base::StringPrintf("{size=%zu, active=%zu}\n\tGameFrameRateOverrides=\n\t\t%s",
                              mActiveLayerInfos.size() + mInactiveLayerInfos.size(),
                              mActiveLayerInfos.size(), dumpGameFrameRateOverridesLocked().c_str());
}

std::string LayerHistory::dumpGameFrameRateOverridesLocked() const {
    std::string overridesString = "(uid, gameModeOverride, gameDefaultOverride)=";
    for (auto it = mGameFrameRateOverride.begin(); it != mGameFrameRateOverride.end(); ++it) {
        base::StringAppendF(&overridesString, "{%u, %d %d} ", it->first,
                            it->second.first.getIntValue(), it->second.second.getIntValue());
    }
    return overridesString;
}

float LayerHistory::getLayerFramerate(nsecs_t now, int32_t id) const {
    std::lock_guard lock(mLock);
    auto [found, layerPair] = findLayer(id);
    if (found != LayerStatus::NotFound) {
        return layerPair->second->getFps(now).getValue();
    }
    return 0.f;
}

auto LayerHistory::findLayer(int32_t id) -> std::pair<LayerStatus, LayerPair*> {
    // the layer could be in either the active or inactive map, try both
    auto it = mActiveLayerInfos.find(id);
    if (it != mActiveLayerInfos.end()) {
        return {LayerStatus::LayerInActiveMap, &(it->second)};
    }
    it = mInactiveLayerInfos.find(id);
    if (it != mInactiveLayerInfos.end()) {
        return {LayerStatus::LayerInInactiveMap, &(it->second)};
    }
    return {LayerStatus::NotFound, nullptr};
}

bool LayerHistory::isSmallDirtyArea(uint32_t dirtyArea, float threshold) const {
    const float ratio = (float)dirtyArea / mDisplayArea;
    const bool isSmallDirty = ratio <= threshold;
    ATRACE_FORMAT_INSTANT("small dirty=%s, ratio=%.3f", isSmallDirty ? "true" : "false", ratio);
    return isSmallDirty;
}

void LayerHistory::updateGameModeFrameRateOverride(FrameRateOverride frameRateOverride) {
    const uid_t uid = frameRateOverride.uid;
    std::lock_guard lock(mLock);
    if (frameRateOverride.frameRateHz != 0.f) {
        mGameFrameRateOverride[uid].first = Fps::fromValue(frameRateOverride.frameRateHz);
    } else {
        if (mGameFrameRateOverride[uid].second.getValue() == 0.f) {
            mGameFrameRateOverride.erase(uid);
        } else {
            mGameFrameRateOverride[uid].first = Fps();
        }
    }
}

void LayerHistory::updateGameDefaultFrameRateOverride(FrameRateOverride frameRateOverride) {
    const uid_t uid = frameRateOverride.uid;
    std::lock_guard lock(mLock);
    if (frameRateOverride.frameRateHz != 0.f) {
        mGameFrameRateOverride[uid].second = Fps::fromValue(frameRateOverride.frameRateHz);
    } else {
        if (mGameFrameRateOverride[uid].first.getValue() == 0.f) {
            mGameFrameRateOverride.erase(uid);
        } else {
            mGameFrameRateOverride[uid].second = Fps();
        }
    }
}

std::pair<Fps, Fps> LayerHistory::getGameFrameRateOverride(uid_t uid) const {
    if (!FlagManager::getInstance().game_default_frame_rate()) {
        return std::pair<Fps, Fps>();
    }

    std::lock_guard lock(mLock);

    return getGameFrameRateOverrideLocked(uid);
}

std::pair<Fps, Fps> LayerHistory::getGameFrameRateOverrideLocked(uid_t uid) const {
    if (!FlagManager::getInstance().game_default_frame_rate()) {
        return std::pair<Fps, Fps>();
    }

    const auto it = mGameFrameRateOverride.find(uid);

    if (it == mGameFrameRateOverride.end()) {
        return std::pair<Fps, Fps>(Fps(), Fps());
    }

    return it->second;
}

} // namespace android::scheduler
