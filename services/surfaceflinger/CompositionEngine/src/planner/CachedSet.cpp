/*
 * Copyright 2021 The Android Open Source Project
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
#define LOG_TAG "Planner"
// #define LOG_NDEBUG 0

#include <android-base/properties.h>
#include <compositionengine/impl/planner/CachedSet.h>
#include <math/HashCombine.h>
#include <renderengine/DisplaySettings.h>
#include <renderengine/RenderEngine.h>

namespace android::compositionengine::impl::planner {

const bool CachedSet::sDebugHighlighLayers =
        base::GetBoolProperty(std::string("debug.sf.layer_caching_highlight"), false);

std::string durationString(std::chrono::milliseconds duration) {
    using namespace std::chrono_literals;

    std::string result;

    if (duration >= 1h) {
        const auto hours = std::chrono::duration_cast<std::chrono::hours>(duration);
        base::StringAppendF(&result, "%d hr ", static_cast<int>(hours.count()));
        duration -= hours;
    }
    if (duration >= 1min) {
        const auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration);
        base::StringAppendF(&result, "%d min ", static_cast<int>(minutes.count()));
        duration -= minutes;
    }
    base::StringAppendF(&result, "%.3f sec ", duration.count() / 1000.0f);

    return result;
}

CachedSet::Layer::Layer(const LayerState* state, std::chrono::steady_clock::time_point lastUpdate)
      : mState(state), mHash(state->getHash(LayerStateField::Buffer)), mLastUpdate(lastUpdate) {}

CachedSet::CachedSet(const LayerState* layer, std::chrono::steady_clock::time_point lastUpdate)
      : mFingerprint(layer->getHash(LayerStateField::Buffer)), mLastUpdate(lastUpdate) {
    addLayer(layer, lastUpdate);
}

CachedSet::CachedSet(Layer layer)
      : mFingerprint(layer.getHash()),
        mLastUpdate(layer.getLastUpdate()),
        mBounds(layer.getDisplayFrame()) {
    mLayers.emplace_back(std::move(layer));
}

void CachedSet::addLayer(const LayerState* layer,
                         std::chrono::steady_clock::time_point lastUpdate) {
    mLayers.emplace_back(layer, lastUpdate);

    Region boundingRegion;
    boundingRegion.orSelf(mBounds);
    boundingRegion.orSelf(layer->getDisplayFrame());
    mBounds = boundingRegion.getBounds();
}

NonBufferHash CachedSet::getNonBufferHash() const {
    if (mLayers.size() == 1) {
        return mFingerprint;
    }

    // TODO(b/181192080): Add all fields which contribute to geometry of override layer (e.g.,
    // dataspace)
    size_t hash = 0;
    android::hashCombineSingle(hash, mBounds);
    return hash;
}

size_t CachedSet::getComponentDisplayCost() const {
    size_t displayCost = 0;

    for (const Layer& layer : mLayers) {
        displayCost += static_cast<size_t>(layer.getDisplayFrame().width() *
                                           layer.getDisplayFrame().height());
    }

    return displayCost;
}

size_t CachedSet::getCreationCost() const {
    if (mLayers.size() == 1) {
        return 0;
    }

    // Reads
    size_t creationCost = getComponentDisplayCost();

    // Write - assumes that the output buffer only gets written once per pixel
    creationCost += static_cast<size_t>(mBounds.width() * mBounds.height());

    return creationCost;
}

size_t CachedSet::getDisplayCost() const {
    return static_cast<size_t>(mBounds.width() * mBounds.height());
}

bool CachedSet::hasBufferUpdate(std::vector<const LayerState*>::const_iterator layers) const {
    for (const Layer& layer : mLayers) {
        if (layer.getFramesSinceBufferUpdate() == 0) {
            return true;
        }
        ++layers;
    }
    return false;
}

bool CachedSet::hasReadyBuffer() const {
    return mBuffer != nullptr && mDrawFence->getStatus() == Fence::Status::Signaled;
}

std::vector<CachedSet> CachedSet::decompose() const {
    std::vector<CachedSet> layers;

    std::transform(mLayers.begin(), mLayers.end(), std::back_inserter(layers),
                   [](Layer layer) { return CachedSet(std::move(layer)); });

    return layers;
}

void CachedSet::updateAge(std::chrono::steady_clock::time_point now) {
    LOG_ALWAYS_FATAL_IF(mLayers.size() > 1, "[%s] This should only be called on single-layer sets",
                        __func__);

    if (mLayers[0].getFramesSinceBufferUpdate() == 0) {
        mLastUpdate = now;
        mAge = 0;
    }
}

void CachedSet::render(renderengine::RenderEngine& renderEngine) {
    renderengine::DisplaySettings displaySettings{
            .physicalDisplay = Rect(0, 0, mBounds.getWidth(), mBounds.getHeight()),
            .clip = mBounds,
    };

    Region clearRegion = Region::INVALID_REGION;
    Rect viewport = mBounds;
    LayerFE::ClientCompositionTargetSettings targetSettings{
            .clip = Region(mBounds),
            .needsFiltering = false,
            .isSecure = true,
            .supportsProtectedContent = false,
            .clearRegion = clearRegion,
            .viewport = viewport,
            // TODO(181192086): Propagate the Output's dataspace instead of using UNKNOWN
            .dataspace = ui::Dataspace::UNKNOWN,
            .realContentIsVisible = true,
            .clearContent = false,
            .disableBlurs = false,
    };

    std::vector<renderengine::LayerSettings> layerSettings;
    for (const auto& layer : mLayers) {
        const auto clientCompositionList =
                layer.getState()->getOutputLayer()->getLayerFE().prepareClientCompositionList(
                        targetSettings);
        layerSettings.insert(layerSettings.end(), clientCompositionList.cbegin(),
                             clientCompositionList.cend());
    }

    std::vector<const renderengine::LayerSettings*> layerSettingsPointers;
    std::transform(layerSettings.cbegin(), layerSettings.cend(),
                   std::back_inserter(layerSettingsPointers),
                   [](const renderengine::LayerSettings& settings) { return &settings; });

    if (sDebugHighlighLayers) {
        renderengine::LayerSettings highlight{
                .geometry =
                        renderengine::Geometry{
                                .boundaries = FloatRect(0.0f, 0.0f,
                                                        static_cast<float>(mBounds.getWidth()),
                                                        static_cast<float>(mBounds.getHeight())),
                        },
                .source =
                        renderengine::PixelSource{
                                .solidColor = half3(0.25f, 0.0f, 0.5f),
                        },
                .alpha = half(0.05f),
        };

        layerSettingsPointers.emplace_back(&highlight);
    }

    const uint64_t usageFlags = GraphicBuffer::USAGE_HW_RENDER | GraphicBuffer::USAGE_HW_COMPOSER |
            GraphicBuffer::USAGE_HW_TEXTURE;
    sp<GraphicBuffer> buffer = new GraphicBuffer(static_cast<uint32_t>(mBounds.getWidth()),
                                                 static_cast<uint32_t>(mBounds.getHeight()),
                                                 HAL_PIXEL_FORMAT_RGBA_8888, 1, usageFlags);
    LOG_ALWAYS_FATAL_IF(buffer->initCheck() != OK);
    base::unique_fd drawFence;
    status_t result = renderEngine.drawLayers(displaySettings, layerSettingsPointers, buffer, false,
                                              base::unique_fd(), &drawFence);

    if (result == NO_ERROR) {
        mBuffer = buffer;
        mDrawFence = new Fence(drawFence.release());
    }
}

void CachedSet::dump(std::string& result) const {
    const auto now = std::chrono::steady_clock::now();

    const auto lastUpdate =
            std::chrono::duration_cast<std::chrono::milliseconds>(now - mLastUpdate);
    base::StringAppendF(&result, "  + Fingerprint %016zx, last update %sago, age %zd\n",
                        mFingerprint, durationString(lastUpdate).c_str(), mAge);

    if (mLayers.size() == 1) {
        base::StringAppendF(&result, "    Layer [%s]\n", mLayers[0].getName().c_str());
        base::StringAppendF(&result, "    Buffer %p", mLayers[0].getBuffer().get());
    } else {
        result.append("    Cached set of:");
        for (const Layer& layer : mLayers) {
            base::StringAppendF(&result, "\n      Layer [%s]", layer.getName().c_str());
        }
    }

    base::StringAppendF(&result, "\n    Creation cost: %zd", getCreationCost());
    base::StringAppendF(&result, "\n    Display cost: %zd\n", getDisplayCost());
}

} // namespace android::compositionengine::impl::planner
