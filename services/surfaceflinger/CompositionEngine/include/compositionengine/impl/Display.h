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

#pragma once

#include <compositionengine/Display.h>
#include <compositionengine/DisplayCreationArgs.h>
#include <compositionengine/impl/Output.h>

#include <memory>

#include "DisplayHardware/DisplayIdentification.h"
#include "DisplayHardware/HWComposer.h"
#include "DisplayHardware/PowerAdvisor.h"

namespace android::compositionengine {

class CompositionEngine;

namespace impl {

// The implementation class contains the common implementation, but does not
// actually contain the final display state.
class Display : public compositionengine::impl::Output, public virtual compositionengine::Display {
public:
    explicit Display(const compositionengine::DisplayCreationArgs&);
    virtual ~Display();

    // compositionengine::Output overrides
    std::optional<DisplayId> getDisplayId() const override;
    void dump(std::string&) const override;
    using compositionengine::impl::Output::setReleasedLayers;
    void setReleasedLayers(const CompositionRefreshArgs&) override;
    void setColorTransform(const CompositionRefreshArgs&) override;
    void setColorProfile(const ColorProfile&) override;
    void chooseCompositionStrategy() override;
    bool getSkipColorTransform() const override;
    compositionengine::Output::FrameFences presentAndGetFrameFences() override;
    void setExpensiveRenderingExpected(bool) override;
    void finishFrame(const CompositionRefreshArgs&) override;

    // compositionengine::Display overrides
    const std::optional<DisplayId>& getId() const override;
    bool isSecure() const override;
    bool isVirtual() const override;
    void disconnect() override;
    void createDisplayColorProfile(
            const compositionengine::DisplayColorProfileCreationArgs&) override;
    void createRenderSurface(const compositionengine::RenderSurfaceCreationArgs&) override;

    // Internal helpers used by chooseCompositionStrategy()
    using ChangedTypes = android::HWComposer::DeviceRequestedChanges::ChangedTypes;
    using DisplayRequests = android::HWComposer::DeviceRequestedChanges::DisplayRequests;
    using LayerRequests = android::HWComposer::DeviceRequestedChanges::LayerRequests;
    virtual bool anyLayersRequireClientComposition() const;
    virtual bool allLayersRequireClientComposition() const;
    virtual void applyChangedTypesToLayers(const ChangedTypes&);
    virtual void applyDisplayRequests(const DisplayRequests&);
    virtual void applyLayerRequestsToLayers(const LayerRequests&);

    // Internal
    std::unique_ptr<compositionengine::OutputLayer> createOutputLayer(
            const std::shared_ptr<compositionengine::Layer>&, const sp<LayerFE>&) const;

private:
    const bool mIsVirtual;
    std::optional<DisplayId> mId;
    Hwc2::PowerAdvisor* const mPowerAdvisor{nullptr};
};

// This template factory function standardizes the implementation details of the
// final class using the types actually required by the implementation. This is
// not possible to do in the base class as those types may not even be visible
// to the base code.
template <typename BaseDisplay, typename CompositionEngine, typename DisplayCreationArgs>
std::shared_ptr<BaseDisplay> createDisplayTemplated(const CompositionEngine& compositionEngine,
                                                    const DisplayCreationArgs& args) {
    return createOutputTemplated<BaseDisplay>(compositionEngine, args);
}

std::shared_ptr<Display> createDisplay(const compositionengine::CompositionEngine&,
                                       const compositionengine::DisplayCreationArgs&);

} // namespace impl
} // namespace android::compositionengine
