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

#include <compositionengine/CompositionEngine.h>
#include <compositionengine/LayerFECompositionState.h>
#include <compositionengine/Output.h>
#include <compositionengine/impl/ClientCompositionRequestCache.h>
#include <compositionengine/impl/GpuCompositionResult.h>
#include <compositionengine/impl/HwcAsyncWorker.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>
#include <compositionengine/impl/planner/Planner.h>
#include <renderengine/DisplaySettings.h>
#include <renderengine/LayerSettings.h>

#include <memory>
#include <utility>
#include <vector>

namespace android::compositionengine::impl {

// The implementation class contains the common implementation, but does not
// actually contain the final output state.
class Output : public virtual compositionengine::Output {
public:
    Output() = default;
    ~Output() override;

    // compositionengine::Output overrides
    bool isValid() const override;
    std::optional<DisplayId> getDisplayId() const override;
    void setCompositionEnabled(bool) override;
    void setLayerCachingEnabled(bool) override;
    void setLayerCachingTexturePoolEnabled(bool) override;
    void setProjection(ui::Rotation orientation, const Rect& layerStackSpaceRect,
                       const Rect& orientedDisplaySpaceRect) override;
    void setNextBrightness(float brightness) override;
    void setDisplaySize(const ui::Size&) override;
    void setLayerFilter(ui::LayerFilter) override;
    ui::Transform::RotationFlags getTransformHint() const override;

    void setColorTransform(const compositionengine::CompositionRefreshArgs&) override;
    void setColorProfile(const ColorProfile&) override;
    void setDisplayBrightness(float sdrWhitePointNits, float displayBrightnessNits) override;

    void dump(std::string&) const override;
    void dumpPlannerInfo(const Vector<String16>& args, std::string&) const override;

    const std::string& getName() const override;
    void setName(const std::string&) override;

    compositionengine::DisplayColorProfile* getDisplayColorProfile() const override;
    void setDisplayColorProfile(std::unique_ptr<compositionengine::DisplayColorProfile>) override;

    compositionengine::RenderSurface* getRenderSurface() const override;
    void setRenderSurface(std::unique_ptr<compositionengine::RenderSurface>) override;

    Region getDirtyRegion() const override;

    bool includesLayer(ui::LayerFilter) const override;
    bool includesLayer(const sp<LayerFE>&) const override;

    compositionengine::OutputLayer* getOutputLayerForLayer(const sp<LayerFE>&) const override;

    void setReleasedLayers(ReleasedLayers&&) override;

    void prepare(const CompositionRefreshArgs&, LayerFESet&) override;
    void present(const CompositionRefreshArgs&) override;

    void rebuildLayerStacks(const CompositionRefreshArgs&, LayerFESet&) override;
    void collectVisibleLayers(const CompositionRefreshArgs&,
                              compositionengine::Output::CoverageState&) override;
    void ensureOutputLayerIfVisible(sp<compositionengine::LayerFE>&,
                                    compositionengine::Output::CoverageState&) override;
    void setReleasedLayers(const compositionengine::CompositionRefreshArgs&) override;

    void updateLayerStateFromFE(const CompositionRefreshArgs&) const override;
    void updateCompositionState(const compositionengine::CompositionRefreshArgs&) override;
    void planComposition() override;
    void writeCompositionState(const compositionengine::CompositionRefreshArgs&) override;
    void updateColorProfile(const compositionengine::CompositionRefreshArgs&) override;
    void beginFrame() override;
    void prepareFrame() override;
    GpuCompositionResult prepareFrameAsync(const CompositionRefreshArgs&) override;
    void devOptRepaintFlash(const CompositionRefreshArgs&) override;
    void finishFrame(const CompositionRefreshArgs&, GpuCompositionResult&&) override;
    std::optional<base::unique_fd> composeSurfaces(const Region&,
                                                   const compositionengine::CompositionRefreshArgs&,
                                                   std::shared_ptr<renderengine::ExternalTexture>,
                                                   base::unique_fd&) override;
    void postFramebuffer() override;
    void renderCachedSets(const CompositionRefreshArgs&) override;
    void cacheClientCompositionRequests(uint32_t) override;
    bool canPredictCompositionStrategy(const CompositionRefreshArgs&) override;
    void setPredictCompositionStrategy(bool) override;
    void setTreat170mAsSrgb(bool) override;

    // Testing
    const ReleasedLayers& getReleasedLayersForTest() const;
    void setDisplayColorProfileForTest(std::unique_ptr<compositionengine::DisplayColorProfile>);
    void setRenderSurfaceForTest(std::unique_ptr<compositionengine::RenderSurface>);
    bool plannerEnabled() const { return mPlanner != nullptr; }
    virtual bool anyLayersRequireClientComposition() const;
    virtual void updateProtectedContentState();
    virtual bool dequeueRenderBuffer(base::unique_fd*,
                                     std::shared_ptr<renderengine::ExternalTexture>*);
    virtual std::future<bool> chooseCompositionStrategyAsync(
            std::optional<android::HWComposer::DeviceRequestedChanges>*);
    virtual void resetCompositionStrategy();

protected:
    std::unique_ptr<compositionengine::OutputLayer> createOutputLayer(const sp<LayerFE>&) const;
    std::optional<size_t> findCurrentOutputLayerForLayer(
            const sp<compositionengine::LayerFE>&) const;
    using DeviceRequestedChanges = android::HWComposer::DeviceRequestedChanges;
    bool chooseCompositionStrategy(
            std::optional<android::HWComposer::DeviceRequestedChanges>*) override {
        return true;
    };
    void applyCompositionStrategy(const std::optional<DeviceRequestedChanges>&) override{};
    bool getSkipColorTransform() const override;
    compositionengine::Output::FrameFences presentAndGetFrameFences() override;
    std::vector<LayerFE::LayerSettings> generateClientCompositionRequests(
          bool supportsProtectedContent, ui::Dataspace outputDataspace,
          std::vector<LayerFE*> &outLayerFEs) override;
    void appendRegionFlashRequests(const Region&, std::vector<LayerFE::LayerSettings>&) override;
    void setExpensiveRenderingExpected(bool enabled) override;
    void setHintSessionGpuFence(std::unique_ptr<FenceTime>&& gpuFence) override;
    bool isPowerHintSessionEnabled() override;
    void dumpBase(std::string&) const;

    // Implemented by the final implementation for the final state it uses.
    virtual compositionengine::OutputLayer* ensureOutputLayer(std::optional<size_t>,
                                                              const sp<LayerFE>&) = 0;
    virtual compositionengine::OutputLayer* injectOutputLayerForTest(const sp<LayerFE>&) = 0;
    virtual void finalizePendingOutputLayers() = 0;
    virtual const compositionengine::CompositionEngine& getCompositionEngine() const = 0;
    virtual void dumpState(std::string& out) const = 0;

private:
    void dirtyEntireOutput();
    compositionengine::OutputLayer* findLayerRequestingBackgroundComposition() const;
    void finishPrepareFrame();
    ui::Dataspace getBestDataspace(ui::Dataspace*, bool*) const;
    compositionengine::Output::ColorProfile pickColorProfile(
            const compositionengine::CompositionRefreshArgs&) const;

    std::string mName;

    std::unique_ptr<compositionengine::DisplayColorProfile> mDisplayColorProfile;
    std::unique_ptr<compositionengine::RenderSurface> mRenderSurface;

    ReleasedLayers mReleasedLayers;
    OutputLayer* mLayerRequestingBackgroundBlur = nullptr;
    std::unique_ptr<ClientCompositionRequestCache> mClientCompositionRequestCache;
    std::unique_ptr<planner::Planner> mPlanner;
    std::unique_ptr<HwcAsyncWorker> mHwComposerAsyncWorker;
};

// This template factory function standardizes the implementation details of the
// final class using the types actually required by the implementation. This is
// not possible to do in the base class as those types may not even be visible
// to the base code.
template <typename BaseOutput, typename CompositionEngine, typename... Args>
std::shared_ptr<BaseOutput> createOutputTemplated(const CompositionEngine& compositionEngine,
                                                  Args... args) {
    class Output final : public BaseOutput {
    public:
// Clang incorrectly complains that these are unused.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-local-typedef"

        using OutputCompositionState = std::remove_const_t<
                std::remove_reference_t<decltype(std::declval<BaseOutput>().getState())>>;
        using OutputLayer = std::remove_pointer_t<decltype(
                std::declval<BaseOutput>().getOutputLayerOrderedByZByIndex(0))>;

#pragma clang diagnostic pop

        explicit Output(const CompositionEngine& compositionEngine, Args... args)
              : BaseOutput(std::forward<Args>(args)...), mCompositionEngine(compositionEngine) {}
        ~Output() override = default;

    private:
        // compositionengine::Output overrides
        const OutputCompositionState& getState() const override { return mState; }

        OutputCompositionState& editState() override { return mState; }

        size_t getOutputLayerCount() const override {
            return mCurrentOutputLayersOrderedByZ.size();
        }

        OutputLayer* getOutputLayerOrderedByZByIndex(size_t index) const override {
            if (index >= mCurrentOutputLayersOrderedByZ.size()) {
                return nullptr;
            }
            return mCurrentOutputLayersOrderedByZ[index].get();
        }

        // compositionengine::impl::Output overrides
        const CompositionEngine& getCompositionEngine() const override {
            return mCompositionEngine;
        };

        OutputLayer* ensureOutputLayer(std::optional<size_t> prevIndex,
                                       const sp<LayerFE>& layerFE) {
            auto outputLayer = (prevIndex && *prevIndex <= mCurrentOutputLayersOrderedByZ.size())
                    ? std::move(mCurrentOutputLayersOrderedByZ[*prevIndex])
                    : BaseOutput::createOutputLayer(layerFE);
            auto result = outputLayer.get();
            mPendingOutputLayersOrderedByZ.emplace_back(std::move(outputLayer));
            return result;
        }

        void finalizePendingOutputLayers() override {
            // The pending layers are added in reverse order. Reverse them to
            // get the back-to-front ordered list of layers.
            std::reverse(mPendingOutputLayersOrderedByZ.begin(),
                         mPendingOutputLayersOrderedByZ.end());

            mCurrentOutputLayersOrderedByZ = std::move(mPendingOutputLayersOrderedByZ);
        }

        void dumpState(std::string& out) const override { mState.dump(out); }

        OutputLayer* injectOutputLayerForTest(const sp<LayerFE>& layerFE) override {
            auto outputLayer = BaseOutput::createOutputLayer(layerFE);
            auto result = outputLayer.get();
            mCurrentOutputLayersOrderedByZ.emplace_back(std::move(outputLayer));
            return result;
        }

        // Note: This is declared as a private virtual non-override so it can be
        // an override implementation in the unit tests, but otherwise is not an
        // accessible override for the normal implementation.
        virtual void injectOutputLayerForTest(std::unique_ptr<OutputLayer> outputLayer) {
            mCurrentOutputLayersOrderedByZ.emplace_back(std::move(outputLayer));
        }

        void clearOutputLayers() override {
            mCurrentOutputLayersOrderedByZ.clear();
            mPendingOutputLayersOrderedByZ.clear();
        }

        const CompositionEngine& mCompositionEngine;
        OutputCompositionState mState;
        std::vector<std::unique_ptr<OutputLayer>> mCurrentOutputLayersOrderedByZ;
        std::vector<std::unique_ptr<OutputLayer>> mPendingOutputLayersOrderedByZ;
    };

    return std::make_shared<Output>(compositionEngine, std::forward<Args>(args)...);
}

std::shared_ptr<Output> createOutput(const compositionengine::CompositionEngine&);

} // namespace android::compositionengine::impl
