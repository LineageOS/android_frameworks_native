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

#include <memory>

#include <compositionengine/Layer.h>
#include <compositionengine/LayerCreationArgs.h>
#include <utils/StrongPointer.h>

namespace android::compositionengine {

struct LayerCreationArgs;

namespace impl {

// The implementation class contains the common implementation, but does not
// actually contain the final layer state.
class Layer : public virtual compositionengine::Layer {
public:
    ~Layer() override;

    // compositionengine::Layer overrides
    void dump(std::string&) const override;

protected:
    // Implemented by the final implementation for the final state it uses.
    virtual void dumpFEState(std::string&) const = 0;
};

// This template factory function standardizes the implementation details of the
// final class using the types actually required by the implementation. This is
// not possible to do in the base class as those types may not even be visible
// to the base code.
template <typename BaseLayer, typename LayerCreationArgs>
std::shared_ptr<BaseLayer> createLayerTemplated(const LayerCreationArgs& args) {
    class Layer final : public BaseLayer {
    public:
// Clang incorrectly complains that these are unused.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-local-typedef"
        using LayerFE = std::remove_pointer_t<decltype(
                std::declval<decltype(std::declval<LayerCreationArgs>().layerFE)>().unsafe_get())>;
        using LayerFECompositionState = std::remove_const_t<
                std::remove_reference_t<decltype(std::declval<BaseLayer>().getFEState())>>;
#pragma clang diagnostic pop

        explicit Layer(const LayerCreationArgs& args) : mLayerFE(args.layerFE) {}
        ~Layer() override = default;

    private:
        // compositionengine::Layer overrides
        sp<compositionengine::LayerFE> getLayerFE() const override { return mLayerFE.promote(); }
        const LayerFECompositionState& getFEState() const override { return mFrontEndState; }
        LayerFECompositionState& editFEState() override { return mFrontEndState; }

        // compositionengine::impl::Layer overrides
        void dumpFEState(std::string& out) const override { mFrontEndState.dump(out); }

        const wp<LayerFE> mLayerFE;
        LayerFECompositionState mFrontEndState;
    };

    return std::make_shared<Layer>(args);
}

std::shared_ptr<Layer> createLayer(const LayerCreationArgs&);

} // namespace impl
} // namespace android::compositionengine
