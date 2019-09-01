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

#include <android-base/stringprintf.h>
#include <compositionengine/CompositionEngine.h>
#include <compositionengine/DisplayColorProfile.h>
#include <compositionengine/Layer.h>
#include <compositionengine/LayerFE.h>
#include <compositionengine/Output.h>
#include <compositionengine/impl/LayerCompositionState.h>
#include <compositionengine/impl/OutputCompositionState.h>
#include <compositionengine/impl/OutputLayer.h>
#include <compositionengine/impl/OutputLayerCompositionState.h>

#include "DisplayHardware/HWComposer.h"

namespace android::compositionengine {

OutputLayer::~OutputLayer() = default;

namespace impl {

namespace {

FloatRect reduce(const FloatRect& win, const Region& exclude) {
    if (CC_LIKELY(exclude.isEmpty())) {
        return win;
    }
    // Convert through Rect (by rounding) for lack of FloatRegion
    return Region(Rect{win}).subtract(exclude).getBounds().toFloatRect();
}

} // namespace

std::unique_ptr<compositionengine::OutputLayer> createOutputLayer(
        const CompositionEngine& compositionEngine, std::optional<DisplayId> displayId,
        const compositionengine::Output& output, std::shared_ptr<compositionengine::Layer> layer,
        sp<compositionengine::LayerFE> layerFE) {
    auto result = std::make_unique<OutputLayer>(output, layer, layerFE);
    result->initialize(compositionEngine, displayId);
    return result;
}

OutputLayer::OutputLayer(const Output& output, std::shared_ptr<Layer> layer, sp<LayerFE> layerFE)
      : mOutput(output), mLayer(layer), mLayerFE(layerFE) {}

OutputLayer::~OutputLayer() = default;

void OutputLayer::initialize(const CompositionEngine& compositionEngine,
                             std::optional<DisplayId> displayId) {
    if (!displayId) {
        return;
    }

    auto& hwc = compositionEngine.getHwComposer();

    mState.hwc.emplace(std::shared_ptr<HWC2::Layer>(hwc.createLayer(*displayId),
                                                    [&hwc, displayId](HWC2::Layer* layer) {
                                                        hwc.destroyLayer(*displayId, layer);
                                                    }));
}

const compositionengine::Output& OutputLayer::getOutput() const {
    return mOutput;
}

compositionengine::Layer& OutputLayer::getLayer() const {
    return *mLayer;
}

compositionengine::LayerFE& OutputLayer::getLayerFE() const {
    return *mLayerFE;
}

const OutputLayerCompositionState& OutputLayer::getState() const {
    return mState;
}

OutputLayerCompositionState& OutputLayer::editState() {
    return mState;
}

Rect OutputLayer::calculateInitialCrop() const {
    const auto& layerState = mLayer->getState().frontEnd;

    // apply the projection's clipping to the window crop in
    // layerstack space, and convert-back to layer space.
    // if there are no window scaling involved, this operation will map to full
    // pixels in the buffer.

    FloatRect activeCropFloat =
            reduce(layerState.geomLayerBounds, layerState.geomActiveTransparentRegion);

    const Rect& viewport = mOutput.getState().viewport;
    const ui::Transform& layerTransform = layerState.geomLayerTransform;
    const ui::Transform& inverseLayerTransform = layerState.geomInverseLayerTransform;
    // Transform to screen space.
    activeCropFloat = layerTransform.transform(activeCropFloat);
    activeCropFloat = activeCropFloat.intersect(viewport.toFloatRect());
    // Back to layer space to work with the content crop.
    activeCropFloat = inverseLayerTransform.transform(activeCropFloat);

    // This needs to be here as transform.transform(Rect) computes the
    // transformed rect and then takes the bounding box of the result before
    // returning. This means
    // transform.inverse().transform(transform.transform(Rect)) != Rect
    // in which case we need to make sure the final rect is clipped to the
    // display bounds.
    Rect activeCrop{activeCropFloat};
    if (!activeCrop.intersect(layerState.geomBufferSize, &activeCrop)) {
        activeCrop.clear();
    }
    return activeCrop;
}

FloatRect OutputLayer::calculateOutputSourceCrop() const {
    const auto& layerState = mLayer->getState().frontEnd;
    const auto& outputState = mOutput.getState();

    if (!layerState.geomUsesSourceCrop) {
        return {};
    }

    // the content crop is the area of the content that gets scaled to the
    // layer's size. This is in buffer space.
    FloatRect crop = layerState.geomContentCrop.toFloatRect();

    // In addition there is a WM-specified crop we pull from our drawing state.
    Rect activeCrop = calculateInitialCrop();
    const Rect& bufferSize = layerState.geomBufferSize;

    int winWidth = bufferSize.getWidth();
    int winHeight = bufferSize.getHeight();

    // The bufferSize for buffer state layers can be unbounded ([0, 0, -1, -1])
    // if display frame hasn't been set and the parent is an unbounded layer.
    if (winWidth < 0 && winHeight < 0) {
        return crop;
    }

    // Transform the window crop to match the buffer coordinate system,
    // which means using the inverse of the current transform set on the
    // SurfaceFlingerConsumer.
    uint32_t invTransform = layerState.geomBufferTransform;
    if (layerState.geomBufferUsesDisplayInverseTransform) {
        /*
         * the code below applies the primary display's inverse transform to the
         * buffer
         */
        uint32_t invTransformOrient = outputState.orientation;
        // calculate the inverse transform
        if (invTransformOrient & HAL_TRANSFORM_ROT_90) {
            invTransformOrient ^= HAL_TRANSFORM_FLIP_V | HAL_TRANSFORM_FLIP_H;
        }
        // and apply to the current transform
        invTransform =
                (ui::Transform(invTransformOrient) * ui::Transform(invTransform)).getOrientation();
    }

    if (invTransform & HAL_TRANSFORM_ROT_90) {
        // If the activeCrop has been rotate the ends are rotated but not
        // the space itself so when transforming ends back we can't rely on
        // a modification of the axes of rotation. To account for this we
        // need to reorient the inverse rotation in terms of the current
        // axes of rotation.
        bool is_h_flipped = (invTransform & HAL_TRANSFORM_FLIP_H) != 0;
        bool is_v_flipped = (invTransform & HAL_TRANSFORM_FLIP_V) != 0;
        if (is_h_flipped == is_v_flipped) {
            invTransform ^= HAL_TRANSFORM_FLIP_V | HAL_TRANSFORM_FLIP_H;
        }
        std::swap(winWidth, winHeight);
    }
    const Rect winCrop =
            activeCrop.transform(invTransform, bufferSize.getWidth(), bufferSize.getHeight());

    // below, crop is intersected with winCrop expressed in crop's coordinate space
    float xScale = crop.getWidth() / float(winWidth);
    float yScale = crop.getHeight() / float(winHeight);

    float insetL = winCrop.left * xScale;
    float insetT = winCrop.top * yScale;
    float insetR = (winWidth - winCrop.right) * xScale;
    float insetB = (winHeight - winCrop.bottom) * yScale;

    crop.left += insetL;
    crop.top += insetT;
    crop.right -= insetR;
    crop.bottom -= insetB;

    return crop;
}

Rect OutputLayer::calculateOutputDisplayFrame() const {
    const auto& layerState = mLayer->getState().frontEnd;
    const auto& outputState = mOutput.getState();

    // apply the layer's transform, followed by the display's global transform
    // here we're guaranteed that the layer's transform preserves rects
    Region activeTransparentRegion = layerState.geomActiveTransparentRegion;
    const ui::Transform& layerTransform = layerState.geomLayerTransform;
    const ui::Transform& inverseLayerTransform = layerState.geomInverseLayerTransform;
    const Rect& bufferSize = layerState.geomBufferSize;
    Rect activeCrop = layerState.geomCrop;
    if (!activeCrop.isEmpty() && bufferSize.isValid()) {
        activeCrop = layerTransform.transform(activeCrop);
        if (!activeCrop.intersect(outputState.viewport, &activeCrop)) {
            activeCrop.clear();
        }
        activeCrop = inverseLayerTransform.transform(activeCrop, true);
        // This needs to be here as transform.transform(Rect) computes the
        // transformed rect and then takes the bounding box of the result before
        // returning. This means
        // transform.inverse().transform(transform.transform(Rect)) != Rect
        // in which case we need to make sure the final rect is clipped to the
        // display bounds.
        if (!activeCrop.intersect(bufferSize, &activeCrop)) {
            activeCrop.clear();
        }
        // mark regions outside the crop as transparent
        activeTransparentRegion.orSelf(Rect(0, 0, bufferSize.getWidth(), activeCrop.top));
        activeTransparentRegion.orSelf(
                Rect(0, activeCrop.bottom, bufferSize.getWidth(), bufferSize.getHeight()));
        activeTransparentRegion.orSelf(Rect(0, activeCrop.top, activeCrop.left, activeCrop.bottom));
        activeTransparentRegion.orSelf(
                Rect(activeCrop.right, activeCrop.top, bufferSize.getWidth(), activeCrop.bottom));
    }

    // reduce uses a FloatRect to provide more accuracy during the
    // transformation. We then round upon constructing 'frame'.
    Rect frame{
            layerTransform.transform(reduce(layerState.geomLayerBounds, activeTransparentRegion))};
    if (!frame.intersect(outputState.viewport, &frame)) {
        frame.clear();
    }
    const ui::Transform displayTransform{outputState.transform};

    return displayTransform.transform(frame);
}

uint32_t OutputLayer::calculateOutputRelativeBufferTransform() const {
    const auto& layerState = mLayer->getState().frontEnd;
    const auto& outputState = mOutput.getState();

    /*
     * Transformations are applied in this order:
     * 1) buffer orientation/flip/mirror
     * 2) state transformation (window manager)
     * 3) layer orientation (screen orientation)
     * (NOTE: the matrices are multiplied in reverse order)
     */
    const ui::Transform& layerTransform = layerState.geomLayerTransform;
    const ui::Transform displayTransform{outputState.orientation};
    const ui::Transform bufferTransform{layerState.geomBufferTransform};
    ui::Transform transform(displayTransform * layerTransform * bufferTransform);

    if (layerState.geomBufferUsesDisplayInverseTransform) {
        /*
         * the code below applies the primary display's inverse transform to the
         * buffer
         */
        uint32_t invTransform = outputState.orientation;
        // calculate the inverse transform
        if (invTransform & HAL_TRANSFORM_ROT_90) {
            invTransform ^= HAL_TRANSFORM_FLIP_V | HAL_TRANSFORM_FLIP_H;
        }

        /*
         * Here we cancel out the orientation component of the WM transform.
         * The scaling and translate components are already included in our bounds
         * computation so it's enough to just omit it in the composition.
         * See comment in BufferLayer::prepareClientLayer with ref to b/36727915 for why.
         */
        transform = ui::Transform(invTransform) * displayTransform * bufferTransform;
    }

    // this gives us only the "orientation" component of the transform
    return transform.getOrientation();
} // namespace impl

void OutputLayer::updateCompositionState(bool includeGeometry) {
    const auto& layerFEState = mLayer->getState().frontEnd;
    const auto& outputState = mOutput.getState();
    const auto& profile = *mOutput.getDisplayColorProfile();

    if (includeGeometry) {
        mState.displayFrame = calculateOutputDisplayFrame();
        mState.sourceCrop = calculateOutputSourceCrop();
        mState.bufferTransform =
                static_cast<Hwc2::Transform>(calculateOutputRelativeBufferTransform());

        if ((layerFEState.isSecure && !outputState.isSecure) ||
            (mState.bufferTransform & ui::Transform::ROT_INVALID)) {
            mState.forceClientComposition = true;
        }
    }

    // Determine the output dependent dataspace for this layer. If it is
    // colorspace agnostic, it just uses the dataspace chosen for the output to
    // avoid the need for color conversion.
    mState.dataspace = layerFEState.isColorspaceAgnostic &&
                    outputState.targetDataspace != ui::Dataspace::UNKNOWN
            ? outputState.targetDataspace
            : layerFEState.dataspace;

    // TODO(lpique): b/121291683 Remove this one we are sure we don't need the
    // value recomputed / set every frame.
    mState.visibleRegion = outputState.transform.transform(
            layerFEState.geomVisibleRegion.intersect(outputState.viewport));

    // These are evaluated every frame as they can potentially change at any
    // time.
    if (layerFEState.forceClientComposition || !profile.isDataspaceSupported(mState.dataspace)) {
        mState.forceClientComposition = true;
    }
}

void OutputLayer::writeStateToHWC(bool includeGeometry) {
    // Skip doing this if there is no HWC interface
    if (!mState.hwc) {
        return;
    }

    auto& hwcLayer = (*mState.hwc).hwcLayer;
    if (!hwcLayer) {
        ALOGE("[%s] failed to write composition state to HWC -- no hwcLayer for output %s",
              mLayerFE->getDebugName(), mOutput.getName().c_str());
        return;
    }

    const auto& outputIndependentState = mLayer->getState().frontEnd;
    auto requestedCompositionType = outputIndependentState.compositionType;

    if (includeGeometry) {
        writeOutputDependentGeometryStateToHWC(hwcLayer.get(), requestedCompositionType);
        writeOutputIndependentGeometryStateToHWC(hwcLayer.get(), outputIndependentState);
    }

    writeOutputDependentPerFrameStateToHWC(hwcLayer.get());
    writeOutputIndependentPerFrameStateToHWC(hwcLayer.get(), outputIndependentState);

    writeCompositionTypeToHWC(hwcLayer.get(), requestedCompositionType);
}

void OutputLayer::writeOutputDependentGeometryStateToHWC(
        HWC2::Layer* hwcLayer, Hwc2::IComposerClient::Composition requestedCompositionType) {
    const auto& outputDependentState = getState();

    if (auto error = hwcLayer->setDisplayFrame(outputDependentState.displayFrame);
        error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set display frame [%d, %d, %d, %d]: %s (%d)",
              mLayerFE->getDebugName(), outputDependentState.displayFrame.left,
              outputDependentState.displayFrame.top, outputDependentState.displayFrame.right,
              outputDependentState.displayFrame.bottom, to_string(error).c_str(),
              static_cast<int32_t>(error));
    }

    if (auto error = hwcLayer->setSourceCrop(outputDependentState.sourceCrop);
        error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set source crop [%.3f, %.3f, %.3f, %.3f]: "
              "%s (%d)",
              mLayerFE->getDebugName(), outputDependentState.sourceCrop.left,
              outputDependentState.sourceCrop.top, outputDependentState.sourceCrop.right,
              outputDependentState.sourceCrop.bottom, to_string(error).c_str(),
              static_cast<int32_t>(error));
    }

    if (auto error = hwcLayer->setZOrder(outputDependentState.z); error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set Z %u: %s (%d)", mLayerFE->getDebugName(), outputDependentState.z,
              to_string(error).c_str(), static_cast<int32_t>(error));
    }

    // Solid-color layers should always use an identity transform.
    const auto bufferTransform =
            requestedCompositionType != Hwc2::IComposerClient::Composition::SOLID_COLOR
            ? outputDependentState.bufferTransform
            : static_cast<Hwc2::Transform>(0);
    if (auto error = hwcLayer->setTransform(static_cast<HWC2::Transform>(bufferTransform));
        error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set transform %s: %s (%d)", mLayerFE->getDebugName(),
              toString(outputDependentState.bufferTransform).c_str(), to_string(error).c_str(),
              static_cast<int32_t>(error));
    }
}

void OutputLayer::writeOutputIndependentGeometryStateToHWC(
        HWC2::Layer* hwcLayer, const LayerFECompositionState& outputIndependentState) {
    if (auto error = hwcLayer->setBlendMode(
                static_cast<HWC2::BlendMode>(outputIndependentState.blendMode));
        error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set blend mode %s: %s (%d)", mLayerFE->getDebugName(),
              toString(outputIndependentState.blendMode).c_str(), to_string(error).c_str(),
              static_cast<int32_t>(error));
    }

    if (auto error = hwcLayer->setPlaneAlpha(outputIndependentState.alpha);
        error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set plane alpha %.3f: %s (%d)", mLayerFE->getDebugName(),
              outputIndependentState.alpha, to_string(error).c_str(), static_cast<int32_t>(error));
    }

    if (auto error = hwcLayer->setInfo(outputIndependentState.type, outputIndependentState.appId);
        error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set info %s (%d)", mLayerFE->getDebugName(), to_string(error).c_str(),
              static_cast<int32_t>(error));
    }
}

void OutputLayer::writeOutputDependentPerFrameStateToHWC(HWC2::Layer* hwcLayer) {
    const auto& outputDependentState = getState();

    // TODO(lpique): b/121291683 visibleRegion is output-dependent geometry
    // state and should not change every frame.
    if (auto error = hwcLayer->setVisibleRegion(outputDependentState.visibleRegion);
        error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set visible region: %s (%d)", mLayerFE->getDebugName(),
              to_string(error).c_str(), static_cast<int32_t>(error));
        outputDependentState.visibleRegion.dump(LOG_TAG);
    }

    if (auto error = hwcLayer->setDataspace(outputDependentState.dataspace);
        error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set dataspace %d: %s (%d)", mLayerFE->getDebugName(),
              outputDependentState.dataspace, to_string(error).c_str(),
              static_cast<int32_t>(error));
    }
}

void OutputLayer::writeOutputIndependentPerFrameStateToHWC(
        HWC2::Layer* hwcLayer, const LayerFECompositionState& outputIndependentState) {
    switch (auto error = hwcLayer->setColorTransform(outputIndependentState.colorTransform)) {
        case HWC2::Error::None:
            break;
        case HWC2::Error::Unsupported:
            editState().forceClientComposition = true;
            break;
        default:
            ALOGE("[%s] Failed to set color transform: %s (%d)", mLayerFE->getDebugName(),
                  to_string(error).c_str(), static_cast<int32_t>(error));
    }

    if (auto error = hwcLayer->setSurfaceDamage(outputIndependentState.surfaceDamage);
        error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set surface damage: %s (%d)", mLayerFE->getDebugName(),
              to_string(error).c_str(), static_cast<int32_t>(error));
        outputIndependentState.surfaceDamage.dump(LOG_TAG);
    }

    // Content-specific per-frame state
    switch (outputIndependentState.compositionType) {
        case Hwc2::IComposerClient::Composition::SOLID_COLOR:
            writeSolidColorStateToHWC(hwcLayer, outputIndependentState);
            break;
        case Hwc2::IComposerClient::Composition::SIDEBAND:
            writeSidebandStateToHWC(hwcLayer, outputIndependentState);
            break;
        case Hwc2::IComposerClient::Composition::CURSOR:
        case Hwc2::IComposerClient::Composition::DEVICE:
            writeBufferStateToHWC(hwcLayer, outputIndependentState);
            break;
        case Hwc2::IComposerClient::Composition::INVALID:
        case Hwc2::IComposerClient::Composition::CLIENT:
            // Ignored
            break;
    }
}

void OutputLayer::writeSolidColorStateToHWC(HWC2::Layer* hwcLayer,
                                            const LayerFECompositionState& outputIndependentState) {
    hwc_color_t color = {static_cast<uint8_t>(std::round(255.0f * outputIndependentState.color.r)),
                         static_cast<uint8_t>(std::round(255.0f * outputIndependentState.color.g)),
                         static_cast<uint8_t>(std::round(255.0f * outputIndependentState.color.b)),
                         255};

    if (auto error = hwcLayer->setColor(color); error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set color: %s (%d)", mLayerFE->getDebugName(),
              to_string(error).c_str(), static_cast<int32_t>(error));
    }
}

void OutputLayer::writeSidebandStateToHWC(HWC2::Layer* hwcLayer,
                                          const LayerFECompositionState& outputIndependentState) {
    if (auto error = hwcLayer->setSidebandStream(outputIndependentState.sidebandStream->handle());
        error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set sideband stream %p: %s (%d)", mLayerFE->getDebugName(),
              outputIndependentState.sidebandStream->handle(), to_string(error).c_str(),
              static_cast<int32_t>(error));
    }
}

void OutputLayer::writeBufferStateToHWC(HWC2::Layer* hwcLayer,
                                        const LayerFECompositionState& outputIndependentState) {
    auto supportedPerFrameMetadata =
            mOutput.getDisplayColorProfile()->getSupportedPerFrameMetadata();
    if (auto error = hwcLayer->setPerFrameMetadata(supportedPerFrameMetadata,
                                                   outputIndependentState.hdrMetadata);
        error != HWC2::Error::None && error != HWC2::Error::Unsupported) {
        ALOGE("[%s] Failed to set hdrMetadata: %s (%d)", mLayerFE->getDebugName(),
              to_string(error).c_str(), static_cast<int32_t>(error));
    }

    uint32_t hwcSlot = 0;
    sp<GraphicBuffer> hwcBuffer;
    // We need access to the output-dependent state for the buffer cache there,
    // though otherwise the buffer is not output-dependent.
    editState().hwc->hwcBufferCache.getHwcBuffer(outputIndependentState.bufferSlot,
                                                 outputIndependentState.buffer, &hwcSlot,
                                                 &hwcBuffer);

    if (auto error = hwcLayer->setBuffer(hwcSlot, hwcBuffer, outputIndependentState.acquireFence);
        error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set buffer %p: %s (%d)", mLayerFE->getDebugName(),
              outputIndependentState.buffer->handle, to_string(error).c_str(),
              static_cast<int32_t>(error));
    }
}

void OutputLayer::writeCompositionTypeToHWC(
        HWC2::Layer* hwcLayer, Hwc2::IComposerClient::Composition requestedCompositionType) {
    auto& outputDependentState = editState();

    // If we are forcing client composition, we need to tell the HWC
    if (outputDependentState.forceClientComposition) {
        requestedCompositionType = Hwc2::IComposerClient::Composition::CLIENT;
    }

    // Set the requested composition type with the HWC whenever it changes
    if (outputDependentState.hwc->hwcCompositionType != requestedCompositionType) {
        outputDependentState.hwc->hwcCompositionType = requestedCompositionType;

        if (auto error = hwcLayer->setCompositionType(
                    static_cast<HWC2::Composition>(requestedCompositionType));
            error != HWC2::Error::None) {
            ALOGE("[%s] Failed to set composition type %s: %s (%d)", mLayerFE->getDebugName(),
                  toString(requestedCompositionType).c_str(), to_string(error).c_str(),
                  static_cast<int32_t>(error));
        }
    }
}

void OutputLayer::writeCursorPositionToHWC() const {
    // Skip doing this if there is no HWC interface
    auto hwcLayer = getHwcLayer();
    if (!hwcLayer) {
        return;
    }

    const auto& layerFEState = mLayer->getState().frontEnd;
    const auto& outputState = mOutput.getState();

    Rect frame = layerFEState.cursorFrame;
    frame.intersect(outputState.viewport, &frame);
    Rect position = outputState.transform.transform(frame);

    if (auto error = hwcLayer->setCursorPosition(position.left, position.top);
        error != HWC2::Error::None) {
        ALOGE("[%s] Failed to set cursor position to (%d, %d): %s (%d)", mLayerFE->getDebugName(),
              position.left, position.top, to_string(error).c_str(), static_cast<int32_t>(error));
    }
}

HWC2::Layer* OutputLayer::getHwcLayer() const {
    return mState.hwc ? mState.hwc->hwcLayer.get() : nullptr;
}

bool OutputLayer::requiresClientComposition() const {
    return !mState.hwc ||
            mState.hwc->hwcCompositionType == Hwc2::IComposerClient::Composition::CLIENT;
}

bool OutputLayer::isHardwareCursor() const {
    return mState.hwc &&
            mState.hwc->hwcCompositionType == Hwc2::IComposerClient::Composition::CURSOR;
}

void OutputLayer::detectDisallowedCompositionTypeChange(
        Hwc2::IComposerClient::Composition from, Hwc2::IComposerClient::Composition to) const {
    bool result = false;
    switch (from) {
        case Hwc2::IComposerClient::Composition::INVALID:
        case Hwc2::IComposerClient::Composition::CLIENT:
            result = false;
            break;

        case Hwc2::IComposerClient::Composition::DEVICE:
        case Hwc2::IComposerClient::Composition::SOLID_COLOR:
            result = (to == Hwc2::IComposerClient::Composition::CLIENT);
            break;

        case Hwc2::IComposerClient::Composition::CURSOR:
        case Hwc2::IComposerClient::Composition::SIDEBAND:
            result = (to == Hwc2::IComposerClient::Composition::CLIENT ||
                      to == Hwc2::IComposerClient::Composition::DEVICE);
            break;
    }

    if (!result) {
        ALOGE("[%s] Invalid device requested composition type change: %s (%d) --> %s (%d)",
              mLayerFE->getDebugName(), toString(from).c_str(), static_cast<int>(from),
              toString(to).c_str(), static_cast<int>(to));
    }
}

void OutputLayer::applyDeviceCompositionTypeChange(
        Hwc2::IComposerClient::Composition compositionType) {
    LOG_FATAL_IF(!mState.hwc);
    auto& hwcState = *mState.hwc;

    detectDisallowedCompositionTypeChange(hwcState.hwcCompositionType, compositionType);

    hwcState.hwcCompositionType = compositionType;
}

void OutputLayer::prepareForDeviceLayerRequests() {
    mState.clearClientTarget = false;
}

void OutputLayer::applyDeviceLayerRequest(Hwc2::IComposerClient::LayerRequest request) {
    switch (request) {
        case Hwc2::IComposerClient::LayerRequest::CLEAR_CLIENT_TARGET:
            mState.clearClientTarget = true;
            break;

        default:
            ALOGE("[%s] Unknown device layer request %s (%d)", mLayerFE->getDebugName(),
                  toString(request).c_str(), static_cast<int>(request));
            break;
    }
}

bool OutputLayer::needsFiltering() const {
    const auto& displayFrame = mState.displayFrame;
    const auto& sourceCrop = mState.sourceCrop;
    return sourceCrop.getHeight() != displayFrame.getHeight() ||
            sourceCrop.getWidth() != displayFrame.getWidth();
}

void OutputLayer::dump(std::string& out) const {
    using android::base::StringAppendF;

    StringAppendF(&out, "  - Output Layer %p (Composition layer %p) (%s)\n", this, mLayer.get(),
                  mLayerFE->getDebugName());
    mState.dump(out);
}

} // namespace impl
} // namespace android::compositionengine
