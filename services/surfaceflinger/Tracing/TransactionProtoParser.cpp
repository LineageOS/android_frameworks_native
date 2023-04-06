/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <gui/SurfaceComposerClient.h>
#include <ui/Fence.h>
#include <ui/Rect.h>

#include "FrontEnd/LayerCreationArgs.h"
#include "LayerProtoHelper.h"
#include "TransactionProtoParser.h"
#include "TransactionState.h"
#include "gui/LayerState.h"

namespace android::surfaceflinger {

class FakeExternalTexture : public renderengine::ExternalTexture {
    const sp<GraphicBuffer> mEmptyBuffer = nullptr;
    uint32_t mWidth;
    uint32_t mHeight;
    uint64_t mId;
    PixelFormat mPixelFormat;
    uint64_t mUsage;

public:
    FakeExternalTexture(uint32_t width, uint32_t height, uint64_t id, PixelFormat pixelFormat,
                        uint64_t usage)
          : mWidth(width), mHeight(height), mId(id), mPixelFormat(pixelFormat), mUsage(usage) {}
    const sp<GraphicBuffer>& getBuffer() const { return mEmptyBuffer; }
    bool hasSameBuffer(const renderengine::ExternalTexture& other) const override {
        return getId() == other.getId();
    }
    uint32_t getWidth() const override { return mWidth; }
    uint32_t getHeight() const override { return mHeight; }
    uint64_t getId() const override { return mId; }
    PixelFormat getPixelFormat() const override { return mPixelFormat; }
    uint64_t getUsage() const override { return mUsage; }
    void remapBuffer() override {}
    ~FakeExternalTexture() = default;
};

proto::TransactionState TransactionProtoParser::toProto(const TransactionState& t) {
    proto::TransactionState proto;
    proto.set_pid(t.originPid);
    proto.set_uid(t.originUid);
    proto.set_vsync_id(t.frameTimelineInfo.vsyncId);
    proto.set_input_event_id(t.frameTimelineInfo.inputEventId);
    proto.set_post_time(t.postTime);
    proto.set_transaction_id(t.id);

    proto.mutable_layer_changes()->Reserve(static_cast<int32_t>(t.states.size()));
    for (auto& layerState : t.states) {
        proto.mutable_layer_changes()->Add(std::move(toProto(layerState)));
    }

    proto.mutable_display_changes()->Reserve(static_cast<int32_t>(t.displays.size()));
    for (auto& displayState : t.displays) {
        proto.mutable_display_changes()->Add(std::move(toProto(displayState)));
    }
    return proto;
}

proto::TransactionState TransactionProtoParser::toProto(
        const std::map<uint32_t /* layerId */, TracingLayerState>& states) {
    proto::TransactionState proto;
    proto.mutable_layer_changes()->Reserve(static_cast<int32_t>(states.size()));
    for (auto& [layerId, state] : states) {
        proto::LayerState layerProto = toProto(state);
        layerProto.set_has_sideband_stream(state.hasSidebandStream);
        proto.mutable_layer_changes()->Add(std::move(layerProto));
    }
    return proto;
}

proto::LayerState TransactionProtoParser::toProto(
        const ResolvedComposerState& resolvedComposerState) {
    proto::LayerState proto;
    auto& layer = resolvedComposerState.state;
    proto.set_layer_id(resolvedComposerState.layerId);
    proto.set_what(layer.what);

    if (layer.what & layer_state_t::ePositionChanged) {
        proto.set_x(layer.x);
        proto.set_y(layer.y);
    }
    if (layer.what & layer_state_t::eLayerChanged) {
        proto.set_z(layer.z);
    }

    if (layer.what & layer_state_t::eLayerStackChanged) {
        proto.set_layer_stack(layer.layerStack.id);
    }
    if (layer.what & layer_state_t::eFlagsChanged) {
        proto.set_flags(layer.flags);
        proto.set_mask(layer.mask);
    }
    if (layer.what & layer_state_t::eMatrixChanged) {
        proto::LayerState_Matrix22* matrixProto = proto.mutable_matrix();
        matrixProto->set_dsdx(layer.matrix.dsdx);
        matrixProto->set_dsdy(layer.matrix.dsdy);
        matrixProto->set_dtdx(layer.matrix.dtdx);
        matrixProto->set_dtdy(layer.matrix.dtdy);
    }
    if (layer.what & layer_state_t::eCornerRadiusChanged) {
        proto.set_corner_radius(layer.cornerRadius);
    }
    if (layer.what & layer_state_t::eBackgroundBlurRadiusChanged) {
        proto.set_background_blur_radius(layer.backgroundBlurRadius);
    }

    if (layer.what & layer_state_t::eAlphaChanged) {
        proto.set_alpha(layer.color.a);
    }

    if (layer.what & layer_state_t::eColorChanged) {
        proto::LayerState_Color3* colorProto = proto.mutable_color();
        colorProto->set_r(layer.color.r);
        colorProto->set_g(layer.color.g);
        colorProto->set_b(layer.color.b);
    }
    if (layer.what & layer_state_t::eTransparentRegionChanged) {
        LayerProtoHelper::writeToProto(layer.transparentRegion, proto.mutable_transparent_region());
    }
    if (layer.what & layer_state_t::eBufferTransformChanged) {
        proto.set_transform(layer.bufferTransform);
    }
    if (layer.what & layer_state_t::eTransformToDisplayInverseChanged) {
        proto.set_transform_to_display_inverse(layer.transformToDisplayInverse);
    }
    if (layer.what & layer_state_t::eCropChanged) {
        LayerProtoHelper::writeToProto(layer.crop, proto.mutable_crop());
    }
    if (layer.what & layer_state_t::eBufferChanged) {
        proto::LayerState_BufferData* bufferProto = proto.mutable_buffer_data();
        if (resolvedComposerState.externalTexture) {
            bufferProto->set_buffer_id(resolvedComposerState.externalTexture->getId());
            bufferProto->set_width(resolvedComposerState.externalTexture->getWidth());
            bufferProto->set_height(resolvedComposerState.externalTexture->getHeight());
            bufferProto->set_pixel_format(static_cast<proto::LayerState_BufferData_PixelFormat>(
                    resolvedComposerState.externalTexture->getPixelFormat()));
            bufferProto->set_usage(resolvedComposerState.externalTexture->getUsage());
        }
        bufferProto->set_frame_number(layer.bufferData->frameNumber);
        bufferProto->set_flags(layer.bufferData->flags.get());
        bufferProto->set_cached_buffer_id(layer.bufferData->cachedBuffer.id);
    }
    if (layer.what & layer_state_t::eSidebandStreamChanged) {
        proto.set_has_sideband_stream(layer.sidebandStream != nullptr);
    }

    if (layer.what & layer_state_t::eApiChanged) {
        proto.set_api(layer.api);
    }

    if (layer.what & layer_state_t::eColorTransformChanged) {
        LayerProtoHelper::writeToProto(layer.colorTransform, proto.mutable_color_transform());
    }
    if (layer.what & layer_state_t::eBlurRegionsChanged) {
        for (auto& region : layer.blurRegions) {
            LayerProtoHelper::writeToProto(region, proto.add_blur_regions());
        }
    }

    if (layer.what & layer_state_t::eReparent) {
        proto.set_parent_id(resolvedComposerState.parentId);
    }
    if (layer.what & layer_state_t::eRelativeLayerChanged) {
        proto.set_relative_parent_id(resolvedComposerState.relativeParentId);
        proto.set_z(layer.z);
    }

    if (layer.what & layer_state_t::eInputInfoChanged) {
        if (layer.windowInfoHandle) {
            const gui::WindowInfo* inputInfo = layer.windowInfoHandle->getInfo();
            proto::LayerState_WindowInfo* windowInfoProto = proto.mutable_window_info_handle();
            windowInfoProto->set_layout_params_flags(inputInfo->layoutParamsFlags.get());
            windowInfoProto->set_layout_params_type(
                    static_cast<int32_t>(inputInfo->layoutParamsType));
            LayerProtoHelper::writeToProto(inputInfo->touchableRegion,
                                           windowInfoProto->mutable_touchable_region());
            windowInfoProto->set_surface_inset(inputInfo->surfaceInset);
            windowInfoProto->set_focusable(
                    !inputInfo->inputConfig.test(gui::WindowInfo::InputConfig::NOT_FOCUSABLE));
            windowInfoProto->set_has_wallpaper(inputInfo->inputConfig.test(
                    gui::WindowInfo::InputConfig::DUPLICATE_TOUCH_TO_WALLPAPER));
            windowInfoProto->set_global_scale_factor(inputInfo->globalScaleFactor);
            proto::Transform* transformProto = windowInfoProto->mutable_transform();
            transformProto->set_dsdx(inputInfo->transform.dsdx());
            transformProto->set_dtdx(inputInfo->transform.dtdx());
            transformProto->set_dtdy(inputInfo->transform.dtdy());
            transformProto->set_dsdy(inputInfo->transform.dsdy());
            transformProto->set_tx(inputInfo->transform.tx());
            transformProto->set_ty(inputInfo->transform.ty());
            windowInfoProto->set_replace_touchable_region_with_crop(
                    inputInfo->replaceTouchableRegionWithCrop);
            windowInfoProto->set_crop_layer_id(resolvedComposerState.touchCropId);
        }
    }
    if (layer.what & layer_state_t::eBackgroundColorChanged) {
        proto.set_bg_color_alpha(layer.bgColor.a);
        proto.set_bg_color_dataspace(static_cast<int32_t>(layer.bgColorDataspace));
        proto::LayerState_Color3* colorProto = proto.mutable_color();
        colorProto->set_r(layer.bgColor.r);
        colorProto->set_g(layer.bgColor.g);
        colorProto->set_b(layer.bgColor.b);
    }
    if (layer.what & layer_state_t::eColorSpaceAgnosticChanged) {
        proto.set_color_space_agnostic(layer.colorSpaceAgnostic);
    }
    if (layer.what & layer_state_t::eShadowRadiusChanged) {
        proto.set_shadow_radius(layer.shadowRadius);
    }
    if (layer.what & layer_state_t::eFrameRateSelectionPriority) {
        proto.set_frame_rate_selection_priority(layer.frameRateSelectionPriority);
    }
    if (layer.what & layer_state_t::eFrameRateChanged) {
        proto.set_frame_rate(layer.frameRate);
        proto.set_frame_rate_compatibility(layer.frameRateCompatibility);
        proto.set_change_frame_rate_strategy(layer.changeFrameRateStrategy);
    }
    if (layer.what & layer_state_t::eFixedTransformHintChanged) {
        proto.set_fixed_transform_hint(layer.fixedTransformHint);
    }
    if (layer.what & layer_state_t::eAutoRefreshChanged) {
        proto.set_auto_refresh(layer.autoRefresh);
    }
    if (layer.what & layer_state_t::eTrustedOverlayChanged) {
        proto.set_is_trusted_overlay(layer.isTrustedOverlay);
    }
    if (layer.what & layer_state_t::eBufferCropChanged) {
        LayerProtoHelper::writeToProto(layer.bufferCrop, proto.mutable_buffer_crop());
    }
    if (layer.what & layer_state_t::eDestinationFrameChanged) {
        LayerProtoHelper::writeToProto(layer.destinationFrame, proto.mutable_destination_frame());
    }
    if (layer.what & layer_state_t::eDropInputModeChanged) {
        proto.set_drop_input_mode(
                static_cast<proto::LayerState_DropInputMode>(layer.dropInputMode));
    }
    return proto;
}

proto::DisplayState TransactionProtoParser::toProto(const DisplayState& display) {
    proto::DisplayState proto;
    proto.set_what(display.what);
    proto.set_id(mMapper->getDisplayId(display.token));

    if (display.what & DisplayState::eLayerStackChanged) {
        proto.set_layer_stack(display.layerStack.id);
    }
    if (display.what & DisplayState::eDisplayProjectionChanged) {
        proto.set_orientation(static_cast<uint32_t>(display.orientation));
        LayerProtoHelper::writeToProto(display.orientedDisplaySpaceRect,
                                       proto.mutable_oriented_display_space_rect());
        LayerProtoHelper::writeToProto(display.layerStackSpaceRect,
                                       proto.mutable_layer_stack_space_rect());
    }
    if (display.what & DisplayState::eDisplaySizeChanged) {
        proto.set_width(display.width);
        proto.set_height(display.height);
    }
    if (display.what & DisplayState::eFlagsChanged) {
        proto.set_flags(display.flags);
    }
    return proto;
}

proto::LayerCreationArgs TransactionProtoParser::toProto(const LayerCreationArgs& args) {
    proto::LayerCreationArgs proto;
    proto.set_layer_id(args.sequence);
    proto.set_name(args.name);
    proto.set_flags(args.flags);
    proto.set_parent_id(args.parentId);
    proto.set_mirror_from_id(args.layerIdToMirror);
    proto.set_add_to_root(args.addToRoot);
    proto.set_layer_stack_to_mirror(args.layerStackToMirror.id);
    return proto;
}

TransactionState TransactionProtoParser::fromProto(const proto::TransactionState& proto) {
    TransactionState t;
    t.originPid = proto.pid();
    t.originUid = proto.uid();
    t.frameTimelineInfo.vsyncId = proto.vsync_id();
    t.frameTimelineInfo.inputEventId = proto.input_event_id();
    t.postTime = proto.post_time();
    t.id = proto.transaction_id();

    int32_t layerCount = proto.layer_changes_size();
    t.states.reserve(static_cast<size_t>(layerCount));
    for (int i = 0; i < layerCount; i++) {
        ResolvedComposerState s;
        s.state.what = 0;
        fromProto(proto.layer_changes(i), s);
        t.states.emplace_back(s);
    }

    int32_t displayCount = proto.display_changes_size();
    t.displays.reserve(static_cast<size_t>(displayCount));
    for (int i = 0; i < displayCount; i++) {
        t.displays.add(fromProto(proto.display_changes(i)));
    }
    return t;
}

void TransactionProtoParser::fromProto(const proto::LayerCreationArgs& proto,
                                       LayerCreationArgs& outArgs) {
    outArgs.sequence = proto.layer_id();

    outArgs.name = proto.name();
    outArgs.flags = proto.flags();
    outArgs.parentId = proto.parent_id();
    outArgs.layerIdToMirror = proto.mirror_from_id();
    outArgs.addToRoot = proto.add_to_root();
    outArgs.layerStackToMirror.id = proto.layer_stack_to_mirror();
}

void TransactionProtoParser::mergeFromProto(const proto::LayerState& proto,
                                            TracingLayerState& outState) {
    ResolvedComposerState resolvedComposerState;
    fromProto(proto, resolvedComposerState);
    layer_state_t& state = resolvedComposerState.state;
    outState.state.merge(state);
    outState.layerId = resolvedComposerState.layerId;

    if (state.what & layer_state_t::eReparent) {
        outState.parentId = resolvedComposerState.parentId;
    }
    if (state.what & layer_state_t::eRelativeLayerChanged) {
        outState.relativeParentId = resolvedComposerState.relativeParentId;
    }
    if (state.what & layer_state_t::eInputInfoChanged) {
        outState.touchCropId = resolvedComposerState.touchCropId;
    }
    if (state.what & layer_state_t::eBufferChanged) {
        outState.externalTexture = resolvedComposerState.externalTexture;
    }
    if (state.what & layer_state_t::eSidebandStreamChanged) {
        outState.hasSidebandStream = proto.has_sideband_stream();
    }
}

void TransactionProtoParser::fromProto(const proto::LayerState& proto,
                                       ResolvedComposerState& resolvedComposerState) {
    auto& layer = resolvedComposerState.state;
    resolvedComposerState.layerId = proto.layer_id();
    layer.what |= proto.what();

    if (proto.what() & layer_state_t::ePositionChanged) {
        layer.x = proto.x();
        layer.y = proto.y();
    }
    if (proto.what() & layer_state_t::eLayerChanged) {
        layer.z = proto.z();
    }
    if (proto.what() & layer_state_t::eLayerStackChanged) {
        layer.layerStack.id = proto.layer_stack();
    }
    if (proto.what() & layer_state_t::eFlagsChanged) {
        layer.flags = proto.flags();
        layer.mask = proto.mask();
    }
    if (proto.what() & layer_state_t::eMatrixChanged) {
        const proto::LayerState_Matrix22& matrixProto = proto.matrix();
        layer.matrix.dsdx = matrixProto.dsdx();
        layer.matrix.dsdy = matrixProto.dsdy();
        layer.matrix.dtdx = matrixProto.dtdx();
        layer.matrix.dtdy = matrixProto.dtdy();
    }
    if (proto.what() & layer_state_t::eCornerRadiusChanged) {
        layer.cornerRadius = proto.corner_radius();
    }
    if (proto.what() & layer_state_t::eBackgroundBlurRadiusChanged) {
        layer.backgroundBlurRadius = proto.background_blur_radius();
    }

    if (proto.what() & layer_state_t::eAlphaChanged) {
        layer.color.a = proto.alpha();
    }

    if (proto.what() & layer_state_t::eColorChanged) {
        const proto::LayerState_Color3& colorProto = proto.color();
        layer.color.r = colorProto.r();
        layer.color.g = colorProto.g();
        layer.color.b = colorProto.b();
    }
    if (proto.what() & layer_state_t::eTransparentRegionChanged) {
        LayerProtoHelper::readFromProto(proto.transparent_region(), layer.transparentRegion);
    }
    if (proto.what() & layer_state_t::eBufferTransformChanged) {
        layer.bufferTransform = proto.transform();
    }
    if (proto.what() & layer_state_t::eTransformToDisplayInverseChanged) {
        layer.transformToDisplayInverse = proto.transform_to_display_inverse();
    }
    if (proto.what() & layer_state_t::eCropChanged) {
        LayerProtoHelper::readFromProto(proto.crop(), layer.crop);
    }
    if (proto.what() & layer_state_t::eBufferChanged) {
        const proto::LayerState_BufferData& bufferProto = proto.buffer_data();
        layer.bufferData =
                std::make_shared<fake::BufferData>(bufferProto.buffer_id(), bufferProto.width(),
                                                   bufferProto.height(), bufferProto.pixel_format(),
                                                   bufferProto.usage());
        resolvedComposerState.externalTexture =
                std::make_shared<FakeExternalTexture>(layer.bufferData->getWidth(),
                                                      layer.bufferData->getHeight(),
                                                      layer.bufferData->getId(),
                                                      layer.bufferData->getPixelFormat(),
                                                      layer.bufferData->getUsage());
        layer.bufferData->frameNumber = bufferProto.frame_number();
        layer.bufferData->flags = ftl::Flags<BufferData::BufferDataChange>(bufferProto.flags());
        layer.bufferData->cachedBuffer.id = bufferProto.cached_buffer_id();
        layer.bufferData->acquireFence = Fence::NO_FENCE;
    }

    if (proto.what() & layer_state_t::eApiChanged) {
        layer.api = proto.api();
    }

    if (proto.what() & layer_state_t::eColorTransformChanged) {
        LayerProtoHelper::readFromProto(proto.color_transform(), layer.colorTransform);
    }
    if (proto.what() & layer_state_t::eBlurRegionsChanged) {
        layer.blurRegions.reserve(static_cast<size_t>(proto.blur_regions_size()));
        for (int i = 0; i < proto.blur_regions_size(); i++) {
            android::BlurRegion region;
            LayerProtoHelper::readFromProto(proto.blur_regions(i), region);
            layer.blurRegions.push_back(region);
        }
    }

    if (proto.what() & layer_state_t::eReparent) {
        resolvedComposerState.parentId = proto.parent_id();
    }
    if (proto.what() & layer_state_t::eRelativeLayerChanged) {
        resolvedComposerState.relativeParentId = proto.relative_parent_id();
        layer.z = proto.z();
    }

    if ((proto.what() & layer_state_t::eInputInfoChanged) && proto.has_window_info_handle()) {
        gui::WindowInfo inputInfo;
        const proto::LayerState_WindowInfo& windowInfoProto = proto.window_info_handle();

        inputInfo.layoutParamsFlags =
                static_cast<gui::WindowInfo::Flag>(windowInfoProto.layout_params_flags());
        inputInfo.layoutParamsType =
                static_cast<gui::WindowInfo::Type>(windowInfoProto.layout_params_type());
        LayerProtoHelper::readFromProto(windowInfoProto.touchable_region(),
                                        inputInfo.touchableRegion);
        inputInfo.surfaceInset = windowInfoProto.surface_inset();
        inputInfo.setInputConfig(gui::WindowInfo::InputConfig::NOT_FOCUSABLE,
                                 !windowInfoProto.focusable());
        inputInfo.setInputConfig(gui::WindowInfo::InputConfig::DUPLICATE_TOUCH_TO_WALLPAPER,
                                 windowInfoProto.has_wallpaper());
        inputInfo.globalScaleFactor = windowInfoProto.global_scale_factor();
        const proto::Transform& transformProto = windowInfoProto.transform();
        inputInfo.transform.set(transformProto.dsdx(), transformProto.dtdx(), transformProto.dtdy(),
                                transformProto.dsdy());
        inputInfo.transform.set(transformProto.tx(), transformProto.ty());
        inputInfo.replaceTouchableRegionWithCrop =
                windowInfoProto.replace_touchable_region_with_crop();
        resolvedComposerState.touchCropId = windowInfoProto.crop_layer_id();

        layer.windowInfoHandle = sp<gui::WindowInfoHandle>::make(inputInfo);
    }
    if (proto.what() & layer_state_t::eBackgroundColorChanged) {
        layer.bgColor.a = proto.bg_color_alpha();
        layer.bgColorDataspace = static_cast<ui::Dataspace>(proto.bg_color_dataspace());
        const proto::LayerState_Color3& colorProto = proto.color();
        layer.bgColor.r = colorProto.r();
        layer.bgColor.g = colorProto.g();
        layer.bgColor.b = colorProto.b();
    }
    if (proto.what() & layer_state_t::eColorSpaceAgnosticChanged) {
        layer.colorSpaceAgnostic = proto.color_space_agnostic();
    }
    if (proto.what() & layer_state_t::eShadowRadiusChanged) {
        layer.shadowRadius = proto.shadow_radius();
    }
    if (proto.what() & layer_state_t::eFrameRateSelectionPriority) {
        layer.frameRateSelectionPriority = proto.frame_rate_selection_priority();
    }
    if (proto.what() & layer_state_t::eFrameRateChanged) {
        layer.frameRate = proto.frame_rate();
        layer.frameRateCompatibility = static_cast<int8_t>(proto.frame_rate_compatibility());
        layer.changeFrameRateStrategy = static_cast<int8_t>(proto.change_frame_rate_strategy());
    }
    if (proto.what() & layer_state_t::eFixedTransformHintChanged) {
        layer.fixedTransformHint =
                static_cast<ui::Transform::RotationFlags>(proto.fixed_transform_hint());
    }
    if (proto.what() & layer_state_t::eAutoRefreshChanged) {
        layer.autoRefresh = proto.auto_refresh();
    }
    if (proto.what() & layer_state_t::eTrustedOverlayChanged) {
        layer.isTrustedOverlay = proto.is_trusted_overlay();
    }
    if (proto.what() & layer_state_t::eBufferCropChanged) {
        LayerProtoHelper::readFromProto(proto.buffer_crop(), layer.bufferCrop);
    }
    if (proto.what() & layer_state_t::eDestinationFrameChanged) {
        LayerProtoHelper::readFromProto(proto.destination_frame(), layer.destinationFrame);
    }
    if (proto.what() & layer_state_t::eDropInputModeChanged) {
        layer.dropInputMode = static_cast<gui::DropInputMode>(proto.drop_input_mode());
    }
}

DisplayState TransactionProtoParser::fromProto(const proto::DisplayState& proto) {
    DisplayState display;
    display.what = proto.what();
    display.token = mMapper->getDisplayHandle(proto.id());

    if (display.what & DisplayState::eLayerStackChanged) {
        display.layerStack.id = proto.layer_stack();
    }
    if (display.what & DisplayState::eDisplayProjectionChanged) {
        display.orientation = static_cast<ui::Rotation>(proto.orientation());
        LayerProtoHelper::readFromProto(proto.oriented_display_space_rect(),
                                        display.orientedDisplaySpaceRect);
        LayerProtoHelper::readFromProto(proto.layer_stack_space_rect(),
                                        display.layerStackSpaceRect);
    }
    if (display.what & DisplayState::eDisplaySizeChanged) {
        display.width = proto.width();
        display.height = proto.height();
    }
    if (display.what & DisplayState::eFlagsChanged) {
        display.flags = proto.flags();
    }
    return display;
}

void asProto(proto::Transform* proto, const ui::Transform& transform) {
    proto->set_dsdx(transform.dsdx());
    proto->set_dtdx(transform.dtdx());
    proto->set_dtdy(transform.dtdy());
    proto->set_dsdy(transform.dsdy());
    proto->set_tx(transform.tx());
    proto->set_ty(transform.ty());
}

proto::DisplayInfo TransactionProtoParser::toProto(const frontend::DisplayInfo& displayInfo,
                                                   uint32_t layerStack) {
    proto::DisplayInfo proto;
    proto.set_layer_stack(layerStack);
    proto.set_display_id(displayInfo.info.displayId);
    proto.set_logical_width(displayInfo.info.logicalWidth);
    proto.set_logical_height(displayInfo.info.logicalHeight);
    asProto(proto.mutable_transform_inverse(), displayInfo.info.transform);
    asProto(proto.mutable_transform(), displayInfo.transform);
    proto.set_receives_input(displayInfo.receivesInput);
    proto.set_is_secure(displayInfo.isSecure);
    proto.set_is_primary(displayInfo.isPrimary);
    proto.set_is_virtual(displayInfo.isVirtual);
    proto.set_rotation_flags((int)displayInfo.rotationFlags);
    proto.set_transform_hint((int)displayInfo.transformHint);
    return proto;
}

void fromProto2(ui::Transform& outTransform, const proto::Transform& proto) {
    outTransform.set(proto.dsdx(), proto.dtdx(), proto.dtdy(), proto.dsdy());
    outTransform.set(proto.tx(), proto.ty());
}

frontend::DisplayInfo TransactionProtoParser::fromProto(const proto::DisplayInfo& proto) {
    frontend::DisplayInfo displayInfo;
    displayInfo.info.displayId = proto.display_id();
    displayInfo.info.logicalWidth = proto.logical_width();
    displayInfo.info.logicalHeight = proto.logical_height();
    fromProto2(displayInfo.info.transform, proto.transform_inverse());
    fromProto2(displayInfo.transform, proto.transform());
    displayInfo.receivesInput = proto.receives_input();
    displayInfo.isSecure = proto.is_secure();
    displayInfo.isPrimary = proto.is_primary();
    displayInfo.isVirtual = proto.is_virtual();
    displayInfo.rotationFlags = (ui::Transform::RotationFlags)proto.rotation_flags();
    displayInfo.transformHint = (ui::Transform::RotationFlags)proto.transform_hint();
    return displayInfo;
}

void TransactionProtoParser::fromProto(
        const google::protobuf::RepeatedPtrField<proto::DisplayInfo>& proto,
        display::DisplayMap<ui::LayerStack, frontend::DisplayInfo>& outDisplayInfos) {
    outDisplayInfos.clear();
    for (const proto::DisplayInfo& displayInfo : proto) {
        outDisplayInfos.emplace_or_replace(ui::LayerStack::fromValue(displayInfo.layer_stack()),
                                           fromProto(displayInfo));
    }
}

} // namespace android::surfaceflinger
