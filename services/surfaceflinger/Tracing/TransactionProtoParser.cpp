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
#include <ui/Rect.h>

#include "LayerProtoHelper.h"
#include "TransactionProtoParser.h"

namespace android::surfaceflinger {

proto::TransactionState TransactionProtoParser::toProto(
        const TransactionState& t, std::function<int32_t(const sp<IBinder>&)> getLayerId,
        std::function<int32_t(const sp<IBinder>&)> getDisplayId) {
    proto::TransactionState proto;
    proto.set_pid(t.originPid);
    proto.set_uid(t.originUid);
    proto.set_vsync_id(t.frameTimelineInfo.vsyncId);
    proto.set_input_event_id(t.frameTimelineInfo.inputEventId);
    proto.set_post_time(t.postTime);

    for (auto& layerState : t.states) {
        proto.mutable_layer_changes()->Add(std::move(toProto(layerState.state, getLayerId)));
    }

    for (auto& displayState : t.displays) {
        proto.mutable_display_changes()->Add(std::move(toProto(displayState, getDisplayId)));
    }
    return proto;
}

proto::LayerState TransactionProtoParser::toProto(
        const layer_state_t& layer, std::function<int32_t(const sp<IBinder>&)> getLayerId) {
    proto::LayerState proto;
    proto.set_layer_id(layer.layerId);
    proto.set_what(layer.what);

    if (layer.what & layer_state_t::ePositionChanged) {
        proto.set_x(layer.x);
        proto.set_y(layer.y);
    }
    if (layer.what & layer_state_t::eLayerChanged) {
        proto.set_z(layer.z);
    }
    if (layer.what & layer_state_t::eSizeChanged) {
        proto.set_w(layer.w);
        proto.set_h(layer.h);
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
        proto.set_alpha(layer.alpha);
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
    if (layer.what & layer_state_t::eTransformChanged) {
        proto.set_transform(layer.transform);
    }
    if (layer.what & layer_state_t::eTransformToDisplayInverseChanged) {
        proto.set_transform_to_display_inverse(layer.transformToDisplayInverse);
    }
    if (layer.what & layer_state_t::eCropChanged) {
        LayerProtoHelper::writeToProto(layer.crop, proto.mutable_crop());
    }
    if (layer.what & layer_state_t::eBufferChanged) {
        proto::LayerState_BufferData* bufferProto = proto.mutable_buffer_data();
        if (layer.bufferData.buffer) {
            bufferProto->set_buffer_id(layer.bufferData.buffer->getId());
            bufferProto->set_width(layer.bufferData.buffer->getWidth());
            bufferProto->set_height(layer.bufferData.buffer->getHeight());
        }
        bufferProto->set_frame_number(layer.bufferData.frameNumber);
        bufferProto->set_flags(layer.bufferData.flags.get());
        bufferProto->set_cached_buffer_id(layer.bufferData.cachedBuffer.id);
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
        int32_t layerId = layer.parentSurfaceControlForChild
                ? getLayerId(layer.parentSurfaceControlForChild->getHandle())
                : -1;
        proto.set_parent_id(layerId);
    }
    if (layer.what & layer_state_t::eRelativeLayerChanged) {
        int32_t layerId = layer.relativeLayerSurfaceControl
                ? getLayerId(layer.relativeLayerSurfaceControl->getHandle())
                : -1;
        proto.set_relative_parent_id(layerId);
    }

    if (layer.what & layer_state_t::eInputInfoChanged) {
        if (layer.windowInfoHandle) {
            const gui::WindowInfo* inputInfo = layer.windowInfoHandle->getInfo();
            proto::LayerState_WindowInfo* windowInfoProto = proto.mutable_window_info_handle();
            windowInfoProto->set_layout_params_flags(inputInfo->flags.get());
            windowInfoProto->set_layout_params_type(static_cast<int32_t>(inputInfo->type));
            LayerProtoHelper::writeToProto(inputInfo->touchableRegion,
                                           windowInfoProto->mutable_touchable_region());
            windowInfoProto->set_surface_inset(inputInfo->surfaceInset);
            windowInfoProto->set_focusable(inputInfo->focusable);
            windowInfoProto->set_has_wallpaper(inputInfo->hasWallpaper);
            windowInfoProto->set_global_scale_factor(inputInfo->globalScaleFactor);
            proto::LayerState_Transform* transformProto = windowInfoProto->mutable_transform();
            transformProto->set_dsdx(inputInfo->transform.dsdx());
            transformProto->set_dtdx(inputInfo->transform.dtdx());
            transformProto->set_dtdy(inputInfo->transform.dtdy());
            transformProto->set_dsdy(inputInfo->transform.dsdy());
            transformProto->set_tx(inputInfo->transform.tx());
            transformProto->set_ty(inputInfo->transform.ty());
            windowInfoProto->set_replace_touchable_region_with_crop(
                    inputInfo->replaceTouchableRegionWithCrop);
            windowInfoProto->set_crop_layer_id(
                    getLayerId(inputInfo->touchableRegionCropHandle.promote()));
        }
    }
    if (layer.what & layer_state_t::eBackgroundColorChanged) {
        proto.set_bg_color_alpha(layer.bgColorAlpha);
        proto.set_bg_color_dataspace(static_cast<int32_t>(layer.bgColorDataspace));
        proto::LayerState_Color3* colorProto = proto.mutable_color();
        colorProto->set_r(layer.color.r);
        colorProto->set_g(layer.color.g);
        colorProto->set_b(layer.color.b);
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

proto::DisplayState TransactionProtoParser::toProto(
        const DisplayState& display, std::function<int32_t(const sp<IBinder>&)> getDisplayId) {
    proto::DisplayState proto;
    proto.set_what(display.what);
    proto.set_id(getDisplayId(display.token));

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

TransactionState TransactionProtoParser::fromProto(
        const proto::TransactionState& proto, std::function<sp<IBinder>(int32_t)> getLayerHandle,
        std::function<sp<IBinder>(int32_t)> getDisplayHandle) {
    TransactionState t;
    t.originPid = proto.pid();
    t.originUid = proto.uid();
    t.frameTimelineInfo.vsyncId = proto.vsync_id();
    t.frameTimelineInfo.inputEventId = proto.input_event_id();
    t.postTime = proto.post_time();
    int32_t layerCount = proto.layer_changes_size();
    t.states.reserve(static_cast<size_t>(layerCount));
    for (int i = 0; i < layerCount; i++) {
        ComposerState s;
        s.state = std::move(fromProto(proto.layer_changes(i), getLayerHandle));
        t.states.add(s);
    }

    int32_t displayCount = proto.display_changes_size();
    t.displays.reserve(static_cast<size_t>(displayCount));
    for (int i = 0; i < displayCount; i++) {
        t.displays.add(fromProto(proto.display_changes(i), getDisplayHandle));
    }
    return t;
}

layer_state_t TransactionProtoParser::fromProto(
        const proto::LayerState& proto, std::function<sp<IBinder>(int32_t)> getLayerHandle) {
    layer_state_t layer;
    layer.layerId = proto.layer_id();
    layer.what = proto.what();

    if (layer.what & layer_state_t::ePositionChanged) {
        layer.x = proto.x();
        layer.y = proto.y();
    }
    if (layer.what & layer_state_t::eLayerChanged) {
        layer.z = proto.z();
    }
    if (layer.what & layer_state_t::eSizeChanged) {
        layer.w = proto.w();
        layer.h = proto.h();
    }
    if (layer.what & layer_state_t::eLayerStackChanged) {
        layer.layerStack.id = proto.layer_stack();
    }
    if (layer.what & layer_state_t::eFlagsChanged) {
        layer.flags = proto.flags();
        layer.mask = proto.mask();
    }
    if (layer.what & layer_state_t::eMatrixChanged) {
        const proto::LayerState_Matrix22& matrixProto = proto.matrix();
        layer.matrix.dsdx = matrixProto.dsdx();
        layer.matrix.dsdy = matrixProto.dsdy();
        layer.matrix.dtdx = matrixProto.dtdx();
        layer.matrix.dtdy = matrixProto.dtdy();
    }
    if (layer.what & layer_state_t::eCornerRadiusChanged) {
        layer.cornerRadius = proto.corner_radius();
    }
    if (layer.what & layer_state_t::eBackgroundBlurRadiusChanged) {
        layer.backgroundBlurRadius = proto.background_blur_radius();
    }

    if (layer.what & layer_state_t::eAlphaChanged) {
        layer.alpha = proto.alpha();
    }

    if (layer.what & layer_state_t::eColorChanged) {
        const proto::LayerState_Color3& colorProto = proto.color();
        layer.color.r = colorProto.r();
        layer.color.g = colorProto.g();
        layer.color.b = colorProto.b();
    }
    if (layer.what & layer_state_t::eTransparentRegionChanged) {
        LayerProtoHelper::readFromProto(proto.transparent_region(), layer.transparentRegion);
    }
    if (layer.what & layer_state_t::eTransformChanged) {
        layer.transform = proto.transform();
    }
    if (layer.what & layer_state_t::eTransformToDisplayInverseChanged) {
        layer.transformToDisplayInverse = proto.transform_to_display_inverse();
    }
    if (layer.what & layer_state_t::eCropChanged) {
        LayerProtoHelper::readFromProto(proto.crop(), layer.crop);
    }
    if (layer.what & layer_state_t::eBufferChanged) {
        const proto::LayerState_BufferData& bufferProto = proto.buffer_data();
        layer.bufferData.buffer = new GraphicBuffer(bufferProto.width(), bufferProto.height(),
                                                    HAL_PIXEL_FORMAT_RGBA_8888, 1, 0);
        layer.bufferData.frameNumber = bufferProto.frame_number();
        layer.bufferData.flags = Flags<BufferData::BufferDataChange>(bufferProto.flags());
        layer.bufferData.cachedBuffer.id = bufferProto.cached_buffer_id();
    }
    if (layer.what & layer_state_t::eSidebandStreamChanged) {
        native_handle_t* handle = native_handle_create(0, 0);
        layer.sidebandStream =
                proto.has_sideband_stream() ? NativeHandle::create(handle, true) : nullptr;
    }

    if (layer.what & layer_state_t::eApiChanged) {
        layer.api = proto.api();
    }

    if (layer.what & layer_state_t::eColorTransformChanged) {
        LayerProtoHelper::readFromProto(proto.color_transform(), layer.colorTransform);
    }
    if (layer.what & layer_state_t::eBlurRegionsChanged) {
        layer.blurRegions.reserve(static_cast<size_t>(proto.blur_regions_size()));
        for (int i = 0; i < proto.blur_regions_size(); i++) {
            android::BlurRegion region;
            LayerProtoHelper::readFromProto(proto.blur_regions(i), region);
            layer.blurRegions.push_back(region);
        }
    }

    if (layer.what & layer_state_t::eReparent) {
        int32_t layerId = proto.parent_id();
        layer.parentSurfaceControlForChild =
                new SurfaceControl(SurfaceComposerClient::getDefault(), getLayerHandle(layerId),
                                   nullptr, layerId);
    }
    if (layer.what & layer_state_t::eRelativeLayerChanged) {
        int32_t layerId = proto.relative_parent_id();
        layer.relativeLayerSurfaceControl =
                new SurfaceControl(SurfaceComposerClient::getDefault(), getLayerHandle(layerId),
                                   nullptr, layerId);
    }

    if ((layer.what & layer_state_t::eInputInfoChanged) && proto.has_window_info_handle()) {
        gui::WindowInfo inputInfo;
        const proto::LayerState_WindowInfo& windowInfoProto = proto.window_info_handle();

        inputInfo.flags = static_cast<gui::WindowInfo::Flag>(windowInfoProto.layout_params_flags());
        inputInfo.type = static_cast<gui::WindowInfo::Type>(windowInfoProto.layout_params_type());
        LayerProtoHelper::readFromProto(windowInfoProto.touchable_region(),
                                        inputInfo.touchableRegion);
        inputInfo.surfaceInset = windowInfoProto.surface_inset();
        inputInfo.focusable = windowInfoProto.focusable();
        inputInfo.hasWallpaper = windowInfoProto.has_wallpaper();
        inputInfo.globalScaleFactor = windowInfoProto.global_scale_factor();
        const proto::LayerState_Transform& transformProto = windowInfoProto.transform();
        inputInfo.transform.set(transformProto.dsdx(), transformProto.dtdx(), transformProto.dtdy(),
                                transformProto.dsdy());
        inputInfo.transform.set(transformProto.tx(), transformProto.ty());
        inputInfo.replaceTouchableRegionWithCrop =
                windowInfoProto.replace_touchable_region_with_crop();
        int32_t layerId = windowInfoProto.crop_layer_id();
        inputInfo.touchableRegionCropHandle = getLayerHandle(layerId);
        layer.windowInfoHandle = sp<gui::WindowInfoHandle>::make(inputInfo);
    }
    if (layer.what & layer_state_t::eBackgroundColorChanged) {
        layer.bgColorAlpha = proto.bg_color_alpha();
        layer.bgColorDataspace = static_cast<ui::Dataspace>(proto.bg_color_dataspace());
        const proto::LayerState_Color3& colorProto = proto.color();
        layer.color.r = colorProto.r();
        layer.color.g = colorProto.g();
        layer.color.b = colorProto.b();
    }
    if (layer.what & layer_state_t::eColorSpaceAgnosticChanged) {
        layer.colorSpaceAgnostic = proto.color_space_agnostic();
    }
    if (layer.what & layer_state_t::eShadowRadiusChanged) {
        layer.shadowRadius = proto.shadow_radius();
    }
    if (layer.what & layer_state_t::eFrameRateSelectionPriority) {
        layer.frameRateSelectionPriority = proto.frame_rate_selection_priority();
    }
    if (layer.what & layer_state_t::eFrameRateChanged) {
        layer.frameRate = proto.frame_rate();
        layer.frameRateCompatibility = static_cast<int8_t>(proto.frame_rate_compatibility());
        layer.changeFrameRateStrategy = static_cast<int8_t>(proto.change_frame_rate_strategy());
    }
    if (layer.what & layer_state_t::eFixedTransformHintChanged) {
        layer.fixedTransformHint =
                static_cast<ui::Transform::RotationFlags>(proto.fixed_transform_hint());
    }
    if (layer.what & layer_state_t::eAutoRefreshChanged) {
        layer.autoRefresh = proto.auto_refresh();
    }
    if (layer.what & layer_state_t::eTrustedOverlayChanged) {
        layer.isTrustedOverlay = proto.is_trusted_overlay();
    }
    if (layer.what & layer_state_t::eBufferCropChanged) {
        LayerProtoHelper::readFromProto(proto.buffer_crop(), layer.bufferCrop);
    }
    if (layer.what & layer_state_t::eDestinationFrameChanged) {
        LayerProtoHelper::readFromProto(proto.destination_frame(), layer.destinationFrame);
    }
    if (layer.what & layer_state_t::eDropInputModeChanged) {
        layer.dropInputMode = static_cast<gui::DropInputMode>(proto.drop_input_mode());
    }
    return layer;
}

DisplayState TransactionProtoParser::fromProto(
        const proto::DisplayState& proto, std::function<sp<IBinder>(int32_t)> getDisplayHandle) {
    DisplayState display;
    display.what = proto.what();
    display.token = getDisplayHandle(proto.id());

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

} // namespace android::surfaceflinger
