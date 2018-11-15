/*
 * Copyright (C) 2008 The Android Open Source Project
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

#define LOG_TAG "LayerState"

#include <utils/Errors.h>
#include <binder/Parcel.h>
#include <gui/ISurfaceComposerClient.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/LayerState.h>

namespace android {

status_t layer_state_t::write(Parcel& output) const
{
    output.writeStrongBinder(surface);
    output.writeUint32(what);
    output.writeFloat(x);
    output.writeFloat(y);
    output.writeInt32(z);
    output.writeUint32(w);
    output.writeUint32(h);
    output.writeUint32(layerStack);
    output.writeFloat(alpha);
    output.writeUint32(flags);
    output.writeUint32(mask);
    *reinterpret_cast<layer_state_t::matrix22_t *>(
            output.writeInplace(sizeof(layer_state_t::matrix22_t))) = matrix;
    output.write(crop_legacy);
    output.writeStrongBinder(barrierHandle_legacy);
    output.writeStrongBinder(reparentHandle);
    output.writeUint64(frameNumber_legacy);
    output.writeInt32(overrideScalingMode);
    output.writeStrongBinder(IInterface::asBinder(barrierGbp_legacy));
    output.writeStrongBinder(relativeLayerHandle);
    output.writeStrongBinder(parentHandleForChild);
    output.writeFloat(color.r);
    output.writeFloat(color.g);
    output.writeFloat(color.b);
#ifndef NO_INPUT
    inputInfo.write(output);
#endif
    output.write(transparentRegion);
    output.writeUint32(transform);
    output.writeBool(transformToDisplayInverse);
    output.write(crop);
    if (buffer) {
        output.writeBool(true);
        output.write(*buffer);
    } else {
        output.writeBool(false);
    }
    if (acquireFence) {
        output.writeBool(true);
        output.write(*acquireFence);
    } else {
        output.writeBool(false);
    }
    output.writeUint32(static_cast<uint32_t>(dataspace));
    output.write(hdrMetadata);
    output.write(surfaceDamageRegion);
    output.writeInt32(api);
    if (sidebandStream) {
        output.writeBool(true);
        output.writeNativeHandle(sidebandStream->handle());
    } else {
        output.writeBool(false);
    }

    memcpy(output.writeInplace(16 * sizeof(float)),
           colorTransform.asArray(), 16 * sizeof(float));

    if (output.writeVectorSize(listenerCallbacks) == NO_ERROR) {
        for (const auto& [listener, callbackIds] : listenerCallbacks) {
            output.writeStrongBinder(IInterface::asBinder(listener));
            output.writeInt64Vector(callbackIds);
        }
    }

    return NO_ERROR;
}

status_t layer_state_t::read(const Parcel& input)
{
    surface = input.readStrongBinder();
    what = input.readUint32();
    x = input.readFloat();
    y = input.readFloat();
    z = input.readInt32();
    w = input.readUint32();
    h = input.readUint32();
    layerStack = input.readUint32();
    alpha = input.readFloat();
    flags = static_cast<uint8_t>(input.readUint32());
    mask = static_cast<uint8_t>(input.readUint32());
    const void* matrix_data = input.readInplace(sizeof(layer_state_t::matrix22_t));
    if (matrix_data) {
        matrix = *reinterpret_cast<layer_state_t::matrix22_t const *>(matrix_data);
    } else {
        return BAD_VALUE;
    }
    input.read(crop_legacy);
    barrierHandle_legacy = input.readStrongBinder();
    reparentHandle = input.readStrongBinder();
    frameNumber_legacy = input.readUint64();
    overrideScalingMode = input.readInt32();
    barrierGbp_legacy = interface_cast<IGraphicBufferProducer>(input.readStrongBinder());
    relativeLayerHandle = input.readStrongBinder();
    parentHandleForChild = input.readStrongBinder();
    color.r = input.readFloat();
    color.g = input.readFloat();
    color.b = input.readFloat();

#ifndef NO_INPUT
    inputInfo = InputWindowInfo::read(input);
#endif

    input.read(transparentRegion);
    transform = input.readUint32();
    transformToDisplayInverse = input.readBool();
    input.read(crop);
    buffer = new GraphicBuffer();
    if (input.readBool()) {
        input.read(*buffer);
    }
    acquireFence = new Fence();
    if (input.readBool()) {
        input.read(*acquireFence);
    }
    dataspace = static_cast<ui::Dataspace>(input.readUint32());
    input.read(hdrMetadata);
    input.read(surfaceDamageRegion);
    api = input.readInt32();
    if (input.readBool()) {
        sidebandStream = NativeHandle::create(input.readNativeHandle(), true);
    }

    colorTransform = mat4(static_cast<const float*>(input.readInplace(16 * sizeof(float))));

    int32_t listenersSize = input.readInt32();
    for (int32_t i = 0; i < listenersSize; i++) {
        auto listener = interface_cast<ITransactionCompletedListener>(input.readStrongBinder());
        std::vector<CallbackId> callbackIds;
        input.readInt64Vector(&callbackIds);
        listenerCallbacks.emplace_back(listener, callbackIds);
    }

    return NO_ERROR;
}

status_t ComposerState::write(Parcel& output) const {
    output.writeStrongBinder(IInterface::asBinder(client));
    return state.write(output);
}

status_t ComposerState::read(const Parcel& input) {
    client = interface_cast<ISurfaceComposerClient>(input.readStrongBinder());
    return state.read(input);
}


DisplayState::DisplayState() :
    what(0),
    layerStack(0),
    orientation(eOrientationDefault),
    viewport(Rect::EMPTY_RECT),
    frame(Rect::EMPTY_RECT),
    width(0),
    height(0) {
}

status_t DisplayState::write(Parcel& output) const {
    output.writeStrongBinder(token);
    output.writeStrongBinder(IInterface::asBinder(surface));
    output.writeUint32(what);
    output.writeUint32(layerStack);
    output.writeUint32(orientation);
    output.write(viewport);
    output.write(frame);
    output.writeUint32(width);
    output.writeUint32(height);
    return NO_ERROR;
}

status_t DisplayState::read(const Parcel& input) {
    token = input.readStrongBinder();
    surface = interface_cast<IGraphicBufferProducer>(input.readStrongBinder());
    what = input.readUint32();
    layerStack = input.readUint32();
    orientation = input.readUint32();
    input.read(viewport);
    input.read(frame);
    width = input.readUint32();
    height = input.readUint32();
    return NO_ERROR;
}

void DisplayState::merge(const DisplayState& other) {
    if (other.what & eSurfaceChanged) {
        what |= eSurfaceChanged;
        surface = other.surface;
    }
    if (other.what & eLayerStackChanged) {
        what |= eLayerStackChanged;
        layerStack = other.layerStack;
    }
    if (other.what & eDisplayProjectionChanged) {
        what |= eDisplayProjectionChanged;
        orientation = other.orientation;
        viewport = other.viewport;
        frame = other.frame;
    }
    if (other.what & eDisplaySizeChanged) {
        what |= eDisplaySizeChanged;
        width = other.width;
        height = other.height;
    }
}

void layer_state_t::merge(const layer_state_t& other) {
    if (other.what & ePositionChanged) {
        what |= ePositionChanged;
        x = other.x;
        y = other.y;
    }
    if (other.what & eLayerChanged) {
        what |= eLayerChanged;
        z = other.z;
    }
    if (other.what & eSizeChanged) {
        what |= eSizeChanged;
        w = other.w;
        h = other.h;
    }
    if (other.what & eAlphaChanged) {
        what |= eAlphaChanged;
        alpha = other.alpha;
    }
    if (other.what & eMatrixChanged) {
        what |= eMatrixChanged;
        matrix = other.matrix;
    }
    if (other.what & eTransparentRegionChanged) {
        what |= eTransparentRegionChanged;
        transparentRegion = other.transparentRegion;
    }
    if (other.what & eFlagsChanged) {
        what |= eFlagsChanged;
        flags = other.flags;
        mask = other.mask;
    }
    if (other.what & eLayerStackChanged) {
        what |= eLayerStackChanged;
        layerStack = other.layerStack;
    }
    if (other.what & eCropChanged_legacy) {
        what |= eCropChanged_legacy;
        crop_legacy = other.crop_legacy;
    }
    if (other.what & eDeferTransaction_legacy) {
        what |= eDeferTransaction_legacy;
        barrierHandle_legacy = other.barrierHandle_legacy;
        barrierGbp_legacy = other.barrierGbp_legacy;
        frameNumber_legacy = other.frameNumber_legacy;
    }
    if (other.what & eOverrideScalingModeChanged) {
        what |= eOverrideScalingModeChanged;
        overrideScalingMode = other.overrideScalingMode;
    }
    if (other.what & eGeometryAppliesWithResize) {
        what |= eGeometryAppliesWithResize;
    }
    if (other.what & eReparentChildren) {
        what |= eReparentChildren;
        reparentHandle = other.reparentHandle;
    }
    if (other.what & eDetachChildren) {
        what |= eDetachChildren;
    }
    if (other.what & eRelativeLayerChanged) {
        what |= eRelativeLayerChanged;
        z = other.z;
        relativeLayerHandle = other.relativeLayerHandle;
    }
    if (other.what & eReparent) {
        what |= eReparent;
        parentHandleForChild = other.parentHandleForChild;
    }
    if (other.what & eDestroySurface) {
        what |= eDestroySurface;
    }
    if (other.what & eTransformChanged) {
        what |= eTransformChanged;
        transform = other.transform;
    }
    if (other.what & eTransformToDisplayInverseChanged) {
        what |= eTransformToDisplayInverseChanged;
        transformToDisplayInverse = other.transformToDisplayInverse;
    }
    if (other.what & eCropChanged) {
        what |= eCropChanged;
        crop = other.crop;
    }
    if (other.what & eBufferChanged) {
        what |= eBufferChanged;
        buffer = other.buffer;
    }
    if (other.what & eAcquireFenceChanged) {
        what |= eAcquireFenceChanged;
        acquireFence = other.acquireFence;
    }
    if (other.what & eDataspaceChanged) {
        what |= eDataspaceChanged;
        dataspace = other.dataspace;
    }
    if (other.what & eHdrMetadataChanged) {
        what |= eHdrMetadataChanged;
        hdrMetadata = other.hdrMetadata;
    }
    if (other.what & eSurfaceDamageRegionChanged) {
        what |= eSurfaceDamageRegionChanged;
        surfaceDamageRegion = other.surfaceDamageRegion;
    }
    if (other.what & eApiChanged) {
        what |= eApiChanged;
        api = other.api;
    }
    if (other.what & eSidebandStreamChanged) {
        what |= eSidebandStreamChanged;
        sidebandStream = other.sidebandStream;
    }
    if (other.what & eColorTransformChanged) {
        what |= eColorTransformChanged;
        colorTransform = other.colorTransform;
    }
    if (other.what & eListenerCallbacksChanged) {
        what |= eListenerCallbacksChanged;
        listenerCallbacks = other.listenerCallbacks;
    }

#ifndef NO_INPUT
    if (other.what & eInputInfoChanged) {
        what |= eInputInfoChanged;
        inputInfo = other.inputInfo;
    }
#endif

    if ((other.what & what) != other.what) {
        ALOGE("Unmerged SurfaceComposer Transaction properties. LayerState::merge needs updating? "
              "other.what=0x%X what=0x%X",
              other.what, what);
    }
}

}; // namespace android
