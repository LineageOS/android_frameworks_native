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
#pragma once

#include <layerproto/TransactionProto.h>
#include <utils/RefBase.h>

#include "TransactionState.h"

namespace android::surfaceflinger {

struct TracingLayerCreationArgs {
    int32_t layerId;
    std::string name;
    uint32_t flags;
    int32_t parentId;
};

struct TracingLayerState : layer_state_t {
    uint64_t bufferId;
    uint32_t bufferHeight;
    uint32_t bufferWidth;
    bool hasSidebandStream;
    int32_t parentId;
    int32_t relativeParentId;
    int32_t inputCropId;
    std::string name;
    uint32_t layerCreationFlags;
};

class TransactionProtoParser {
public:
    typedef std::function<sp<IBinder>(int32_t)> LayerIdToHandleFn;
    typedef std::function<sp<IBinder>(int32_t)> DisplayIdToHandleFn;
    typedef std::function<int32_t(const sp<IBinder>&)> LayerHandleToIdFn;
    typedef std::function<int32_t(const sp<IBinder>&)> DisplayHandleToIdFn;

    static proto::TransactionState toProto(const TransactionState&, LayerHandleToIdFn getLayerIdFn,
                                           DisplayHandleToIdFn getDisplayIdFn);
    static proto::TransactionState toProto(
            const std::unordered_map<int32_t /* layerId */, TracingLayerState>);

    static proto::LayerCreationArgs toProto(const TracingLayerCreationArgs& args);

    static TransactionState fromProto(const proto::TransactionState&,
                                      LayerIdToHandleFn getLayerHandleFn,
                                      DisplayIdToHandleFn getDisplayHandleFn);
    static void fromProto(const proto::LayerState&, LayerIdToHandleFn getLayerHandleFn,
                          TracingLayerState& outState);
    static void fromProto(const proto::LayerCreationArgs&, TracingLayerCreationArgs& outArgs);

private:
    static proto::LayerState toProto(const layer_state_t&, LayerHandleToIdFn getLayerId);
    static proto::DisplayState toProto(const DisplayState&, DisplayHandleToIdFn getDisplayId);
    static void fromProto(const proto::LayerState&, LayerIdToHandleFn getLayerHandle,
                          layer_state_t& out);
    static DisplayState fromProto(const proto::DisplayState&, DisplayIdToHandleFn getDisplayHandle);
};

} // namespace android::surfaceflinger