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

#include <gui/fake/BufferData.h>
#include <layerproto/TransactionProto.h>
#include <utils/RefBase.h>

#include "FrontEnd/DisplayInfo.h"
#include "FrontEnd/LayerCreationArgs.h"
#include "TransactionState.h"

namespace android::surfaceflinger {

struct TracingLayerState : ResolvedComposerState {
    bool hasSidebandStream;
    LayerCreationArgs args;
};

class TransactionProtoParser {
public:
    // Utility class to map handles to ids and buffers to buffer properties without pulling
    // in SurfaceFlinger dependencies.
    class FlingerDataMapper {
    public:
        virtual ~FlingerDataMapper() = default;
        virtual sp<IBinder> getDisplayHandle(int32_t /* displayId */) const { return nullptr; }
        virtual int32_t getDisplayId(const sp<IBinder>& /* displayHandle */) const { return -1; }
    };

    TransactionProtoParser(std::unique_ptr<FlingerDataMapper> provider)
          : mMapper(std::move(provider)) {}

    proto::TransactionState toProto(const TransactionState&);
    proto::TransactionState toProto(const std::map<uint32_t /* layerId */, TracingLayerState>&);
    proto::LayerCreationArgs toProto(const LayerCreationArgs& args);
    proto::LayerState toProto(const ResolvedComposerState&);
    static proto::DisplayInfo toProto(const frontend::DisplayInfo&, uint32_t layerStack);

    TransactionState fromProto(const proto::TransactionState&);
    void mergeFromProto(const proto::LayerState&, TracingLayerState& outState);
    void fromProto(const proto::LayerCreationArgs&, LayerCreationArgs& outArgs);
    std::unique_ptr<FlingerDataMapper> mMapper;
    static frontend::DisplayInfo fromProto(const proto::DisplayInfo&);
    static void fromProto(const google::protobuf::RepeatedPtrField<proto::DisplayInfo>&,
                          frontend::DisplayInfos& outDisplayInfos);

private:
    proto::DisplayState toProto(const DisplayState&);
    void fromProto(const proto::LayerState&, ResolvedComposerState& out);
    DisplayState fromProto(const proto::DisplayState&);

};

} // namespace android::surfaceflinger
