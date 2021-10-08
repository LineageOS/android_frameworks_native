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
class TransactionProtoParser {
public:
    static proto::TransactionState toProto(
            const TransactionState&, std::function<int32_t(const sp<IBinder>&)> getLayerIdFn,
            std::function<int32_t(const sp<IBinder>&)> getDisplayIdFn);
    static TransactionState fromProto(const proto::TransactionState&,
                                      std::function<sp<IBinder>(int32_t)> getLayerHandleFn,
                                      std::function<sp<IBinder>(int32_t)> getDisplayHandleFn);

private:
    static proto::LayerState toProto(const layer_state_t&,
                                     std::function<int32_t(const sp<IBinder>&)> getLayerId);
    static proto::DisplayState toProto(const DisplayState&,
                                       std::function<int32_t(const sp<IBinder>&)> getDisplayId);
    static layer_state_t fromProto(const proto::LayerState&,
                                   std::function<sp<IBinder>(int32_t)> getLayerHandle);
    static DisplayState fromProto(const proto::DisplayState&,
                                  std::function<sp<IBinder>(int32_t)> getDisplayHandle);
};

} // namespace android::surfaceflinger