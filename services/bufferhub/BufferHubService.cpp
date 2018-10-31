/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <bufferhub/BufferHubService.h>

namespace android {
namespace frameworks {
namespace bufferhub {
namespace V1_0 {
namespace implementation {

using ::android::status_t;
using ::android::hardware::Void;

Return<void> BufferHubService::allocateBuffer(const HardwareBufferDescription& /*description*/,
                                              allocateBuffer_cb /*hidl_cb*/) {
    return Void();
}

Return<sp<IBase>> BufferHubService::importBuffer(const hidl_handle& /*nativeHandle*/) {
    return nullptr;
}

} // namespace implementation
} // namespace V1_0
} // namespace bufferhub
} // namespace frameworks
} // namespace android
