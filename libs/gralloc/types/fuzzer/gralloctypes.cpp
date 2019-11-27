/*
 * Copyright (C) 2019 The Android Open Source Project
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
#define FUZZ_LOG_TAG "gralloctypes"

#include <cstdint>

#include <aidl/android/hardware/graphics/common/BlendMode.h>
#include <aidl/android/hardware/graphics/common/Dataspace.h>
#include <aidl/android/hardware/graphics/common/ExtendableType.h>
#include <aidl/android/hardware/graphics/common/PlaneLayout.h>
#include <android/hardware/graphics/common/1.2/types.h>
#include <gralloctypes/Gralloc4.h>
#include <hidl/HidlSupport.h>
#include <utils/Errors.h>

#include "gralloctypes.h"
#include "util.h"

using ::android::status_t;

#define GRALLOCTYPES_DECODE(T, FUNC) \
    [] (const ::android::hardware::hidl_vec<uint8_t>& vec, uint8_t /*data*/) {\
        FUZZ_LOG() << "about to read " #T " using " #FUNC;\
        T t;\
        status_t err = FUNC(vec, &t);\
        (void) err;\
        FUZZ_LOG() << #T " done " /* << "err: " << err*/;\
    }


// clang-format off
std::vector<GrallocTypesDecode> GRALLOCTYPES_DECODE_FUNCTIONS {
    GRALLOCTYPES_DECODE(uint64_t, ::android::gralloc4::decodeBufferId),
    GRALLOCTYPES_DECODE(std::string, ::android::gralloc4::decodeName),
    GRALLOCTYPES_DECODE(uint64_t, ::android::gralloc4::decodeWidth),
    GRALLOCTYPES_DECODE(uint64_t, ::android::gralloc4::decodeHeight),
    GRALLOCTYPES_DECODE(uint64_t, ::android::gralloc4::decodeLayerCount),
    GRALLOCTYPES_DECODE(::android::hardware::graphics::common::V1_2::PixelFormat, ::android::gralloc4::decodePixelFormatRequested),
    GRALLOCTYPES_DECODE(uint32_t, ::android::gralloc4::decodePixelFormatFourCC),
    GRALLOCTYPES_DECODE(uint64_t, ::android::gralloc4::decodePixelFormatModifier),
    GRALLOCTYPES_DECODE(uint64_t, ::android::gralloc4::decodeUsage),
    GRALLOCTYPES_DECODE(uint64_t, ::android::gralloc4::decodeAllocationSize),
    GRALLOCTYPES_DECODE(uint64_t, ::android::gralloc4::decodeProtectedContent),
    GRALLOCTYPES_DECODE(aidl::android::hardware::graphics::common::ExtendableType, ::android::gralloc4::decodeCompression),
    GRALLOCTYPES_DECODE(aidl::android::hardware::graphics::common::ExtendableType, ::android::gralloc4::decodeInterlaced),
    GRALLOCTYPES_DECODE(aidl::android::hardware::graphics::common::ExtendableType, ::android::gralloc4::decodeChromaSiting),
    GRALLOCTYPES_DECODE(std::vector<aidl::android::hardware::graphics::common::PlaneLayout>, ::android::gralloc4::decodePlaneLayouts),
    GRALLOCTYPES_DECODE(aidl::android::hardware::graphics::common::Dataspace, ::android::gralloc4::decodeDataspace),
    GRALLOCTYPES_DECODE(aidl::android::hardware::graphics::common::BlendMode, ::android::gralloc4::decodeBlendMode),
};
// clang-format on
