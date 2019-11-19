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

#include <cstring>
#include <cinttypes>
#include <limits>

#include <hidl/HidlSupport.h>
#include <log/log.h>

#include "gralloctypes/Gralloc4.h"

using android::hardware::hidl_vec;

using ::aidl::android::hardware::graphics::common::BlendMode;
using ::aidl::android::hardware::graphics::common::Dataspace;
using ::aidl::android::hardware::graphics::common::PlaneLayout;
using ::aidl::android::hardware::graphics::common::PlaneLayoutComponent;
using ::aidl::android::hardware::graphics::common::ExtendableType;
using ::aidl::android::hardware::graphics::common::Rect;
using ::aidl::android::hardware::graphics::common::StandardMetadataType;

using MetadataType = ::android::hardware::graphics::mapper::V4_0::IMapper::MetadataType;

namespace android {

namespace gralloc4 {

bool isStandardMetadataType(const MetadataType& metadataType) {
    return !std::strncmp(metadataType.name.c_str(), GRALLOC4_STANDARD_METADATA_TYPE, metadataType.name.size());
}

StandardMetadataType getStandardMetadataTypeValue(const MetadataType& metadataType) {
    return static_cast<StandardMetadataType>(metadataType.value);
}

status_t copyToHidlVec(const std::vector<uint8_t>& vec, hidl_vec<uint8_t>* hidlVec) {
    if (!hidlVec) {
        return BAD_VALUE;
    }

    hidlVec->setToExternal(const_cast<uint8_t*>(vec.data()), vec.size(), false /*shouldOwn*/);

    return NO_ERROR;
}

template <class T>
status_t encodeInteger(T input, std::vector<uint8_t>* output) {
    static_assert(std::is_same<T, uint32_t>::value ||
                  std::is_same<T, int32_t>::value ||
                  std::is_same<T, uint64_t>::value ||
                  std::is_same<T, int64_t>::value);
    if (!output) {
        return BAD_VALUE;
    }

    size_t outputOffset = output->size();
    size_t size = sizeof(input);

    if (outputOffset > UINT_MAX - size) {
        return BAD_VALUE;
    }
    output->resize(size + outputOffset);

    uint8_t* tmp = reinterpret_cast<uint8_t*>(&input);
    std::copy(tmp, tmp + size, output->data() + outputOffset);

    return NO_ERROR;
}

template <class T>
status_t decodeInteger(const hidl_vec<uint8_t>& input, T* output, size_t* inputOffset = nullptr) {
    if (!output) {
        return BAD_VALUE;
    }

    size_t offset = (inputOffset)? *inputOffset: 0;
    if (offset >= input.size()) {
        return BAD_VALUE;
    }
    size_t inputMaxSize = input.size() - offset;
    size_t outputSize = sizeof(*output);

    if (inputMaxSize < outputSize) {
        return BAD_VALUE;
    }

    uint8_t* tmp = reinterpret_cast<uint8_t*>(output);
    const uint8_t* data = input.data() + offset;
    std::copy(data, data + outputSize, tmp);

    if (inputOffset) {
        *inputOffset += outputSize;
    }

    return NO_ERROR;
}

status_t encodeString(const std::string& input, std::vector<uint8_t>* output) {
    if (!output) {
        return BAD_VALUE;
    }

    status_t err = encodeInteger<int64_t>(input.size(), output);
    if (err) {
        return err;
    }

    size_t outputOffset = output->size();
    size_t size = input.size();
    output->resize(size + outputOffset);

    std::copy(input.c_str(), input.c_str() + size, output->data() + outputOffset);

    return NO_ERROR;
}

status_t decodeString(const hidl_vec<uint8_t>& input, std::string* output, size_t* inputOffset = nullptr) {
    if (!output) {
        return BAD_VALUE;
    }

    int64_t size = 0;
    status_t err = decodeInteger<int64_t>(input, &size, inputOffset);
    if (err || size < 0) {
        return err;
    }

    size_t offset = (inputOffset)? *inputOffset + sizeof(size): sizeof(size);
    if ((offset > UINT_MAX - size) || (offset + size > input.size())) {
        return BAD_VALUE;
    }

    auto data = input.data() + offset;
    output->assign(data, data + size);

    if (inputOffset) {
        *inputOffset += size;
    }

    return NO_ERROR;
}

status_t encodeExtendableType(const ExtendableType& input, std::vector<uint8_t>* output) {
    status_t err = encodeString(input.name, output);
    if (err) {
        return err;
    }

    return encodeInteger<int64_t>(input.value, output);
}

status_t decodeExtendableType(const hidl_vec<uint8_t>& input, ExtendableType* output, size_t* inputOffset = nullptr) {
    status_t err = decodeString(input, &output->name, inputOffset);
    if (err) {
        return err;
    }

    err = decodeInteger<int64_t>(input, &output->value, inputOffset);
    if (err) {
        output->name.clear();
        return err;
    }

    return NO_ERROR;
}

status_t encodeRect(const Rect& input, std::vector<uint8_t>* output) {
    status_t err = encodeInteger<int32_t>(static_cast<int32_t>(input.left), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int32_t>(static_cast<int32_t>(input.top), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int32_t>(static_cast<int32_t>(input.right), output);
    if (err) {
        return err;
    }
    return encodeInteger<int32_t>(static_cast<int32_t>(input.bottom), output);
}

status_t decodeRect(const hidl_vec<uint8_t>& input, Rect* output, size_t* inputOffset = nullptr) {
    status_t err = decodeInteger<int32_t>(input, &output->left, inputOffset);
    if (err) {
        return err;
    }
    err = decodeInteger<int32_t>(input, &output->top, inputOffset);
    if (err) {
        return err;
    }
    err = decodeInteger<int32_t>(input, &output->right, inputOffset);
    if (err) {
        return err;
    }
    return decodeInteger<int32_t>(input, &output->bottom, inputOffset);
}

status_t encodePlaneLayoutComponent(const PlaneLayoutComponent& input, std::vector<uint8_t>* output) {
    if (!output) {
        return BAD_VALUE;
    }

    status_t err = encodeExtendableType(input.type, output);
    if (err) {
        return err;
    }
    err = encodeInteger<int64_t>(static_cast<int64_t>(input.offsetInBits), output);
    if (err) {
        return err;
    }
    return encodeInteger<int64_t>(static_cast<int64_t>(input.sizeInBits), output);
}

status_t decodePlaneLayoutComponent(const hidl_vec<uint8_t>& input, PlaneLayoutComponent* output, size_t* inputOffset = nullptr) {
    if (!output) {
        return BAD_VALUE;
    }

    status_t err = decodeExtendableType(input, &output->type, inputOffset);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->offsetInBits, inputOffset);
    if (err) {
        return err;
    }
    return decodeInteger<int64_t>(input, &output->sizeInBits, inputOffset);
}

status_t encodePlaneLayoutComponents(const std::vector<PlaneLayoutComponent>& input, std::vector<uint8_t>* output) {
    if (!output) {
        return BAD_VALUE;
    }

    status_t err = encodeInteger<int64_t>(static_cast<int64_t>(input.size()), output);
    if (err) {
        return err;
    }

    for (const auto& planeLayoutComponent: input) {
        err = encodePlaneLayoutComponent(planeLayoutComponent, output);
        if (err) {
            return err;
        }
    }

    return NO_ERROR;
}

status_t decodePlaneLayoutComponents(const hidl_vec<uint8_t>& input, std::vector<PlaneLayoutComponent>* output, size_t* inputOffset = nullptr) {
    if (!output) {
        return BAD_VALUE;
    }

    int64_t size = 0;
    status_t err = decodeInteger<int64_t>(input, &size, inputOffset);
    if (err || size < 0) {
        return err;
    }

    for (int i = 0; i < size; i++) {
        output->emplace_back();
        err = decodePlaneLayoutComponent(input, &output->back(), inputOffset);
        if (err) {
            return err;
        }
    }
    return NO_ERROR;
}

status_t encodePlaneLayout(const PlaneLayout& input, std::vector<uint8_t>* output) {
    if (!output) {
        return BAD_VALUE;
    }

    status_t err = encodePlaneLayoutComponents(input.components, output);
    if (err) {
        return err;
    }

    err = encodeInteger<int64_t>(static_cast<int32_t>(input.offsetInBytes), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int64_t>(static_cast<int32_t>(input.sampleIncrementInBits), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int64_t>(static_cast<int32_t>(input.strideInBytes), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int64_t>(static_cast<int32_t>(input.widthInSamples), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int64_t>(static_cast<int32_t>(input.heightInSamples), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int64_t>(static_cast<int32_t>(input.totalSizeInBytes), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int64_t>(static_cast<int32_t>(input.horizontalSubsampling), output);
    if (err) {
        return err;
    }
    err = encodeInteger<int64_t>(static_cast<int32_t>(input.verticalSubsampling), output);
    if (err) {
        return err;
    }

    return encodeRect(input.crop, output);
}

status_t decodePlaneLayout(const hidl_vec<uint8_t>& input, PlaneLayout* output, size_t* inputOffset = nullptr) {
    if (!output) {
        return BAD_VALUE;
    }

    status_t err = decodePlaneLayoutComponents(input, &output->components, inputOffset);
    if (err) {
        return err;
    }

    err = decodeInteger<int64_t>(input, &output->offsetInBytes, inputOffset);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->sampleIncrementInBits, inputOffset);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->strideInBytes, inputOffset);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->widthInSamples, inputOffset);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->heightInSamples, inputOffset);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->totalSizeInBytes, inputOffset);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->horizontalSubsampling, inputOffset);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->verticalSubsampling, inputOffset);
    if (err) {
        return err;
    }

    return decodeRect(input, &output->crop, inputOffset);
}

status_t encodePlaneLayouts(const std::vector<PlaneLayout>& planeLayouts, hidl_vec<uint8_t>* outPlaneLayouts) {
    if (!outPlaneLayouts) {
        return BAD_VALUE;
    }

    std::vector<uint8_t> tmpOutPlaneLayouts;

    status_t err = encodeInteger<int64_t>(static_cast<int64_t>(planeLayouts.size()), &tmpOutPlaneLayouts);
    if (err) {
        return err;
    }

    for (const auto& planeLayout : planeLayouts) {
        err = encodePlaneLayout(planeLayout, &tmpOutPlaneLayouts);
        if (err) {
            return err;
        }
    }

    return copyToHidlVec(tmpOutPlaneLayouts, outPlaneLayouts);
}

status_t decodePlaneLayouts(const hidl_vec<uint8_t>& planeLayouts, std::vector<PlaneLayout>* outPlaneLayouts) {
    if (!outPlaneLayouts) {
        return BAD_VALUE;
    }

    size_t offset = 0;
    int64_t size = 0;
    status_t err = decodeInteger<int64_t>(planeLayouts, &size, &offset);
    if (err || size < 0) {
        return err;
    }

    for (size_t i = 0; i < size; i++) {
        outPlaneLayouts->emplace_back();
        err = decodePlaneLayout(planeLayouts, &outPlaneLayouts->back(), &offset);
        if (err) {
            outPlaneLayouts->resize(0);
            return err;
        }
    }
    if (offset < planeLayouts.size()) {
        return BAD_VALUE;
    }

    return NO_ERROR;
}

status_t encodeBufferId(uint64_t bufferId, hidl_vec<uint8_t>* outBufferId) {
    std::vector<uint8_t> tmpOutBufferId;
    status_t err = encodeInteger<uint64_t>(bufferId, &tmpOutBufferId);
    if (err) {
        return err;
    }
    return copyToHidlVec(tmpOutBufferId, outBufferId);
}

status_t decodeBufferId(const hidl_vec<uint8_t>& bufferId, uint64_t* outBufferId) {
    return decodeInteger<uint64_t>(bufferId, outBufferId);
}

status_t encodeName(const std::string& name, hidl_vec<uint8_t>* outName) {
    std::vector<uint8_t> tmpOutName;
    status_t err = encodeString(name, &tmpOutName);
    if (err) {
        return err;
    }
    return copyToHidlVec(tmpOutName, outName);
}

status_t decodeName(const hidl_vec<uint8_t>& name, std::string* outName) {
    return decodeString(name, outName);
}

status_t encodeWidth(uint64_t width, hidl_vec<uint8_t>* outWidth) {
    std::vector<uint8_t> tmpOutWidth;
    status_t err = encodeInteger<uint64_t>(width, &tmpOutWidth);
    if (err) {
        return err;
    }
    return copyToHidlVec(tmpOutWidth, outWidth);
}

status_t decodeWidth(const hidl_vec<uint8_t>& width, uint64_t* outWidth) {
    return decodeInteger<uint64_t>(width, outWidth);
}

status_t encodeHeight(uint64_t height, hidl_vec<uint8_t>* outHeight) {
    std::vector<uint8_t> tmpOutHeight;
    status_t err = encodeInteger<uint64_t>(height, &tmpOutHeight);
    if (err) {
        return err;
    }
    return copyToHidlVec(tmpOutHeight, outHeight);
}

status_t decodeHeight(const hidl_vec<uint8_t>& height, uint64_t* outHeight) {
    return decodeInteger<uint64_t>(height, outHeight);
}

status_t encodeLayerCount(uint64_t layerCount, hidl_vec<uint8_t>* outLayerCount) {
    std::vector<uint8_t> tmpOutLayerCount;
    status_t err = encodeInteger<uint64_t>(layerCount, &tmpOutLayerCount);
    if (err) {
        return err;
    }
    return copyToHidlVec(tmpOutLayerCount, outLayerCount);
}

status_t decodeLayerCount(const hidl_vec<uint8_t>& layerCount, uint64_t* outLayerCount) {
    return decodeInteger<uint64_t>(layerCount, outLayerCount);
}

status_t encodePixelFormatRequested(const hardware::graphics::common::V1_2::PixelFormat& pixelFormatRequested, hidl_vec<uint8_t>* outPixelFormatRequested) {
    std::vector<uint8_t> tmpOutPixelFormatRequested;
    status_t err = encodeInteger<int32_t>(static_cast<int32_t>(pixelFormatRequested), &tmpOutPixelFormatRequested);
    if (err) {
        return err;
    }
    return copyToHidlVec(tmpOutPixelFormatRequested, outPixelFormatRequested);
}

status_t decodePixelFormatRequested(const hidl_vec<uint8_t>& pixelFormatRequested, hardware::graphics::common::V1_2::PixelFormat* outPixelFormatRequested) {
    return decodeInteger<int32_t>(pixelFormatRequested, reinterpret_cast<int32_t*>(outPixelFormatRequested));
}

status_t encodePixelFormatFourCC(uint32_t pixelFormatFourCC, hidl_vec<uint8_t>* outPixelFormatFourCC) {
    std::vector<uint8_t> tmpOutPixelFormatFourCC;
    status_t err = encodeInteger<uint32_t>(pixelFormatFourCC, &tmpOutPixelFormatFourCC);
    if (err) {
        return err;
    }
    return copyToHidlVec(tmpOutPixelFormatFourCC, outPixelFormatFourCC);
}

status_t decodePixelFormatFourCC(const hidl_vec<uint8_t>& pixelFormatFourCC, uint32_t* outPixelFormatFourCC) {
    return decodeInteger<uint32_t>(pixelFormatFourCC, outPixelFormatFourCC);
}

status_t encodePixelFormatModifier(uint64_t pixelFormatModifier, hidl_vec<uint8_t>* outPixelFormatModifier) {
    std::vector<uint8_t> tmpOutPixelFormatModifier;
    status_t err = encodeInteger<uint64_t>(pixelFormatModifier, &tmpOutPixelFormatModifier);
    if (err) {
        return err;
    }
    return copyToHidlVec(tmpOutPixelFormatModifier, outPixelFormatModifier);
}

status_t decodePixelFormatModifier(const hidl_vec<uint8_t>& pixelFormatModifier, uint64_t* outPixelFormatModifier) {
    return decodeInteger<uint64_t>(pixelFormatModifier, outPixelFormatModifier);
}

status_t encodeUsage(uint64_t usage, hidl_vec<uint8_t>* outUsage) {
    std::vector<uint8_t> tmpOutUsage;
    status_t err = encodeInteger<uint64_t>(usage, &tmpOutUsage);
    if (err) {
        return err;
    }
    return copyToHidlVec(tmpOutUsage, outUsage);
}

status_t decodeUsage(const hidl_vec<uint8_t>& usage, uint64_t* outUsage) {
    return decodeInteger<uint64_t>(usage, outUsage);
}

status_t encodeAllocationSize(uint64_t allocationSize, hidl_vec<uint8_t>* outAllocationSize) {
    std::vector<uint8_t> tmpOutAllocationSize;
    status_t err = encodeInteger<uint64_t>(allocationSize, &tmpOutAllocationSize);
    if (err) {
        return err;
    }
    return copyToHidlVec(tmpOutAllocationSize, outAllocationSize);
}

status_t decodeAllocationSize(const hidl_vec<uint8_t>& allocationSize, uint64_t* outAllocationSize) {
    return decodeInteger<uint64_t>(allocationSize, outAllocationSize);
}

status_t encodeProtectedContent(uint64_t protectedContent, hidl_vec<uint8_t>* outProtectedContent) {
    std::vector<uint8_t> tmpOutProtectedContent;
    status_t err = encodeInteger<uint64_t>(protectedContent, &tmpOutProtectedContent);
    if (err) {
        return err;
    }
    return copyToHidlVec(tmpOutProtectedContent, outProtectedContent);
}

status_t decodeProtectedContent(const hidl_vec<uint8_t>& protectedContent, uint64_t* outProtectedContent) {
    return decodeInteger<uint64_t>(protectedContent, outProtectedContent);
}

status_t encodeCompression(const ExtendableType& compression, hidl_vec<uint8_t>* outCompression) {
    std::vector<uint8_t> tmpOutCompression;
    status_t err = encodeExtendableType(compression, &tmpOutCompression);
    if (err) {
        return err;
    }
    return copyToHidlVec(tmpOutCompression, outCompression);
}

status_t decodeCompression(const hidl_vec<uint8_t>& compression, ExtendableType* outCompression) {
    return decodeExtendableType(compression, outCompression);
}

status_t encodeInterlaced(const ExtendableType& interlaced, hidl_vec<uint8_t>* outInterlaced) {
    std::vector<uint8_t> tmpOutInterlaced;
    status_t err = encodeExtendableType(interlaced, &tmpOutInterlaced);
    if (err) {
        return err;
    }
    return copyToHidlVec(tmpOutInterlaced, outInterlaced);
}

status_t decodeInterlaced(const hidl_vec<uint8_t>& interlaced, ExtendableType* outInterlaced) {
    return decodeExtendableType(interlaced, outInterlaced);
}

status_t encodeChromaSiting(const ExtendableType& chromaSiting, hidl_vec<uint8_t>* outChromaSiting) {
    std::vector<uint8_t> tmpOutChromaSiting;
    status_t err = encodeExtendableType(chromaSiting, &tmpOutChromaSiting);
    if (err) {
        return err;
    }
    return copyToHidlVec(tmpOutChromaSiting, outChromaSiting);
}

status_t decodeChromaSiting(const hidl_vec<uint8_t>& chromaSiting, ExtendableType* outChromaSiting) {
    return decodeExtendableType(chromaSiting, outChromaSiting);
}

status_t encodeDataspace(const Dataspace& dataspace, hidl_vec<uint8_t>* outDataspace) {
    std::vector<uint8_t> tmpOutDataspace;
    status_t err = encodeInteger<int32_t>(static_cast<int32_t>(dataspace), &tmpOutDataspace);
    if (err) {
        return err;
    }
    return copyToHidlVec(tmpOutDataspace, outDataspace);
}

status_t decodeDataspace(const hidl_vec<uint8_t>& dataspace, Dataspace* outDataspace) {
    return decodeInteger<int32_t>(dataspace, reinterpret_cast<int32_t*>(outDataspace));
}

status_t encodeBlendMode(const BlendMode& blendMode, hidl_vec<uint8_t>* outBlendMode) {
    std::vector<uint8_t> tmpOutBlendMode;
    status_t err = encodeInteger<int32_t>(static_cast<int32_t>(blendMode), &tmpOutBlendMode);
    if (err) {
        return err;
    }
    return copyToHidlVec(tmpOutBlendMode, outBlendMode);
}

status_t decodeBlendMode(const hidl_vec<uint8_t>& blendMode, BlendMode* outBlendMode) {
    return decodeInteger<int32_t>(blendMode, reinterpret_cast<int32_t*>(outBlendMode));
}

} // namespace gralloc4

} // namespace android
