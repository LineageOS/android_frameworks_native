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

static inline bool hasAdditionOverflow(size_t a, size_t b) {
    return a > SIZE_MAX - b;
}

/**
 * OutputHidlVec represents the hidl_vec that is outputed when a type is encoded into a byte stream.
 * This class is used to track the current state of a hidl_vec as it is filled with the encoded
 * byte stream.
 *
 * This type is needed because hidl_vec's resize() allocates a new backing array every time.
 * This type does not need an copies and only needs one resize operation.
 */
class OutputHidlVec {
public:
    OutputHidlVec(hidl_vec<uint8_t>* vec)
        : mVec(vec) {}

    status_t resize() {
        if (!mVec) {
            return BAD_VALUE;
        }
        mVec->resize(mNeededResize);
        return NO_ERROR;
    }

    status_t encode(const uint8_t* data, size_t size) {
        if (!mVec) {
            return BAD_VALUE;
        }
        if (mVec->size() == 0) {
            if (hasAdditionOverflow(mNeededResize, size)) {
                clear();
                return BAD_VALUE;
            }
            mNeededResize += size;
            return NO_ERROR;
        }

        if (hasAdditionOverflow(mOffset, size) || (mVec->size() < size + mOffset)) {
            clear();
            return BAD_VALUE;
        }

        std::copy(data, data + size, mVec->data() + mOffset);

        mOffset += size;
        return NO_ERROR;
    }

    void clear() {
        if (mVec) {
            mVec->resize(0);
        }
        mNeededResize = 0;
        mOffset = 0;
    }

private:
    hidl_vec<uint8_t>* mVec;
    size_t mNeededResize = 0;
    size_t mOffset = 0;
};

/**
 * InputHidlVec represents the hidl_vec byte stream that is inputed when a type is decoded.
 * This class is used to track the current index of the byte stream of the hidl_vec as it is
 * decoded.
 */
class InputHidlVec {
public:
    InputHidlVec(const hidl_vec<uint8_t>* vec)
        : mVec(vec) {}

    status_t decode(uint8_t* data, size_t size) {
        if (!mVec || hasAdditionOverflow(mOffset, size) || mOffset + size > mVec->size()) {
            return BAD_VALUE;
        }

        std::copy(mVec->data() + mOffset, mVec->data() + mOffset + size, data);

        mOffset += size;
        return NO_ERROR;
    }

    status_t decode(std::string* string, size_t size) {
        if (!mVec || hasAdditionOverflow(mOffset, size) || mOffset + size > mVec->size()) {
            return BAD_VALUE;
        }

        string->assign(mVec->data() + mOffset, mVec->data() + mOffset + size);

        mOffset += size;
        return NO_ERROR;
    }

    bool hasRemainingData() {
        if (!mVec) {
            return false;
        }
        return mVec->size() - mOffset;
    }

private:
    const hidl_vec<uint8_t>* mVec;
    size_t mOffset = 0;
};

/**
 * EncodeHelper is a function type that encodes T into the OutputHidlVec.
 */
template<class T>
using EncodeHelper = status_t(*)(const T&, OutputHidlVec*);

/**
 * DecodeHelper is a function type that decodes InputHidlVec into T.
 */
template<class T>
using DecodeHelper = status_t(*)(InputHidlVec*, T*);

/**
 * ErrorHandler is a function type that is called when the corresponding DecodeHelper function
 * fails. ErrorHandler cleans up the object T so the caller doesn't receive a partially created
 * T.
 */
template<class T>
using ErrorHandler = void(*)(T*);

/**
 * encode is the main encoding function. It takes in T and uses the encodeHelper function to turn T
 * into the hidl_vec byte stream.
 *
 * This function first calls the encodeHelper function to determine how large the hidl_vec
 * needs to be. It resizes the hidl_vec. Finally, it reruns the encodeHelper function which
 * encodes T into the hidl_vec byte stream.
 */
template <class T>
status_t encode(const T& input, hidl_vec<uint8_t>* output, EncodeHelper<T> encodeHelper) {
    OutputHidlVec outputHidlVec{output};
    status_t err = encodeHelper(input, &outputHidlVec);
    if (err) {
        return err;
    }

    err = outputHidlVec.resize();
    if (err) {
        return err;
    }

    return encodeHelper(input, &outputHidlVec);
}

/**
 * decode is the main decode function. It takes in a hidl_vec and uses the decodeHelper function to
 * turn the hidl_vec byte stream into T. If an error occurs, the errorHandler function cleans up
 * T.
 */
template <class T>
status_t decode(const hidl_vec<uint8_t>& input, T* output, DecodeHelper<T> decodeHelper,
                ErrorHandler<T> errorHandler = nullptr) {
    InputHidlVec inputHidlVec{&input};
    status_t err = decodeHelper(&inputHidlVec, output);
    if (err) {
        return err;
    }

    err = inputHidlVec.hasRemainingData();
    if (err) {
        if (errorHandler) {
            errorHandler(output);
        }
        return BAD_VALUE;
    }

    return NO_ERROR;
}

/**
 * Private helper functions
 */
template <class T>
status_t encodeInteger(const T& input, OutputHidlVec* output) {
    static_assert(std::is_same<T, uint32_t>::value || std::is_same<T, int32_t>::value ||
                  std::is_same<T, uint64_t>::value || std::is_same<T, int64_t>::value);
    if (!output) {
        return BAD_VALUE;
    }

    const uint8_t* tmp = reinterpret_cast<const uint8_t*>(&input);
    return output->encode(tmp, sizeof(input));
}

template <class T>
status_t decodeInteger(InputHidlVec* input, T* output) {
    static_assert(std::is_same<T, uint32_t>::value || std::is_same<T, int32_t>::value ||
                  std::is_same<T, uint64_t>::value || std::is_same<T, int64_t>::value);
    if (!output) {
        return BAD_VALUE;
    }

    uint8_t* tmp = reinterpret_cast<uint8_t*>(output);
    return input->decode(tmp, sizeof(*output));
}

status_t encodeString(const std::string& input, OutputHidlVec* output) {
    if (!output) {
        return BAD_VALUE;
    }

    status_t err = encodeInteger<int64_t>(input.size(), output);
    if (err) {
        return err;
    }

    return output->encode(reinterpret_cast<const uint8_t*>(input.c_str()), input.size());
}

status_t decodeString(InputHidlVec* input, std::string* output) {
    if (!output) {
        return BAD_VALUE;
    }

    int64_t size = 0;
    status_t err = decodeInteger<int64_t>(input, &size);
    if (err || size < 0) {
        return err;
    }

    return input->decode(output, size);
}

status_t encodeExtendableType(const ExtendableType& input, OutputHidlVec* output) {
    status_t err = encodeString(input.name, output);
    if (err) {
        return err;
    }

    err = encodeInteger<int64_t>(input.value, output);
    if (err) {
        return err;
    }

    return NO_ERROR;
}

status_t decodeExtendableType(InputHidlVec* input, ExtendableType* output) {
    status_t err = decodeString(input, &output->name);
    if (err) {
        return err;
    }

    err = decodeInteger<int64_t>(input, &output->value);
    if (err) {
        return err;
    }

    return NO_ERROR;
}

void clearExtendableType(ExtendableType* output) {
    if (!output) {
        return;
    }
    output->name.clear();
    output->value = 0;
}

status_t encodeRect(const Rect& input, OutputHidlVec* output) {
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

status_t decodeRect(InputHidlVec* input, Rect* output) {
    status_t err = decodeInteger<int32_t>(input, &output->left);
    if (err) {
        return err;
    }
    err = decodeInteger<int32_t>(input, &output->top);
    if (err) {
        return err;
    }
    err = decodeInteger<int32_t>(input, &output->right);
    if (err) {
        return err;
    }
    return decodeInteger<int32_t>(input, &output->bottom);
}

status_t encodePlaneLayoutComponent(const PlaneLayoutComponent& input, OutputHidlVec* output) {
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

status_t decodePlaneLayoutComponent(InputHidlVec* input, PlaneLayoutComponent* output) {
    if (!output) {
        return BAD_VALUE;
    }

    status_t err = decodeExtendableType(input, &output->type);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->offsetInBits);
    if (err) {
        return err;
    }
    return decodeInteger<int64_t>(input, &output->sizeInBits);
}

status_t encodePlaneLayoutComponents(const std::vector<PlaneLayoutComponent>& input, OutputHidlVec* output) {
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

status_t decodePlaneLayoutComponents(InputHidlVec* input, std::vector<PlaneLayoutComponent>* output) {
    if (!output) {
        return BAD_VALUE;
    }

    int64_t size = 0;
    status_t err = decodeInteger<int64_t>(input, &size);
    if (err || size < 0) {
        return err;
    }

    for (int i = 0; i < size; i++) {
        output->emplace_back();
        err = decodePlaneLayoutComponent(input, &output->back());
        if (err) {
            return err;
        }
    }
    return NO_ERROR;
}

status_t encodePlaneLayout(const PlaneLayout& input, OutputHidlVec* output) {
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

status_t decodePlaneLayout(InputHidlVec* input, PlaneLayout* output) {
    if (!output) {
        return BAD_VALUE;
    }

    status_t err = decodePlaneLayoutComponents(input, &output->components);
    if (err) {
        return err;
    }

    err = decodeInteger<int64_t>(input, &output->offsetInBytes);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->sampleIncrementInBits);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->strideInBytes);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->widthInSamples);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->heightInSamples);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->totalSizeInBytes);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->horizontalSubsampling);
    if (err) {
        return err;
    }
    err = decodeInteger<int64_t>(input, &output->verticalSubsampling);
    if (err) {
        return err;
    }

    return decodeRect(input, &output->crop);
}

status_t encodePlaneLayoutsHelper(const std::vector<PlaneLayout>& planeLayouts, OutputHidlVec* outOutputHidlVec) {
    status_t err = encodeInteger<int64_t>(static_cast<int64_t>(planeLayouts.size()), outOutputHidlVec);
    if (err) {
        return err;
    }

    for (const auto& planeLayout : planeLayouts) {
        err = encodePlaneLayout(planeLayout, outOutputHidlVec);
        if (err) {
            return err;
        }
    }

    return NO_ERROR;
}

status_t decodePlaneLayoutsHelper(InputHidlVec* inputHidlVec, std::vector<PlaneLayout>* outPlaneLayouts) {
    int64_t size = 0;
    status_t err = decodeInteger<int64_t>(inputHidlVec, &size);
    if (err || size < 0) {
        return err;
    }

    for (size_t i = 0; i < size; i++) {
        outPlaneLayouts->emplace_back();
        err = decodePlaneLayout(inputHidlVec, &outPlaneLayouts->back());
        if (err) {
            return err;
        }
    }
    return NO_ERROR;
}

void clearPlaneLayouts(std::vector<PlaneLayout>* output) {
    if (!output) {
        return;
    }
    output->clear();
}

/**
 * Public API functions
 */
bool isStandardMetadataType(const MetadataType& metadataType) {
    return !std::strncmp(metadataType.name.c_str(), GRALLOC4_STANDARD_METADATA_TYPE, metadataType.name.size());
}

StandardMetadataType getStandardMetadataTypeValue(const MetadataType& metadataType) {
    return static_cast<StandardMetadataType>(metadataType.value);
}

status_t encodeBufferId(uint64_t bufferId, hidl_vec<uint8_t>* outBufferId) {
    return encode(bufferId, outBufferId, encodeInteger);
}

status_t decodeBufferId(const hidl_vec<uint8_t>& bufferId, uint64_t* outBufferId) {
    return decode(bufferId, outBufferId, decodeInteger);
}

status_t encodeName(const std::string& name, hidl_vec<uint8_t>* outName) {
    return encode(name, outName, encodeString);
}

status_t decodeName(const hidl_vec<uint8_t>& name, std::string* outName) {
    return decode(name, outName, decodeString);
}

status_t encodeWidth(uint64_t width, hidl_vec<uint8_t>* outWidth) {
    return encode(width, outWidth, encodeInteger);
}

status_t decodeWidth(const hidl_vec<uint8_t>& width, uint64_t* outWidth) {
    return decode(width, outWidth, decodeInteger);
}

status_t encodeHeight(uint64_t height, hidl_vec<uint8_t>* outHeight) {
    return encode(height, outHeight, encodeInteger);
}

status_t decodeHeight(const hidl_vec<uint8_t>& height, uint64_t* outHeight) {
    return decode(height, outHeight, decodeInteger);
}

status_t encodeLayerCount(uint64_t layerCount, hidl_vec<uint8_t>* outLayerCount) {
    return encode(layerCount, outLayerCount, encodeInteger);
}

status_t decodeLayerCount(const hidl_vec<uint8_t>& layerCount, uint64_t* outLayerCount) {
    return decode(layerCount, outLayerCount, decodeInteger);
}

status_t encodePixelFormatRequested(const hardware::graphics::common::V1_2::PixelFormat& pixelFormatRequested,
        hidl_vec<uint8_t>* outPixelFormatRequested) {
    return encode(static_cast<int32_t>(pixelFormatRequested), outPixelFormatRequested, encodeInteger);
}

status_t decodePixelFormatRequested(const hidl_vec<uint8_t>& pixelFormatRequested,
        hardware::graphics::common::V1_2::PixelFormat* outPixelFormatRequested) {
    return decode(pixelFormatRequested, reinterpret_cast<int32_t*>(outPixelFormatRequested), decodeInteger);
}

status_t encodePixelFormatFourCC(uint32_t pixelFormatFourCC, hidl_vec<uint8_t>* outPixelFormatFourCC) {
    return encode(pixelFormatFourCC, outPixelFormatFourCC, encodeInteger);
}

status_t decodePixelFormatFourCC(const hidl_vec<uint8_t>& pixelFormatFourCC, uint32_t* outPixelFormatFourCC) {
    return decode(pixelFormatFourCC, outPixelFormatFourCC, decodeInteger);
}

status_t encodePixelFormatModifier(uint64_t pixelFormatModifier, hidl_vec<uint8_t>* outPixelFormatModifier) {
    return encode(pixelFormatModifier, outPixelFormatModifier, encodeInteger);
}

status_t decodePixelFormatModifier(const hidl_vec<uint8_t>& pixelFormatModifier, uint64_t* outPixelFormatModifier) {
    return decode(pixelFormatModifier, outPixelFormatModifier, decodeInteger);
}

status_t encodeUsage(uint64_t usage, hidl_vec<uint8_t>* outUsage) {
    return encode(usage, outUsage, encodeInteger);
}

status_t decodeUsage(const hidl_vec<uint8_t>& usage, uint64_t* outUsage) {
    return decode(usage, outUsage, decodeInteger);
}

status_t encodeAllocationSize(uint64_t allocationSize, hidl_vec<uint8_t>* outAllocationSize) {
    return encode(allocationSize, outAllocationSize, encodeInteger);
}

status_t decodeAllocationSize(const hidl_vec<uint8_t>& allocationSize, uint64_t* outAllocationSize) {
    return decode(allocationSize, outAllocationSize, decodeInteger);
}

status_t encodeProtectedContent(uint64_t protectedContent, hidl_vec<uint8_t>* outProtectedContent) {
    return encode(protectedContent, outProtectedContent, encodeInteger);
}

status_t decodeProtectedContent(const hidl_vec<uint8_t>& protectedContent, uint64_t* outProtectedContent) {
    return decode(protectedContent, outProtectedContent, decodeInteger);
}

status_t encodeCompression(const ExtendableType& compression, hidl_vec<uint8_t>* outCompression) {
    return encode(compression, outCompression, encodeExtendableType);
}

status_t decodeCompression(const hidl_vec<uint8_t>& compression, ExtendableType* outCompression) {
    return decode(compression, outCompression, decodeExtendableType, clearExtendableType);
}

status_t encodeInterlaced(const ExtendableType& interlaced, hidl_vec<uint8_t>* outInterlaced) {
    return encode(interlaced, outInterlaced, encodeExtendableType);
}

status_t decodeInterlaced(const hidl_vec<uint8_t>& interlaced, ExtendableType* outInterlaced) {
    return decode(interlaced, outInterlaced, decodeExtendableType, clearExtendableType);
}

status_t encodeChromaSiting(const ExtendableType& chromaSiting, hidl_vec<uint8_t>* outChromaSiting) {
    return encode(chromaSiting, outChromaSiting, encodeExtendableType);
}

status_t decodeChromaSiting(const hidl_vec<uint8_t>& chromaSiting, ExtendableType* outChromaSiting) {
    return decode(chromaSiting, outChromaSiting, decodeExtendableType, clearExtendableType);
}

status_t encodePlaneLayouts(const std::vector<PlaneLayout>& planeLayouts, hidl_vec<uint8_t>* outPlaneLayouts) {
    return encode(planeLayouts, outPlaneLayouts, encodePlaneLayoutsHelper);
}

status_t decodePlaneLayouts(const hidl_vec<uint8_t>& planeLayouts, std::vector<PlaneLayout>* outPlaneLayouts) {
    return decode(planeLayouts, outPlaneLayouts, decodePlaneLayoutsHelper, clearPlaneLayouts);
}

status_t encodeDataspace(const Dataspace& dataspace, hidl_vec<uint8_t>* outDataspace) {
    return encode(static_cast<int32_t>(dataspace), outDataspace, encodeInteger);
}

status_t decodeDataspace(const hidl_vec<uint8_t>& dataspace, Dataspace* outDataspace) {
    return decode(dataspace, reinterpret_cast<int32_t*>(outDataspace), decodeInteger);
}

status_t encodeBlendMode(const BlendMode& blendMode, hidl_vec<uint8_t>* outBlendMode) {
    return encode(static_cast<int32_t>(blendMode), outBlendMode, encodeInteger);
}

status_t decodeBlendMode(const hidl_vec<uint8_t>& blendMode, BlendMode* outBlendMode) {
    return decode(blendMode, reinterpret_cast<int32_t*>(outBlendMode), decodeInteger);
}

} // namespace gralloc4

} // namespace android
