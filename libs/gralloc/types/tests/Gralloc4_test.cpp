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

#define LOG_TAG "Gralloc4Test"

#include <limits>

#include <gralloctypes/Gralloc4.h>

#include <gtest/gtest.h>

using android::hardware::hidl_vec;

using android::hardware::graphics::common::V1_2::PixelFormat;
using android::hardware::graphics::common::V1_2::BufferUsage;

using aidl::android::hardware::graphics::common::BlendMode;
using aidl::android::hardware::graphics::common::ChromaSiting;
using aidl::android::hardware::graphics::common::Compression;
using aidl::android::hardware::graphics::common::Cta861_3;
using aidl::android::hardware::graphics::common::Dataspace;
using aidl::android::hardware::graphics::common::ExtendableType;
using aidl::android::hardware::graphics::common::Interlaced;
using aidl::android::hardware::graphics::common::PlaneLayout;
using aidl::android::hardware::graphics::common::PlaneLayoutComponent;
using aidl::android::hardware::graphics::common::PlaneLayoutComponentType;
using aidl::android::hardware::graphics::common::Rect;
using aidl::android::hardware::graphics::common::Smpte2086;
using aidl::android::hardware::graphics::common::StandardMetadataType;
using aidl::android::hardware::graphics::common::XyColor;

using BufferDescriptorInfo = android::hardware::graphics::mapper::V4_0::IMapper::BufferDescriptorInfo;
using MetadataType = android::hardware::graphics::mapper::V4_0::IMapper::MetadataType;

namespace android {

template<class T>
using EncodeFunction = status_t(*)(T, hidl_vec<uint8_t>*);

template<class T>
using EncodeConstFunction = status_t(*)(const T&, hidl_vec<uint8_t>*);

template<class T>
using EncodeMetadataTypeFunction = status_t(*)(const MetadataType&, T, hidl_vec<uint8_t>*);

template<class T>
using EncodeMetadataTypeConstFunction = status_t(*)(const MetadataType&, const T&, hidl_vec<uint8_t>*);

template<class T>
using EncodeOptionalFunction = status_t(*)(const std::optional<T>&, hidl_vec<uint8_t>*);

template<class T>
using DecodeFunction = status_t(*)(const hidl_vec<uint8_t>&, T*);

template<class T>
using DecodeMetadataTypeFunction = status_t(*)(const MetadataType&, const hidl_vec<uint8_t>&, T*);

template<class T>
using DecodeOptionalFunction = status_t(*)(const hidl_vec<uint8_t>&, std::optional<T>*);

template<class T>
void testHelper(const T& input, EncodeFunction<T> encode, DecodeFunction<T> decode) {
    hidl_vec<uint8_t> vec;
    T output;
    ASSERT_EQ(NO_ERROR, encode(input, &vec));
    ASSERT_EQ(NO_ERROR, decode(vec, &output));
    ASSERT_EQ(input, output);
}

template<class T>
void testHelperConst(const T& input, EncodeConstFunction<T> encode, DecodeFunction<T> decode) {
    hidl_vec<uint8_t> vec;
    T output;
    ASSERT_EQ(NO_ERROR, encode(input, &vec));
    ASSERT_EQ(NO_ERROR, decode(vec, &output));
    ASSERT_EQ(input, output);
}

template<class T>
void testHelperMetadataType(const T& input, EncodeMetadataTypeFunction<T> encode, DecodeMetadataTypeFunction<T> decode) {
    hidl_vec<uint8_t> vec;
    MetadataType metadataType{"vendor.mycompanyname.graphics.common.MetadataType", 0};
    T output;
    ASSERT_EQ(NO_ERROR, encode(metadataType, input, &vec));
    ASSERT_EQ(NO_ERROR, decode(metadataType, vec, &output));
    ASSERT_EQ(input, output);
}

template<class T>
void testHelperMetadataTypeConst(const T& input, EncodeMetadataTypeConstFunction<T> encode, DecodeMetadataTypeFunction<T> decode) {
    hidl_vec<uint8_t> vec;
    MetadataType metadataType{"vendor.mycompanyname.graphics.common.MetadataType", 0};
    T output;
    ASSERT_EQ(NO_ERROR, encode(metadataType, input, &vec));
    ASSERT_EQ(NO_ERROR, decode(metadataType, vec, &output));
    ASSERT_EQ(input, output);
}

template<class T>
void testHelperStableAidlType(const T& input, EncodeConstFunction<T> encode, DecodeFunction<T> decode) {
    hidl_vec<uint8_t> vec;
    T output;
    ASSERT_EQ(NO_ERROR, encode(input, &vec));
    ASSERT_EQ(NO_ERROR, decode(vec, &output));
    ASSERT_TRUE(input == output);
}

template<class T>
void testHelperStableAidlTypeOptional(const std::optional<T>& input, EncodeOptionalFunction<T> encode,
                                      DecodeOptionalFunction<T> decode) {
    hidl_vec<uint8_t> vec;
    std::optional<T> tmp = input;
    std::optional<T> output;
    ASSERT_EQ(NO_ERROR, encode(tmp, &vec));
    ASSERT_EQ(NO_ERROR, decode(vec, &output));
    ASSERT_EQ(tmp.has_value(), output.has_value());
    if (!tmp.has_value()) {
        return;
    }
    ASSERT_TRUE(*tmp == *output);
}

class Gralloc4TestUint32 : public testing::TestWithParam<uint32_t> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestUint32Params, Gralloc4TestUint32,
        ::testing::Values(0, -1, 1, 5, 100, 0xFF, std::numeric_limits<uint32_t>::min(),
                          std::numeric_limits<uint32_t>::max()));

TEST_P(Gralloc4TestUint32, Uint32) {
    ASSERT_NO_FATAL_FAILURE(testHelperMetadataType(GetParam(), gralloc4::encodeUint32, gralloc4::decodeUint32));
}

TEST_P(Gralloc4TestUint32, PixelFormatFourCC) {
    ASSERT_NO_FATAL_FAILURE(testHelper(GetParam(), gralloc4::encodePixelFormatFourCC, gralloc4::decodePixelFormatFourCC));
}

class Gralloc4TestInt32 : public testing::TestWithParam<int32_t> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestInt32Params, Gralloc4TestInt32,
        ::testing::Values(0, 1, 5, 100, 0xFF, std::numeric_limits<int32_t>::min(),
                          std::numeric_limits<int32_t>::max()));

TEST_P(Gralloc4TestInt32, Int32) {
    ASSERT_NO_FATAL_FAILURE(testHelperMetadataType(GetParam(), gralloc4::encodeInt32, gralloc4::decodeInt32));
}

class Gralloc4TestUint64 : public testing::TestWithParam<uint64_t> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestUint64Params, Gralloc4TestUint64,
        ::testing::Values(0, -1, 1, 5, 100, 0xFF, std::numeric_limits<uint64_t>::min(),
                          std::numeric_limits<uint64_t>::max()));

TEST_P(Gralloc4TestUint64, Uint64) {
    ASSERT_NO_FATAL_FAILURE(testHelperMetadataType(GetParam(), gralloc4::encodeUint64, gralloc4::decodeUint64));
}

TEST_P(Gralloc4TestUint64, BufferId) {
    ASSERT_NO_FATAL_FAILURE(testHelper(GetParam(), gralloc4::encodeBufferId, gralloc4::decodeBufferId));
}

TEST_P(Gralloc4TestUint64, Width) {
    ASSERT_NO_FATAL_FAILURE(testHelper(GetParam(), gralloc4::encodeWidth, gralloc4::decodeWidth));
}

TEST_P(Gralloc4TestUint64, Height) {
    ASSERT_NO_FATAL_FAILURE(testHelper(GetParam(), gralloc4::encodeHeight, gralloc4::decodeHeight));
}

TEST_P(Gralloc4TestUint64, LayerCount) {
    ASSERT_NO_FATAL_FAILURE(testHelper(GetParam(), gralloc4::encodeLayerCount, gralloc4::decodeLayerCount));
}

TEST_P(Gralloc4TestUint64, PixelFormatModifier) {
    ASSERT_NO_FATAL_FAILURE(testHelper(GetParam(), gralloc4::encodePixelFormatModifier, gralloc4::decodePixelFormatModifier));
}

TEST_P(Gralloc4TestUint64, Usage) {
    ASSERT_NO_FATAL_FAILURE(testHelper(GetParam(), gralloc4::encodeUsage, gralloc4::decodeUsage));
}

TEST_P(Gralloc4TestUint64, AllocationSize) {
    ASSERT_NO_FATAL_FAILURE(testHelper(GetParam(), gralloc4::encodeAllocationSize, gralloc4::decodeAllocationSize));
}

TEST_P(Gralloc4TestUint64, ProtectedContent) {
    ASSERT_NO_FATAL_FAILURE(testHelper(GetParam(), gralloc4::encodeProtectedContent, gralloc4::decodeProtectedContent));
}

class Gralloc4TestInt64 : public testing::TestWithParam<int64_t> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestInt64Params, Gralloc4TestInt64,
        ::testing::Values(0, 1, 5, 100, 0xFF, std::numeric_limits<int64_t>::min(),
                          std::numeric_limits<int64_t>::max()));

TEST_P(Gralloc4TestInt64, Int64) {
    ASSERT_NO_FATAL_FAILURE(testHelperMetadataType(GetParam(), gralloc4::encodeInt64, gralloc4::decodeInt64));
}

class Gralloc4TestFloat : public testing::TestWithParam<float> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestFloatParams, Gralloc4TestFloat,
        ::testing::Values(0.0, 1.999999, 5.5, 100.1, 1234.5678, std::numeric_limits<float>::min(),
                          std::numeric_limits<float>::max()));

TEST_P(Gralloc4TestFloat, Float) {
    ASSERT_NO_FATAL_FAILURE(testHelperMetadataType(GetParam(), gralloc4::encodeFloat, gralloc4::decodeFloat));
}

class Gralloc4TestDouble : public testing::TestWithParam<double> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestDoubleParams, Gralloc4TestDouble,
        ::testing::Values(0.0, 1.999999, 5.5, 100.1, 1234.5678, std::numeric_limits<double>::min(),
                          std::numeric_limits<double>::max()));

TEST_P(Gralloc4TestDouble, Double) {
    ASSERT_NO_FATAL_FAILURE(testHelperMetadataType(GetParam(), gralloc4::encodeDouble, gralloc4::decodeDouble));
}

class Gralloc4TestString : public testing::TestWithParam<std::string> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestStringParams, Gralloc4TestString,
        ::testing::Values("name", "aaaaa", "", "abcdefghijklmnopqrstuvwxyz", "0xFF"));

TEST_P(Gralloc4TestString, String) {
    ASSERT_NO_FATAL_FAILURE(testHelperMetadataTypeConst(GetParam(), gralloc4::encodeString, gralloc4::decodeString));
}

TEST_P(Gralloc4TestString, Name) {
    ASSERT_NO_FATAL_FAILURE(testHelperConst(GetParam(), gralloc4::encodeName, gralloc4::decodeName));
}

class Gralloc4TestPixelFormat : public testing::TestWithParam<PixelFormat> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestPixelFormatParams, Gralloc4TestPixelFormat,
        ::testing::Values(PixelFormat::RGBA_8888, PixelFormat::BLOB,
                          PixelFormat::IMPLEMENTATION_DEFINED, PixelFormat::YCBCR_420_888,
                          PixelFormat::YV12));

TEST_P(Gralloc4TestPixelFormat, PixelFormatRequested) {
    ASSERT_NO_FATAL_FAILURE(testHelperConst(GetParam(), gralloc4::encodePixelFormatRequested, gralloc4::decodePixelFormatRequested));
}

class Gralloc4TestCompression : public testing::TestWithParam<ExtendableType> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestCompressionParams, Gralloc4TestCompression,
        ::testing::Values(gralloc4::Compression_None, gralloc4::Compression_DisplayStreamCompression,
            ExtendableType{"", 0},
            ExtendableType{"vendor.mycompanyname.graphics.common.Compression", 0xFF},
            ExtendableType{"vendor.mycompanyname.graphics.common.Compression", std::numeric_limits<int64_t>::max()}));

TEST_P(Gralloc4TestCompression, Compression) {
    ASSERT_NO_FATAL_FAILURE(testHelperStableAidlType(GetParam(), gralloc4::encodeCompression, gralloc4::decodeCompression));
}

class Gralloc4TestInterlaced : public testing::TestWithParam<ExtendableType> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestInterlacedParams, Gralloc4TestInterlaced,
        ::testing::Values(gralloc4::Interlaced_None, gralloc4::Interlaced_TopBottom,
            gralloc4::Interlaced_RightLeft,
            ExtendableType{"", 0},
            ExtendableType{"vendor.mycompanyname.graphics.common.Interlaced", 0xFF},
            ExtendableType{"vendor.mycompanyname.graphics.common.Interlaced", std::numeric_limits<int64_t>::max()}));

TEST_P(Gralloc4TestInterlaced, Interlaced) {
    ASSERT_NO_FATAL_FAILURE(testHelperStableAidlType(GetParam(), gralloc4::encodeInterlaced, gralloc4::decodeInterlaced));
}

class Gralloc4TestChromaSiting : public testing::TestWithParam<ExtendableType> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestChromaSitingParams, Gralloc4TestChromaSiting,
        ::testing::Values(gralloc4::ChromaSiting_None, gralloc4::ChromaSiting_Unknown,
            gralloc4::ChromaSiting_SitedInterstitial, gralloc4::ChromaSiting_CositedHorizontal,
            ExtendableType{"", 0},
            ExtendableType{"vendor.mycompanyname.graphics.common.ChromaSiting", 0xFF},
            ExtendableType{"vendor.mycompanyname.graphics.common.ChromaSiting", std::numeric_limits<int64_t>::max()}));

TEST_P(Gralloc4TestChromaSiting, ChromaSiting) {
    ASSERT_NO_FATAL_FAILURE(testHelperStableAidlType(GetParam(), gralloc4::encodeChromaSiting, gralloc4::decodeChromaSiting));
}

class Gralloc4TestPlaneLayouts : public testing::Test { };

TEST_F(Gralloc4TestPlaneLayouts, PlaneLayouts) {
    uint32_t width = 64;
    uint32_t height = 64;

    std::vector<PlaneLayout> planeLayouts;
    PlaneLayout planeLayoutA;
    PlaneLayout planeLayoutRGB;
    PlaneLayoutComponent component;

    planeLayoutA.offsetInBytes = 0;
    planeLayoutA.sampleIncrementInBits = 8;
    planeLayoutA.strideInBytes = width + 20;
    planeLayoutA.widthInSamples = width;
    planeLayoutA.heightInSamples = height;
    planeLayoutA.totalSizeInBytes = planeLayoutA.strideInBytes * height;
    planeLayoutA.horizontalSubsampling = 1;
    planeLayoutA.verticalSubsampling = 1;

    component.type = gralloc4::PlaneLayoutComponentType_A;
    component.offsetInBits = 0;
    component.sizeInBits = 8;
    planeLayoutA.components.push_back(component);

    planeLayouts.push_back(planeLayoutA);

    planeLayoutRGB.offsetInBytes = 0;
    planeLayoutRGB.sampleIncrementInBits = 32;
    planeLayoutRGB.strideInBytes = width + 20;
    planeLayoutRGB.widthInSamples = width;
    planeLayoutRGB.heightInSamples = height;
    planeLayoutRGB.totalSizeInBytes = planeLayoutRGB.strideInBytes * height;
    planeLayoutRGB.horizontalSubsampling = 1;
    planeLayoutRGB.verticalSubsampling = 1;
    component.type = gralloc4::PlaneLayoutComponentType_R;
    planeLayoutRGB.components.push_back(component);
    component.type = gralloc4::PlaneLayoutComponentType_G;
    planeLayoutRGB.components.push_back(component);
    component.type = gralloc4::PlaneLayoutComponentType_B;
    planeLayoutRGB.components.push_back(component);

    planeLayouts.push_back(planeLayoutRGB);

    ASSERT_NO_FATAL_FAILURE(testHelperStableAidlType(planeLayouts, gralloc4::encodePlaneLayouts, gralloc4::decodePlaneLayouts));
}

class Gralloc4TestCrop : public testing::Test { };

TEST_F(Gralloc4TestCrop, Crop) {
    std::vector<Rect> crops;
    Rect crop1, crop2, crop3;

    crop1.left = 0;
    crop1.top = 0;
    crop1.right = 64;
    crop1.bottom = 64;
    crops.push_back(crop1);

    crop2.left = std::numeric_limits<int32_t>::min();
    crop2.top = 0xFF;
    crop2.right = std::numeric_limits<int32_t>::max();
    crop2.bottom = 0xFFFF;
    crops.push_back(crop2);

    crop3.left = 0;
    crop3.top = 0;
    crop3.right = -1;
    crop3.bottom = -1;
    crops.push_back(crop3);

    ASSERT_NO_FATAL_FAILURE(testHelperStableAidlType(crops, gralloc4::encodeCrop, gralloc4::decodeCrop));
}

class Gralloc4TestDataspace : public testing::TestWithParam<Dataspace> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestDataspaceParams, Gralloc4TestDataspace,
        ::testing::Values(Dataspace::UNKNOWN, Dataspace::ARBITRARY, Dataspace::DISPLAY_P3,
                          Dataspace::ADOBE_RGB));

TEST_P(Gralloc4TestDataspace, DataspaceRequested) {
    ASSERT_NO_FATAL_FAILURE(testHelperConst(GetParam(), gralloc4::encodeDataspace, gralloc4::decodeDataspace));
}

class Gralloc4TestBlendMode : public testing::TestWithParam<BlendMode> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestBlendModeParams, Gralloc4TestBlendMode,
        ::testing::Values(BlendMode::INVALID, BlendMode::NONE, BlendMode::PREMULTIPLIED,
                          BlendMode::COVERAGE));

TEST_P(Gralloc4TestBlendMode, BlendMode) {
    ASSERT_NO_FATAL_FAILURE(testHelperConst(GetParam(), gralloc4::encodeBlendMode, gralloc4::decodeBlendMode));
}

class Gralloc4TestSmpte2086 : public testing::TestWithParam<std::optional<Smpte2086>> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestSmpte2086Params, Gralloc4TestSmpte2086,
        ::testing::Values(std::optional<Smpte2086>(Smpte2086{XyColor{0.680, 0.320},
                                                             XyColor{0.265, 0.690},
                                                             XyColor{0.150, 0.060},
                                                             XyColor{0.3127, 0.3290},
                                                             100.0, 0.1}),
                          std::optional<Smpte2086>(Smpte2086{XyColor{-1.0, 100.0},
                                                             XyColor{0xFF, -0xFF},
                                                             XyColor{999.9, 0.0},
                                                             XyColor{0.0, -1.0},
                                                             -0.1, -100.0}),
                          std::nullopt));

TEST_P(Gralloc4TestSmpte2086, Smpte2086) {
    ASSERT_NO_FATAL_FAILURE(testHelperStableAidlTypeOptional(GetParam(), gralloc4::encodeSmpte2086, gralloc4::decodeSmpte2086));
}

class Gralloc4TestCta861_3 : public testing::TestWithParam<std::optional<Cta861_3>> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestCta861_3Params, Gralloc4TestCta861_3,
        ::testing::Values(std::optional<Cta861_3>(Cta861_3{78.0, 62.0}),
                          std::optional<Cta861_3>(Cta861_3{10.0, 10.0}),
                          std::optional<Cta861_3>(Cta861_3{0.0, 0.0}),
                          std::optional<Cta861_3>(Cta861_3{std::numeric_limits<float>::min(), std::numeric_limits<float>::min()}),
                          std::optional<Cta861_3>(Cta861_3{std::numeric_limits<float>::max(), std::numeric_limits<float>::max()}),
                          std::nullopt));

TEST_P(Gralloc4TestCta861_3, Cta861_3) {
    ASSERT_NO_FATAL_FAILURE(testHelperStableAidlTypeOptional(GetParam(), gralloc4::encodeCta861_3, gralloc4::decodeCta861_3));
}

class Gralloc4TestSmpte2094_40 : public testing::TestWithParam<std::optional<std::vector<uint8_t>>> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestSmpte2094_40Params, Gralloc4TestSmpte2094_40,
        ::testing::Values(std::optional<std::vector<uint8_t>>({}),
                          std::optional<std::vector<uint8_t>>({0, 1, 2, 3, 4, 5, 6, 7, 8, 9}),
                          std::optional<std::vector<uint8_t>>({std::numeric_limits<uint8_t>::min(),
                                                               std::numeric_limits<uint8_t>::min() + 1,
                                                               std::numeric_limits<uint8_t>::min() + 2,
                                                               std::numeric_limits<uint8_t>::min() + 3,
                                                               std::numeric_limits<uint8_t>::min() + 4}),
                          std::optional<std::vector<uint8_t>>({std::numeric_limits<uint8_t>::max(),
                                                               std::numeric_limits<uint8_t>::max() - 1,
                                                               std::numeric_limits<uint8_t>::max() - 2,
                                                               std::numeric_limits<uint8_t>::max() - 3,
                                                               std::numeric_limits<uint8_t>::max() - 4}),
                          std::nullopt));

TEST_P(Gralloc4TestSmpte2094_40, Smpte2094_40) {
    ASSERT_NO_FATAL_FAILURE(testHelperStableAidlTypeOptional(GetParam(), gralloc4::encodeSmpte2094_40, gralloc4::decodeSmpte2094_40));
}

class Gralloc4TestSmpte2094_10
      : public testing::TestWithParam<std::optional<std::vector<uint8_t>>> {};

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestSmpte2094_10Params, Gralloc4TestSmpte2094_10,
        ::testing::Values(
                std::optional<std::vector<uint8_t>>({}),
                std::optional<std::vector<uint8_t>>({0, 1, 2, 3, 4, 5, 6, 7, 8, 9}),
                std::optional<std::vector<uint8_t>>({std::numeric_limits<uint8_t>::min(),
                                                     std::numeric_limits<uint8_t>::min() + 1,
                                                     std::numeric_limits<uint8_t>::min() + 2,
                                                     std::numeric_limits<uint8_t>::min() + 3,
                                                     std::numeric_limits<uint8_t>::min() + 4}),
                std::optional<std::vector<uint8_t>>({std::numeric_limits<uint8_t>::max(),
                                                     std::numeric_limits<uint8_t>::max() - 1,
                                                     std::numeric_limits<uint8_t>::max() - 2,
                                                     std::numeric_limits<uint8_t>::max() - 3,
                                                     std::numeric_limits<uint8_t>::max() - 4}),
                std::nullopt));

TEST_P(Gralloc4TestSmpte2094_10, Smpte2094_10) {
    ASSERT_NO_FATAL_FAILURE(testHelperStableAidlTypeOptional(GetParam(),
                                                             gralloc4::encodeSmpte2094_10,
                                                             gralloc4::decodeSmpte2094_10));
}

class Gralloc4TestBufferDescriptorInfo : public testing::TestWithParam<BufferDescriptorInfo> { };

INSTANTIATE_TEST_CASE_P(
        Gralloc4TestBufferDescriptorInfoParams, Gralloc4TestBufferDescriptorInfo,
        ::testing::Values(BufferDescriptorInfo{"BufferName", 64, 64, 1,
                PixelFormat::RGBA_8888,
                static_cast<uint64_t>(BufferUsage::CPU_READ_OFTEN | BufferUsage::CPU_WRITE_OFTEN),
                1024}));

TEST_P(Gralloc4TestBufferDescriptorInfo, BufferDescriptorInfo) {
    ASSERT_NO_FATAL_FAILURE(testHelperConst(GetParam(), gralloc4::encodeBufferDescriptorInfo, gralloc4::decodeBufferDescriptorInfo));
}

class Gralloc4TestErrors : public testing::Test { };

TEST_F(Gralloc4TestErrors, Gralloc4TestEncodeNull) {
    ASSERT_NE(NO_ERROR, gralloc4::encodeBufferId(0, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodeName("", nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodeWidth(0, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodeHeight(0, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodeLayerCount(0, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodePixelFormatRequested(PixelFormat::RGBA_8888, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodePixelFormatFourCC(0, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodePixelFormatModifier(0, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodeUsage(0, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodeAllocationSize(0, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodeProtectedContent(0, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodeCompression(gralloc4::Compression_None, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodeInterlaced(gralloc4::Interlaced_None, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodeChromaSiting(gralloc4::ChromaSiting_None, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodePlaneLayouts({}, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodeDataspace(Dataspace::UNKNOWN, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodeBlendMode(BlendMode::NONE, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodeSmpte2086({{}}, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodeCta861_3({{}}, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodeSmpte2094_40({{}}, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::encodeSmpte2094_10({{}}, nullptr));
}

TEST_F(Gralloc4TestErrors, Gralloc4TestDecodeNull) {
    hidl_vec<uint8_t> vec;

    ASSERT_NE(NO_ERROR, gralloc4::decodeBufferId(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodeName(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodeWidth(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodeHeight(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodeLayerCount(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodePixelFormatRequested(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodePixelFormatFourCC(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodePixelFormatModifier(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodeUsage(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodeAllocationSize(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodeProtectedContent(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodeCompression(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodeInterlaced(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodeChromaSiting(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodePlaneLayouts(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodeDataspace(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodeBlendMode(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodeSmpte2086(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodeCta861_3(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodeSmpte2094_40(vec, nullptr));
    ASSERT_NE(NO_ERROR, gralloc4::decodeSmpte2094_10(vec, nullptr));
}

TEST_F(Gralloc4TestErrors, Gralloc4TestDecodeBadVec) {
    hidl_vec<uint8_t> vec = { 0 };

    uint64_t bufferId, width, height, layerCount, pixelFormatModifier, usage, allocationSize,
            protectedContent;
    std::string name;
    PixelFormat pixelFormatRequested;
    uint32_t pixelFormatFourCC;
    ExtendableType compression, interlaced, chromaSiting;
    std::vector<PlaneLayout> planeLayouts;
    Dataspace dataspace;
    BlendMode blendMode;
    std::optional<Smpte2086> smpte2086;
    std::optional<Cta861_3> cta861_3;
    std::optional<std::vector<uint8_t>> smpte2094_40;

    ASSERT_NE(NO_ERROR, gralloc4::decodeBufferId(vec, &bufferId));
    ASSERT_NE(NO_ERROR, gralloc4::decodeName(vec, &name));
    ASSERT_NE(NO_ERROR, gralloc4::decodeWidth(vec, &width));
    ASSERT_NE(NO_ERROR, gralloc4::decodeHeight(vec, &height));
    ASSERT_NE(NO_ERROR, gralloc4::decodeLayerCount(vec, &layerCount));
    ASSERT_NE(NO_ERROR, gralloc4::decodePixelFormatRequested(vec, &pixelFormatRequested));
    ASSERT_NE(NO_ERROR, gralloc4::decodePixelFormatFourCC(vec, &pixelFormatFourCC));
    ASSERT_NE(NO_ERROR, gralloc4::decodePixelFormatModifier(vec, &pixelFormatModifier));
    ASSERT_NE(NO_ERROR, gralloc4::decodeUsage(vec, &usage));
    ASSERT_NE(NO_ERROR, gralloc4::decodeAllocationSize(vec, &allocationSize));
    ASSERT_NE(NO_ERROR, gralloc4::decodeProtectedContent(vec, &protectedContent));
    ASSERT_NE(NO_ERROR, gralloc4::decodeCompression(vec, &compression));
    ASSERT_NE(NO_ERROR, gralloc4::decodeInterlaced(vec, &interlaced));
    ASSERT_NE(NO_ERROR, gralloc4::decodeChromaSiting(vec, &chromaSiting));
    ASSERT_NE(NO_ERROR, gralloc4::decodePlaneLayouts(vec, &planeLayouts));
    ASSERT_NE(NO_ERROR, gralloc4::decodeDataspace(vec, &dataspace));
    ASSERT_NE(NO_ERROR, gralloc4::decodeBlendMode(vec, &blendMode));
    ASSERT_NE(NO_ERROR, gralloc4::decodeSmpte2086(vec, &smpte2086));
    ASSERT_NE(NO_ERROR, gralloc4::decodeCta861_3(vec, &cta861_3));
    ASSERT_NE(NO_ERROR, gralloc4::decodeSmpte2094_40(vec, &smpte2094_40));
}

class Gralloc4TestHelpers : public testing::Test { };

TEST_F(Gralloc4TestHelpers, Gralloc4TestIsStandard) {
    ASSERT_TRUE(gralloc4::isStandardMetadataType(gralloc4::MetadataType_BufferId));
    ASSERT_TRUE(gralloc4::isStandardCompression(gralloc4::Compression_None));
    ASSERT_TRUE(gralloc4::isStandardInterlaced(gralloc4::Interlaced_None));
    ASSERT_TRUE(gralloc4::isStandardChromaSiting(gralloc4::ChromaSiting_None));
    ASSERT_TRUE(gralloc4::isStandardPlaneLayoutComponentType(gralloc4::PlaneLayoutComponentType_Y));
}

TEST_F(Gralloc4TestHelpers, Gralloc4TestIsNotStandard) {
    ASSERT_FALSE(gralloc4::isStandardMetadataType({"vendor.mycompanyname.graphics.common.MetadataType", 0}));
    ASSERT_FALSE(gralloc4::isStandardCompression({"vendor.mycompanyname.graphics.common.Compression", 0}));
    ASSERT_FALSE(gralloc4::isStandardInterlaced({"vendor.mycompanyname.graphics.common.Interlaced", 0}));
    ASSERT_FALSE(gralloc4::isStandardChromaSiting({"vendor.mycompanyname.graphics.common.ChromaSiting", 0}));
    ASSERT_FALSE(gralloc4::isStandardPlaneLayoutComponentType({"vendor.mycompanyname.graphics.common.PlaneLayoutComponentType", 0}));
}

TEST_F(Gralloc4TestHelpers, Gralloc4TestGetStandardValue) {
    ASSERT_EQ(StandardMetadataType::BUFFER_ID, gralloc4::getStandardMetadataTypeValue(gralloc4::MetadataType_BufferId));
    ASSERT_EQ(Compression::NONE, gralloc4::getStandardCompressionValue(gralloc4::Compression_None));
    ASSERT_EQ(Interlaced::NONE, gralloc4::getStandardInterlacedValue(gralloc4::Interlaced_None));
    ASSERT_EQ(ChromaSiting::NONE, gralloc4::getStandardChromaSitingValue(gralloc4::ChromaSiting_None));
    ASSERT_EQ(PlaneLayoutComponentType::Y, gralloc4::getStandardPlaneLayoutComponentTypeValue(gralloc4::PlaneLayoutComponentType_Y));
}

} // namespace android
