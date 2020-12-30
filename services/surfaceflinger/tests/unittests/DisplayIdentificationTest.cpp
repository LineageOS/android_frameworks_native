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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wextra"

#include <functional>
#include <string_view>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "DisplayHardware/DisplayIdentification.h"

using ::testing::ElementsAre;

namespace android {
namespace {

const unsigned char kInternalEdid[] =
        "\x00\xff\xff\xff\xff\xff\xff\x00\x4c\xa3\x42\x31\x00\x00\x00\x00"
        "\x00\x15\x01\x03\x80\x1a\x10\x78\x0a\xd3\xe5\x95\x5c\x60\x90\x27"
        "\x19\x50\x54\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x9e\x1b\x00\xa0\x50\x20\x12\x30\x10\x30"
        "\x13\x00\x05\xa3\x10\x00\x00\x19\x00\x00\x00\x0f\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x23\x87\x02\x64\x00\x00\x00\x00\xfe\x00\x53"
        "\x41\x4d\x53\x55\x4e\x47\x0a\x20\x20\x20\x20\x20\x00\x00\x00\xfe"
        "\x00\x31\x32\x31\x41\x54\x31\x31\x2d\x38\x30\x31\x0a\x20\x00\x45";

const unsigned char kExternalEdid[] =
        "\x00\xff\xff\xff\xff\xff\xff\x00\x22\xf0\x6c\x28\x01\x01\x01\x01"
        "\x02\x16\x01\x04\xb5\x40\x28\x78\xe2\x8d\x85\xad\x4f\x35\xb1\x25"
        "\x0e\x50\x54\x00\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\xe2\x68\x00\xa0\xa0\x40\x2e\x60\x30\x20"
        "\x36\x00\x81\x90\x21\x00\x00\x1a\xbc\x1b\x00\xa0\x50\x20\x17\x30"
        "\x30\x20\x36\x00\x81\x90\x21\x00\x00\x1a\x00\x00\x00\xfc\x00\x48"
        "\x50\x20\x5a\x52\x33\x30\x77\x0a\x20\x20\x20\x20\x00\x00\x00\xff"
        "\x00\x43\x4e\x34\x32\x30\x32\x31\x33\x37\x51\x0a\x20\x20\x00\x71";

// Extended EDID with timing extension.
const unsigned char kExternalEedid[] =
        "\x00\xff\xff\xff\xff\xff\xff\x00\x4c\x2d\xfe\x08\x00\x00\x00\x00"
        "\x29\x15\x01\x03\x80\x10\x09\x78\x0a\xee\x91\xa3\x54\x4c\x99\x26"
        "\x0f\x50\x54\xbd\xef\x80\x71\x4f\x81\xc0\x81\x00\x81\x80\x95\x00"
        "\xa9\xc0\xb3\x00\x01\x01\x02\x3a\x80\x18\x71\x38\x2d\x40\x58\x2c"
        "\x45\x00\xa0\x5a\x00\x00\x00\x1e\x66\x21\x56\xaa\x51\x00\x1e\x30"
        "\x46\x8f\x33\x00\xa0\x5a\x00\x00\x00\x1e\x00\x00\x00\xfd\x00\x18"
        "\x4b\x0f\x51\x17\x00\x0a\x20\x20\x20\x20\x20\x20\x00\x00\x00\xfc"
        "\x00\x53\x41\x4d\x53\x55\x4e\x47\x0a\x20\x20\x20\x20\x20\x01\x1d"
        "\x02\x03\x1f\xf1\x47\x90\x04\x05\x03\x20\x22\x07\x23\x09\x07\x07"
        "\x83\x01\x00\x00\xe2\x00\x0f\x67\x03\x0c\x00\x20\x00\xb8\x2d\x01"
        "\x1d\x80\x18\x71\x1c\x16\x20\x58\x2c\x25\x00\xa0\x5a\x00\x00\x00"
        "\x9e\x01\x1d\x00\x72\x51\xd0\x1e\x20\x6e\x28\x55\x00\xa0\x5a\x00"
        "\x00\x00\x1e\x8c\x0a\xd0\x8a\x20\xe0\x2d\x10\x10\x3e\x96\x00\xa0"
        "\x5a\x00\x00\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc6";

const unsigned char kPanasonicTvEdid[] =
        "\x00\xff\xff\xff\xff\xff\xff\x00\x34\xa9\x96\xa2\x01\x01\x01"
        "\x01\x00\x1d\x01\x03\x80\x80\x48\x78\x0a\xda\xff\xa3\x58\x4a"
        "\xa2\x29\x17\x49\x4b\x20\x08\x00\x31\x40\x61\x40\x01\x01\x01"
        "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x08\xe8\x00\x30\xf2\x70"
        "\x5a\x80\xb0\x58\x8a\x00\xba\x88\x21\x00\x00\x1e\x02\x3a\x80"
        "\x18\x71\x38\x2d\x40\x58\x2c\x45\x00\xba\x88\x21\x00\x00\x1e"
        "\x00\x00\x00\xfc\x00\x50\x61\x6e\x61\x73\x6f\x6e\x69\x63\x2d"
        "\x54\x56\x0a\x00\x00\x00\xfd\x00\x17\x3d\x0f\x88\x3c\x00\x0a"
        "\x20\x20\x20\x20\x20\x20\x01\x1d\x02\x03\x6b\xf0\x57\x61\x60"
        "\x10\x1f\x66\x65\x05\x14\x20\x21\x22\x04\x13\x03\x12\x07\x16"
        "\x5d\x5e\x5f\x62\x63\x64\x2c\x0d\x07\x01\x15\x07\x50\x57\x07"
        "\x01\x67\x04\x03\x83\x0f\x00\x00\x6e\x03\x0c\x00\x20\x00\x38"
        "\x3c\x2f\x08\x80\x01\x02\x03\x04\x67\xd8\x5d\xc4\x01\x78\x80"
        "\x03\xe2\x00\x4b\xe3\x05\xff\x01\xe2\x0f\x33\xe3\x06\x0f\x01"
        "\xe5\x01\x8b\x84\x90\x01\xeb\x01\x46\xd0\x00\x44\x03\x70\x80"
        "\x5e\x75\x94\xe6\x11\x46\xd0\x00\x70\x00\x66\x21\x56\xaa\x51"
        "\x00\x1e\x30\x46\x8f\x33\x00\xba\x88\x21\x00\x00\x1e\x00\x00"
        "\xc8";

const unsigned char kHisenseTvEdid[] =
        "\x00\xff\xff\xff\xff\xff\xff\x00\x20\xa3\x00\x00\x00\x00\x00"
        "\x00\x12\x1d\x01\x03\x80\x00\x00\x78\x0a\xd7\xa5\xa2\x59\x4a"
        "\x96\x24\x14\x50\x54\xa3\x08\x00\xd1\xc0\xb3\x00\x81\x00\x81"
        "\x80\x81\x40\x81\xc0\x01\x01\x01\x01\x02\x3a\x80\x18\x71\x38"
        "\x2d\x40\x58\x2c\x45\x00\x3f\x43\x21\x00\x00\x1a\x02\x3a\x80"
        "\x18\x71\x38\x2d\x40\x58\x2c\x45\x00\x3f\x43\x21\x00\x00\x1a"
        "\x00\x00\x00\xfd\x00\x1e\x4c\x1e\x5a\x1e\x00\x0a\x20\x20\x20"
        "\x20\x20\x20\x00\x00\x00\xfc\x00\x48\x69\x73\x65\x6e\x73\x65"
        "\x0a\x20\x20\x20\x20\x20\x01\x47\x02\x03\x2d\x71\x50\x90\x05"
        "\x04\x03\x07\x02\x06\x01\x1f\x14\x13\x12\x16\x11\x15\x20\x2c"
        "\x09\x07\x03\x15\x07\x50\x57\x07\x00\x39\x07\xbb\x66\x03\x0c"
        "\x00\x12\x34\x00\x83\x01\x00\x00\x01\x1d\x00\x72\x51\xd0\x1e"
        "\x20\x6e\x28\x55\x00\xc4\x8e\x21\x00\x00\x1e\x01\x1d\x80\x18"
        "\x71\x1c\x16\x20\x58\x2c\x25\x00\xc4\x8e\x21\x00\x00\x9e\x8c"
        "\x0a\xd0\x8a\x20\xe0\x2d\x10\x10\x3e\x96\x00\x13\x8e\x21\x00"
        "\x00\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x07";

const unsigned char kCtlDisplayEdid[] =
        "\x00\xff\xff\xff\xff\xff\xff\x00\x0e\x8c\x9d\x24\x00\x00\x00\x00"
        "\xff\x17\x01\x04\xa5\x34\x1d\x78\x3a\xa7\x25\xa4\x57\x51\xa0\x26"
        "\x10\x50\x54\xbf\xef\x80\xb3\x00\xa9\x40\x95\x00\x81\x40\x81\x80"
        "\x95\x0f\x71\x4f\x90\x40\x02\x3a\x80\x18\x71\x38\x2d\x40\x58\x2c"
        "\x45\x00\x09\x25\x21\x00\x00\x1e\x66\x21\x50\xb0\x51\x00\x1b\x30"
        "\x40\x70\x36\x00\x09\x25\x21\x00\x00\x1e\x00\x00\x00\xfd\x00\x31"
        "\x4c\x1e\x52\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xfc"
        "\x00\x4c\x50\x32\x33\x36\x31\x0a\x20\x20\x20\x20\x20\x20\x01\x3e"
        "\x02\x03\x22\xf2\x4f\x90\x9f\x05\x14\x04\x13\x03\x02\x12\x11\x07"
        "\x06\x16\x15\x01\x23\x09\x07\x07\x83\x01\x00\x00\x65\xb9\x14\x00"
        "\x04\x00\x02\x3a\x80\x18\x71\x38\x2d\x40\x58\x2c\x45\x00\x09\x25"
        "\x21\x00\x00\x1e\x02\x3a\x80\xd0\x72\x38\x2d\x40\x10\x2c\x45\x80"
        "\x09\x25\x21\x00\x00\x1e\x01\x1d\x00\x72\x51\xd0\x1e\x20\x6e\x28"
        "\x55\x00\x09\x25\x21\x00\x00\x1e\x8c\x0a\xd0\x8a\x20\xe0\x2d\x10"
        "\x10\x3e\x96\x00\x09\x25\x21\x00\x00\x18\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf4";

template <size_t N>
DisplayIdentificationData asDisplayIdentificationData(const unsigned char (&bytes)[N]) {
    return DisplayIdentificationData(bytes, bytes + N - 1);
}

uint32_t hash(const char* str) {
    return static_cast<uint32_t>(std::hash<std::string_view>()(str));
}

} // namespace

const DisplayIdentificationData& getInternalEdid() {
    static const DisplayIdentificationData data = asDisplayIdentificationData(kInternalEdid);
    return data;
}

const DisplayIdentificationData& getExternalEdid() {
    static const DisplayIdentificationData data = asDisplayIdentificationData(kExternalEdid);
    return data;
}

const DisplayIdentificationData& getExternalEedid() {
    static const DisplayIdentificationData data = asDisplayIdentificationData(kExternalEedid);
    return data;
}

const DisplayIdentificationData& getPanasonicTvEdid() {
    static const DisplayIdentificationData data = asDisplayIdentificationData(kPanasonicTvEdid);
    return data;
}

const DisplayIdentificationData& getHisenseTvEdid() {
    static const DisplayIdentificationData data = asDisplayIdentificationData(kHisenseTvEdid);
    return data;
}

const DisplayIdentificationData& getCtlDisplayEdid() {
    static const DisplayIdentificationData data = asDisplayIdentificationData(kCtlDisplayEdid);
    return data;
}

TEST(DisplayIdentificationTest, isEdid) {
    EXPECT_FALSE(isEdid({}));

    EXPECT_TRUE(isEdid(getInternalEdid()));
    EXPECT_TRUE(isEdid(getExternalEdid()));
    EXPECT_TRUE(isEdid(getExternalEedid()));
    EXPECT_TRUE(isEdid(getPanasonicTvEdid()));
    EXPECT_TRUE(isEdid(getHisenseTvEdid()));
    EXPECT_TRUE(isEdid(getCtlDisplayEdid()));
}

TEST(DisplayIdentificationTest, parseEdid) {
    auto edid = parseEdid(getInternalEdid());
    ASSERT_TRUE(edid);
    EXPECT_EQ(0x4ca3u, edid->manufacturerId);
    EXPECT_STREQ("SEC", edid->pnpId.data());
    // ASCII text should be used as fallback if display name and serial number are missing.
    EXPECT_EQ(hash("121AT11-801"), edid->modelHash);
    EXPECT_TRUE(edid->displayName.empty());
    EXPECT_EQ(12610, edid->productId);
    EXPECT_EQ(21, edid->manufactureOrModelYear);
    EXPECT_EQ(0, edid->manufactureWeek);
    EXPECT_FALSE(edid->cea861Block);

    edid = parseEdid(getExternalEdid());
    ASSERT_TRUE(edid);
    EXPECT_EQ(0x22f0u, edid->manufacturerId);
    EXPECT_STREQ("HWP", edid->pnpId.data());
    EXPECT_EQ(hash("HP ZR30w"), edid->modelHash);
    EXPECT_EQ("HP ZR30w", edid->displayName);
    EXPECT_EQ(10348, edid->productId);
    EXPECT_EQ(22, edid->manufactureOrModelYear);
    EXPECT_EQ(2, edid->manufactureWeek);
    EXPECT_FALSE(edid->cea861Block);

    edid = parseEdid(getExternalEedid());
    ASSERT_TRUE(edid);
    EXPECT_EQ(0x4c2du, edid->manufacturerId);
    EXPECT_STREQ("SAM", edid->pnpId.data());
    EXPECT_EQ(hash("SAMSUNG"), edid->modelHash);
    EXPECT_EQ("SAMSUNG", edid->displayName);
    EXPECT_EQ(2302, edid->productId);
    EXPECT_EQ(21, edid->manufactureOrModelYear);
    EXPECT_EQ(41, edid->manufactureWeek);
    ASSERT_TRUE(edid->cea861Block);
    ASSERT_TRUE(edid->cea861Block->hdmiVendorDataBlock);
    auto physicalAddress = edid->cea861Block->hdmiVendorDataBlock->physicalAddress;
    EXPECT_EQ(2, physicalAddress.a);
    EXPECT_EQ(0, physicalAddress.b);
    EXPECT_EQ(0, physicalAddress.c);
    EXPECT_EQ(0, physicalAddress.d);

    edid = parseEdid(getPanasonicTvEdid());
    ASSERT_TRUE(edid);
    EXPECT_EQ(13481, edid->manufacturerId);
    EXPECT_STREQ("MEI", edid->pnpId.data());
    EXPECT_EQ(hash("Panasonic-TV"), edid->modelHash);
    EXPECT_EQ("Panasonic-TV", edid->displayName);
    EXPECT_EQ(41622, edid->productId);
    EXPECT_EQ(29, edid->manufactureOrModelYear);
    EXPECT_EQ(0, edid->manufactureWeek);
    ASSERT_TRUE(edid->cea861Block);
    ASSERT_TRUE(edid->cea861Block->hdmiVendorDataBlock);
    physicalAddress = edid->cea861Block->hdmiVendorDataBlock->physicalAddress;
    EXPECT_EQ(2, physicalAddress.a);
    EXPECT_EQ(0, physicalAddress.b);
    EXPECT_EQ(0, physicalAddress.c);
    EXPECT_EQ(0, physicalAddress.d);

    edid = parseEdid(getHisenseTvEdid());
    ASSERT_TRUE(edid);
    EXPECT_EQ(8355, edid->manufacturerId);
    EXPECT_STREQ("HEC", edid->pnpId.data());
    EXPECT_EQ(hash("Hisense"), edid->modelHash);
    EXPECT_EQ("Hisense", edid->displayName);
    EXPECT_EQ(0, edid->productId);
    EXPECT_EQ(29, edid->manufactureOrModelYear);
    EXPECT_EQ(18, edid->manufactureWeek);
    ASSERT_TRUE(edid->cea861Block);
    ASSERT_TRUE(edid->cea861Block->hdmiVendorDataBlock);
    physicalAddress = edid->cea861Block->hdmiVendorDataBlock->physicalAddress;
    EXPECT_EQ(1, physicalAddress.a);
    EXPECT_EQ(2, physicalAddress.b);
    EXPECT_EQ(3, physicalAddress.c);
    EXPECT_EQ(4, physicalAddress.d);

    edid = parseEdid(getCtlDisplayEdid());
    ASSERT_TRUE(edid);
    EXPECT_EQ(3724, edid->manufacturerId);
    EXPECT_STREQ("CTL", edid->pnpId.data());
    EXPECT_EQ(hash("LP2361"), edid->modelHash);
    EXPECT_EQ("LP2361", edid->displayName);
    EXPECT_EQ(9373, edid->productId);
    EXPECT_EQ(23, edid->manufactureOrModelYear);
    EXPECT_EQ(0xff, edid->manufactureWeek);
    ASSERT_TRUE(edid->cea861Block);
    EXPECT_FALSE(edid->cea861Block->hdmiVendorDataBlock);
}

TEST(DisplayIdentificationTest, parseInvalidEdid) {
    EXPECT_FALSE(isEdid({}));
    EXPECT_FALSE(parseEdid({}));

    // Display name must be printable.
    auto data = getExternalEdid();
    data[97] = '\x1b';
    auto edid = parseEdid(data);
    ASSERT_TRUE(edid);
    // Serial number should be used as fallback if display name is invalid.
    const auto modelHash = hash("CN4202137Q");
    EXPECT_EQ(modelHash, edid->modelHash);
    EXPECT_TRUE(edid->displayName.empty());

    // Parsing should succeed even if EDID is truncated.
    data.pop_back();
    edid = parseEdid(data);
    ASSERT_TRUE(edid);
    EXPECT_EQ(modelHash, edid->modelHash);
}

TEST(DisplayIdentificationTest, getPnpId) {
    EXPECT_FALSE(getPnpId(0));
    EXPECT_FALSE(getPnpId(static_cast<uint16_t>(-1)));

    EXPECT_STREQ("SEC", getPnpId(0x4ca3u).value_or(PnpId{}).data());
    EXPECT_STREQ("HWP", getPnpId(0x22f0u).value_or(PnpId{}).data());
    EXPECT_STREQ("SAM", getPnpId(0x4c2du).value_or(PnpId{}).data());
}

TEST(DisplayIdentificationTest, parseDisplayIdentificationData) {
    const auto primaryInfo = parseDisplayIdentificationData(0, getInternalEdid());
    ASSERT_TRUE(primaryInfo);

    const auto secondaryInfo = parseDisplayIdentificationData(1, getExternalEdid());
    ASSERT_TRUE(secondaryInfo);

    const auto tertiaryInfo = parseDisplayIdentificationData(2, getExternalEedid());
    ASSERT_TRUE(tertiaryInfo);

    // Display IDs should be unique.
    EXPECT_NE(primaryInfo->id, secondaryInfo->id);
    EXPECT_NE(primaryInfo->id, tertiaryInfo->id);
    EXPECT_NE(secondaryInfo->id, tertiaryInfo->id);
}

TEST(DisplayIdentificationTest, deviceProductInfo) {
    using ManufactureYear = DeviceProductInfo::ManufactureYear;
    using ManufactureWeekAndYear = DeviceProductInfo::ManufactureWeekAndYear;
    using ModelYear = DeviceProductInfo::ModelYear;

    {
        const auto displayIdInfo = parseDisplayIdentificationData(0, getInternalEdid());
        ASSERT_TRUE(displayIdInfo);
        ASSERT_TRUE(displayIdInfo->deviceProductInfo);
        const auto& info = *displayIdInfo->deviceProductInfo;
        EXPECT_EQ("", info.name);
        EXPECT_STREQ("SEC", info.manufacturerPnpId.data());
        EXPECT_EQ("12610", info.productId);
        ASSERT_TRUE(std::holds_alternative<ManufactureYear>(info.manufactureOrModelDate));
        EXPECT_EQ(2011, std::get<ManufactureYear>(info.manufactureOrModelDate).year);
        EXPECT_TRUE(info.relativeAddress.empty());
    }
    {
        const auto displayIdInfo = parseDisplayIdentificationData(0, getExternalEdid());
        ASSERT_TRUE(displayIdInfo);
        ASSERT_TRUE(displayIdInfo->deviceProductInfo);
        const auto& info = *displayIdInfo->deviceProductInfo;
        EXPECT_EQ("HP ZR30w", info.name);
        EXPECT_STREQ("HWP", info.manufacturerPnpId.data());
        EXPECT_EQ("10348", info.productId);
        ASSERT_TRUE(std::holds_alternative<ManufactureWeekAndYear>(info.manufactureOrModelDate));
        const auto& date = std::get<ManufactureWeekAndYear>(info.manufactureOrModelDate);
        EXPECT_EQ(2012, date.year);
        EXPECT_EQ(2, date.week);
        EXPECT_TRUE(info.relativeAddress.empty());
    }
    {
        const auto displayIdInfo = parseDisplayIdentificationData(0, getExternalEedid());
        ASSERT_TRUE(displayIdInfo);
        ASSERT_TRUE(displayIdInfo->deviceProductInfo);
        const auto& info = *displayIdInfo->deviceProductInfo;
        EXPECT_EQ("SAMSUNG", info.name);
        EXPECT_STREQ("SAM", info.manufacturerPnpId.data());
        EXPECT_EQ("2302", info.productId);
        ASSERT_TRUE(std::holds_alternative<ManufactureWeekAndYear>(info.manufactureOrModelDate));
        const auto& date = std::get<ManufactureWeekAndYear>(info.manufactureOrModelDate);
        EXPECT_EQ(2011, date.year);
        EXPECT_EQ(41, date.week);
        EXPECT_THAT(info.relativeAddress, ElementsAre(2, 0, 0, 0));
    }
    {
        const auto displayIdInfo = parseDisplayIdentificationData(0, getPanasonicTvEdid());
        ASSERT_TRUE(displayIdInfo);
        ASSERT_TRUE(displayIdInfo->deviceProductInfo);
        const auto& info = *displayIdInfo->deviceProductInfo;
        EXPECT_EQ("Panasonic-TV", info.name);
        EXPECT_STREQ("MEI", info.manufacturerPnpId.data());
        EXPECT_EQ("41622", info.productId);
        ASSERT_TRUE(std::holds_alternative<ManufactureYear>(info.manufactureOrModelDate));
        const auto& date = std::get<ManufactureYear>(info.manufactureOrModelDate);
        EXPECT_EQ(2019, date.year);
        EXPECT_THAT(info.relativeAddress, ElementsAre(2, 0, 0, 0));
    }
    {
        const auto displayIdInfo = parseDisplayIdentificationData(0, getHisenseTvEdid());
        ASSERT_TRUE(displayIdInfo);
        ASSERT_TRUE(displayIdInfo->deviceProductInfo);
        const auto& info = *displayIdInfo->deviceProductInfo;
        EXPECT_EQ("Hisense", info.name);
        EXPECT_STREQ("HEC", info.manufacturerPnpId.data());
        EXPECT_EQ("0", info.productId);
        ASSERT_TRUE(std::holds_alternative<ManufactureWeekAndYear>(info.manufactureOrModelDate));
        const auto& date = std::get<ManufactureWeekAndYear>(info.manufactureOrModelDate);
        EXPECT_EQ(2019, date.year);
        EXPECT_EQ(18, date.week);
        EXPECT_THAT(info.relativeAddress, ElementsAre(1, 2, 3, 4));
    }
    {
        const auto displayIdInfo = parseDisplayIdentificationData(0, getCtlDisplayEdid());
        ASSERT_TRUE(displayIdInfo);
        ASSERT_TRUE(displayIdInfo->deviceProductInfo);
        const auto& info = *displayIdInfo->deviceProductInfo;
        EXPECT_EQ("LP2361", info.name);
        EXPECT_STREQ("CTL", info.manufacturerPnpId.data());
        EXPECT_EQ("9373", info.productId);
        ASSERT_TRUE(std::holds_alternative<ModelYear>(info.manufactureOrModelDate));
        EXPECT_EQ(2013, std::get<ModelYear>(info.manufactureOrModelDate).year);
        EXPECT_TRUE(info.relativeAddress.empty());
    }
}

TEST(DisplayIdentificationTest, fromPort) {
    // Manufacturer ID should be invalid.
    ASSERT_FALSE(getPnpId(PhysicalDisplayId::fromPort(0)));
    ASSERT_FALSE(getPnpId(PhysicalDisplayId::fromPort(0xffu)));
}

TEST(DisplayIdentificationTest, getVirtualDisplayId) {
    // Manufacturer ID should be invalid.
    ASSERT_FALSE(getPnpId(getVirtualDisplayId(0)));
    ASSERT_FALSE(getPnpId(getVirtualDisplayId(0xffff'ffffu)));
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wextra"