/*
 * Copyright 2020 The Android Open Source Project
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

#include <ui/DisplayId.h>

#include <gtest/gtest.h>

namespace android::ui {

TEST(DisplayIdTest, createPhysicalIdFromEdid) {
    constexpr uint8_t port = 1;
    constexpr uint16_t manufacturerId = 13;
    constexpr uint32_t modelHash = 42;
    const PhysicalDisplayId id = PhysicalDisplayId::fromEdid(port, manufacturerId, modelHash);
    EXPECT_EQ(port, id.getPort());
    EXPECT_EQ(manufacturerId, id.getManufacturerId());
    EXPECT_FALSE(VirtualDisplayId::tryCast(id));
    EXPECT_FALSE(HalVirtualDisplayId::tryCast(id));
    EXPECT_FALSE(GpuVirtualDisplayId::tryCast(id));
    EXPECT_TRUE(PhysicalDisplayId::tryCast(id));
    EXPECT_TRUE(HalDisplayId::tryCast(id));

    EXPECT_EQ(id, DisplayId::fromValue(id.value));
    EXPECT_EQ(id, DisplayId::fromValue<PhysicalDisplayId>(id.value));
}

TEST(DisplayIdTest, createPhysicalIdFromPort) {
    constexpr uint8_t port = 3;
    const PhysicalDisplayId id = PhysicalDisplayId::fromPort(port);
    EXPECT_EQ(port, id.getPort());
    EXPECT_FALSE(VirtualDisplayId::tryCast(id));
    EXPECT_FALSE(HalVirtualDisplayId::tryCast(id));
    EXPECT_FALSE(GpuVirtualDisplayId::tryCast(id));
    EXPECT_TRUE(PhysicalDisplayId::tryCast(id));
    EXPECT_TRUE(HalDisplayId::tryCast(id));

    EXPECT_EQ(id, DisplayId::fromValue(id.value));
    EXPECT_EQ(id, DisplayId::fromValue<PhysicalDisplayId>(id.value));
}

TEST(DisplayIdTest, createGpuVirtualId) {
    const GpuVirtualDisplayId id(42);
    EXPECT_TRUE(VirtualDisplayId::tryCast(id));
    EXPECT_TRUE(GpuVirtualDisplayId::tryCast(id));
    EXPECT_FALSE(HalVirtualDisplayId::tryCast(id));
    EXPECT_FALSE(PhysicalDisplayId::tryCast(id));
    EXPECT_FALSE(HalDisplayId::tryCast(id));

    EXPECT_EQ(id, DisplayId::fromValue(id.value));
    EXPECT_EQ(id, DisplayId::fromValue<GpuVirtualDisplayId>(id.value));
}

TEST(DisplayIdTest, createVirtualIdFromGpuVirtualId) {
    const VirtualDisplayId id(GpuVirtualDisplayId(42));
    EXPECT_TRUE(VirtualDisplayId::tryCast(id));
    EXPECT_TRUE(GpuVirtualDisplayId::tryCast(id));
    EXPECT_FALSE(HalVirtualDisplayId::tryCast(id));
    EXPECT_FALSE(PhysicalDisplayId::tryCast(id));
    EXPECT_FALSE(HalDisplayId::tryCast(id));

    const bool isGpuVirtualId = (id.value & VirtualDisplayId::FLAG_GPU);
    EXPECT_EQ((id.isVirtual() && isGpuVirtualId), GpuVirtualDisplayId::tryCast(id).has_value());
}

TEST(DisplayIdTest, createGpuVirtualIdFromUniqueId) {
    static const std::string kUniqueId("virtual:ui:DisplayId_test");
    const auto idOpt = GpuVirtualDisplayId::fromUniqueId(kUniqueId);
    ASSERT_TRUE(idOpt.has_value());
    const GpuVirtualDisplayId id = idOpt.value();
    EXPECT_TRUE(VirtualDisplayId::tryCast(id));
    EXPECT_TRUE(GpuVirtualDisplayId::tryCast(id));
    EXPECT_FALSE(HalVirtualDisplayId::tryCast(id));
    EXPECT_FALSE(PhysicalDisplayId::tryCast(id));
    EXPECT_FALSE(HalDisplayId::tryCast(id));

    EXPECT_EQ(id, DisplayId::fromValue(id.value));
    EXPECT_EQ(id, DisplayId::fromValue<GpuVirtualDisplayId>(id.value));
}

TEST(DisplayIdTest, createHalVirtualId) {
    const HalVirtualDisplayId id(42);
    EXPECT_TRUE(VirtualDisplayId::tryCast(id));
    EXPECT_TRUE(HalVirtualDisplayId::tryCast(id));
    EXPECT_FALSE(GpuVirtualDisplayId::tryCast(id));
    EXPECT_FALSE(PhysicalDisplayId::tryCast(id));
    EXPECT_TRUE(HalDisplayId::tryCast(id));

    EXPECT_EQ(id, DisplayId::fromValue(id.value));
    EXPECT_EQ(id, DisplayId::fromValue<HalVirtualDisplayId>(id.value));
}

TEST(DisplayIdTest, createVirtualIdFromHalVirtualId) {
    const VirtualDisplayId id(HalVirtualDisplayId(42));
    EXPECT_TRUE(VirtualDisplayId::tryCast(id));
    EXPECT_TRUE(HalVirtualDisplayId::tryCast(id));
    EXPECT_FALSE(GpuVirtualDisplayId::tryCast(id));
    EXPECT_FALSE(PhysicalDisplayId::tryCast(id));
    EXPECT_TRUE(HalDisplayId::tryCast(id));

    const bool isGpuVirtualId = (id.value & VirtualDisplayId::FLAG_GPU);
    EXPECT_EQ((id.isVirtual() && !isGpuVirtualId), HalVirtualDisplayId::tryCast(id).has_value());
}

} // namespace android::ui
