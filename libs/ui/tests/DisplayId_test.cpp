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
    PhysicalDisplayId id = PhysicalDisplayId::fromEdid(port, manufacturerId, modelHash);
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
    PhysicalDisplayId id = PhysicalDisplayId::fromPort(port);
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
    GpuVirtualDisplayId id(42);
    EXPECT_TRUE(VirtualDisplayId::tryCast(id));
    EXPECT_TRUE(GpuVirtualDisplayId::tryCast(id));
    EXPECT_FALSE(HalVirtualDisplayId::tryCast(id));
    EXPECT_FALSE(PhysicalDisplayId::tryCast(id));
    EXPECT_FALSE(HalDisplayId::tryCast(id));

    EXPECT_EQ(id, DisplayId::fromValue(id.value));
    EXPECT_EQ(id, DisplayId::fromValue<GpuVirtualDisplayId>(id.value));
}

TEST(DisplayIdTest, createHalVirtualId) {
    HalVirtualDisplayId id(42);
    EXPECT_TRUE(VirtualDisplayId::tryCast(id));
    EXPECT_TRUE(HalVirtualDisplayId::tryCast(id));
    EXPECT_FALSE(GpuVirtualDisplayId::tryCast(id));
    EXPECT_FALSE(PhysicalDisplayId::tryCast(id));
    EXPECT_TRUE(HalDisplayId::tryCast(id));

    EXPECT_EQ(id, DisplayId::fromValue(id.value));
    EXPECT_EQ(id, DisplayId::fromValue<HalVirtualDisplayId>(id.value));
}

} // namespace android::ui
