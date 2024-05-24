/*
 * Copyright 2024 The Android Open Source Project
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
 *
 */

#pragma once

#include <string>

namespace android::vkprofiles {

/*
 * vk**GetSupport is a function call to determine if the device supports a
 * specific Vulkan Profile. These functions call into
 * generated/vulkan_profiles.h and so only work with select profiles. If the
 * device supports the profile, the string "SUPPORTED" is returned, otherwise an
 * error message is returned.
 */
std::string vkAbp2021GetSupport();
std::string vkAbp2021GetSupportCpuOnly();
std::string vkAbp2022GetSupport();
std::string vkVpa15GetSupport();

// Returns a json string that enumerates support for any of the Vulkan profiles
// specified in the above functions
std::string vkProfiles();

}  // namespace android::vkprofiles
