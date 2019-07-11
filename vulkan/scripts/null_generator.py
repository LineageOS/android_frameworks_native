#!/usr/bin/env python3
#
# Copyright 2019 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This script provides the functions for generating the null driver
# framework directly from the vulkan registry (vk.xml).

import generator_common as gencom
import os

copyright = """/*
 * Copyright 2015 The Android Open Source Project
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

"""

def isDriverExtension(extensionName):
  switchCase = {
    'VK_ANDROID_native_buffer' : True,
    'VK_EXT_debug_report' : True,
    'VK_KHR_get_physical_device_properties2' : True
  }

  if extensionName in switchCase:
    return switchCase[extensionName]
  return False

def isDriverFunction(functionName):
  if functionName in gencom.extensionsDict:
    return isDriverExtension(gencom.extensionsDict[functionName])
  return True

def null_driver_genh():
  header = """#ifndef NULLDRV_NULL_DRIVER_H
#define NULLDRV_NULL_DRIVER_H 1

#include <vulkan/vk_android_native_buffer.h>
#include <vulkan/vulkan.h>

namespace null_driver {

PFN_vkVoidFunction GetGlobalProcAddr(const char* name);
PFN_vkVoidFunction GetInstanceProcAddr(const char* name);

"""
  genfile = os.path.join(os.path.dirname(__file__),'..','nulldrv','null_driver_gen2.h')
  with open(genfile, 'w') as f:
    f.write (copyright)
    f.write (gencom.warning)
    f.write (header)
    gencom.clang_off(f,0)

    for cmds in gencom.allCommandsList:
      if isDriverFunction(cmds):
        paramList = [''.join(i) for i in gencom.paramDict[cmds]]
        f.write ('VKAPI_ATTR ' + gencom.returnTypeDict[cmds] + ' ' + cmds[2:] + '(' +', '.join(paramList) + ');\n')
    f.write ("""VKAPI_ATTR VkResult GetSwapchainGrallocUsageANDROID(VkDevice device, VkFormat format, VkImageUsageFlags imageUsage, int* grallocUsage);
VKAPI_ATTR VkResult AcquireImageANDROID(VkDevice device, VkImage image, int nativeFenceFd, VkSemaphore semaphore, VkFence fence);
VKAPI_ATTR VkResult QueueSignalReleaseImageANDROID(VkQueue queue, uint32_t waitSemaphoreCount, const VkSemaphore* pWaitSemaphores, VkImage image, int* pNativeFenceFd);\n""")
    gencom.clang_on(f,0)

    f.write ('\n}  // namespace null_driver\n')
    f.write ('\n#endif  // NULLDRV_NULL_DRIVER_H\n')

def null_driver_gencpp():
  header = """#include <algorithm>

#include "null_driver_gen.h"

using namespace null_driver;

namespace {

struct NameProc {
    const char* name;
    PFN_vkVoidFunction proc;
};

PFN_vkVoidFunction Lookup(const char* name,
                          const NameProc* begin,
                          const NameProc* end) {
    const auto& entry = std::lower_bound(
        begin, end, name,
        [](const NameProc& e, const char* n) { return strcmp(e.name, n) < 0; });
    if (entry == end || strcmp(entry->name, name) != 0)
        return nullptr;
    return entry->proc;
}

template <size_t N>
PFN_vkVoidFunction Lookup(const char* name, const NameProc (&procs)[N]) {
    return Lookup(name, procs, procs + N);
}

const NameProc kGlobalProcs[] = {
"""
  genfile = os.path.join(os.path.dirname(__file__),'..','nulldrv','null_driver_gen2.cpp')
  with open(genfile, 'w') as f:
    f.write (copyright)
    f.write (gencom.warning)
    f.write (header)
    gencom.clang_off(f,1)

    sortedCommandsList = sorted(gencom.allCommandsList)
    for cmds in sortedCommandsList:
      if isDriverFunction(cmds) and gencom.getDispatchTableType(cmds) == 'Global':
        f.write (gencom.clang_off_spaces + '{\"' + cmds + '\", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_' + cmds + '>(' + cmds[2:] + '))},\n')
    gencom.clang_on(f,1)
    f.write ('};\n\n')

    f.write ('const NameProc kInstanceProcs[] = {\n')
    gencom.clang_off(f,1)
    for cmds in sortedCommandsList:
      if isDriverFunction(cmds):
        f.write (gencom.clang_off_spaces + '{\"' + cmds + '\", reinterpret_cast<PFN_vkVoidFunction>(static_cast<PFN_' + cmds + '>(' + cmds[2:] + '))},\n')
    gencom.clang_on(f,1)
    f.write ('};\n\n}  // namespace\n\n')

    f.write ("""namespace null_driver {

PFN_vkVoidFunction GetGlobalProcAddr(const char* name) {
    return Lookup(name, kGlobalProcs);
}

PFN_vkVoidFunction GetInstanceProcAddr(const char* name) {
    return Lookup(name, kInstanceProcs);
}

}  // namespace null_driver\n""")

