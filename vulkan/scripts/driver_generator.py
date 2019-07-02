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
# This script provides the functions for generating the
# vulkan driver framework directly from the vulkan registry (vk.xml).

import generator_common as gencom
import os

interceptedExtensions = [
  'VK_ANDROID_native_buffer',
  'VK_EXT_debug_report',
  'VK_EXT_hdr_metadata',
  'VK_EXT_swapchain_colorspace',
  'VK_GOOGLE_display_timing',
  'VK_KHR_android_surface',
  'VK_KHR_incremental_present',
  'VK_KHR_shared_presentable_image',
  'VK_KHR_surface',
  'VK_KHR_swapchain',
  'VK_KHR_get_surface_capabilities2'
]

knownExtensions = interceptedExtensions + [
  'VK_KHR_get_physical_device_properties2',
  'VK_ANDROID_external_memory_android_hardware_buffer',
  'VK_KHR_bind_memory2'
]

def defineProcHookType(f):
  f.write ("""struct ProcHook {
    enum Type {
        GLOBAL,
        INSTANCE,
        DEVICE,
    };
    enum Extension {\n""")
  for exts in knownExtensions:
    f.write (gencom.clang_off_spaces*2 + exts[3:] + ',\n')
  f.write ('\n')
  f.write (gencom.clang_off_spaces*2 + """EXTENSION_CORE,  // valid bit
        EXTENSION_COUNT,
        EXTENSION_UNKNOWN,
    };

    const char* name;
    Type type;
    Extension extension;

    PFN_vkVoidFunction proc;
    PFN_vkVoidFunction checked_proc;  // always nullptr for non-device hooks
};\n\n""")

def isExtensionIntercepted(extensionName):
  if extensionName in interceptedExtensions:
    return True
  return False

def isDriverTableEntry(functionName):
  switchCase = {
    # Create functions of dispatchable objects
    'vkCreateDevice' : True,
    'vkGetDeviceQueue' : True,
    'vkGetDeviceQueue2' : True,
    'vkAllocateCommandBuffers' : True,

    # Destroy functions of dispatchable objects
    'vkDestroyInstance' : True,
    'vkDestroyDevice' : True,

    # Enumeration of extensions
    'vkEnumerateDeviceExtensionProperties' : True,

    # We cache physical devices in loader.cpp
    'vkEnumeratePhysicalDevices' : True,
    'vkEnumeratePhysicalDeviceGroups' : True,

    'vkGetInstanceProcAddr' : True,
    'vkGetDeviceProcAddr' : True,

    # VK_KHR_swapchain->VK_ANDROID_native_buffer translation
    'vkCreateImage' : True,
    'vkDestroyImage' : True,

    'vkGetPhysicalDeviceProperties' : True,
    'vkGetPhysicalDeviceProperties2' : True,
    'vkGetPhysicalDeviceProperties2KHR' : True,

    # VK_KHR_swapchain v69 requirement
    'vkBindImageMemory2' : True,
    'vkBindImageMemory2KHR' : True
  }
  if gencom.isFunctionSupported(functionName):
    if functionName in switchCase:
      return True
    if functionName in gencom.extensionsDict:
      if gencom.extensionsDict[functionName] == 'VK_ANDROID_native_buffer' or gencom.extensionsDict[functionName] == 'VK_EXT_debug_report':
        return True
  return False

def isInstanceDriverTableEntry(functionName):
  if isDriverTableEntry(functionName) and gencom.isInstanceDispatched(functionName):
    return True
  return False

def isDeviceDriverTableEntry(functionName):
  if isDriverTableEntry(functionName) and gencom.isDeviceDispatched(functionName):
    return True
  return False

def driver_genh():
  header = """#ifndef LIBVULKAN_DRIVER_GEN_H
#define LIBVULKAN_DRIVER_GEN_H

#include <vulkan/vk_android_native_buffer.h>
#include <vulkan/vulkan.h>

#include <bitset>

namespace vulkan {
namespace driver {\n\n"""
  genfile = os.path.join(os.path.dirname(__file__),'..','libvulkan','driver_gen2.h')
  with open(genfile, 'w') as f:
    f.write (gencom.copyright)
    f.write (gencom.warning)
    f.write (header)
    defineProcHookType(f)
    f.write ('struct InstanceDriverTable {\n')
    gencom.clang_off(f, 1)
    for cmds in gencom.allCommandsList:
      if isInstanceDriverTableEntry(cmds):
        f.write (gencom.clang_off_spaces + 'PFN_' + cmds + ' ' + cmds[2:] + ';\n')
    gencom.clang_on(f, 1)
    f.write ('};\n\n')
    f.write ('struct DeviceDriverTable {\n')
    gencom.clang_off(f,1)
    for cmds in gencom.allCommandsList:
      if isDeviceDriverTableEntry(cmds):
        f.write (gencom.clang_off_spaces + 'PFN_' + cmds + ' ' + cmds[2:] + ';\n')
    gencom.clang_on(f,1)
    f.write ('};\n\n')
    f.write ("""const ProcHook* GetProcHook(const char* name);
ProcHook::Extension GetProcHookExtension(const char* name);

bool InitDriverTable(VkInstance instance,
                     PFN_vkGetInstanceProcAddr get_proc,
                     const std::bitset<ProcHook::EXTENSION_COUNT>& extensions);
bool InitDriverTable(VkDevice dev,
                     PFN_vkGetDeviceProcAddr get_proc,
                     const std::bitset<ProcHook::EXTENSION_COUNT>& extensions);

}  // namespace driver
}  // namespace vulkan

#endif  // LIBVULKAN_DRIVER_TABLE_H\n""")

def isIntercepted(functionName):
  switchCase = {
    # Create functions of dispatchable objects
    'vkCreateInstance' : True,
    'vkCreateDevice' : True,
    'vkEnumeratePhysicalDevices' : True,
    'vkEnumeratePhysicalDeviceGroups' : True,
    'vkGetDeviceQueue' : True,
    'vkGetDeviceQueue2' : True,
    'vkAllocateCommandBuffers' : True,

    # Destroy functions of dispatchable objects
    'vkDestroyInstance' : True,
    'vkDestroyDevice' : True,

    # Enumeration of extensions
    'vkEnumerateInstanceExtensionProperties' : True,
    'vkEnumerateDeviceExtensionProperties' : True,

    'vkGetInstanceProcAddr' : True,
    'vkGetDeviceProcAddr' : True,

    # VK_KHR_swapchain v69 requirement
    'vkBindImageMemory2' : True,
    'vkBindImageMemory2KHR' : True
  }
  if gencom.isFunctionSupported(functionName):
    if functionName in switchCase:
      return switchCase[functionName]

    if functionName in gencom.extensionsDict:
      return isExtensionIntercepted(gencom.extensionsDict[functionName])
  return False

def needProcHookStub(functionName):
  if isIntercepted(functionName) and gencom.isDeviceDispatched(functionName):
    if functionName in gencom.extensionsDict:
      if not gencom.isExtensionInternal(gencom.extensionsDict[functionName]):
        return True
  return False

def defineInitProc(name, f):
  f.write ('#define UNLIKELY(expr) __builtin_expect((expr), 0)\n')
  f.write ('\n')
  f.write ("""#define INIT_PROC(required, obj, proc)                                 \\
    do {                                                               \\
        data.""" + name + """.proc =                                             \\
            reinterpret_cast<PFN_vk##proc>(get_proc(obj, "vk" #proc)); \\
        if (UNLIKELY(required && !data.""" + name + """.proc)) {                 \\
            ALOGE("missing " #obj " proc: vk" #proc);                  \\
            success = false;                                           \\
        }                                                              \\
    } while (0)\n\n""")

def defineInitProcExt(f):
  f.write ("""#define INIT_PROC_EXT(ext, required, obj, proc) \\
    do {                                        \\
        if (extensions[ProcHook::ext])          \\
            INIT_PROC(required, obj, proc);     \\
    } while (0)\n\n""")

def defineProcHookStub(functionName, f):
  if needProcHookStub(functionName):
    ext_name = gencom.extensionsDict[functionName]
    base_name = functionName[2:]
    paramList = [''.join(i) for i in gencom.paramDict[functionName]]
    p0 = gencom.paramDict[functionName][0][1]
    f.write ('VKAPI_ATTR ' + gencom.returnTypeDict[functionName] + ' checked' + base_name + '(' + ', '.join(paramList) + ') {\n')
    ext_hook = 'ProcHook::' + ext_name[3:]

    f.write (gencom.clang_off_spaces + 'if (GetData(' + p0 + ').hook_extensions[' + ext_hook + ']) {\n')
    f.write (gencom.clang_off_spaces *2)
    if gencom.returnTypeDict[functionName] != 'void':
      f.write ('return ')
    paramNames = [''.join(i[1]) for i in gencom.paramDict[functionName]]
    f.write (base_name + '(' + ', '.join(paramNames) + ');\n')
    f.write (gencom.clang_off_spaces + '} else {\n')
    f.write (gencom.clang_off_spaces*2 + 'Logger(' + p0 + ').Err(' + p0 + ', \"' + ext_name + ' not enabled. ' + functionName + ' not executed.\");\n')
    if gencom.returnTypeDict[functionName] != 'void':
      f.write (gencom.clang_off_spaces*2 + 'return VK_SUCCESS;\n')
    f.write (gencom.clang_off_spaces + '}\n')
    f.write ('}\n\n')

def defineGlobalProcHook(functionName, f):
  base_name = functionName[2:]
  assert (functionName not in gencom.extensionsDict)
  f.write (gencom.clang_off_spaces + '{\n' + gencom.clang_off_spaces*2 + '\"' + functionName + '\",\n' + gencom.clang_off_spaces*2)
  f.write ("""ProcHook::GLOBAL,
        ProcHook::EXTENSION_CORE,
        reinterpret_cast<PFN_vkVoidFunction>(""" + base_name  + """),
        nullptr,
    },\n""")

def defineInstanceProcHook(functionName, f):
  base_name = functionName[2:]
  f.write (gencom.clang_off_spaces + '{\n')
  f.write (gencom.clang_off_spaces*2 + '\"' + functionName + '\",\n')
  f.write (gencom.clang_off_spaces*2 + 'ProcHook::INSTANCE,\n')

  if functionName in gencom.extensionsDict:
    ext_name = gencom.extensionsDict[functionName]
    f.write (gencom.clang_off_spaces*2 + 'ProcHook::' + ext_name[3:] + ',\n')
    if gencom.isExtensionInternal(ext_name):
      f.write (gencom.clang_off_spaces*2 + 'nullptr,\n' + gencom.clang_off_spaces*2 + 'nullptr,\n')
    else:
      f.write (gencom.clang_off_spaces*2 + 'reinterpret_cast<PFN_vkVoidFunction>(' + base_name + '),\n' + gencom.clang_off_spaces*2 + 'nullptr,\n')

  else:
    f.write (gencom.clang_off_spaces*2 + """ProcHook::EXTENSION_CORE,
        reinterpret_cast<PFN_vkVoidFunction>(""" + base_name + """),
        nullptr,\n""")

  f.write (gencom.clang_off_spaces + '},\n')

def defineDeviceProcHook(functionName, f):
  base_name = functionName[2:]
  f.write (gencom.clang_off_spaces + '{\n')
  f.write (gencom.clang_off_spaces*2 + '\"' + functionName + '\",\n')
  f.write (gencom.clang_off_spaces*2 + 'ProcHook::DEVICE,\n')

  if functionName in gencom.extensionsDict:
    ext_name = gencom.extensionsDict[functionName]
    f.write (gencom.clang_off_spaces*2 + 'ProcHook::' + ext_name[3:] + ',\n')
    if gencom.isExtensionInternal(ext_name):
      f.write (gencom.clang_off_spaces*2 + 'nullptr,\n' + gencom.clang_off_spaces*2 + 'nullptr,\n')
    else:
      f.write (gencom.clang_off_spaces*2 + 'reinterpret_cast<PFN_vkVoidFunction>(' + base_name + '),\n' + gencom.clang_off_spaces*2 + 'reinterpret_cast<PFN_vkVoidFunction>(checked' + base_name + '),\n')

  else:
    f.write (gencom.clang_off_spaces*2 + """ProcHook::EXTENSION_CORE,
        reinterpret_cast<PFN_vkVoidFunction>(""" + base_name + """),
        nullptr,\n""")

  f.write (gencom.clang_off_spaces + '},\n')

def driver_gencpp():
  header = """#include <log/log.h>
#include <string.h>

#include <algorithm>

#include "driver.h"

namespace vulkan {
namespace driver {

namespace {

// clang-format off\n\n"""

  genfile = os.path.join(os.path.dirname(__file__),'..','libvulkan','driver_gen2.cpp')

  with open(genfile, 'w') as f:
    f.write (gencom.copyright)
    f.write (gencom.warning)
    f.write (header)

    for cmds in gencom.allCommandsList:
      defineProcHookStub(cmds, f)
    gencom.clang_on(f, 0)
    f.write ('\n')

    f.write ('const ProcHook g_proc_hooks[] = {\n')
    gencom.clang_off(f, 1)
    sortedCommandsList = sorted(gencom.allCommandsList)
    for cmds in sortedCommandsList:
      if isIntercepted(cmds):
        if gencom.isGloballyDispatched(cmds):
          defineGlobalProcHook(cmds, f)
        elif gencom.isInstanceDispatched(cmds):
          defineInstanceProcHook(cmds, f)
        elif gencom.isDeviceDispatched(cmds):
          defineDeviceProcHook(cmds, f)
    gencom.clang_on(f, 1)
    f.write ('};\n\n}  // namespace\n\n')

    f.write ("""const ProcHook* GetProcHook(const char* name) {
    const auto& begin = g_proc_hooks;
    const auto& end =
        g_proc_hooks + sizeof(g_proc_hooks) / sizeof(g_proc_hooks[0]);
    const auto hook = std::lower_bound(
        begin, end, name,
        [](const ProcHook& e, const char* n) { return strcmp(e.name, n) < 0; });
    return (hook < end && strcmp(hook->name, name) == 0) ? hook : nullptr;
}\n\n""")

    f.write ('ProcHook::Extension GetProcHookExtension(const char* name) {\n')
    gencom.clang_off(f, 1)
    for exts in knownExtensions:
      f.write (gencom.clang_off_spaces + 'if (strcmp(name, \"' + exts + '\") == 0) return ProcHook::' + exts[3:] + ';\n')
    gencom.clang_on(f, 1)
    f.write (gencom.clang_off_spaces + 'return ProcHook::EXTENSION_UNKNOWN;\n')
    f.write ('}\n\n')

    defineInitProc('driver', f)
    defineInitProcExt(f)

    f.write ("""bool InitDriverTable(VkInstance instance,
                     PFN_vkGetInstanceProcAddr get_proc,
                     const std::bitset<ProcHook::EXTENSION_COUNT>& extensions) {
    auto& data = GetData(instance);
    bool success = true;\n\n""")
    gencom.clang_off(f, 1)
    for cmds in gencom.allCommandsList:
      if isInstanceDriverTableEntry(cmds):
        gencom.initProc(cmds, f)
    gencom.clang_on(f, 1)
    f.write ('\n' + gencom.clang_off_spaces + 'return success;\n')
    f.write ('}\n\n')

    f.write ("""bool InitDriverTable(VkDevice dev,
                     PFN_vkGetDeviceProcAddr get_proc,
                     const std::bitset<ProcHook::EXTENSION_COUNT>& extensions) {
    auto& data = GetData(dev);
    bool success = true;\n\n""")
    gencom.clang_off(f, 1)
    for cmds in gencom.allCommandsList:
      if isDeviceDriverTableEntry(cmds):
        gencom.initProc(cmds, f)
    gencom.clang_on(f, 1)
    f.write ('\n' + gencom.clang_off_spaces + 'return success;\n')
    f.write ('}\n\n}  // namespace driver\n}  // namespace vulkan\n\n')
    gencom.clang_on(f, 0)

