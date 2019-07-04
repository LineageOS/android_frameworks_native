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
# This script provides the functions required for generating the
# vulkan api framework directly from the vulkan registry (vk.xml)

import os
import generator_common as gencom

def isInstanceDispatchTableEntry(functionName):
  if functionName == 'vkEnumerateDeviceLayerProperties': # deprecated, unused internally - @dbd33bc
    return False
  if gencom.gencom.isFunctionExported(functionName) and gencom.isInstanceDispatched(functionName):
    return True
  return False

def isDeviceDispatchTableEntry(functionName):
  if gencom.gencom.isFunctionExported(functionName) and gencom.gencom.isDeviceDispatched(functionName):
    return True
  return False

def api_genh():

  header = """#ifndef LIBVULKAN_API_GEN_H
#define LIBVULKAN_API_GEN_H

#include <vulkan/vulkan.h>

#include <bitset>

#include "driver_gen.h"

namespace vulkan {
namespace api {

"""

  tail = """
bool InitDispatchTable(
    VkInstance instance,
    PFN_vkGetInstanceProcAddr get_proc,
    const std::bitset<driver::ProcHook::EXTENSION_COUNT>& extensions);
bool InitDispatchTable(
    VkDevice dev,
    PFN_vkGetDeviceProcAddr get_proc,
    const std::bitset<driver::ProcHook::EXTENSION_COUNT>& extensions);

}  // namespace api
}  // namespace vulkan

#endif  // LIBVULKAN_API_GEN_H
"""
  genfile = os.path.join(os.path.dirname(__file__),'..','libvulkan','api_gen2.h')
  with open(genfile, 'w') as f:
    instanceDispatchTableEntries = []
    deviceDispatchTableEntries = []
    for commands in gencom.allCommandsList:
      if commands not in gencom.aliasDict:
        if gencom.isInstanceDispatchTableEntry(commands):
          instanceDispatchTableEntries.append('PFN_'+commands+' '+commands[2:]+';')
        elif gencom.isDeviceDispatchTableEntry(commands):
          deviceDispatchTableEntries.append('PFN_'+commands+' '+commands[2:]+';')

    f.write (gencom.copyright)
    f.write (gencom.warning)
    f.write (header)
    f.write ('struct InstanceDispatchTable {\n')
    gencom.clang_off(f,1)
    for functions in instanceDispatchTableEntries:
      f.write(gencom.clang_off_spaces + functions + '\n')
    gencom.clang_on(f,1)
    f.write ('};\n\n')

    f.write ('struct DeviceDispatchTable {\n')
    gencom.clang_off(f,1)
    for functions in deviceDispatchTableEntries:
      f.write(gencom.clang_off_spaces + functions + '\n')
    gencom.clang_on(f,1)
    f.write ('};\n')

    f.write (tail)
    f.close()

def defineInitProc(name, f):
  f.write ('#define UNLIKELY(expr) __builtin_expect((expr), 0)\n')
  f.write ('\n')
  f.write ("""#define INIT_PROC(required, obj, proc)                                 \\
    do {                                                               \\
        data.""" + name + """.proc =                                           \\
            reinterpret_cast<PFN_vk##proc>(get_proc(obj, "vk" #proc)); \\
        if (UNLIKELY(required && !data.""" + name + """.proc)) {               \\
            ALOGE("missing " #obj " proc: vk" #proc);                  \\
            success = false;                                           \\
        }                                                              \\
    } while (0)\n\n""")

def defineInitProcExt(f):
  f.write ('// Exported extension functions may be invoked even when their extensions\n')
  f.write ('// are disabled.  Dispatch to stubs when that happens.\n')
  f.write ("""#define INIT_PROC_EXT(ext, required, obj, proc)  \\
    do {                                         \\
        if (extensions[driver::ProcHook::ext])   \\
            INIT_PROC(required, obj, proc);      \\
        else                                     \\
            data.dispatch.proc = disabled##proc; \\
    } while (0)\n\n""")

def defineExtensionStub(functionName, f):
  if functionName in gencom.extensionsDict and gencom.isFunctionExported(functionName):
    extname = gencom.extensionsDict[functionName]
    base_name = functionName[2:]
    pList = gencom.paramDict[functionName]
    firstParam = pList[0][0] + pList[0][1]
    tailParams = [x[0][:-1] for x in pList[1:]]
    tailP = ', '.join(tailParams)
    f.write ('VKAPI_ATTR ' + gencom.returnTypeDict[functionName] + ' disabled' + base_name + '(' + firstParam + ', ' + tailP + ') {\n')
    f.write (gencom.clang_off_spaces)
    f.write ('driver::Logger(' + pList[0][1] + ').Err(' + pList[0][1] + ', \"' + extname + ' not enabled. Exported ' + functionName + ' not executed.\");\n')
    if gencom.returnTypeDict[functionName] != 'void':
      f.write(gencom.clang_off_spaces + 'return VK_SUCCESS;\n')
    f.write ('}\n\n')

def isIntercepted(functionName):
  if gencom.isFunctionSupported(functionName):
    if gencom.isGloballyDispatched(functionName):
      return True
    elif functionName == 'vkCreateDevice':
      return True
    elif functionName == 'vkEnumerateDeviceLayerProperties':
      return True
    elif functionName == 'vkEnumerateDeviceExtensionProperties':
      return True
    elif functionName == 'vkDestroyInstance':
      return True
    elif functionName == 'vkDestroyDevice':
      return True
  return False

def interceptInstanceProcAddr(functionName, f):
  indent = 1
  f.write (gencom.clang_off_spaces*indent + '// global functions\n' + gencom.clang_off_spaces*indent+ 'if (instance == VK_NULL_HANDLE) {\n')
  indent = indent + 1
  for cmds in gencom.allCommandsList:
    if gencom.isGloballyDispatched(cmds):
      f.write(gencom.clang_off_spaces*indent + 'if (strcmp(pName, \"' + cmds + '\") == 0) return reinterpret_cast<PFN_vkVoidFunction>(' + cmds[2:] + ');\n')

  f.write ('\n')
  f.write ("""        ALOGE("invalid vkGetInstanceProcAddr(VK_NULL_HANDLE, \\\"%s\\\") call", pName);
        return nullptr;
    }

    static const struct Hook {
        const char* name;
        PFN_vkVoidFunction proc;
    } hooks[] = {\n""")
  sortedCommandsList = sorted(gencom.allCommandsList)
  for cmds in sortedCommandsList:
    if gencom.isFunctionExported(cmds):
      if gencom.isGloballyDispatched(cmds):
        f.write (gencom.clang_off_spaces*2 + '{ \"' + cmds + '\", nullptr },\n')
      elif isIntercepted(cmds) or cmds == 'vkGetInstanceProcAddr' or gencom.isDeviceDispatched(cmds):
        f.write (gencom.clang_off_spaces*2 + '{ \"' + cmds + '\", reinterpret_cast<PFN_vkVoidFunction>(' + cmds[2:] + ') },\n')
  f.write (gencom.clang_off_spaces + """};
    // clang-format on
    constexpr size_t count = sizeof(hooks) / sizeof(hooks[0]);
    auto hook = std::lower_bound(
        hooks, hooks + count, pName,
        [](const Hook& h, const char* n) { return strcmp(h.name, n) < 0; });
    if (hook < hooks + count && strcmp(hook->name, pName) == 0) {
        if (!hook->proc) {
            vulkan::driver::Logger(instance).Err(
                instance, "invalid vkGetInstanceProcAddr(%p, \\\"%s\\\") call",
                instance, pName);
        }
        return hook->proc;
    }
    // clang-format off\n\n""")

def interceptDeviceProcAddr(functionName, f):
  f.write (gencom.clang_off_spaces + """if (device == VK_NULL_HANDLE) {
        ALOGE("invalid vkGetDeviceProcAddr(VK_NULL_HANDLE, ...) call");
        return nullptr;
    }\n\n""")
  f.write (gencom.clang_off_spaces + 'static const char* const known_non_device_names[] = {\n')
  sortedCommandsList = sorted(gencom.allCommandsList)
  for cmds in sortedCommandsList:
    if gencom.isFunctionSupported(cmds):
      if not gencom.isDeviceDispatched(cmds):
        f.write(gencom.clang_off_spaces*2 + '\"' + cmds + '\",\n')
  f.write(gencom.clang_off_spaces + '};\n')
  f.write(gencom.clang_off_spaces + """// clang-format on
    constexpr size_t count =
        sizeof(known_non_device_names) / sizeof(known_non_device_names[0]);
    if (!pName ||
        std::binary_search(
            known_non_device_names, known_non_device_names + count, pName,
            [](const char* a, const char* b) { return (strcmp(a, b) < 0); })) {
        vulkan::driver::Logger(device).Err(
            device, "invalid vkGetDeviceProcAddr(%p, \\\"%s\\\") call", device,
            (pName) ? pName : "(null)");
        return nullptr;
    }
    // clang-format off\n\n""")
  for cmds in gencom.allCommandsList:
    if gencom.isDeviceDispatched(cmds):
      if isIntercepted(cmds) or cmds == 'vkGetDeviceProcAddr':
        f.write (gencom.clang_off_spaces + 'if (strcmp(pName, "' + cmds + '") == 0) return reinterpret_cast<PFN_vkVoidFunction>(' + cmds[2:] + ');\n')
  f.write ('\n')

def apiDispatch(functionName, f):
  assert not isIntercepted(functionName)

  f.write (gencom.clang_off_spaces)
  if gencom.returnTypeDict[functionName] != 'void':
    f.write ('return ')

  paramList = gencom.paramDict[functionName]
  p0 = paramList[0][1]
  f.write('GetData(' + p0 + ').dispatch.' + functionName[2:] + '(' + ', '.join(i[1] for i in paramList) + ');\n')


def api_gencpp():
  genfile = os.path.join(os.path.dirname(__file__),'..','libvulkan','api_gen2.cpp')
  header = """#include <log/log.h>
#include <string.h>

#include <algorithm>

// to catch mismatches between vulkan.h and this file
#undef VK_NO_PROTOTYPES
#include "api.h"

namespace vulkan {
namespace api {

"""
  with open(genfile, 'w') as f:
    f.write (gencom.copyright)
    f.write (gencom.warning)
    f.write ("""#include <log/log.h>
#include <string.h>

#include <algorithm>

// to catch mismatches between vulkan.h and this file
#undef VK_NO_PROTOTYPES
#include "api.h"

namespace vulkan {
namespace api {\n\n""")
    defineInitProc('dispatch',f)
    defineInitProcExt(f)
    f.write ('namespace {\n\n')
    gencom.clang_off(f,0)
    f.write ('\n')
    for cmds in gencom.allCommandsList:
      defineExtensionStub(cmds,f)
    gencom.clang_on(f,0)
    f.write ('\n}  // namespace\n\n')
    f.write ("""bool InitDispatchTable(
    VkInstance instance,
    PFN_vkGetInstanceProcAddr get_proc,
    const std::bitset<driver::ProcHook::EXTENSION_COUNT>& extensions) {
    auto& data = GetData(instance);
    bool success = true;\n\n""")
    gencom.clang_off(f,1)
    for cmds in gencom.allCommandsList:
      if gencom.isInstanceDispatchTableEntry(cmds):
        gencom.initProc(cmds, f)
    gencom.clang_on(f,1)
    f.write ('\n')
    f.write ('    return success;\n}\n\n')
    f.write ("""bool InitDispatchTable(
    VkDevice dev,
    PFN_vkGetDeviceProcAddr get_proc,
    const std::bitset<driver::ProcHook::EXTENSION_COUNT>& extensions) {
    auto& data = GetData(dev);
    bool success = true;\n\n""")

    gencom.clang_off(f,1)
    for cmds in gencom.allCommandsList:
      if gencom.isDeviceDispatchTableEntry(cmds):
        gencom.initProc(cmds, f)
    gencom.clang_on(f,1)
    f.write ('\n')
    f.write ('    return success;\n}\n\n')

    gencom.clang_off(f,0)

    f.write ('\nnamespace {\n\n')
    f.write('// forward declarations needed by GetInstanceProcAddr and GetDeviceProcAddr\n')
    for cmds in gencom.allCommandsList:
      if gencom.isFunctionExported(cmds) and not isIntercepted(cmds):
        paramList = [''.join(i) for i in gencom.paramDict[cmds]]
        f.write ('VKAPI_ATTR '+gencom.returnTypeDict[cmds] + ' ' + cmds[2:] + '(' + ', '.join(paramList) + ');\n')

    f.write ('\n')

    for cmds in gencom.allCommandsList:
      if gencom.isFunctionExported(cmds) and not isIntercepted(cmds):
        paramList = [''.join(i) for i in gencom.paramDict[cmds]]
        f.write ('VKAPI_ATTR ' + gencom.returnTypeDict[cmds] + ' ' + cmds[2:] + '(' + ', '.join(paramList) + ') {\n')
        if cmds == 'vkGetInstanceProcAddr':
          interceptInstanceProcAddr(cmds, f)
        elif cmds == 'vkGetDeviceProcAddr':
          interceptDeviceProcAddr(cmds, f)
        apiDispatch(cmds, f)
        f.write('}\n\n')
    f.write ("""\n}  // anonymous namespace

// clang-format on

}  // namespace api
}  // namespace vulkan

// clang-format off\n\n""")

    for cmds in gencom.allCommandsList:
      if gencom.isFunctionExported(cmds):
        paramList = [''.join(i) for i in gencom.paramDict[cmds]]
        f.write ('__attribute__((visibility("default")))\n')
        f.write ('VKAPI_ATTR ' + gencom.returnTypeDict[cmds] + ' ' + cmds + '(' + ', '.join(paramList) + ') {\n')
        f.write (gencom.clang_off_spaces)
        if gencom.returnTypeDict[cmds] != 'void':
          f.write ('return ')
        paramList = gencom.paramDict[cmds]
        f.write ('vulkan::api::' + cmds[2:] + '(' + ', '.join(i[1] for i in paramList) + ');\n')
        f.write ('}\n\n')

    gencom.clang_on(f, 0)

