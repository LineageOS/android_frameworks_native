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
# This script provides the common functions for generating the
# vulkan framework directly from the vulkan registry (vk.xml).

import os
import subprocess
import xml.etree.ElementTree as element_tree

_BLACKLISTED_EXTENSIONS = [
    'VK_EXT_acquire_xlib_display',
    'VK_EXT_direct_mode_display',
    'VK_EXT_display_control',
    'VK_EXT_display_surface_counter',
    'VK_EXT_full_screen_exclusive',
    'VK_EXT_headless_surface',
    'VK_EXT_metal_surface',
    'VK_FUCHSIA_imagepipe_surface',
    'VK_GGP_stream_descriptor_surface',
    'VK_KHR_display',
    'VK_KHR_display_swapchain',
    'VK_KHR_external_fence_win32',
    'VK_KHR_external_memory_win32',
    'VK_KHR_external_semaphore_win32',
    'VK_KHR_mir_surface',
    'VK_KHR_wayland_surface',
    'VK_KHR_win32_keyed_mutex',
    'VK_KHR_win32_surface',
    'VK_KHR_xcb_surface',
    'VK_KHR_xlib_surface',
    'VK_MVK_ios_surface',
    'VK_MVK_macos_surface',
    'VK_NN_vi_surface',
    'VK_NV_cooperative_matrix',
    'VK_NV_coverage_reduction_mode',
    'VK_NV_external_memory_win32',
    'VK_NV_win32_keyed_mutex',
    'VK_NVX_image_view_handle',
]

_EXPORTED_EXTENSIONS = [
    'VK_ANDROID_external_memory_android_hardware_buffer',
    'VK_KHR_android_surface',
    'VK_KHR_surface',
    'VK_KHR_swapchain',
]

_OPTIONAL_COMMANDS = [
    'vkGetSwapchainGrallocUsageANDROID',
    'vkGetSwapchainGrallocUsage2ANDROID',
]

_DISPATCH_TYPE_DICT = {
    'VkInstance ': 'Instance',
    'VkPhysicalDevice ': 'Instance',
    'VkDevice ': 'Device',
    'VkQueue ': 'Device',
    'VkCommandBuffer ': 'Device'
}

alias_dict = {}
command_list = []
extension_dict = {}
param_dict = {}
return_type_dict = {}
version_dict = {}


def indent(num):
  return '    ' * num


def copyright_and_warning(year):
  return """\
/*
 * Copyright """ + str(year) + """ The Android Open Source Project
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

// WARNING: This file is generated. See ../README.md for instructions.

"""


def run_clang_format(args):
  clang_call = ['clang-format', '--style', 'file', '-i', args]
  subprocess.check_call(clang_call)


def is_extension_internal(extension_name):
  return extension_name == 'VK_ANDROID_native_buffer'


def base_name(cmd):
  return cmd[2:]


def is_function_supported(cmd):
  if cmd not in extension_dict:
    return True
  else:
    if extension_dict[cmd] not in _BLACKLISTED_EXTENSIONS:
      return True
  return False


def get_dispatch_table_type(cmd):
  if cmd not in param_dict:
    return None

  if param_dict[cmd]:
    return _DISPATCH_TYPE_DICT.get(param_dict[cmd][0][0], 'Global')
  return 'Global'


def is_globally_dispatched(cmd):
  return is_function_supported(cmd) and get_dispatch_table_type(cmd) == 'Global'


def is_instance_dispatched(cmd):
  return (is_function_supported(cmd) and
          get_dispatch_table_type(cmd) == 'Instance')


def is_device_dispatched(cmd):
  return is_function_supported(cmd) and get_dispatch_table_type(cmd) == 'Device'


def is_extension_exported(extension_name):
  return extension_name in _EXPORTED_EXTENSIONS


def is_function_exported(cmd):
  if is_function_supported(cmd):
    if cmd in extension_dict:
      return is_extension_exported(extension_dict[cmd])
    return True
  return False


def is_instance_dispatch_table_entry(cmd):
  if cmd == 'vkEnumerateDeviceLayerProperties':
    # deprecated, unused internally - @dbd33bc
    return False
  return is_function_exported(cmd) and is_instance_dispatched(cmd)


def is_device_dispatch_table_entry(cmd):
  return is_function_exported(cmd) and is_device_dispatched(cmd)


def init_proc(name, f):
  f.write(indent(1))
  if name in extension_dict:
    f.write('INIT_PROC_EXT(' + extension_dict[name][3:] + ', ')
  else:
    f.write('INIT_PROC(')

  if name in version_dict and version_dict[name] == 'VK_VERSION_1_1':
    f.write('false, ')
  elif name in _OPTIONAL_COMMANDS:
    f.write('false, ')
  else:
    f.write('true, ')

  if is_instance_dispatched(name):
    f.write('instance, ')
  else:
    f.write('dev, ')

  f.write(base_name(name) + ');\n')


def parse_vulkan_registry():
  registry = os.path.join(os.path.dirname(__file__), '..', '..', '..', '..',
                          'external', 'vulkan-headers', 'registry', 'vk.xml')
  tree = element_tree.parse(registry)
  root = tree.getroot()
  for commands in root.iter('commands'):
    for command in commands:
      if command.tag == 'command':
        parameter_list = []
        protoset = False
        cmd_name = ''
        cmd_type = ''
        if command.get('alias') is not None:
          alias = command.get('alias')
          cmd_name = command.get('name')
          alias_dict[cmd_name] = alias
          command_list.append(cmd_name)
          param_dict[cmd_name] = param_dict[alias].copy()
          return_type_dict[cmd_name] = return_type_dict[alias]
        for params in command:
          if params.tag == 'param':
            param_type = ''
            if params.text is not None and params.text.strip():
              param_type = params.text.strip() + ' '
            type_val = params.find('type')
            param_type = param_type + type_val.text
            if type_val.tail is not None:
              param_type += type_val.tail.strip() + ' '
            pname = params.find('name')
            param_name = pname.text
            if pname.tail is not None and pname.tail.strip():
              parameter_list.append(
                  (param_type, param_name, pname.tail.strip()))
            else:
              parameter_list.append((param_type, param_name))
          if params.tag == 'proto':
            for c in params:
              if c.tag == 'type':
                cmd_type = c.text
              if c.tag == 'name':
                cmd_name = c.text
                protoset = True
                command_list.append(cmd_name)
                return_type_dict[cmd_name] = cmd_type
        if protoset:
          param_dict[cmd_name] = parameter_list.copy()

  for exts in root.iter('extensions'):
    for extension in exts:
      apiversion = ''
      if extension.tag == 'extension':
        extname = extension.get('name')
        for req in extension:
          if req.get('feature') is not None:
            apiversion = req.get('feature')
          for commands in req:
            if commands.tag == 'command':
              cmd_name = commands.get('name')
              if cmd_name not in extension_dict:
                extension_dict[cmd_name] = extname
                if apiversion:
                  version_dict[cmd_name] = apiversion

  for feature in root.iter('feature'):
    apiversion = feature.get('name')
    for req in feature:
      for command in req:
        if command.tag == 'command':
          cmd_name = command.get('name')
          if cmd_name in command_list:
            version_dict[cmd_name] = apiversion
