# Copyright (C) 2017 The Android Open Source Project
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

LOCAL_PATH := $(call my-dir)

src_files := \
  vr_manager.cpp \

inc_files := \
  frameworks/native/include/vr/vr_manager

static_libs := \
  libutils \
  libbinder \

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(src_files)
LOCAL_C_INCLUDES := $(inc_files)
LOCAL_CFLAGS += -Wall
LOCAL_CFLAGS += -Werror
LOCAL_CFLAGS += -Wunused
LOCAL_CFLAGS += -Wunreachable-code
LOCAL_EXPORT_C_INCLUDE_DIRS := $(inc_files)
#LOCAL_SHARED_LIBRARIES := $(sharedLibraries)
LOCAL_STATIC_LIBRARIES := $(static_libs)
LOCAL_MODULE := libvr_manager
include $(BUILD_STATIC_LIBRARY)
