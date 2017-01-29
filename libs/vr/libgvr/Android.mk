# Copyright (C) 2016 The Android Open Source Project
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

include_dirs := \
  $(LOCAL_PATH)/include \
  $(LOCAL_PATH)/prebuilt/include

# Java platform library for the system implementation of the GVR API.
include $(CLEAR_VARS)
LOCAL_MODULE := gvr_platform
LOCAL_MODULE_STEM := com.google.vr.gvr.platform
LOCAL_REQUIRED_MODULES := libgvr_system_loader libgvr_system
LOCAL_SRC_FILES := $(call all-subdir-java-files)
include $(BUILD_JAVA_LIBRARY)

# Library to perform dlopen on the actual platform library.
include $(CLEAR_VARS)
LOCAL_MODULE := libgvr_system_loader
LOCAL_SRC_FILES := library_loader.cpp
include $(BUILD_SHARED_LIBRARY)

# Shared library implementing the GVR API.
include $(CLEAR_VARS)
LOCAL_MODULE := libgvr_system

LOCAL_SRC_FILES := \
    shim_gvr.cpp \
    shim_gvr_controller.cpp \
    shim_gvr_private.cpp \
    deviceparams/CardboardDevice.nolite.proto

LOCAL_MODULE_CLASS := SHARED_LIBRARIES

LOCAL_C_INCLUDES := $(include_dirs)
LOCAL_C_INCLUDES += $(call local-generated-sources-dir)/proto/$(LOCAL_PATH)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(include_dirs)

gvr_api_linker_script := $(LOCAL_PATH)/exported_apis.lds
LOCAL_ADDITIONAL_DEPENDENCIES := $(gvr_api_linker_script)

LOCAL_CFLAGS += -DGL_GLEXT_PROTOTYPES
LOCAL_CFLAGS += -DEGL_EGLEXT_PROTOTYPES
LOCAL_LDFLAGS += -Wl,-version-script,$(gvr_api_linker_script)

LOCAL_SHARED_LIBRARIES := \
    libandroid_runtime \
    libbase \
    libbinder \
    libcutils \
    libutils \
    libgui \
    libui \
    libEGL \
    libGLESv2 \
    libvulkan \
    libhardware \
    liblog \
    libsync \
    libevent \
    libprotobuf-cpp-full

LOCAL_STATIC_LIBRARIES := \
    libdisplay \
    libbufferhub \
    libbufferhubqueue \
    libchrome \
    libdvrcommon \
    libeds \
    libdvrgraphics \
    libsensor \
    libperformance \
    libpdx_default_transport \

include $(BUILD_SHARED_LIBRARY)

# Prebuilt shared library for libgvr_audio.so
include $(CLEAR_VARS)
LOCAL_MODULE := libgvr_audio
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
LOCAL_MODULE_SUFFIX := .so
LOCAL_MULTILIB := both
LOCAL_MODULE_TARGET_ARCH := arm arm64 x86 x86_64
LOCAL_SRC_FILES_arm := prebuilt/lib/android_arm/libgvr_audio.so
LOCAL_SRC_FILES_arm64 := prebuilt/lib/android_arm64/libgvr_audio.so
LOCAL_SRC_FILES_x86 := prebuilt/lib/android_x86/libgvr_audio.so
LOCAL_SRC_FILES_x86_64 := prebuilt/lib/android_x86_64/libgvr_audio.so
include $(BUILD_PREBUILT)

# Prebuilt shared library for libgvr.so
include $(CLEAR_VARS)
LOCAL_MODULE := libgvr
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/prebuilt/include
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
LOCAL_MODULE_SUFFIX := .so
LOCAL_MULTILIB := both
LOCAL_MODULE_TARGET_ARCH := arm arm64 x86 x86_64
LOCAL_SRC_FILES_arm := prebuilt/lib/android_arm/libgvr.so
LOCAL_SRC_FILES_arm64 := prebuilt/lib/android_arm64/libgvr.so
LOCAL_SRC_FILES_x86 := prebuilt/lib/android_x86/libgvr.so
LOCAL_SRC_FILES_x86_64 := prebuilt/lib/android_x86_64/libgvr.so
include $(BUILD_PREBUILT)

# Prebuilt Java static library for common_library.aar
include $(CLEAR_VARS)
LOCAL_PREBUILT_STATIC_JAVA_LIBRARIES := \
    gvr_common_library_aar:prebuilt/lib/common_library.aar
include $(BUILD_MULTI_PREBUILT)

# Dummy libgvr_ext to be used along side libgvr.so prebuilt.
# This shall be replaced with Google3 prebuilts in future.
include $(CLEAR_VARS)
LOCAL_MODULE := libgvr_ext
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
LOCAL_SRC_FILES := dummy_gvr_ext.cpp
LOCAL_STATIC_LIBRARIES := libchrome
LOCAL_LDLIBS := -llog
LOCAL_MODULE_TAGS := optional
LOCAL_SHARED_LIBRARIES += libgvr
LOCAL_MODULE_TARGET_ARCH := arm arm64 x86 x86_64
include $(BUILD_STATIC_LIBRARY)
