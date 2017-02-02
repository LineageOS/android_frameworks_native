# Copyright (C) 2015 The Android Open Source Project
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

sourceFiles := \
	native_window.cpp \
	native_buffer_queue.cpp \
	display_client.cpp \
	display_manager_client.cpp \
	display_manager_client_impl.cpp \
	display_rpc.cpp \
	dummy_native_window.cpp \
	gl_fenced_flush.cpp \
	graphics.cpp \
	late_latch.cpp \
	video_mesh_surface_client.cpp \
	vsync_client.cpp \
	vsync_client_api.cpp \
	screenshot_client.cpp \
	frame_history.cpp

includeFiles := \
	$(LOCAL_PATH)/include \
	frameworks/native/vulkan/include

sharedLibraries := \
	libbase \
	libcutils \
	liblog \
	libutils \
	libEGL \
	libGLESv2 \
	libvulkan \
	libui \
	libgui \
	libhardware \
	libsync

staticLibraries := \
	libbufferhub \
	libbufferhubqueue \
	libdvrcommon \
	libdvrgraphics \
	libsensor \
	libpdx_default_transport \

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := tests
LOCAL_SRC_FILES := $(sourceFiles)
LOCAL_C_INCLUDES := $(includeFiles)
#LOCAL_CPPFLAGS := -UNDEBUG -DDEBUG -O0 -g
LOCAL_CFLAGS += -DLOG_TAG=\"libdisplay\"
LOCAL_CFLAGS += -DTRACE=0
LOCAL_CFLAGS += -DATRACE_TAG=ATRACE_TAG_GRAPHICS
LOCAL_CFLAGS += -DGL_GLEXT_PROTOTYPES -DEGL_EGLEXT_PROTOTYPES
LOCAL_EXPORT_C_INCLUDE_DIRS := $(includeFiles)
LOCAL_SHARED_LIBRARIES := $(sharedLibraries)
LOCAL_STATIC_LIBRARIES := $(staticLibraries)
LOCAL_MODULE := libdisplay
include $(BUILD_STATIC_LIBRARY)


testFiles := \
  tests/graphics_app_tests.cpp

include $(CLEAR_VARS)
LOCAL_MODULE := graphics_app_tests
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
  $(testFiles) \

LOCAL_C_INCLUDES := \
  $(includeFiles) \

LOCAL_SHARED_LIBRARIES := \
  $(sharedLibraries) \

LOCAL_STATIC_LIBRARIES := \
  libdisplay \
  $(staticLibraries) \

include $(BUILD_NATIVE_TEST)
