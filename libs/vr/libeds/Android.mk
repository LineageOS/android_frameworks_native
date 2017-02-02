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
	eds.cpp \
	eds_mesh.cpp \
	composite_hmd.cpp \
	cpu_thread_pose_updater.cpp \
	display_metrics.cpp \
	distortion_renderer.cpp \
	lucid_metrics.cpp \
	lucid_pose_tracker.cpp \
	lookup_radial_distortion.cpp \
	polynomial_radial_distortion.cpp

includeFiles += \
	$(LOCAL_PATH)/include

sharedLibraries := \
	libbase \
	libcutils \
	liblog \
	libEGL \
	libGLESv1_CM \
	libGLESv2 \
	libvulkan

staticLibraries := \
	libdisplay \
	libdvrcommon \
	libdvrgraphics \
	libsensor \
	libpdx_default_transport \

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(sourceFiles)
LOCAL_C_INCLUDES := $(includeFiles)
LOCAL_CFLAGS := -DGL_GLEXT_PROTOTYPES -DEGL_EGLEXT_PROTOTYPES
LOCAL_CFLAGS += -Wno-unused-parameter
# Enable debug options below to show GL errors and use gdb.
# LOCAL_CFLAGS += -UNDEBUG -DDEBUG -O0 -g
LOCAL_EXPORT_C_INCLUDE_DIRS := $(includeFiles)
LOCAL_SHARED_LIBRARIES := $(sharedLibraries)
LOCAL_STATIC_LIBRARIES := $(staticLibraries)
LOCAL_MODULE := libeds
include $(BUILD_STATIC_LIBRARY)


testFiles := \
  tests/eds_app_tests.cpp

include $(CLEAR_VARS)
LOCAL_MODULE := eds_app_tests
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
  $(testFiles) \

LOCAL_C_INCLUDES := \
  $(includeFiles) \

LOCAL_SHARED_LIBRARIES := \
  libhardware \
  libsync \
  $(sharedLibraries) \

LOCAL_STATIC_LIBRARIES := \
  libgmock_main \
  libgmock \
  libdisplay \
  libeds \
  libbufferhub \
  $(staticLibraries) \

include $(BUILD_NATIVE_TEST)
