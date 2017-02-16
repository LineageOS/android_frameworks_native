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

binder_src := \
  vr_window_manager_binder.cpp \
  aidl/android/service/vr/IVrWindowManager.aidl

static_libs := \
  libcutils

shared_libs := \
  libbase \
  libbinder \
  libutils

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(binder_src)
LOCAL_STATIC_LIBRARIES := $(static_libs)
LOCAL_SHARED_LIBRARIES := $(shared_libs)
LOCAL_CPPFLAGS += -std=c++11
LOCAL_CFLAGS += -DLOG_TAG=\"VrWindowManager\"
LOCAL_LDLIBS := -llog
LOCAL_MODULE := libvrwm_binder
LOCAL_MODULE_TAGS := optional
include $(BUILD_STATIC_LIBRARY)

native_src := \
  application.cpp \
  controller_mesh.cpp \
  elbow_model.cpp \
  hwc_callback.cpp \
  reticle.cpp \
  shell_view.cpp \
  surface_flinger_view.cpp \
  texture.cpp \
  vr_window_manager.cpp \
  ../virtual_touchpad/aidl/android/dvr/VirtualTouchpadService.aidl \

static_libs := \
  libdisplay \
  libbufferhub \
  libbufferhubqueue \
  libeds \
  libdvrgraphics \
  libdvrcommon \
  libhwcomposer-client \
  libsensor \
  libperformance \
  libpdx_default_transport \
  libcutils \

shared_libs := \
  android.dvr.composer@1.0 \
  android.hardware.graphics.composer@2.1 \
  libvrhwc \
  libandroid \
  libbase \
  libbinder \
  libinput \
  libhardware \
  libhwbinder \
  libsync \
  libutils \
  libgui \
  libEGL \
  libGLESv2 \
  libvulkan \
  libsync \
  libui \
  libhidlbase \
  libhidltransport

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(native_src)
LOCAL_STATIC_LIBRARIES := $(static_libs) libvrwm_binder
LOCAL_SHARED_LIBRARIES := $(shared_libs)
LOCAL_CFLAGS += -DGL_GLEXT_PROTOTYPES
LOCAL_CFLAGS += -DEGL_EGLEXT_PROTOTYPES
LOCAL_CFLAGS += -DLOG_TAG=\"VrWindowManager\"
LOCAL_LDLIBS := -llog
LOCAL_MODULE := vr_wm
LOCAL_MODULE_TAGS := optional
LOCAL_INIT_RC := vr_wm.rc
include $(BUILD_EXECUTABLE)

cmd_src := \
  vr_wm_ctl.cpp \
  aidl/android/service/vr/IVrWindowManager.aidl

static_libs := \
  libcutils

shared_libs := \
  libbase \
  libbinder \
  libutils

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(cmd_src)
LOCAL_STATIC_LIBRARIES := $(static_libs)
LOCAL_SHARED_LIBRARIES := $(shared_libs)
LOCAL_CPPFLAGS += -std=c++11
LOCAL_CFLAGS += -DLOG_TAG=\"vrwmctl\"
LOCAL_LDLIBS := -llog
LOCAL_MODULE := vr_wm_ctl
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)
