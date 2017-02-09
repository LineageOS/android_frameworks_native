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
  render_thread.cpp \
  shell_view.cpp \
  surface_flinger_view.cpp \
  texture.cpp \
  vr_window_manager.cpp \
  ../virtual_touchpad/aidl/android/dvr/VirtualTouchpadService.aidl \

src := \
  vr_window_manager_jni.cpp \
  application.cpp \
  controller_mesh.cpp \
  elbow_model.cpp \
  hwc_callback.cpp \
  reticle.cpp \
  render_thread.cpp \
  shell_view.cpp \
  surface_flinger_view.cpp \
  texture.cpp \
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
LOCAL_SRC_FILES := $(src)
LOCAL_STATIC_LIBRARIES := $(static_libs)
LOCAL_SHARED_LIBRARIES := $(shared_libs)
LOCAL_SHARED_LIBRARIES += libgvr
LOCAL_STATIC_LIBRARIES += libgvr_ext
LOCAL_CFLAGS += -DGL_GLEXT_PROTOTYPES
LOCAL_CFLAGS += -DEGL_EGLEXT_PROTOTYPES
LOCAL_CFLAGS += -DLOG_TAG=\"VrWindowManager\"
LOCAL_LDLIBS := -llog
LOCAL_MODULE := libvr_window_manager_jni
LOCAL_MODULE_TAGS := optional
LOCAL_MULTILIB := 64
LOCAL_CXX_STL := libc++_static
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(native_src)
LOCAL_STATIC_LIBRARIES := $(static_libs) libvrwm_binder
LOCAL_SHARED_LIBRARIES := $(shared_libs)
LOCAL_SHARED_LIBRARIES += libgvr
LOCAL_STATIC_LIBRARIES += libgvr_ext
LOCAL_CFLAGS += -DGL_GLEXT_PROTOTYPES
LOCAL_CFLAGS += -DEGL_EGLEXT_PROTOTYPES
LOCAL_CFLAGS += -DLOG_TAG=\"VrWindowManager\"
LOCAL_LDLIBS := -llog
LOCAL_MODULE := vr_wm
LOCAL_MODULE_TAGS := optional
LOCAL_INIT_RC := vr_wm.rc
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_PACKAGE_NAME := VrWindowManager

# We need to be priveleged to run as the system user, which is necessary for
# getting hmd input events and doing input injection.
LOCAL_CERTIFICATE := platform
LOCAL_PRIVILEGED_MODULE := true

LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := $(call all-java-files-under, java)
LOCAL_JNI_SHARED_LIBRARIES := libvr_window_manager_jni
LOCAL_STATIC_JAVA_AAR_LIBRARIES := gvr_common_library_aar
# gvr_common_library_aar depends on nano version of libprotobuf
LOCAL_STATIC_JAVA_LIBRARIES := libprotobuf-java-nano
# Make sure that libgvr's resources are loaded
LOCAL_AAPT_FLAGS += --auto-add-overlay
LOCAL_AAPT_FLAGS += --extra-packages com.google.vr.cardboard
LOCAL_PROGUARD_FLAG_FILES := proguard.flags
include $(BUILD_PACKAGE)


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
