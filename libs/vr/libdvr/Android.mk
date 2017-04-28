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

include $(CLEAR_VARS)
LOCAL_MODULE := libdvr
LOCAL_MODULE_OWNER := google
LOCAL_MODULE_CLASS := STATIC_LIBRARIES

LOCAL_CFLAGS += \
    -fvisibility=hidden \
    -D DVR_EXPORT='__attribute__ ((visibility ("default")))'

LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/include \

LOCAL_EXPORT_C_INCLUDE_DIRS := \
    $(LOCAL_PATH)/include \

LOCAL_SRC_FILES := \
    display_manager_client.cpp \
    dvr_api.cpp \
    dvr_buffer.cpp \
    dvr_buffer_queue.cpp \
    dvr_hardware_composer_client.cpp \
    dvr_surface.cpp \
    vsync_client_api.cpp \

LOCAL_STATIC_LIBRARIES := \
    libbufferhub \
    libbufferhubqueue \
    libdisplay \
    libvrsensor \
    libvirtualtouchpadclient \
    libvr_hwc-impl \
    libvr_hwc-binder \
    libgrallocusage \

LOCAL_SHARED_LIBRARIES := \
    android.hardware.graphics.bufferqueue@1.0 \
    android.hidl.token@1.0-utils \
    libbase \
    libnativewindow \

include $(BUILD_STATIC_LIBRARY)

include $(call all-makefiles-under,$(LOCAL_PATH))
