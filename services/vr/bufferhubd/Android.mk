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

sourceFiles := \
    buffer_hub.cpp \
    bufferhubd.cpp \
    consumer_channel.cpp \
    producer_channel.cpp \
    consumer_queue_channel.cpp \
    producer_queue_channel.cpp \

staticLibraries := \
	libperformance \
	libpdx_default_transport \
	libbufferhub

sharedLibraries := \
	libbase \
	libcutils \
	libhardware \
	liblog \
	libsync \
	libutils \
        libgui \
        libui

include $(CLEAR_VARS)
# Don't strip symbols so we see stack traces in logcat.
LOCAL_STRIP_MODULE := false
LOCAL_SRC_FILES := $(sourceFiles)
LOCAL_CFLAGS := -DLOG_TAG=\"bufferhubd\"
LOCAL_CFLAGS += -DTRACE=0
LOCAL_CFLAGS += -DATRACE_TAG=ATRACE_TAG_GRAPHICS
LOCAL_STATIC_LIBRARIES := $(staticLibraries)
LOCAL_SHARED_LIBRARIES := $(sharedLibraries)
LOCAL_MODULE := bufferhubd
LOCAL_INIT_RC := bufferhubd.rc
include $(BUILD_EXECUTABLE)

