# Copyright 2016 The Android Open Source Project
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

LOCAL_TARGET_DIR := $(TARGET_OUT_DATA)/local/tmp

LOCAL_PATH:= $(call my-dir)

include $(call first-makefiles-under, /frameworks/native/cmds/surfacereplayer/proto)

include $(CLEAR_VARS)

LOCAL_CPPFLAGS := -Weverything -Werror
LOCAL_CPPFLAGS := -Wno-unused-parameter
LOCAL_CPPFLAGS := -Wno-format

LOCAL_MODULE := libsurfacereplayer

LOCAL_SRC_FILES := \
    BufferQueueScheduler.cpp \
    Event.cpp \
    Replayer.cpp \

LOCAL_SHARED_LIBRARIES := \
    libEGL \
    libGLESv2 \
    libbinder \
    liblog \
    libcutils \
    libgui \
    libui \
    libutils \
    libprotobuf-cpp-full \

LOCAL_STATIC_LIBRARIES := \
    libtrace_proto \

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/..

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

LOCAL_MODULE := surfacereplayer

LOCAL_SRC_FILES := \
    Main.cpp \

LOCAL_SHARED_LIBRARIES := \
    libprotobuf-cpp-full \
    libsurfacereplayer \
    libutils \

LOCAL_STATIC_LIBRARIES := \
    libtrace_proto \

LOCAL_CPPFLAGS := -Weverything -Werror
LOCAL_CPPFLAGS := -Wno-unused-parameter

LOCAL_MODULE_PATH := $(LOCAL_TARGET_DIR)

include $(BUILD_EXECUTABLE)
