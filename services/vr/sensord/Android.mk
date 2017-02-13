# Copyright (C) 2008 The Android Open Source Project
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
	pose_service.cpp \
	sensord.cpp \
	sensor_fusion.cpp \
	sensor_hal_thread.cpp \
	sensor_ndk_thread.cpp \
	sensor_service.cpp \
	sensor_thread.cpp \

includeFiles += \
	$(LOCAL_PATH)/include

staticLibraries := \
	libdvrcommon \
	libsensor \
	libperformance \
	libbufferhub \
	libpdx_default_transport \
	libposepredictor \

sharedLibraries := \
	libandroid \
	libbase \
	libbinder \
	libcutils \
	liblog \
	libhardware \
	libutils \

cFlags := -DLOG_TAG=\"sensord\" \
          -DTRACE=0

include $(CLEAR_VARS)
# Don't strip symbols so we see stack traces in logcat.
LOCAL_STRIP_MODULE := false
LOCAL_SRC_FILES := $(sourceFiles)
LOCAL_CFLAGS := $(cFlags)
LOCAL_STATIC_LIBRARIES := $(staticLibraries)
LOCAL_SHARED_LIBRARIES := $(sharedLibraries)
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_MODULE := sensord
LOCAL_C_INCLUDES := $(includeFiles)
LOCAL_C_INCLUDES += \
    $(call local-generated-sources-dir)/proto/frameworks/native/services/vr/sensord
LOCAL_INIT_RC := sensord.rc
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_STATIC_LIBRARIES := $(staticLibraries)
LOCAL_SHARED_LIBRARIES := $(sharedLibraries)
LOCAL_SRC_FILES := test/poselatencytest.cpp
LOCAL_MODULE := poselatencytest
include $(BUILD_EXECUTABLE)
