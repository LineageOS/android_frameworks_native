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
	buffer_hub_client.cpp \
	buffer_hub_rpc.cpp \
	ion_buffer.cpp

includeFiles := \
	$(LOCAL_PATH)/include

staticLibraries := \
	libchrome \
	libdvrcommon \
	libpdx_default_transport \

sharedLibraries := \
	libbase \
	libcutils \
	libhardware \
	liblog \
	libui \
	libutils

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(sourceFiles)
LOCAL_C_INCLUDES := $(includeFiles)
LOCAL_CFLAGS := -DLOG_TAG=\"libbufferhub\"
LOCAL_CFLAGS += -DTRACE=0
LOCAL_EXPORT_C_INCLUDE_DIRS := $(includeFiles)
LOCAL_STATIC_LIBRARIES := $(staticLibraries)
LOCAL_SHARED_LIBRARIES := $(sharedLibraries)
LOCAL_MODULE := libbufferhub
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := bufferhub_tests.cpp
LOCAL_STATIC_LIBRARIES := libbufferhub $(staticLibraries)
LOCAL_SHARED_LIBRARIES := $(sharedLibraries)
LOCAL_MODULE := bufferhub_tests
include $(BUILD_NATIVE_TEST)

include $(call all-makefiles-under,$(LOCAL_PATH))
