# Copyright (C) 2010 The Android Open Source Project
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

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	Fence.cpp \
	FramebufferNativeWindow.cpp \
	FrameStats.cpp \
	GraphicBuffer.cpp \
	GraphicBufferAllocator.cpp \
	GraphicBufferMapper.cpp \
	PixelFormat.cpp \
	Rect.cpp \
	Region.cpp \
	UiConfig.cpp

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libhardware \
	libsync \
	libutils \
	liblog

ifneq ($(BOARD_FRAMEBUFFER_FORCE_FORMAT),)
LOCAL_CFLAGS += -DFRAMEBUFFER_FORCE_FORMAT=$(BOARD_FRAMEBUFFER_FORCE_FORMAT)
endif

# Executed only on QCOM BSPs
ifeq ($(TARGET_USES_QCOM_BSP),true)
    LOCAL_CFLAGS += -DQCOM_BSP
endif

ifeq ($(BOARD_HAVE_PIXEL_FORMAT_INFO),true)
LOCAL_CFLAGS += -DHAVE_PIXEL_FORMAT_INFO
endif

LOCAL_MODULE:= libui

include $(BUILD_SHARED_LIBRARY)


# Include subdirectory makefiles
# ============================================================

# If we're building with ONE_SHOT_MAKEFILE (mm, mmm), then what the framework
# team really wants is to build the stuff defined by this makefile.
ifeq (,$(ONE_SHOT_MAKEFILE))
include $(call first-makefiles-under,$(LOCAL_PATH))
endif
