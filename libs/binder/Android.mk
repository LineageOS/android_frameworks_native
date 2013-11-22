# Copyright (C) 2009 The Android Open Source Project
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

# we have the common sources, plus some device-specific stuff
sources := \
    AppOpsManager.cpp \
    Binder.cpp \
    BpBinder.cpp \
    BufferedTextOutput.cpp \
    Debug.cpp \
    IAppOpsCallback.cpp \
    IAppOpsService.cpp \
    IInterface.cpp \
    IMemory.cpp \
    IPCThreadState.cpp \
    IPermissionController.cpp \
    IServiceManager.cpp \
    MemoryDealer.cpp \
    MemoryBase.cpp \
    MemoryHeapBase.cpp \
    Parcel.cpp \
    PermissionCache.cpp \
    ProcessState.cpp \
    Static.cpp \
    TextOutput.cpp \

ifeq ($(BOARD_NEEDS_MEMORYHEAPPMEM),true)
sources += \
    MemoryHeapPmem.cpp
endif

ifeq ($(BOARD_NEEDS_MEMORYHEAPION),true)
sources += \
    MemoryHeapIon.cpp
endif

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

ifeq ($(BOARD_NEEDS_MEMORYHEAPION),true)
LOCAL_SHARED_LIBRARIES += libion_exynos
LOCAL_CFLAGS += -DUSE_MEMORY_HEAP_ION
ifneq ($(TARGET_SLSI_VARIANT),)
PLATFORM_DIR := $(TARGET_BOARD_PLATFORM)-$(TARGET_SLSI_VARIANT)
else
PLATFORM_DIR := $(TARGET_BOARD_PLATFORM)
endif
LOCAL_C_INCLUDES += hardware/samsung_slsi/$(PLATFORM_DIR)/include
endif

LOCAL_LDLIBS += -lpthread
LOCAL_MODULE := libbinder
LOCAL_SHARED_LIBRARIES += liblog libcutils libutils
LOCAL_SRC_FILES := $(sources)

include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)

ifeq ($(BOARD_NEEDS_MEMORYHEAPION),true)
LOCAL_SHARED_LIBRARIES += libion_exynos
LOCAL_CFLAGS += -DUSE_MEMORY_HEAP_ION
ifneq ($(TARGET_SLSI_VARIANT),)
PLATFORM_DIR := $(TARGET_BOARD_PLATFORM)-$(TARGET_SLSI_VARIANT)
else
PLATFORM_DIR := $(TARGET_BOARD_PLATFORM)
endif
LOCAL_C_INCLUDES += hardware/samsung_slsi/$(PLATFORM_DIR)/include
endif

LOCAL_LDLIBS += -lpthread
LOCAL_MODULE := libbinder
LOCAL_STATIC_LIBRARIES += libutils
LOCAL_SRC_FILES := $(sources)

include $(BUILD_STATIC_LIBRARY)
