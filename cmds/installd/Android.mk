LOCAL_PATH := $(call my-dir)

#
# OTA Executable
#

include $(CLEAR_VARS)
LOCAL_MODULE := otapreopt
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -Wall -Werror

# Base & ASLR boundaries for boot image creation.
ifndef LIBART_IMG_HOST_MIN_BASE_ADDRESS_DELTA
  LOCAL_LIBART_IMG_HOST_MIN_BASE_ADDRESS_DELTA := -0x1000000
else
  LOCAL_LIBART_IMG_HOST_MIN_BASE_ADDRESS_DELTA := $(LIBART_IMG_HOST_MIN_BASE_ADDRESS_DELTA)
endif
ifndef LIBART_IMG_HOST_MAX_BASE_ADDRESS_DELTA
  LOCAL_LIBART_IMG_HOST_MAX_BASE_ADDRESS_DELTA := 0x1000000
else
  LOCAL_LIBART_IMG_HOST_MAX_BASE_ADDRESS_DELTA := $(LIBART_IMG_HOST_MAX_BASE_ADDRESS_DELTA)
endif
LOCAL_CFLAGS += -DART_BASE_ADDRESS=$(LIBART_IMG_HOST_BASE_ADDRESS)
LOCAL_CFLAGS += -DART_BASE_ADDRESS_MIN_DELTA=$(LOCAL_LIBART_IMG_HOST_MIN_BASE_ADDRESS_DELTA)
LOCAL_CFLAGS += -DART_BASE_ADDRESS_MAX_DELTA=$(LOCAL_LIBART_IMG_HOST_MAX_BASE_ADDRESS_DELTA)

LOCAL_SRC_FILES := otapreopt.cpp commands.cpp globals.cpp utils.cpp
LOCAL_SHARED_LIBRARIES := \
    libbase \
    libcutils \
    liblog \
    liblogwrap \
    libselinux \

LOCAL_STATIC_LIBRARIES := libdiskusage
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
LOCAL_CLANG := true
include $(BUILD_EXECUTABLE)

# OTA postinstall script

include $(CLEAR_VARS)
LOCAL_MODULE:= otapreopt_script
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_SRC_FILES := otapreopt_script.sh

# Let this depend on otapreopt, the chroot tool and the slot script, so we just have to mention one
# in a configuration.
LOCAL_REQUIRED_MODULES := otapreopt otapreopt_chroot otapreopt_slot

include $(BUILD_PREBUILT)

common_src_files := commands.cpp globals.cpp utils.cpp
common_cflags := -Wall -Werror

#
# Static library used in testing and executable
#

include $(CLEAR_VARS)
LOCAL_MODULE := libinstalld
LOCAL_MODULE_TAGS := eng tests
LOCAL_SRC_FILES := $(common_src_files)
LOCAL_CFLAGS := $(common_cflags)
LOCAL_SHARED_LIBRARIES := \
    libbase \
    liblogwrap \
    libselinux \

LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
LOCAL_CLANG := true
include $(BUILD_STATIC_LIBRARY)

#
# Executable
#

include $(CLEAR_VARS)
LOCAL_MODULE := installd
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := $(common_cflags)
LOCAL_SRC_FILES := $(common_src_files) \
    installd.cpp \
    InstalldNativeService.cpp \
    binder/android/os/IInstalld.aidl \

LOCAL_SHARED_LIBRARIES := \
    libbase \
    libbinder \
    libcutils \
    liblog \
    liblogwrap \
    libselinux \
    libutils

LOCAL_STATIC_LIBRARIES := libdiskusage
LOCAL_ADDITIONAL_DEPENDENCIES += $(LOCAL_PATH)/Android.mk
LOCAL_INIT_RC := installd.rc
LOCAL_CLANG := true
include $(BUILD_EXECUTABLE)
