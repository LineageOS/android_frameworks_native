LOCAL_PATH := $(call my-dir)

sourceFiles := \
	image_io.cpp \
	image_io_png.cpp \
	image_io_ppm.cpp

includeFiles := \
  $(LOCAL_PATH)/include

sharedLibraries := \
	libcutils \
	libpng

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(sourceFiles)
LOCAL_C_INCLUDES += $(includeFiles)
LOCAL_EXPORT_C_INCLUDE_DIRS := $(includeFiles)
LOCAL_SHARED_LIBRARIES := $(sharedLibraries)
LOCAL_CFLAGS := -Wall -Wextra
LOCAL_MODULE := libimageio
LOCAL_MODULE_TAGS := optional
include $(BUILD_STATIC_LIBRARY)
