LOCAL_PATH := $(call my-dir)

shared_libraries := \
    libbase \
    libbinder \
    libcutils \
    libgui \
    liblog \
    libhardware \
    libui \
    libutils \
    libnativewindow \

static_libraries := \
    libdvr \
    libbufferhubqueue \
    libbufferhub \
    libchrome \
    libdvrcommon \
    libdisplay \
    libpdx_default_transport \

include $(CLEAR_VARS)
LOCAL_SRC_FILES := \
    dvr_buffer_queue-test.cpp \
    dvr_named_buffer-test.cpp \

LOCAL_STATIC_LIBRARIES := $(static_libraries)
LOCAL_SHARED_LIBRARIES := $(shared_libraries)
LOCAL_EXPORT_C_INCLUDE_DIRS := ${LOCAL_C_INCLUDES}
LOCAL_CFLAGS := -DLOG_TAG=\"dvr_api-test\" -DTRACE=0 -O0 -g
LOCAL_MODULE := dvr_api-test
LOCAL_MODULE_TAGS := optional
include $(BUILD_NATIVE_TEST)
