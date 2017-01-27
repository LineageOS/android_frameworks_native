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

static_libraries := \
	libbufferhubqueue \
	libbufferhub \
	libchrome \
	libdvrcommon \
	libpdx_default_transport \

include $(CLEAR_VARS)
LOCAL_SRC_FILES := buffer_hub_queue-test.cpp
LOCAL_STATIC_LIBRARIES := $(static_libraries)
LOCAL_SHARED_LIBRARIES := $(shared_libraries)
LOCAL_EXPORT_C_INCLUDE_DIRS := ${LOCAL_C_INCLUDES}
LOCAL_CFLAGS := -DTRACE=0 -O0 -g
LOCAL_MODULE := buffer_hub_queue-test
LOCAL_MODULE_TAGS := optional
include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := buffer_hub_queue_producer-test.cpp
LOCAL_STATIC_LIBRARIES := $(static_libraries)
LOCAL_SHARED_LIBRARIES := $(shared_libraries)
LOCAL_EXPORT_C_INCLUDE_DIRS := ${LOCAL_C_INCLUDES}
LOCAL_CFLAGS := -DTRACE=0 -O0 -g
LOCAL_MODULE := buffer_hub_queue_producer-test
LOCAL_MODULE_TAGS := optional
include $(BUILD_NATIVE_TEST)
