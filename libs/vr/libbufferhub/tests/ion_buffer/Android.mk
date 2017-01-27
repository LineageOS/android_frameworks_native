LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

COMPONENT_TOP := ${LOCAL_PATH}/../..

LOCAL_SRC_FILES := \
        ion_buffer-test.cpp \
        ../../ion_buffer.cpp \
        ../../mocks/gralloc/gralloc.cpp

LOCAL_SHARED_LIBRARIES := \
        libc \
        libcutils \
        libutils \
        liblog

LOCAL_STATIC_LIBRARIES := \
        libgmock

LOCAL_C_INCLUDES := \
        ${COMPONENT_TOP}/mocks/gralloc \
        ${COMPONENT_TOP}/include \
        $(TOP)/system/core/base/include

LOCAL_EXPORT_C_INCLUDE_DIRS := ${LOCAL_C_INCLUDES}

LOCAL_NATIVE_COVERAGE := true

LOCAL_CFLAGS := -DTRACE=0 -g

LOCAL_MODULE := ion_buffer-test
LOCAL_MODULE_TAGS := tests

include $(BUILD_NATIVE_TEST)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
        ion_buffer-test.cpp \
        ../../ion_buffer.cpp \
        ../../mocks/gralloc/gralloc.cpp

LOCAL_SHARED_LIBRARIES := \
        liblog

LOCAL_STATIC_LIBRARIES := \
        libgmock_host

LOCAL_C_INCLUDES := \
        ${COMPONENT_TOP}/mocks/gralloc \
        ${COMPONENT_TOP}/include \
        $(TOP)/system/core/base/include

LOCAL_EXPORT_C_INCLUDE_DIRS := ${LOCAL_C_INCLUDES}

LOCAL_NATIVE_COVERAGE := true

LOCAL_CFLAGS := -DTRACE=0

LOCAL_MODULE := ion_buffer-host_test
LOCAL_MODULE_TAGS := tests
include $(BUILD_HOST_NATIVE_TEST)

.PHONY: dvr_host_native_unit_tests
dvr_host_native_unit_tests: ion_buffer-host_test
ifeq (true,$(NATIVE_COVERAGE))
  ion_buffer-host_test: llvm-cov
  ion_buffer-test: llvm-cov
  # This shouldn't be necessary, but the default build with
  # NATIVE_COVERAGE=true manages to ion_buffer-test without
  # building llvm-cov (droid is the default target).
  droid: llvm-cov
endif
