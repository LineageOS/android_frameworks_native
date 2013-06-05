LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	surface.cpp

LOCAL_C_INCLUDES += hardware/qcom/display/libgralloc
LOCAL_C_INCLUDES += hardware/qcom/display/libqdutils

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libutils \
	libbinder \
	libui \
    libgui \
    libqdMetaData

LOCAL_MODULE:= test-surface

LOCAL_MODULE_TAGS := tests

include $(BUILD_EXECUTABLE)
