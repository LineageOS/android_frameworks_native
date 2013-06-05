LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	surface.cpp

LOCAL_C_INCLUDES += $(call project-path-for,qcom-display)/libgralloc
LOCAL_C_INCLUDES += $(call project-path-for,qcom-display)/libqdutils

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libutils \
	libbinder \
	libui \
	libgui \
	liblog \
	libqdMetaData

LOCAL_MODULE:= test-surface

LOCAL_MODULE_TAGS := tests

include $(BUILD_EXECUTABLE)
