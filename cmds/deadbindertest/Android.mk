LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	main.cpp

LOCAL_SHARED_LIBRARIES := libutils libbinder liblog

ifeq ($(TARGET_OS),linux)
	LOCAL_CFLAGS += -DXP_UNIX
	#LOCAL_SHARED_LIBRARIES += librt
endif

LOCAL_MODULE:= deadbindertest

include $(BUILD_EXECUTABLE)
