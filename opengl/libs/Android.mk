LOCAL_PATH:= $(call my-dir)

# OpenGL drivers config file
ifneq ($(BOARD_EGL_CFG),)
include $(CLEAR_VARS)
LOCAL_MODULE := egl.cfg
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := ETC
LOCAL_MODULE_PATH := $(TARGET_OUT)/lib/egl
LOCAL_SRC_FILES := ../../../../$(BOARD_EGL_CFG)
include $(BUILD_PREBUILT)
endif
