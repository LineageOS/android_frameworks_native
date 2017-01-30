LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	vrscreencap.cpp

LOCAL_STATIC_LIBRARIES := \
	libdisplay \
	libimageio \
	libpdx_default_transport \

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	liblog \
	libpng \
	libsync

LOCAL_MODULE := vrscreencap

LOCAL_MODULE_TAGS := optional

include $(BUILD_EXECUTABLE)

ifeq ($(TARGET_BUILD_VARIANT),eng)
ALL_DEFAULT_INSTALLED_MODULES += vrscreencap
all_modules: vrscreencap
endif
