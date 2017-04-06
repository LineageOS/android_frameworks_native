LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	vrscreencap.cpp

LOCAL_STATIC_LIBRARIES := \
	libbufferhub \
	libdisplay \
	libimageio \
	libpdx_default_transport \

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	liblog \
	libpng \
	libsync \
	libui \

LOCAL_MODULE := vrscreencap

LOCAL_MODULE_TAGS := optional

include $(BUILD_EXECUTABLE)
