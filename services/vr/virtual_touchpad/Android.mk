LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)


# Touchpad implementation.

src := \
  EvdevInjector.cpp \
  VirtualTouchpadEvdev.cpp

shared_libs := \
  libbase \
  libutils

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(src)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_SHARED_LIBRARIES := $(shared_libs)
LOCAL_CPPFLAGS += -std=c++11
LOCAL_CFLAGS += -DLOG_TAG=\"VrVirtualTouchpad\"
LOCAL_MODULE := libvirtualtouchpad
LOCAL_MODULE_TAGS := optional
include $(BUILD_STATIC_LIBRARY)


# Touchpad unit tests.

test_static_libs := \
  libbase \
  libcutils \
  libvirtualtouchpad

test_shared_libs := \
  libutils

test_src_files := \
  tests/VirtualTouchpad_test.cpp

$(foreach file,$(test_src_files), \
    $(eval include $(CLEAR_VARS)) \
    $(eval LOCAL_SRC_FILES := $(file)) \
    $(eval LOCAL_C_INCLUDES := $(LOCAL_PATH)/include) \
    $(eval LOCAL_STATIC_LIBRARIES := $(test_static_libs)) \
    $(eval LOCAL_SHARED_LIBRARIES := $(test_shared_libs)) \
    $(eval LOCAL_CPPFLAGS += -std=c++11) \
    $(eval LOCAL_LDLIBS := -llog) \
    $(eval LOCAL_MODULE := $(notdir $(file:%.cpp=%))) \
    $(eval LOCAL_MODULE_TAGS := optional) \
    $(eval LOCAL_CXX_STL := libc++_static) \
    $(eval include $(BUILD_NATIVE_TEST)) \
)


# Service.

src := \
  main.cpp \
  VirtualTouchpadService.cpp \
  aidl/android/dvr/VirtualTouchpadService.aidl

static_libs := \
  libcutils \
  libvirtualtouchpad

shared_libs := \
  libbase \
  libbinder \
  libutils

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(src)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_STATIC_LIBRARIES := $(static_libs)
LOCAL_SHARED_LIBRARIES := $(shared_libs)
LOCAL_CPPFLAGS += -std=c++11
LOCAL_CFLAGS += -DLOG_TAG=\"VrVirtualTouchpad\" -DSELINUX_ACCESS_CONTROL
LOCAL_LDLIBS := -llog
LOCAL_MODULE := virtual_touchpad
LOCAL_MODULE_TAGS := optional
LOCAL_INIT_RC := virtual_touchpad.rc
LOCAL_MULTILIB := 64
LOCAL_CXX_STL := libc++_static
include $(BUILD_EXECUTABLE)


# Touchpad client library.

src := \
  VirtualTouchpadClient.cpp \
  aidl/android/dvr/VirtualTouchpadService.aidl

shared_libs := \
  libbase \
  libbinder \
  libutils

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(src)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_SHARED_LIBRARIES := $(shared_libs)
LOCAL_CPPFLAGS += -std=c++11
LOCAL_CFLAGS += -DLOG_TAG=\"VirtualTouchpadClient\"
LOCAL_LDLIBS := -llog
LOCAL_MODULE := libvirtualtouchpadclient
LOCAL_MODULE_TAGS := optional
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/include
include $(BUILD_STATIC_LIBRARY)
