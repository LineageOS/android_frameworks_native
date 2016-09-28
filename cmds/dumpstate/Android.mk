LOCAL_PATH:= $(call my-dir)

# ================#
# Common settings #
# ================#
# ZipArchive support, the order matters here to get all symbols.
COMMON_ZIP_LIBRARIES := libziparchive libz libcrypto_static

# TODO: ideally the tests should depend on a shared dumpstate library, but currently libdumpstate
# is used to define the device-specific HAL library. Instead, both dumpstate and dumpstate_test
# shares a lot of common settings
COMMON_LOCAL_CFLAGS := \
       -Wall -Werror -Wno-missing-field-initializers -Wno-unused-variable -Wunused-parameter
COMMON_SRC_FILES := \
        utils.cpp
COMMON_SHARED_LIBRARIES := \
        libbase \
        libcutils \
        libhardware_legacy \
        liblog \
        libselinux

# ==========#
# dumpstate #
# ==========#
include $(CLEAR_VARS)

ifdef BOARD_WLAN_DEVICE
LOCAL_CFLAGS := -DFWDUMP_$(BOARD_WLAN_DEVICE)
endif

LOCAL_SRC_FILES := $(COMMON_SRC_FILES) \
        dumpstate.cpp

LOCAL_MODULE := dumpstate

LOCAL_SHARED_LIBRARIES := $(COMMON_SHARED_LIBRARIES)

LOCAL_STATIC_LIBRARIES := $(COMMON_ZIP_LIBRARIES)

LOCAL_HAL_STATIC_LIBRARIES := libdumpstate

LOCAL_CFLAGS += $(COMMON_LOCAL_CFLAGS)

LOCAL_INIT_RC := dumpstate.rc

include $(BUILD_EXECUTABLE)

# ===============#
# dumpstate_test #
# ===============#
include $(CLEAR_VARS)

LOCAL_MODULE := dumpstate_test

LOCAL_MODULE_TAGS := tests

LOCAL_CFLAGS := $(COMMON_LOCAL_CFLAGS)

LOCAL_SRC_FILES := $(COMMON_SRC_FILES) \
        tests/dumpstate_test.cpp

LOCAL_STATIC_LIBRARIES := $(COMMON_ZIP_LIBRARIES) \
        libgmock

LOCAL_SHARED_LIBRARIES := $(COMMON_SHARED_LIBRARIES)

include $(BUILD_NATIVE_TEST)

# =======================#
# dumpstate_test_fixture #
# =======================#
include $(CLEAR_VARS)

LOCAL_MODULE := dumpstate_test_fixture

LOCAL_MODULE_TAGS := tests

LOCAL_CFLAGS := $(COMMON_LOCAL_CFLAGS)

LOCAL_SRC_FILES := \
        tests/dumpstate_test_fixture.cpp

include $(BUILD_NATIVE_TEST)
