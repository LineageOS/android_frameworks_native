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

# ====================#
# libdumpstateheaders #
# ====================#
# TODO: this module is necessary so the device-specific libdumpstate implementations do not
# need to add any other dependency (like libbase). Should go away once dumpstate HAL changes.
include $(CLEAR_VARS)

LOCAL_EXPORT_C_INCLUDE_DIRS = $(LOCAL_PATH)
LOCAL_MODULE := libdumpstateheaders
LOCAL_EXPORT_SHARED_LIBRARY_HEADERS := \
        $(COMMON_SHARED_LIBRARIES)
LOCAL_EXPORT_STATIC_LIBRARY_HEADERS := \
        $(COMMON_ZIP_LIBRARIES)
# Soong requires that whats is on LOCAL_EXPORTED_ is also on LOCAL_
LOCAL_SHARED_LIBRARIES := $(LOCAL_EXPORT_SHARED_LIBRARY_HEADERS)
LOCAL_STATIC_LIBRARIES := $(LOCAL_EXPORT_STATIC_LIBRARY_HEADERS)

include $(BUILD_STATIC_LIBRARY)

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

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk

LOCAL_SRC_FILES := \
        tests/dumpstate_test_fixture.cpp

dist_zip_root := $(TARGET_OUT_DATA)
dumpstate_tests_subpath_from_data := nativetest/dumpstate_test_fixture
dumpstate_tests_root_in_device := /data/$(dumpstate_tests_subpath_from_data)
dumpstate_tests_root_for_test_zip := $(dist_zip_root)/$(dumpstate_tests_subpath_from_data)
testdata_files := $(call find-subdir-files, testdata/*)

GEN := $(addprefix $(dumpstate_tests_root_for_test_zip)/, $(testdata_files))
$(GEN): PRIVATE_PATH := $(LOCAL_PATH)
$(GEN): PRIVATE_CUSTOM_TOOL = cp $< $@
$(GEN): $(dumpstate_tests_root_for_test_zip)/testdata/% : $(LOCAL_PATH)/testdata/%
	$(transform-generated-source)
LOCAL_GENERATED_SOURCES += $(GEN)
LOCAL_PICKUP_FILES := $(dist_zip_root)

include $(BUILD_NATIVE_TEST)
