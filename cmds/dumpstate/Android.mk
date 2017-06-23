LOCAL_PATH:= $(call my-dir)

# =======================#
# dumpstate_test_fixture #
# =======================#
include $(CLEAR_VARS)

LOCAL_MODULE := dumpstate_test_fixture
LOCAL_COMPATIBILITY_SUITE := device-tests
LOCAL_MODULE_TAGS := tests

LOCAL_CFLAGS := \
       -Wall -Werror -Wno-missing-field-initializers -Wno-unused-variable -Wunused-parameter

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk

LOCAL_SRC_FILES := \
        tests/dumpstate_test_fixture.cpp

LOCAL_MODULE_CLASS := NATIVE_TESTS

dumpstate_tests_intermediates := $(local-intermediates-dir)/DATA
dumpstate_tests_subpath_from_data := nativetest/dumpstate_test_fixture
dumpstate_tests_root_in_device := /data/$(dumpstate_tests_subpath_from_data)
dumpstate_tests_root_for_test_zip := $(dumpstate_tests_intermediates)/$(dumpstate_tests_subpath_from_data)
testdata_files := $(call find-subdir-files, testdata/*)

# Copy test data files to intermediates/DATA for use with LOCAL_PICKUP_FILES
GEN := $(addprefix $(dumpstate_tests_root_for_test_zip)/, $(testdata_files))
$(GEN): PRIVATE_PATH := $(LOCAL_PATH)
$(GEN): PRIVATE_CUSTOM_TOOL = cp $< $@
$(GEN): $(dumpstate_tests_root_for_test_zip)/testdata/% : $(LOCAL_PATH)/testdata/%
	$(transform-generated-source)
LOCAL_GENERATED_SOURCES += $(GEN)

# Copy test data files again to $OUT/data so the tests can be run with adb sync
# TODO: the build system should do this automatically
GEN := $(addprefix $(TARGET_OUT_DATA)/$(dumpstate_tests_subpath_from_data)/, $(testdata_files))
$(GEN): PRIVATE_PATH := $(LOCAL_PATH)
$(GEN): PRIVATE_CUSTOM_TOOL = cp $< $@
$(GEN): $(TARGET_OUT_DATA)/$(dumpstate_tests_subpath_from_data)/testdata/% : $(LOCAL_PATH)/testdata/%
	$(transform-generated-source)
LOCAL_GENERATED_SOURCES += $(GEN)

LOCAL_PICKUP_FILES := $(dumpstate_tests_intermediates)

include $(BUILD_NATIVE_TEST)
