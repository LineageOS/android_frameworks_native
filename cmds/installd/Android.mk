LOCAL_PATH := $(call my-dir)

# OTA slot script

include $(CLEAR_VARS)
LOCAL_MODULE:= otapreopt_slot
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_SRC_FILES := otapreopt_slot.sh
LOCAL_INIT_RC := otapreopt.rc

include $(BUILD_PREBUILT)

# OTA postinstall script

include $(CLEAR_VARS)
LOCAL_MODULE:= otapreopt_script
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_SRC_FILES := otapreopt_script.sh

# Let this depend on otapreopt, the chroot tool and the slot script, so we just have to mention one
# in a configuration.
LOCAL_REQUIRED_MODULES := otapreopt otapreopt_chroot otapreopt_slot

include $(BUILD_PREBUILT)
