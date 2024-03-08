# Copyright (C) 2023 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_DIR := $(GET_LOCAL_DIR)
LIBBINDER_DIR := $(LOCAL_DIR)/../../..
LIBBINDER_NDK_BINDGEN_FLAG_FILE := \
	$(LIBBINDER_DIR)/rust/libbinder_ndk_bindgen_flags.txt

MODULE := $(LOCAL_DIR)

MODULE_SRCS := $(LIBBINDER_DIR)/rust/sys/lib.rs

MODULE_CRATE_NAME := binder_ndk_sys

MODULE_LIBRARY_DEPS += \
	$(LIBBINDER_DIR)/trusty \
	$(LIBBINDER_DIR)/trusty/ndk \
	trusty/user/base/lib/trusty-sys \

MODULE_BINDGEN_SRC_HEADER := $(LIBBINDER_DIR)/rust/sys/BinderBindings.hpp

# Add the flags from the flag file
MODULE_BINDGEN_FLAGS += $(shell cat $(LIBBINDER_NDK_BINDGEN_FLAG_FILE))
MODULE_SRCDEPS += $(LIBBINDER_NDK_BINDGEN_FLAG_FILE)

include make/library.mk
