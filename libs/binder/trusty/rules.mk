# Copyright (C) 2021 The Android Open Source Project
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

MODULE := $(LOCAL_DIR)

LIBBINDER_DIR := frameworks/native/libs/binder
# TODO(b/302723053): remove libbase after aidl prebuilt gets updated to December release
LIBBASE_DIR := system/libbase
LIBLOG_STUB_DIR := $(LIBBINDER_DIR)/liblog_stub
LIBUTILS_BINDER_DIR := system/core/libutils/binder
FMTLIB_DIR := external/fmtlib

MODULE_SRCS := \
	$(LOCAL_DIR)/OS.cpp \
	$(LOCAL_DIR)/RpcServerTrusty.cpp \
	$(LOCAL_DIR)/RpcTransportTipcTrusty.cpp \
	$(LOCAL_DIR)/TrustyStatus.cpp \
	$(LOCAL_DIR)/socket.cpp \
	$(LIBBINDER_DIR)/Binder.cpp \
	$(LIBBINDER_DIR)/BpBinder.cpp \
	$(LIBBINDER_DIR)/FdTrigger.cpp \
	$(LIBBINDER_DIR)/IInterface.cpp \
	$(LIBBINDER_DIR)/IResultReceiver.cpp \
	$(LIBBINDER_DIR)/Parcel.cpp \
	$(LIBBINDER_DIR)/ParcelFileDescriptor.cpp \
	$(LIBBINDER_DIR)/RpcServer.cpp \
	$(LIBBINDER_DIR)/RpcSession.cpp \
	$(LIBBINDER_DIR)/RpcState.cpp \
	$(LIBBINDER_DIR)/Stability.cpp \
	$(LIBBINDER_DIR)/Status.cpp \
	$(LIBBINDER_DIR)/Utils.cpp \
	$(LIBBINDER_DIR)/file.cpp \
	$(LIBUTILS_BINDER_DIR)/Errors.cpp \
	$(LIBUTILS_BINDER_DIR)/RefBase.cpp \
	$(LIBUTILS_BINDER_DIR)/SharedBuffer.cpp \
	$(LIBUTILS_BINDER_DIR)/String16.cpp \
	$(LIBUTILS_BINDER_DIR)/String8.cpp \
	$(LIBUTILS_BINDER_DIR)/StrongPointer.cpp \
	$(LIBUTILS_BINDER_DIR)/Unicode.cpp \
	$(LIBUTILS_BINDER_DIR)/VectorImpl.cpp \

MODULE_EXPORT_INCLUDES += \
	$(LOCAL_DIR)/include \
	$(LIBLOG_STUB_DIR)/include \
	$(LIBBINDER_DIR)/include \
	$(LIBBASE_DIR)/include \
	$(LIBUTILS_BINDER_DIR)/include \
	$(FMTLIB_DIR)/include \

# The android/binder_to_string.h header is shared between libbinder and
# libbinder_ndk and included by auto-generated AIDL C++ files
MODULE_EXPORT_INCLUDES += \
	$(LIBBINDER_DIR)/ndk/include_cpp \

MODULE_EXPORT_COMPILEFLAGS += \
	-DBINDER_RPC_SINGLE_THREADED \
	-DBINDER_ENABLE_LIBLOG_ASSERT \
	-DBINDER_DISABLE_NATIVE_HANDLE \
	-DBINDER_DISABLE_BLOB \
	-DBINDER_NO_LIBBASE \
	-D__ANDROID_VENDOR__ \
	-D__ANDROID_VNDK__ \

# libbinder has some deprecated declarations that we want to produce warnings
# not errors
MODULE_EXPORT_COMPILEFLAGS += \
	-Wno-error=deprecated-declarations \

MODULE_LIBRARY_DEPS += \
	trusty/user/base/lib/libstdc++-trusty \
	trusty/user/base/lib/tipc \
	external/boringssl \

include make/library.mk
