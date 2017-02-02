LOCAL_PATH := $(call my-dir)

sourceFiles := \
	blur.cpp \
	debug_text.cpp \
	egl_image.cpp \
	gpu_profiler.cpp \
	shader_program.cpp \
	timer_query.cpp \
	vr_gl_extensions.cpp \

includeFiles := \
	$(LOCAL_PATH)/include

staticLibraries := \
	libbufferhub \
	libdvrcommon \
	libpdx_default_transport \

sharedLibraries := \
	libcutils \
	libbase \
	libpng

include $(CLEAR_VARS)
LOCAL_SRC_FILES := $(sourceFiles)
LOCAL_C_INCLUDES := $(includeFiles)
LOCAL_CFLAGS := -DGL_GLEXT_PROTOTYPES -DEGL_EGLEXT_PROTOTYPES
LOCAL_EXPORT_C_INCLUDE_DIRS := $(includeFiles)
LOCAL_SHARED_LIBRARIES := $(sharedLibraries)
LOCAL_STATIC_LIBRARIES := $(staticLibraries)
LOCAL_MODULE := libdvrgraphics
include $(BUILD_STATIC_LIBRARY)

