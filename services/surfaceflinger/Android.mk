LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

LOCAL_CLANG := true

LOCAL_ADDITIONAL_DEPENDENCIES := $(LOCAL_PATH)/Android.mk
LOCAL_SRC_FILES := \
    Client.cpp \
    DisplayDevice.cpp \
    DispSync.cpp \
    EventControlThread.cpp \
    StartBootAnimThread.cpp \
    EventThread.cpp \
    FrameTracker.cpp \
    GpuService.cpp \
    Layer.cpp \
    LayerDim.cpp \
    LayerRejecter.cpp \
    LayerVector.cpp \
    MessageQueue.cpp \
    MonitoredProducer.cpp \
    SurfaceFlingerConsumer.cpp \
    SurfaceInterceptor.cpp \
    Transform.cpp \
    DisplayHardware/ComposerHal.cpp \
    DisplayHardware/FramebufferSurface.cpp \
    DisplayHardware/HWC2.cpp \
    DisplayHardware/HWComposerBufferCache.cpp \
    DisplayHardware/PowerHAL.cpp \
    DisplayHardware/VirtualDisplaySurface.cpp \
    Effects/Daltonizer.cpp \
    EventLog/EventLogTags.logtags \
    EventLog/EventLog.cpp \
    RenderEngine/Description.cpp \
    RenderEngine/Mesh.cpp \
    RenderEngine/Program.cpp \
    RenderEngine/ProgramCache.cpp \
    RenderEngine/GLExtensions.cpp \
    RenderEngine/RenderEngine.cpp \
    RenderEngine/Texture.cpp \
    RenderEngine/GLES20RenderEngine.cpp \
    DisplayUtils.cpp \
    ExSurfaceFlinger/ExLayer.cpp \
    ExSurfaceFlinger/ExSurfaceFlinger.cpp \
    ExSurfaceFlinger/ExVirtualDisplaySurface.cpp

LOCAL_MODULE := libsurfaceflinger
LOCAL_C_INCLUDES := \
    frameworks/native/vulkan/include \
    external/vulkan-validation-layers/libs/vkjson \
    system/libhwbinder/fast_msgq/include \

LOCAL_CFLAGS := -DLOG_TAG=\"SurfaceFlinger\"

ifeq ($(TARGET_BUILD_VARIANT),userdebug)
LOCAL_CFLAGS += -DDEBUG_CONT_DUMPSYS
endif

LOCAL_CFLAGS += -DGL_GLEXT_PROTOTYPES -DEGL_EGLEXT_PROTOTYPES

ifeq ($(TARGET_USES_QCOM_DISPLAY_BSP), true)
LOCAL_CFLAGS += -DQTI_BSP
  ifeq ($(TARGET_USES_COLOR_METADATA), true)
    LOCAL_CFLAGS += -DUSE_COLOR_METADATA
  endif
LOCAL_HEADER_LIBRARIES := display_headers
endif

ifeq ($(TARGET_USES_HWC2),true)
    LOCAL_CFLAGS += -DUSE_HWC2
    LOCAL_SRC_FILES += \
        SurfaceFlinger.cpp \
        DisplayHardware/HWComposer.cpp
else
    LOCAL_SRC_FILES += \
        SurfaceFlinger_hwc1.cpp \
        DisplayHardware/HWComposer_hwc1.cpp
endif

ifneq ($(MAX_VIRTUAL_DISPLAY_DIMENSION),)
    LOCAL_CFLAGS += -DMAX_VIRTUAL_DISPLAY_DIMENSION=$(MAX_VIRTUAL_DISPLAY_DIMENSION)
else
    LOCAL_CFLAGS += -DMAX_VIRTUAL_DISPLAY_DIMENSION=0
endif

LOCAL_CFLAGS += -fvisibility=hidden -Werror=format

LOCAL_STATIC_LIBRARIES := \
    libhwcomposer-command-buffer \
    libtrace_proto \
    libvkjson \
    libvr_manager \
    libvrflinger

LOCAL_SHARED_LIBRARIES := \
    android.frameworks.vr.composer@1.0 \
    android.hardware.graphics.allocator@2.0 \
    android.hardware.graphics.composer@2.1 \
    android.hardware.configstore@1.0 \
    android.hardware.configstore-utils \
    libcutils \
    liblog \
    libdl \
    libfmq \
    libhardware \
    libhidlbase \
    libhidltransport \
    libhwbinder \
    libutils \
    libEGL \
    libGLESv1_CM \
    libGLESv2 \
    libbinder \
    libui \
    libgui \
    libpowermanager \
    libvulkan \
    libsync \
    libprotobuf-cpp-lite \
    libbase \
    android.hardware.power@1.0

LOCAL_EXPORT_SHARED_LIBRARY_HEADERS := \
    android.hardware.graphics.allocator@2.0 \
    android.hardware.graphics.composer@2.1 \
    libhidlbase \
    libhidltransport \
    libhwbinder

LOCAL_CFLAGS += -Wall -Werror -Wunused -Wunreachable-code

include $(BUILD_SHARED_LIBRARY)

###############################################################
# build surfaceflinger's executable
include $(CLEAR_VARS)

LOCAL_CLANG := true

LOCAL_LDFLAGS_32 := -Wl,--version-script,art/sigchainlib/version-script32.txt -Wl,--export-dynamic
LOCAL_LDFLAGS_64 := -Wl,--version-script,art/sigchainlib/version-script64.txt -Wl,--export-dynamic
LOCAL_CFLAGS := -DLOG_TAG=\"SurfaceFlinger\"

LOCAL_INIT_RC := surfaceflinger.rc

ifeq ($(TARGET_USES_HWC2),true)
    LOCAL_CFLAGS += -DUSE_HWC2
endif

LOCAL_SRC_FILES := \
    main_surfaceflinger.cpp

LOCAL_SHARED_LIBRARIES := \
    android.frameworks.displayservice@1.0 \
    android.hardware.configstore@1.0 \
    android.hardware.configstore-utils \
    android.hardware.graphics.allocator@2.0 \
    libsurfaceflinger \
    libcutils \
    libdisplayservicehidl \
    liblog \
    libbinder \
    libhidlbase \
    libhidltransport \
    libutils \
    libui \
    libgui \
    libdl

LOCAL_WHOLE_STATIC_LIBRARIES := libsigchain
LOCAL_STATIC_LIBRARIES := libtrace_proto

LOCAL_MODULE := surfaceflinger

ifdef TARGET_32_BIT_SURFACEFLINGER
LOCAL_32_BIT_ONLY := true
endif

LOCAL_CFLAGS += -Wall -Werror -Wunused -Wunreachable-code

include $(BUILD_EXECUTABLE)

###############################################################
# uses jni which may not be available in PDK
ifneq ($(wildcard libnativehelper/include),)
include $(CLEAR_VARS)

LOCAL_CLANG := true

LOCAL_CFLAGS := -DLOG_TAG=\"SurfaceFlinger\"

LOCAL_SRC_FILES := \
    DdmConnection.cpp

LOCAL_SHARED_LIBRARIES := \
    libcutils \
    liblog \
    libdl

LOCAL_MODULE := libsurfaceflinger_ddmconnection

LOCAL_CFLAGS += -Wall -Werror -Wunused -Wunreachable-code

include $(BUILD_SHARED_LIBRARY)
endif # libnativehelper

include $(call first-makefiles-under,$(LOCAL_PATH))
