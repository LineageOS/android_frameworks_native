LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:= \
	BitTube.cpp \
	BufferQueue.cpp \
	DisplayEventReceiver.cpp \
	IDisplayEventConnection.cpp \
	ISensorEventConnection.cpp \
	ISensorServer.cpp \
	ISurfaceTexture.cpp \
	Sensor.cpp \
	SensorEventQueue.cpp \
	SensorManager.cpp \
	SurfaceTexture.cpp \
	SurfaceTextureClient.cpp \
	ISurfaceComposer.cpp \
	ISurface.cpp \
	ISurfaceComposerClient.cpp \
	IGraphicBufferAlloc.cpp \
	LayerState.cpp \
	Surface.cpp \
	SurfaceComposerClient.cpp \
	DummyConsumer.cpp

LOCAL_SHARED_LIBRARIES := \
	libcutils \
	libutils \
	libbinder \
	libhardware \
	libhardware_legacy \
	libui \
	libEGL \
	libGLESv2 \


LOCAL_MODULE:= libgui

ifeq ($(TARGET_BOARD_PLATFORM), omap4)
	LOCAL_CFLAGS += -DUSE_FENCE_SYNC
endif
ifeq ($(TARGET_BOARD_PLATFORM), s5pc110)
	LOCAL_CFLAGS += -DUSE_FENCE_SYNC
endif
ifneq ($(filter generic%,$(TARGET_DEVICE)),)
    # Emulator build
    LOCAL_CFLAGS += -DUSE_FENCE_SYNC
endif

ifeq ($(TARGET_BOARD_PLATFORM), tegra)
	LOCAL_CFLAGS += -DALLOW_DEQUEUE_CURRENT_BUFFER
endif

ifeq ($(BOARD_USES_QCOM_HARDWARE), true)
    LOCAL_C_INCLUDES += hardware/qcom/display/libgralloc
    LOCAL_C_INCLUDES += hardware/qcom/display/libqdutils
    LOCAL_CFLAGS += -DQCOMHW
endif

include $(BUILD_SHARED_LIBRARY)

ifeq (,$(ONE_SHOT_MAKEFILE))
include $(call first-makefiles-under,$(LOCAL_PATH))
endif
