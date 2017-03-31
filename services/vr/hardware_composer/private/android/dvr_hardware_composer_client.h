#ifndef VR_HARDWARE_COMPOSER_PRIVATE_ANDROID_DVR_HARDWARE_COMPOSER_CLIENT_H
#define VR_HARDWARE_COMPOSER_PRIVATE_ANDROID_DVR_HARDWARE_COMPOSER_CLIENT_H

#include <android/dvr_hardware_composer_defs.h>
#include <android/hardware_buffer.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DvrHwcClient DvrHwcClient;
typedef struct DvrHwcFrame DvrHwcFrame;

// Called when a new frame has arrived.
//
// @param frame New frame. Owned by the client.
// @return fence FD for the release of the last frame.
typedef int(*DvrHwcOnFrameCallback)(DvrHwcFrame* frame);

DvrHwcClient* dvrHwcCreateClient(DvrHwcOnFrameCallback callback);

// Called to free the frame information.
void dvrHwcFrameDestroy(DvrHwcFrame* frame);

Display dvrHwcFrameGetDisplayId(DvrHwcFrame* frame);

// @return Number of layers in the frame.
size_t dvrHwcFrameGetLayerCount(DvrHwcFrame* frame);

Layer dvrHwcFrameGetLayerId(DvrHwcFrame* frame, size_t layer_index);

// Return the graphic buffer associated with the layer at |layer_index| in
// |frame|.
//
// @return Graphic buffer. Caller owns the buffer and is responsible for freeing
// it. (see AHardwareBuffer_release())
AHardwareBuffer* dvrHwcFrameGetLayerBuffer(DvrHwcFrame* frame,
                                           size_t layer_index);

// Returns the fence FD for the layer at index |layer_index| in |frame|.
//
// @return Fence FD. Caller owns the FD and is responsible for closing it.
int dvrHwcFrameGetLayerFence(DvrHwcFrame* frame, size_t layer_index);

Recti dvrHwcFrameGetLayerDisplayFrame(DvrHwcFrame* frame, size_t layer_index);

Rectf dvrHwcFrameGetLayerCrop(DvrHwcFrame* frame, size_t layer_index);

BlendMode dvrHwcFrameGetLayerBlendMode(DvrHwcFrame* frame, size_t layer_index);

float dvrHwcFrameGetLayerAlpha(DvrHwcFrame* frame, size_t layer_index);

uint32_t dvrHwcFrameGetLayerType(DvrHwcFrame* frame, size_t layer_index);

uint32_t dvrHwcFrameGetLayerApplicationId(DvrHwcFrame* frame,
                                          size_t layer_index);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // VR_HARDWARE_COMPOSER_PRIVATE_ANDROID_DVR_HARDWARE_COMPOSER_CLIENT_H
