#ifndef ANDROID_DVR_HARDWARE_COMPOSER_CLIENT_H
#define ANDROID_DVR_HARDWARE_COMPOSER_CLIENT_H

#include <dvr/dvr_hardware_composer_defs.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AHardwareBuffer AHardwareBuffer;
typedef struct DvrHwcClient DvrHwcClient;
typedef struct DvrHwcFrame DvrHwcFrame;

// Called when a new frame has arrived.
//
// @param client_state Pointer to client state passed in |dvrHwcCreateClient()|.
// @param frame New frame. Owned by the client.
// @return fence FD for the release of the last frame.
typedef int(*DvrHwcOnFrameCallback)(void* client_state, DvrHwcFrame* frame);

// @param callback Called when a new frame is available.
// @param client_state Pointer to client state passed back in the callback.
DvrHwcClient* dvrHwcClientCreate(DvrHwcOnFrameCallback callback,
                                 void* client_state);

void dvrHwcClientDestroy(DvrHwcClient* client);

// Called to free the frame information.
void dvrHwcFrameDestroy(DvrHwcFrame* frame);

DvrHwcDisplay dvrHwcFrameGetDisplayId(DvrHwcFrame* frame);

int32_t dvrHwcFrameGetDisplayWidth(DvrHwcFrame* frame);

int32_t dvrHwcFrameGetDisplayHeight(DvrHwcFrame* frame);

// @return True if the display has been removed. In this case the current frame
// does not contain any valid layers to display. It is a signal to clean up any
// display related state.
bool dvrHwcFrameGetDisplayRemoved(DvrHwcFrame* frame);

// @return Number of layers in the frame.
size_t dvrHwcFrameGetLayerCount(DvrHwcFrame* frame);

uint32_t dvrHwcFrameGetActiveConfig(DvrHwcFrame* frame);
uint32_t dvrHwcFrameGetColorMode(DvrHwcFrame* frame);
void dvrHwcFrameGetColorTransform(DvrHwcFrame* frame, float* out_matrix,
                                  int32_t* out_hint);
uint32_t dvrHwcFrameGetPowerMode(DvrHwcFrame* frame);
uint32_t dvrHwcFrameGetVsyncEnabled(DvrHwcFrame* frame);

DvrHwcLayer dvrHwcFrameGetLayerId(DvrHwcFrame* frame, size_t layer_index);

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

DvrHwcRecti dvrHwcFrameGetLayerDisplayFrame(DvrHwcFrame* frame,
                                            size_t layer_index);

DvrHwcRectf dvrHwcFrameGetLayerCrop(DvrHwcFrame* frame, size_t layer_index);

DvrHwcBlendMode dvrHwcFrameGetLayerBlendMode(DvrHwcFrame* frame,
                                             size_t layer_index);

float dvrHwcFrameGetLayerAlpha(DvrHwcFrame* frame, size_t layer_index);

uint32_t dvrHwcFrameGetLayerType(DvrHwcFrame* frame, size_t layer_index);

uint32_t dvrHwcFrameGetLayerApplicationId(DvrHwcFrame* frame,
                                          size_t layer_index);

uint32_t dvrHwcFrameGetLayerZOrder(DvrHwcFrame* frame, size_t layer_index);

void dvrHwcFrameGetLayerCursor(DvrHwcFrame* frame, size_t layer_index,
                               int32_t* out_x, int32_t* out_y);

uint32_t dvrHwcFrameGetLayerTransform(DvrHwcFrame* frame, size_t layer_index);

uint32_t dvrHwcFrameGetLayerDataspace(DvrHwcFrame* frame, size_t layer_index);

uint32_t dvrHwcFrameGetLayerColor(DvrHwcFrame* frame, size_t layer_index);

uint32_t dvrHwcFrameGetLayerNumVisibleRegions(DvrHwcFrame* frame,
                                              size_t layer_index);
DvrHwcRecti dvrHwcFrameGetLayerVisibleRegion(DvrHwcFrame* frame,
                                             size_t layer_index, size_t index);

uint32_t dvrHwcFrameGetLayerNumDamagedRegions(DvrHwcFrame* frame,
                                              size_t layer_index);
DvrHwcRecti dvrHwcFrameGetLayerDamagedRegion(DvrHwcFrame* frame,
                                             size_t layer_index, size_t index);
#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ANDROID_DVR_HARDWARE_COMPOSER_CLIENT_H
