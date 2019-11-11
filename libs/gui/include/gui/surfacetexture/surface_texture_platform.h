/*
 * Copyright 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _ANDROID_GRAPHICS_SURFACE_TEXTURE_PLATFORM_H
#define _ANDROID_GRAPHICS_SURFACE_TEXTURE_PLATFORM_H

#include <EGL/egl.h>
#include <EGL/eglext.h>

#include <system/graphics.h>

#include <gui/IGraphicBufferProducer.h>
#include <gui/surfacetexture/SurfaceTexture.h>

// This file provides a facade API on top of SurfaceTexture, which avoids using
// C++ types. This is still a C++ unstable API though. Ideally features here
// will be exposed via public NDK API and this file will be deleted.

struct ASurfaceTexture {
    android::sp<android::SurfaceTexture> consumer;
    android::sp<android::IGraphicBufferProducer> producer;
};

namespace android {

/**
 * ASurfaceTexture_getCurrentTextureTarget returns the texture target of the
 * current texture.
 */
unsigned int ASurfaceTexture_getCurrentTextureTarget(ASurfaceTexture* st);

/**
 * ASurfaceTexture_takeConsumerOwnership attaches an ASurfaceTexture that is
 * currently in the 'detached' state to a consumer context.
 */
void ASurfaceTexture_takeConsumerOwnership(ASurfaceTexture* st);

/**
 * ASurfaceTexture_releaseConsumerOwnership detaches a SurfaceTexture from
 * a consumer context.
 */
void ASurfaceTexture_releaseConsumerOwnership(ASurfaceTexture* st);

/**
 * Callback function needed by ASurfaceTexture_dequeueBuffer. It creates a
 * fence that is signalled when the previous buffer is no longer in use by the
 * consumer (usually HWUI RenderThread) and can be written to by the producer.
 */
typedef int (*ASurfaceTexture_createReleaseFence)(bool useFenceSync, EGLSyncKHR* eglFence,
                                                  EGLDisplay* display, int* releaseFence,
                                                  void* fencePassThroughHandle);

/**
 * Callback function needed by ASurfaceTexture_dequeueBuffer. It waits for the
 * new buffer fence to signal before issuing any draw commands.
 */
typedef int (*ASurfaceTexture_fenceWait)(int fence, void* fencePassThroughHandle);

/**
 * ASurfaceTexture_dequeueBuffer returns the next available AHardwareBuffer.
 */
AHardwareBuffer* ASurfaceTexture_dequeueBuffer(ASurfaceTexture* st, int* outSlotid,
                                               android_dataspace* outDataspace,
                                               float* outTransformMatrix, bool* outNewContent,
                                               ASurfaceTexture_createReleaseFence createFence,
                                               ASurfaceTexture_fenceWait fenceWait,
                                               void* fencePassThroughHandle);

/**
 * ASurfaceTexture_create creates an ASurfaceTexture, which is
 * a simple struct containing a SurfaceTexture and an IGraphicBufferProducer.
 */
ASurfaceTexture* ASurfaceTexture_create(sp<SurfaceTexture> consumer,
                                        sp<IGraphicBufferProducer> producer);

} // namespace android

#endif // _ANDROID_GRAPHICS_SURFACE_TEXTURE_PLATFORM_H
