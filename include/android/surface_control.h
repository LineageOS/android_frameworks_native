/*
 * Copyright 2018 The Android Open Source Project
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

/**
 * @addtogroup NativeActivity Native Activity
 * @{
 */

/**
 * @file surface_control.h
 */

#ifndef ANDROID_SURFACE_CONTROL_H
#define ANDROID_SURFACE_CONTROL_H

#include <sys/cdefs.h>

#include <android/hardware_buffer.h>
#include <android/native_window.h>

__BEGIN_DECLS

#if __ANDROID_API__ >= 29

struct ASurfaceControl;

/**
 * The SurfaceControl API can be used to provide a heirarchy of surfaces for
 * composition to the system compositor. ASurfaceControl represents a content node in
 * this heirarchy.
 */
typedef struct ASurfaceControl ASurfaceControl;

/*
 * Creates an ASurfaceControl with either ANativeWindow or an ASurfaceControl as its parent.
 * |debug_name| is a debug name associated with this surface. It can be used to
 * identify this surface in the SurfaceFlinger's layer tree. It must not be
 * null.
 *
 * The caller takes ownership of the ASurfaceControl returned and must release it
 * using ASurfaceControl_release below.
 */
ASurfaceControl* ASurfaceControl_createFromWindow(ANativeWindow* parent, const char* debug_name)
                                                  __INTRODUCED_IN(29);

ASurfaceControl* ASurfaceControl_create(ASurfaceControl* parent, const char* debug_name)
                                        __INTRODUCED_IN(29);

/**
 * Destroys the |surface_control| object. After releasing the ASurfaceControl the caller no longer
 * has ownership of the AsurfaceControl.
 */
void ASurfaceControl_destroy(ASurfaceControl* surface_control) __INTRODUCED_IN(29);

struct ASurfaceTransaction;

/**
 * ASurfaceTransaction is a collection of updates to the surface tree that must
 * be applied atomically.
 */
typedef struct ASurfaceTransaction ASurfaceTransaction;

/**
 * The caller takes ownership of the transaction and must release it using
 * ASurfaceControl_delete below.
 */
ASurfaceTransaction* ASurfaceTransaction_create() __INTRODUCED_IN(29);

/**
 * Destroys the |transaction| object.
 */
void ASurfaceTransaction_delete(ASurfaceTransaction* transaction) __INTRODUCED_IN(29);

/**
 * Applies the updates accumulated in |transaction|.
 *
 * Note that the transaction is guaranteed to be applied atomically. The
 * transactions which are applied on the same thread are also guaranteed to be
 * applied in order.
 */
void ASurfaceTransaction_apply(ASurfaceTransaction* transaction) __INTRODUCED_IN(29);

/**
 * Since the transactions are applied asynchronously, the
 * ASurfaceTransaction_OnComplete callback can be used to be notified when a frame
 * including the updates in a transaction was presented.
 *
 * |context| is the optional context provided by the client that is passed into
 * the callback.
 * |present_fence| is the sync fence that signals when the transaction has been presented.
 * The recipient of the callback takes ownership of the present_fence and is responsible for closing
 * it.
 *
 * It is safe to assume that once the present fence singals, that reads for all buffers,
 * submitted in previous transactions, which are not in the surface tree after a transaction is
 * applied, are finished and the buffers may be reused.
 *
 * THREADING
 * The transaction completed callback can be invoked on any thread.
 */
typedef void (*ASurfaceTransaction_OnComplete)(void* context, int32_t present_fence);

/**
 * Sets the callback that will be invoked when the updates from this transaction
 * are presented. For details on the callback semantics and data, see the
 * comments on the ASurfaceTransaction_OnComplete declaration above.
 */
void ASurfaceTransaction_setOnComplete(ASurfaceTransaction* transaction, void* context,
                                       ASurfaceTransaction_OnComplete func) __INTRODUCED_IN(29);

/* Parameter for ASurfaceTransaction_setVisibility */
enum {
    ASURFACE_TRANSACTION_VISIBILITY_HIDE = 0,
    ASURFACE_TRANSACTION_VISIBILITY_SHOW = 1,
};
/**
 * Updates the visibility of |surface_control|. If show is set to
 * ASURFACE_TRANSACTION_VISIBILITY_HIDE, the |surface_control| and all surfaces in its subtree will
 * be hidden.
 */
void ASurfaceTransaction_setVisibility(ASurfaceTransaction* transaction,
                                       ASurfaceControl* surface_control, int8_t visibility)
                                       __INTRODUCED_IN(29);

/**
 * Updates the z order index for |surface_control|. Note that the z order for a surface
 * is relative to other surfaces which are siblings of this surface. The behavior of sibilings with
 * the same z order is undefined.
 *
 * Z orders may be from MIN_INT32 to MAX_INT32. A layer's default z order index is 0.
 */
void ASurfaceTransaction_setZOrder(ASurfaceTransaction* transaction,
                                   ASurfaceControl* surface_control, int32_t z_order)
                                   __INTRODUCED_IN(29);

/**
 * Updates the AHardwareBuffer displayed for |surface_control|. If not -1, the
 * fence_fd should be a file descriptor that is signaled when all pending work
 * for the buffer is complete and the buffer can be safely read.
 *
 * The frameworks takes ownership of the |fence_fd| passed and is responsible
 * for closing it.
 */
void ASurfaceTransaction_setBuffer(ASurfaceTransaction* transaction,
                                   ASurfaceControl* surface_control, AHardwareBuffer* buffer,
                                   int fence_fd = -1) __INTRODUCED_IN(29);

/**
 * |source| the sub-rect within the buffer's content to be rendered inside the surface's area
 * The surface's source rect is clipped by the bounds of its current buffer. The source rect's width
 * and height must be > 0.
 *
 * |destination| specifies the rect in the parent's space where this surface will be drawn. The post
 * source rect bounds are scaled to fit the destination rect. The surface's destination rect is
 * clipped by the bounds of its parent. The destination rect's width and height must be > 0.
 *
 * |transform| the transform applied after the source rect is applied to the buffer. This parameter
 * should be set to 0 for no transform. To specify a transfrom use the NATIVE_WINDOW_TRANSFORM_*
 * enum.
 */
void ASurfaceTransaction_setGeometry(ASurfaceTransaction* transaction,
                                     ASurfaceControl* surface_control, const ARect& source,
                                     const ARect& destination, int32_t transform)
                                     __INTRODUCED_IN(29);


/* Parameter for ASurfaceTransaction_setBufferTransparency */
enum {
    ASURFACE_TRANSACTION_TRANSPARENCY_TRANSPARENT = 0,
    ASURFACE_TRANSACTION_TRANSPARENCY_TRANSLUCENT = 1,
    ASURFACE_TRANSACTION_TRANSPARENCY_OPAQUE = 2,
};
/**
 * Updates whether the content for the buffer associated with this surface is
 * completely opaque. If true, every pixel of content inside the buffer must be
 * opaque or visual errors can occur.
 */
void ASurfaceTransaction_setBufferTransparency(ASurfaceTransaction* transaction,
                                         ASurfaceControl* surface_control, int8_t transparency)
                                         __INTRODUCED_IN(29);

/**
 * Updates the region for the content on this surface updated in this
 * transaction. If unspecified, the complete surface is assumed to be damaged.
 */
void ASurfaceTransaction_setDamageRegion(ASurfaceTransaction* transaction,
                                         ASurfaceControl* surface_control, const ARect rects[],
                                         uint32_t count) __INTRODUCED_IN(29);

#endif // __ANDROID_API__ >= 29

__END_DECLS

#endif // ANDROID_SURFACE_CONTROL_H
