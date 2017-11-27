/*
 * Copyright (C) 2010 The Android Open Source Project
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

#ifndef ANDROID_BUFFERLAYERCONSUMER_H
#define ANDROID_BUFFERLAYERCONSUMER_H

#include <EGL/egl.h>
#include <EGL/eglext.h>

#include <gui/BufferQueueDefs.h>
#include <gui/ConsumerBase.h>

#include <ui/FenceTime.h>
#include <ui/GraphicBuffer.h>
#include <ui/Region.h>

#include <utils/String8.h>
#include <utils/Vector.h>
#include <utils/threads.h>

namespace android {
// ----------------------------------------------------------------------------

class DispSync;
class Layer;
class String8;

/*
 * BufferLayerConsumer consumes buffers of graphics data from a BufferQueue,
 * and makes them available to OpenGL as a texture.
 *
 * A typical usage pattern is to set up the BufferLayerConsumer with the
 * desired options, and call updateTexImage() when a new frame is desired.
 * If a new frame is available, the texture will be updated.  If not,
 * the previous contents are retained.
 *
 * The texture is attached to the GL_TEXTURE_EXTERNAL_OES texture target, in
 * the EGL context of the first thread that calls updateTexImage(). After that
 * point, all calls to updateTexImage must be made with the same OpenGL ES
 * context current.
 *
 * This class was previously called SurfaceTexture.
 */
class BufferLayerConsumer : public ConsumerBase {
public:
    static const status_t BUFFER_REJECTED = UNKNOWN_ERROR + 8;

    class BufferRejecter {
        friend class BufferLayerConsumer;
        virtual bool reject(const sp<GraphicBuffer>& buf, const BufferItem& item) = 0;

    protected:
        virtual ~BufferRejecter() {}
    };

    struct ContentsChangedListener : public FrameAvailableListener {
        virtual void onSidebandStreamChanged() = 0;
    };

    // BufferLayerConsumer constructs a new BufferLayerConsumer object.
    // The tex parameter indicates the name of the OpenGL ES
    // texture to which images are to be streamed.
    BufferLayerConsumer(const sp<IGraphicBufferConsumer>& bq, uint32_t tex, Layer* layer);

    // Sets the contents changed listener. This should be used instead of
    // ConsumerBase::setFrameAvailableListener().
    void setContentsChangedListener(const wp<ContentsChangedListener>& listener);

    nsecs_t computeExpectedPresent(const DispSync& dispSync);

    // updateTexImage acquires the most recently queued buffer, and sets the
    // image contents of the target texture to it.
    //
    // This call may only be made while the OpenGL ES context to which the
    // target texture belongs is bound to the calling thread.
    //
    // This calls doGLFenceWait to ensure proper synchronization.
    //
    // This version of updateTexImage() takes a functor that may be used to
    // reject the newly acquired buffer.  Unlike the GLConsumer version,
    // this does not guarantee that the buffer has been bound to the GL
    // texture.
    status_t updateTexImage(BufferRejecter* rejecter, const DispSync& dispSync, bool* autoRefresh,
                            bool* queuedBuffer, uint64_t maxFrameNumber);

    // setReleaseFence stores a fence that will signal when the current buffer
    // is no longer being read. This fence will be returned to the producer
    // when the current buffer is released by updateTexImage(). Multiple
    // fences can be set for a given buffer; they will be merged into a single
    // union fence.
    void setReleaseFence(const sp<Fence>& fence);

    bool releasePendingBuffer();

    // getTransformMatrix retrieves the 4x4 texture coordinate transform matrix
    // associated with the texture image set by the most recent call to
    // updateTexImage.
    //
    // This transform matrix maps 2D homogeneous texture coordinates of the form
    // (s, t, 0, 1) with s and t in the inclusive range [0, 1] to the texture
    // coordinate that should be used to sample that location from the texture.
    // Sampling the texture outside of the range of this transform is undefined.
    //
    // This transform is necessary to compensate for transforms that the stream
    // content producer may implicitly apply to the content. By forcing users of
    // a BufferLayerConsumer to apply this transform we avoid performing an extra
    // copy of the data that would be needed to hide the transform from the
    // user.
    //
    // The matrix is stored in column-major order so that it may be passed
    // directly to OpenGL ES via the glLoadMatrixf or glUniformMatrix4fv
    // functions.
    void getTransformMatrix(float mtx[16]);

    // getTimestamp retrieves the timestamp associated with the texture image
    // set by the most recent call to updateTexImage.
    //
    // The timestamp is in nanoseconds, and is monotonically increasing. Its
    // other semantics (zero point, etc) are source-dependent and should be
    // documented by the source.
    int64_t getTimestamp();

    // getDataSpace retrieves the DataSpace associated with the texture image
    // set by the most recent call to updateTexImage.
    android_dataspace getCurrentDataSpace();

    // getFrameNumber retrieves the frame number associated with the texture
    // image set by the most recent call to updateTexImage.
    //
    // The frame number is an incrementing counter set to 0 at the creation of
    // the BufferQueue associated with this consumer.
    uint64_t getFrameNumber();

    bool getTransformToDisplayInverse() const;

    // must be called from SF main thread
    const Region& getSurfaceDamage() const;

    // setDefaultBufferSize is used to set the size of buffers returned by
    // requestBuffers when a with and height of zero is requested.
    // A call to setDefaultBufferSize() may trigger requestBuffers() to
    // be called from the client.
    // The width and height parameters must be no greater than the minimum of
    // GL_MAX_VIEWPORT_DIMS and GL_MAX_TEXTURE_SIZE (see: glGetIntegerv).
    // An error due to invalid dimensions might not be reported until
    // updateTexImage() is called.
    status_t setDefaultBufferSize(uint32_t width, uint32_t height);

    // setFilteringEnabled sets whether the transform matrix should be computed
    // for use with bilinear filtering.
    void setFilteringEnabled(bool enabled);

    // getCurrentBuffer returns the buffer associated with the current image.
    // When outSlot is not nullptr, the current buffer slot index is also
    // returned.
    sp<GraphicBuffer> getCurrentBuffer(int* outSlot = nullptr) const;

    // getCurrentCrop returns the cropping rectangle of the current buffer.
    Rect getCurrentCrop() const;

    // getCurrentTransform returns the transform of the current buffer.
    uint32_t getCurrentTransform() const;

    // getCurrentScalingMode returns the scaling mode of the current buffer.
    uint32_t getCurrentScalingMode() const;

    // getCurrentFence returns the fence indicating when the current buffer is
    // ready to be read from.
    sp<Fence> getCurrentFence() const;

    // getCurrentFence returns the FenceTime indicating when the current
    // buffer is ready to be read from.
    std::shared_ptr<FenceTime> getCurrentFenceTime() const;

    // setConsumerUsageBits overrides the ConsumerBase method to OR
    // DEFAULT_USAGE_FLAGS to usage.
    status_t setConsumerUsageBits(uint64_t usage);

protected:
    // abandonLocked overrides the ConsumerBase method to clear
    // mCurrentTextureImage in addition to the ConsumerBase behavior.
    virtual void abandonLocked();

    // dumpLocked overrides the ConsumerBase method to dump BufferLayerConsumer-
    // specific info in addition to the ConsumerBase behavior.
    virtual void dumpLocked(String8& result, const char* prefix) const;

    // acquireBufferLocked overrides the ConsumerBase method to update the
    // mEglSlots array in addition to the ConsumerBase behavior.
    virtual status_t acquireBufferLocked(BufferItem* item, nsecs_t presentWhen,
                                         uint64_t maxFrameNumber = 0) override;

    struct PendingRelease {
        PendingRelease() : isPending(false), currentTexture(-1), graphicBuffer() {}

        bool isPending;
        int currentTexture;
        sp<GraphicBuffer> graphicBuffer;
    };

    // This releases the buffer in the slot referenced by mCurrentTexture,
    // then updates state to refer to the BufferItem, which must be a
    // newly-acquired buffer. If pendingRelease is not null, the parameters
    // which would have been passed to releaseBufferLocked upon the successful
    // completion of the method will instead be returned to the caller, so that
    // it may call releaseBufferLocked itself later.
    status_t updateAndReleaseLocked(const BufferItem& item,
                                    PendingRelease* pendingRelease = nullptr);

    // Binds mTexName and the current buffer to sTexTarget.  Uses
    // mCurrentTexture if it's set, mCurrentTextureImage if not.  If the
    // bind succeeds, this calls doGLFenceWait.
    status_t bindTextureImageLocked();

    // Gets the current EGLDisplay and EGLContext values, and compares them
    // to mEglDisplay and mEglContext.  If the fields have been previously
    // set, the values must match; if not, the fields are set to the current
    // values.
    status_t checkAndUpdateEglStateLocked();

private:
    // EglImage is a utility class for tracking and creating EGLImageKHRs. There
    // is primarily just one image per slot, but there is also special cases:
    //  - After freeBuffer, we must still keep the current image/buffer
    // Reference counting EGLImages lets us handle all these cases easily while
    // also only creating new EGLImages from buffers when required.
    class EglImage : public LightRefBase<EglImage> {
    public:
        EglImage(sp<GraphicBuffer> graphicBuffer);

        // createIfNeeded creates an EGLImage if required (we haven't created
        // one yet, or the EGLDisplay or crop-rect has changed).
        status_t createIfNeeded(EGLDisplay display, const Rect& cropRect);

        // This calls glEGLImageTargetTexture2DOES to bind the image to the
        // texture in the specified texture target.
        void bindToTextureTarget(uint32_t texTarget);

        const sp<GraphicBuffer>& graphicBuffer() { return mGraphicBuffer; }
        const native_handle* graphicBufferHandle() {
            return mGraphicBuffer == NULL ? NULL : mGraphicBuffer->handle;
        }

    private:
        // Only allow instantiation using ref counting.
        friend class LightRefBase<EglImage>;
        virtual ~EglImage();

        // createImage creates a new EGLImage from a GraphicBuffer.
        EGLImageKHR createImage(EGLDisplay dpy, const sp<GraphicBuffer>& graphicBuffer,
                                const Rect& crop);

        // Disallow copying
        EglImage(const EglImage& rhs);
        void operator=(const EglImage& rhs);

        // mGraphicBuffer is the buffer that was used to create this image.
        sp<GraphicBuffer> mGraphicBuffer;

        // mEglImage is the EGLImage created from mGraphicBuffer.
        EGLImageKHR mEglImage;

        // mEGLDisplay is the EGLDisplay that was used to create mEglImage.
        EGLDisplay mEglDisplay;

        // mCropRect is the crop rectangle passed to EGL when mEglImage
        // was created.
        Rect mCropRect;
    };

    // freeBufferLocked frees up the given buffer slot. If the slot has been
    // initialized this will release the reference to the GraphicBuffer in that
    // slot and destroy the EGLImage in that slot.  Otherwise it has no effect.
    //
    // This method must be called with mMutex locked.
    virtual void freeBufferLocked(int slotIndex);

    // IConsumerListener interface
    void onDisconnect() override;
    void onSidebandStreamChanged() override;
    void addAndGetFrameTimestamps(const NewFrameEventsEntry* newTimestamps,
                                  FrameEventHistoryDelta* outDelta) override;

    // computeCurrentTransformMatrixLocked computes the transform matrix for the
    // current texture.  It uses mCurrentTransform and the current GraphicBuffer
    // to compute this matrix and stores it in mCurrentTransformMatrix.
    // mCurrentTextureImage must not be NULL.
    void computeCurrentTransformMatrixLocked();

    // doGLFenceWaitLocked inserts a wait command into the OpenGL ES command
    // stream to ensure that it is safe for future OpenGL ES commands to
    // access the current texture buffer.
    status_t doGLFenceWaitLocked() const;

    // syncForReleaseLocked performs the synchronization needed to release the
    // current slot from an OpenGL ES context.  If needed it will set the
    // current slot's fence to guard against a producer accessing the buffer
    // before the outstanding accesses have completed.
    status_t syncForReleaseLocked(EGLDisplay dpy);

    // sTexTarget is the GL texture target with which the GL texture object is
    // associated.
    static constexpr uint32_t sTexTarget = 0x8D65; // GL_TEXTURE_EXTERNAL_OES

    // The default consumer usage flags that BufferLayerConsumer always sets on its
    // BufferQueue instance; these will be OR:d with any additional flags passed
    // from the BufferLayerConsumer user. In particular, BufferLayerConsumer will always
    // consume buffers as hardware textures.
    static const uint64_t DEFAULT_USAGE_FLAGS = GraphicBuffer::USAGE_HW_TEXTURE;

    // mCurrentTextureImage is the EglImage/buffer of the current texture. It's
    // possible that this buffer is not associated with any buffer slot, so we
    // must track it separately in order to support the getCurrentBuffer method.
    sp<EglImage> mCurrentTextureImage;

    // mCurrentCrop is the crop rectangle that applies to the current texture.
    // It gets set each time updateTexImage is called.
    Rect mCurrentCrop;

    // mCurrentTransform is the transform identifier for the current texture. It
    // gets set each time updateTexImage is called.
    uint32_t mCurrentTransform;

    // mCurrentScalingMode is the scaling mode for the current texture. It gets
    // set each time updateTexImage is called.
    uint32_t mCurrentScalingMode;

    // mCurrentFence is the fence received from BufferQueue in updateTexImage.
    sp<Fence> mCurrentFence;

    // The FenceTime wrapper around mCurrentFence.
    std::shared_ptr<FenceTime> mCurrentFenceTime{FenceTime::NO_FENCE};

    // mCurrentTransformMatrix is the transform matrix for the current texture.
    // It gets computed by computeTransformMatrix each time updateTexImage is
    // called.
    float mCurrentTransformMatrix[16];

    // mCurrentTimestamp is the timestamp for the current texture. It
    // gets set each time updateTexImage is called.
    int64_t mCurrentTimestamp;

    // mCurrentDataSpace is the dataspace for the current texture. It
    // gets set each time updateTexImage is called.
    android_dataspace mCurrentDataSpace;

    // mCurrentFrameNumber is the frame counter for the current texture.
    // It gets set each time updateTexImage is called.
    uint64_t mCurrentFrameNumber;

    // Indicates this buffer must be transformed by the inverse transform of the screen
    // it is displayed onto. This is applied after BufferLayerConsumer::mCurrentTransform.
    // This must be set/read from SurfaceFlinger's main thread.
    bool mCurrentTransformToDisplayInverse;

    // The portion of this surface that has changed since the previous frame
    Region mCurrentSurfaceDamage;

    uint32_t mDefaultWidth, mDefaultHeight;

    // mFilteringEnabled indicates whether the transform matrix is computed for
    // use with bilinear filtering. It defaults to true and is changed by
    // setFilteringEnabled().
    bool mFilteringEnabled;

    // mTexName is the name of the OpenGL texture to which streamed images will
    // be bound when updateTexImage is called. It is set at construction time.
    const uint32_t mTexName;

    // The layer for this BufferLayerConsumer
    const wp<Layer> mLayer;

    wp<ContentsChangedListener> mContentsChangedListener;

    // EGLSlot contains the information and object references that
    // BufferLayerConsumer maintains about a BufferQueue buffer slot.
    struct EglSlot {
        // mEglImage is the EGLImage created from mGraphicBuffer.
        sp<EglImage> mEglImage;
    };

    // mEglDisplay is the EGLDisplay with which this BufferLayerConsumer is currently
    // associated.  It is intialized to EGL_NO_DISPLAY and gets set to the
    // current display when updateTexImage is called for the first time.
    EGLDisplay mEglDisplay;

    // mEglContext is the OpenGL ES context with which this BufferLayerConsumer is
    // currently associated.  It is initialized to EGL_NO_CONTEXT and gets set
    // to the current GL context when updateTexImage is called for the first
    // time.
    EGLContext mEglContext;

    // mEGLSlots stores the buffers that have been allocated by the BufferQueue
    // for each buffer slot.  It is initialized to null pointers, and gets
    // filled in with the result of BufferQueue::acquire when the
    // client dequeues a buffer from a
    // slot that has not yet been used. The buffer allocated to a slot will also
    // be replaced if the requested buffer usage or geometry differs from that
    // of the buffer allocated to a slot.
    EglSlot mEglSlots[BufferQueueDefs::NUM_BUFFER_SLOTS];

    // mCurrentTexture is the buffer slot index of the buffer that is currently
    // bound to the OpenGL texture. It is initialized to INVALID_BUFFER_SLOT,
    // indicating that no buffer slot is currently bound to the texture. Note,
    // however, that a value of INVALID_BUFFER_SLOT does not necessarily mean
    // that no buffer is bound to the texture. A call to setBufferCount will
    // reset mCurrentTexture to INVALID_BUFFER_SLOT.
    int mCurrentTexture;

    // A release that is pending on the receipt of a new release fence from
    // presentDisplay
    PendingRelease mPendingRelease;
};

// ----------------------------------------------------------------------------
}; // namespace android

#endif // ANDROID_BUFFERLAYERCONSUMER_H
