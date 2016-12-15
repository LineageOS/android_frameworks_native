/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <mutex>
#include <array>
#include <sstream>
#include <algorithm>

#include <gui/Surface.h>
#include <gui/BufferItemConsumer.h>
#include <gui/GraphicBufferAlloc.h>

#include <ui/GraphicBuffer.h>
#include <ui/vec4.h>

#include <GLES3/gl3.h>

#include "Hwc2TestBuffer.h"
#include "Hwc2TestLayers.h"

using namespace android;

/* Returns a fence from egl */
typedef void (*FenceCallback)(int32_t fence, void* callbackArgs);

/* Returns fence to fence generator */
static void setFence(int32_t fence, void* fenceGenerator);


/* Used to receive the surfaces and fences from egl. The egl buffers are thrown
 * away. The fences are sent to the requester via a callback */
class Hwc2TestSurfaceManager {
public:
    /* Listens for a new frame, detaches the buffer and returns the fence
     * through saved callback. */
    class BufferListener : public ConsumerBase::FrameAvailableListener {
    public:
        BufferListener(sp<IGraphicBufferConsumer> consumer,
                FenceCallback callback, void* callbackArgs)
            : mConsumer(consumer),
              mCallback(callback),
              mCallbackArgs(callbackArgs) { }

        void onFrameAvailable(const BufferItem& /*item*/)
        {
            BufferItem item;

            if (mConsumer->acquireBuffer(&item, 0))
                return;
            if (mConsumer->detachBuffer(item.mSlot))
                return;

            mCallback(item.mFence->dup(), mCallbackArgs);
        }

    private:
        sp<IGraphicBufferConsumer> mConsumer;
        FenceCallback mCallback;
        void* mCallbackArgs;
    };

    /* Creates a buffer listener that waits on a new frame from the buffer
     * queue. */
    void initialize(const Area& bufferArea, android_pixel_format_t format,
            FenceCallback callback, void* callbackArgs)
    {
        sp<IGraphicBufferProducer> producer;
        sp<IGraphicBufferConsumer> consumer;
        BufferQueue::createBufferQueue(&producer, &consumer);

        consumer->setDefaultBufferSize(bufferArea.width, bufferArea.height);
        consumer->setDefaultBufferFormat(format);

        mBufferItemConsumer = new BufferItemConsumer(consumer, 0);

        mListener = new BufferListener(consumer, callback, callbackArgs);
        mBufferItemConsumer->setFrameAvailableListener(mListener);

        mSurface = new Surface(producer, true);
    }

    /* Used by Egl manager. The surface is never displayed. */
    sp<Surface> getSurface() const
    {
        return mSurface;
    }

private:
    sp<BufferItemConsumer> mBufferItemConsumer;
    sp<BufferListener> mListener;
    /* Used by Egl manager. The surface is never displayed */
    sp<Surface> mSurface;
};


/* Used to generate valid fences. It is not possible to create a dummy sync
 * fence for testing. Egl can generate buffers along with a valid fence.
 * The buffer cannot be guaranteed to be the same format across all devices so
 * a CPU filled buffer is used instead. The Egl fence is used along with the
 * CPU filled buffer. */
class Hwc2TestEglManager {
public:
    Hwc2TestEglManager()
        : mEglDisplay(EGL_NO_DISPLAY),
          mEglSurface(EGL_NO_SURFACE),
          mEglContext(EGL_NO_CONTEXT) { }

    ~Hwc2TestEglManager()
    {
        cleanup();
    }

    int initialize(sp<Surface> surface)
    {
        mSurface = surface;

        mEglDisplay = eglGetDisplay(EGL_DEFAULT_DISPLAY);
        if (mEglDisplay == EGL_NO_DISPLAY) return false;

        EGLint major;
        EGLint minor;
        if (!eglInitialize(mEglDisplay, &major, &minor)) {
            ALOGW("Could not initialize EGL");
            return false;
        }

        /* We're going to use a 1x1 pbuffer surface later on
         * The configuration distance doesn't really matter for what we're
         * trying to do */
        EGLint configAttrs[] = {
                EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
                EGL_RED_SIZE, 8,
                EGL_GREEN_SIZE, 8,
                EGL_BLUE_SIZE, 8,
                EGL_ALPHA_SIZE, 0,
                EGL_DEPTH_SIZE, 24,
                EGL_STENCIL_SIZE, 0,
                EGL_NONE
        };

        EGLConfig configs[1];
        EGLint configCnt;
        if (!eglChooseConfig(mEglDisplay, configAttrs, configs, 1,
                &configCnt)) {
            ALOGW("Could not select EGL configuration");
            eglReleaseThread();
            eglTerminate(mEglDisplay);
            return false;
        }

        if (configCnt <= 0) {
            ALOGW("Could not find EGL configuration");
            eglReleaseThread();
            eglTerminate(mEglDisplay);
            return false;
        }

        /* These objects are initialized below but the default "null" values are
         * used to cleanup properly at any point in the initialization sequence */
        EGLint attrs[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
        mEglContext = eglCreateContext(mEglDisplay, configs[0], EGL_NO_CONTEXT,
                attrs);
        if (mEglContext == EGL_NO_CONTEXT) {
            ALOGW("Could not create EGL context");
            cleanup();
            return false;
        }

        EGLint surfaceAttrs[] = { EGL_NONE };
        mEglSurface = eglCreateWindowSurface(mEglDisplay, configs[0],
                mSurface.get(), surfaceAttrs);
        if (mEglSurface == EGL_NO_SURFACE) {
            ALOGW("Could not create EGL surface");
            cleanup();
            return false;
        }

        if (!eglMakeCurrent(mEglDisplay, mEglSurface, mEglSurface, mEglContext)) {
            ALOGW("Could not change current EGL context");
            cleanup();
            return false;
        }

        return true;
    }

    void makeCurrent() const
    {
        eglMakeCurrent(mEglDisplay, mEglSurface, mEglSurface, mEglContext);
    }

    void present() const
    {
        eglSwapBuffers(mEglDisplay, mEglSurface);
    }

private:
    void cleanup()
    {
        if (mEglDisplay == EGL_NO_DISPLAY)
            return;
        if (mEglSurface != EGL_NO_SURFACE)
            eglDestroySurface(mEglDisplay, mEglSurface);
        if (mEglContext != EGL_NO_CONTEXT)
            eglDestroyContext(mEglDisplay, mEglContext);

        eglMakeCurrent(mEglDisplay, EGL_NO_SURFACE, EGL_NO_SURFACE,
                EGL_NO_CONTEXT);
        eglReleaseThread();
        eglTerminate(mEglDisplay);
    }

    sp<Surface> mSurface;
    EGLDisplay mEglDisplay;
    EGLSurface mEglSurface;
    EGLContext mEglContext;
};


static const std::array<vec2, 4> triangles = {{
    {  1.0f,  1.0f },
    { -1.0f,  1.0f },
    {  1.0f, -1.0f },
    { -1.0f, -1.0f },
}};

class Hwc2TestFenceGenerator {
public:

    Hwc2TestFenceGenerator()
    {
        mSurfaceManager.initialize({1, 1}, HAL_PIXEL_FORMAT_RGBA_8888,
                setFence, this);

        if (!mEglManager.initialize(mSurfaceManager.getSurface()))
            return;

        mEglManager.makeCurrent();

        glClearColor(0.0, 0.0, 0.0, 1.0);
        glEnableVertexAttribArray(0);
    }

    ~Hwc2TestFenceGenerator()
    {
        if (mFence >= 0)
            close(mFence);
        mFence = -1;

        mEglManager.makeCurrent();
    }

    /* It is not possible to simply generate a fence. The easiest way is to
     * generate a buffer using egl and use the associated fence. The buffer
     * cannot be guaranteed to be a certain format across all devices using this
     * method. Instead the buffer is generated using the CPU */
    int32_t get()
    {
        if (mFence >= 0) {
            return dup(mFence);
        }

        std::unique_lock<std::mutex> lock(mMutex);

        /* If the pending is still set to false and times out, we cannot recover.
         * Set an error and return */
        while (mPending != false) {
            if (mCv.wait_for(lock, std::chrono::seconds(2)) == std::cv_status::timeout)
                return -ETIME;
        }

        /* Generate a fence. The fence will be returned through the setFence
         * callback */
        mEglManager.makeCurrent();

        glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 0, triangles.data());
        glClear(GL_COLOR_BUFFER_BIT);

        mEglManager.present();

        /* Wait for the setFence callback */
        while (mPending != true) {
            if (mCv.wait_for(lock, std::chrono::seconds(2)) == std::cv_status::timeout)
                return -ETIME;
        }

        mPending = false;

        return dup(mFence);
    }

    /* Callback that sets the fence */
    void set(int32_t fence)
    {
        mFence = fence;
        mPending = true;

        mCv.notify_all();
    }

private:

    Hwc2TestSurfaceManager mSurfaceManager;
    Hwc2TestEglManager mEglManager;

    std::mutex mMutex;
    std::condition_variable mCv;

    int32_t mFence = -1;
    bool mPending = false;
};


static void setFence(int32_t fence, void* fenceGenerator)
{
    static_cast<Hwc2TestFenceGenerator*>(fenceGenerator)->set(fence);
}


Hwc2TestBuffer::Hwc2TestBuffer()
    : mFenceGenerator(new Hwc2TestFenceGenerator()) { }

Hwc2TestBuffer::~Hwc2TestBuffer() = default;

/* When the buffer changes sizes, save the new size and invalidate the current
 * buffer */
void Hwc2TestBuffer::updateBufferArea(const Area& bufferArea)
{
    if (mBufferArea.width == bufferArea.width
            && mBufferArea.height == bufferArea.height)
        return;

    mBufferArea.width = bufferArea.width;
    mBufferArea.height = bufferArea.height;

    mValidBuffer = false;
}

/* Returns a valid buffer handle and fence. The handle is filled using the CPU
 * to ensure the correct format across all devices. The fence is created using
 * egl. */
int Hwc2TestBuffer::get(buffer_handle_t* outHandle, int32_t* outFence)
{
    if (mBufferArea.width == -1 || mBufferArea.height == -1)
        return -EINVAL;

    /* If the current buffer is valid, the previous buffer can be reused.
     * Otherwise, create new buffer */
    if (!mValidBuffer) {
        int ret = generateBuffer();
        if (ret)
            return ret;
    }

    *outFence = mFenceGenerator->get();
    *outHandle = mHandle;

    mValidBuffer = true;

    return 0;
}

/* CPU fills a buffer to guarantee the correct buffer format across all
 * devices */
int Hwc2TestBuffer::generateBuffer()
{
    int ret;

    /* Create new graphic buffer with correct dimensions */
    mGraphicBuffer = mGraphicBufferAlloc.createGraphicBuffer(
            mBufferArea.width, mBufferArea.height, mFormat,
            GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_HW_RENDER,
            "hwc2_test_buffer", &ret);
    if (ret)
        return ret;

    /* Locks the buffer for writing */
    uint8_t* img;
    mGraphicBuffer->lock(GRALLOC_USAGE_SW_WRITE_OFTEN, (void**)(&img));

    uint32_t stride = mGraphicBuffer->getStride();

    /* Iterate from the top row of the buffer to the bottom row */
    for (int32_t y = 0; y < mBufferArea.height; y++) {

        /* Will be used as R, G and B values for pixel colors */
        uint8_t max = 255;
        uint8_t min = 0;

        /* Divide the rows into 3 sections. The first section will contain
         * the lighest colors. The last section will contain the darkest
         * colors. */
        if (y < mBufferArea.height * 1.0 / 3.0) {
            min = 255 / 2;
        } else if (y >= mBufferArea.height * 2.0 / 3.0) {
            max = 255 / 2;
        }

        /* Divide the columns into 3 sections. The first section is red,
         * the second is green and the third is blue */
        int32_t x = 0;
        for (; x < mBufferArea.width / 3; x++) {
            setColor(x, y, mFormat, stride, img, max, min, min, 255);
        }

        for (; x < mBufferArea.width * 2 / 3; x++) {
            setColor(x, y, mFormat, stride, img, min, max, min, 255);
        }

        for (; x < mBufferArea.width; x++) {
            setColor(x, y, mFormat, stride, img, min, min, max, 255);
        }
    }

    /* Unlock the buffer for reading */
    mGraphicBuffer->unlock();

    mHandle = mGraphicBuffer->handle;

    return 0;
}

/* Sets the pixel of a buffer given the location, format, stride and color.
 * Currently only supports RGBA_8888 */
void Hwc2TestBuffer::setColor(int32_t x, int32_t y,
        android_pixel_format_t format, uint32_t stride, uint8_t* img, uint8_t r,
        uint8_t g, uint8_t b, uint8_t a)
{
       switch (format) {
       case HAL_PIXEL_FORMAT_RGBA_8888:
           img[(y * stride + x) * 4 + 0] = r;
           img[(y * stride + x) * 4 + 1] = g;
           img[(y * stride + x) * 4 + 2] = b;
           img[(y * stride + x) * 4 + 3] = a;
           break;
       default:
           break;
       }
}
