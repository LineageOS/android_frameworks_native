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

#include <cutils/memory.h>

#include <utils/Log.h>

#include <binder/IPCThreadState.h>
#include <binder/ProcessState.h>
#include <binder/IServiceManager.h>

#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>
#include <gralloc_priv.h>
#include <qdMetaData.h>

template <class Type>
inline Type ALIGN(Type x, Type align) {
    return (x + align-1) & ~(align-1);
}

using namespace android;

int main(int argc, char** argv)
{
    // set up the thread-pool
    sp<ProcessState> proc(ProcessState::self());
    ProcessState::self()->startThreadPool();

    // create a client to surfaceflinger
    sp<SurfaceComposerClient> client = new SurfaceComposerClient();
    int width = 1600, height = 2304;

    sp<SurfaceControl> surfaceControl = client->createSurface(
            String8("BlurSurface"), width, height, PIXEL_FORMAT_RGBX_8888, 0);
    const char* path = "/storage/emulated/0/Pictures/1600x2344_RGBX_8888.raw";
    SurfaceComposerClient::openGlobalTransaction();
    // Set a higher zorder
    surfaceControl->setLayer(0x800000);
    SurfaceComposerClient::closeGlobalTransaction();
    sp<Surface> surface = surfaceControl->getSurface();

    sp<ANativeWindow> anw;
    anw = surface;
    native_window_api_connect(anw.get(), NATIVE_WINDOW_API_MEDIA);
    uint32_t usage = 0;
    ANativeWindowBuffer* buffer;
    int count = 0;

    int minUndequeuedBufs = 0;
    int err = anw->query(anw.get(), NATIVE_WINDOW_MIN_UNDEQUEUED_BUFFERS,
                      &minUndequeuedBufs);
    ALOGE("minUndequeuedBufs=%d", minUndequeuedBufs);
    int buffCount  = 3 + minUndequeuedBufs;
    err = native_window_set_buffer_count(anw.get(), buffCount);
    ALOGE("setBuffCount = %d", buffCount);
    SurfaceComposerClient::openGlobalTransaction();
 //   surfaceControl->setPosition(0,72);
//    surfaceControl->setSize(width, height);
    SurfaceComposerClient::closeGlobalTransaction();
    usage = GRALLOC_USAGE_SW_WRITE_MASK;
    err = native_window_set_usage(anw.get(), usage);
    if (err != 0) {
        ALOGE("native_window_set_usage failed: %s (%d)", strerror(-err), err);
    }
    uint32_t blur = 1;
#if 1
    for (int i = 0; i < buffCount-1; i++) { // XXX: if looped thru buffCount, its not working.
        native_window_dequeue_buffer_and_wait(anw.get(),&buffer);
        private_handle_t* hnd = static_cast<private_handle_t*>
            (const_cast<native_handle_t*>(buffer->handle));
        setMetaData(hnd, BLUR_LAYER, (void*) &blur);
        // Read the input file
        FILE *fp = fopen(path, "r");
        ALOGE("Writing to buffer %d", i);
        if (fp) {
            int stride = ALIGN(width, 32)*4;
            for (int i = 0; i < height; i++) {
                size_t err = fread((void*)hnd->base, 1, (width*4), fp);
                fseek ( fp , width*4 , SEEK_CUR);
                hnd->base += stride;
            }
            fclose(fp);
            fp = NULL;
        }
        anw->queueBuffer(anw.get(), buffer, -1);
    }
    ALOGE("wrote to the buffers....");
#endif
    while (true) {
        ALOGE("dequeue and wait");
        native_window_dequeue_buffer_and_wait(anw.get(),&buffer);
        usleep(16666);

        ALOGE("queueBuffer...");
        anw->queueBuffer(anw.get(),buffer,-1);
    }

    printf("test complete. CTRL+C to finish.\n");

    IPCThreadState::self()->joinThreadPool();
    return 0;
}
