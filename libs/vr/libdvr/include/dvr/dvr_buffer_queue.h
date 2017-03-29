#ifndef ANDROID_DVR_BUFFER_QUEUE_H_
#define ANDROID_DVR_BUFFER_QUEUE_H_

#include <dvr/dvr_buffer.h>
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DvrWriteBufferQueue DvrWriteBufferQueue;
typedef struct DvrReadBufferQueue DvrReadBufferQueue;

// WriteBufferQueue
void dvrWriteBufferQueueDestroy(DvrWriteBufferQueue* write_queue);
size_t dvrWriteBufferQueueGetCapacity(DvrWriteBufferQueue* write_queue);

// Returns ANativeWindow in the form of jobject. Can be casted to ANativeWindow
// using ANativeWindow_fromSurface NDK API.
jobject dvrWriteBufferQueueGetExternalSurface(DvrWriteBufferQueue* write_queue,
                                              JNIEnv* env);

int dvrWriteBufferQueueCreateReadQueue(DvrWriteBufferQueue* write_queue,
                                       DvrReadBufferQueue** out_read_queue);
int dvrWriteBufferQueueDequeue(DvrWriteBufferQueue* write_queue, int timeout,
                               DvrWriteBuffer** out_buffer, int* out_fence_fd);

// ReadeBufferQueue
void dvrReadBufferQueueDestroy(DvrReadBufferQueue* read_queue);
size_t dvrReadBufferQueueGetCapacity(DvrReadBufferQueue* read_queue);
int dvrReadBufferQueueCreateReadQueue(DvrReadBufferQueue* read_queue,
                                      DvrReadBufferQueue** out_read_queue);
int dvrReadBufferQueueDequeue(DvrReadBufferQueue* read_queue, int timeout,
                              DvrReadBuffer** out_buffer, int* out_fence_fd,
                              void* out_meta, size_t meta_size_bytes);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ANDROID_DVR_BUFFER_QUEUE_H_
