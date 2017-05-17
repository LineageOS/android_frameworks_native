#ifndef ANDROID_DVR_BUFFER_QUEUE_H_
#define ANDROID_DVR_BUFFER_QUEUE_H_

#include <sys/cdefs.h>

#include <dvr/dvr_buffer.h>

__BEGIN_DECLS

typedef struct ANativeWindow ANativeWindow;

typedef struct DvrWriteBufferQueue DvrWriteBufferQueue;
typedef struct DvrReadBufferQueue DvrReadBufferQueue;

// WriteBufferQueue
void dvrWriteBufferQueueDestroy(DvrWriteBufferQueue* write_queue);
ssize_t dvrWriteBufferQueueGetCapacity(DvrWriteBufferQueue* write_queue);
int dvrWriteBufferQueueGetId(DvrWriteBufferQueue* write_queue);

// Returns ANativeWindow. Can be casted to a Java Surface using
// ANativeWindow_toSurface NDK API. Note that this method does not acquire an
// additional reference to the ANativeWindow returned, don't call
// ANativeWindow_release on it.
int dvrWriteBufferQueueGetExternalSurface(DvrWriteBufferQueue* write_queue,
                                          ANativeWindow** out_window);

int dvrWriteBufferQueueCreateReadQueue(DvrWriteBufferQueue* write_queue,
                                       DvrReadBufferQueue** out_read_queue);
int dvrWriteBufferQueueDequeue(DvrWriteBufferQueue* write_queue, int timeout,
                               DvrWriteBuffer* out_buffer, int* out_fence_fd);

// ReadeBufferQueue
void dvrReadBufferQueueDestroy(DvrReadBufferQueue* read_queue);
ssize_t dvrReadBufferQueueGetCapacity(DvrReadBufferQueue* read_queue);
int dvrReadBufferQueueGetId(DvrReadBufferQueue* read_queue);
int dvrReadBufferQueueCreateReadQueue(DvrReadBufferQueue* read_queue,
                                      DvrReadBufferQueue** out_read_queue);
int dvrReadBufferQueueDequeue(DvrReadBufferQueue* read_queue, int timeout,
                              DvrReadBuffer* out_buffer, int* out_fence_fd,
                              void* out_meta, size_t meta_size_bytes);

__END_DECLS

#endif  // ANDROID_DVR_BUFFER_QUEUE_H_
