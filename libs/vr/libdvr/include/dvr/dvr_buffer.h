#ifndef ANDROID_DVR_BUFFER_H_
#define ANDROID_DVR_BUFFER_H_

#include <memory>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DvrWriteBuffer DvrWriteBuffer;
typedef struct DvrReadBuffer DvrReadBuffer;
typedef struct AHardwareBuffer AHardwareBuffer;

// Write buffer
void dvrWriteBufferDestroy(DvrWriteBuffer* client);
void dvrWriteBufferGetBlobFds(DvrWriteBuffer* client, int* fds,
                              size_t* fds_count, size_t max_fds_count);
int dvrWriteBufferGetAHardwareBuffer(DvrWriteBuffer* client,
                                     AHardwareBuffer** hardware_buffer);
int dvrWriteBufferPost(DvrWriteBuffer* client, int ready_fence_fd,
                       const void* meta, size_t meta_size_bytes);
int dvrWriteBufferGain(DvrWriteBuffer* client, int* release_fence_fd);
int dvrWriteBufferGainAsync(DvrWriteBuffer* client);

// Read buffer
void dvrReadBufferGetBlobFds(DvrReadBuffer* client, int* fds, size_t* fds_count,
                             size_t max_fds_count);
int dvrReadBufferGetAHardwareBuffer(DvrReadBuffer* client,
                                    AHardwareBuffer** hardware_buffer);
int dvrReadBufferAcquire(DvrReadBuffer* client, int* ready_fence_fd, void* meta,
                         size_t meta_size_bytes);
int dvrReadBufferRelease(DvrReadBuffer* client, int release_fence_fd);
int dvrReadBufferReleaseAsync(DvrReadBuffer* client);

#ifdef __cplusplus
}  // extern "C"
#endif

namespace android {
namespace dvr {

class BufferProducer;
class BufferConsumer;

DvrWriteBuffer* CreateDvrWriteBufferFromBufferProducer(
    std::unique_ptr<BufferProducer> buffer_producer);
DvrReadBuffer* CreateDvrReadBufferFromBufferConsumer(
    std::unique_ptr<BufferConsumer> buffer_consumer);

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFER_H_
