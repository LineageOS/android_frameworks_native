#ifndef ANDROID_DVR_BUFFER_H_
#define ANDROID_DVR_BUFFER_H_

#include <stdbool.h>
#include <stdint.h>
#include <memory>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct DvrWriteBuffer DvrWriteBuffer;
typedef struct DvrReadBuffer DvrReadBuffer;
typedef struct DvrBuffer DvrBuffer;
typedef struct AHardwareBuffer AHardwareBuffer;
struct native_handle;

// Write buffer
void dvrWriteBufferDestroy(DvrWriteBuffer* write_buffer);
int dvrWriteBufferGetId(DvrWriteBuffer* write_buffer);
// Caller must call AHardwareBuffer_release on hardware_buffer.
int dvrWriteBufferGetAHardwareBuffer(DvrWriteBuffer* write_buffer,
                                     AHardwareBuffer** hardware_buffer);
int dvrWriteBufferPost(DvrWriteBuffer* write_buffer, int ready_fence_fd,
                       const void* meta, size_t meta_size_bytes);
int dvrWriteBufferGain(DvrWriteBuffer* write_buffer, int* release_fence_fd);
int dvrWriteBufferGainAsync(DvrWriteBuffer* write_buffer);
const struct native_handle* dvrWriteBufferGetNativeHandle(
    DvrWriteBuffer* write_buffer);

// Read buffer
void dvrReadBufferDestroy(DvrReadBuffer* read_buffer);
int dvrReadBufferGetId(DvrReadBuffer* read_buffer);
// Caller must call AHardwareBuffer_release on hardware_buffer.
int dvrReadBufferGetAHardwareBuffer(DvrReadBuffer* read_buffer,
                                    AHardwareBuffer** hardware_buffer);
int dvrReadBufferAcquire(DvrReadBuffer* read_buffer, int* ready_fence_fd,
                         void* meta, size_t meta_size_bytes);
int dvrReadBufferRelease(DvrReadBuffer* read_buffer, int release_fence_fd);
int dvrReadBufferReleaseAsync(DvrReadBuffer* read_buffer);
const struct native_handle* dvrReadBufferGetNativeHandle(
    DvrReadBuffer* read_buffer);

// Buffer
void dvrBufferDestroy(DvrBuffer* buffer);
// Caller must call AHardwareBuffer_release on hardware_buffer.
int dvrBufferGetAHardwareBuffer(DvrBuffer* buffer,
                                AHardwareBuffer** hardware_buffer);
const struct native_handle* dvrBufferGetNativeHandle(DvrBuffer* buffer);

#ifdef __cplusplus
}  // extern "C"
#endif

namespace android {
namespace dvr {

class BufferProducer;
class BufferConsumer;
class IonBuffer;

DvrWriteBuffer* CreateDvrWriteBufferFromBufferProducer(
    const std::shared_ptr<BufferProducer>& buffer_producer);
DvrReadBuffer* CreateDvrReadBufferFromBufferConsumer(
    const std::shared_ptr<BufferConsumer>& buffer_consumer);
DvrBuffer* CreateDvrBufferFromIonBuffer(
    const std::shared_ptr<IonBuffer>& ion_buffer);

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_BUFFER_H_
