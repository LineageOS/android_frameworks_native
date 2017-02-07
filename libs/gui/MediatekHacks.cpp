#include <gui/IGraphicBufferAlloc.h>
extern "C" {
    void _ZN7android11BufferQueueC1ERKNS_2spINS_19IGraphicBufferAllocEEE(const android::sp<android::IGraphicBufferAlloc>& allocator);
    void _ZN7android11BufferQueueC2ERKNS_2spINS_19IGraphicBufferAllocEEE(const android::sp<android::IGraphicBufferAlloc>& allocator);

    void _ZN7android11BufferQueueC1ERKNS_2spINS_19IGraphicBufferAllocEEE(const android::sp<android::IGraphicBufferAlloc>& allocator){
        _ZN7android11BufferQueueC2ERKNS_2spINS_19IGraphicBufferAllocEEE(allocator);
    }

    void _ZN7android14SurfaceControl8setLayerEi(int32_t);
    void _ZN7android14SurfaceControl8setLayerEj(uint32_t);

    void _ZN7android14SurfaceControl8setLayerEi(int32_t layer){
        _ZN7android14SurfaceControl8setLayerEj(static_cast<uint32_t>(layer));
    }
}
