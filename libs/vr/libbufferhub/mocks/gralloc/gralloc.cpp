#include <gralloc_mock.h>
#include <hardware/gralloc.h>

static alloc_device_t sdevice;

static int local_registerBuffer(struct gralloc_module_t const*,
                                buffer_handle_t handle) {
  return GrallocMock::staticObject->registerBuffer(handle);
}

static int local_unregisterBuffer(struct gralloc_module_t const*,
                                  buffer_handle_t handle) {
  return GrallocMock::staticObject->unregisterBuffer(handle);
}

static int local_unlock(struct gralloc_module_t const*,
                        buffer_handle_t handle) {
  return GrallocMock::staticObject->unlock(handle);
}

static int local_lock(struct gralloc_module_t const*, buffer_handle_t handle,
                      int usage, int l, int t, int w, int h, void** vaddr) {
  return GrallocMock::staticObject->lock(handle, usage, l, t, w, h, vaddr);
}

static int local_alloc(struct alloc_device_t*, int w, int h, int format,
                       int usage, buffer_handle_t* handle, int* stride) {
  return GrallocMock::staticObject->alloc(w, h, format, usage, handle, stride);
}

static int local_free(struct alloc_device_t*, buffer_handle_t handle) {
  return GrallocMock::staticObject->free(handle);
}

static int local_open(const struct hw_module_t*, const char*,
                      struct hw_device_t** device) {
  sdevice.alloc = local_alloc;
  sdevice.free = local_free;
  *device = reinterpret_cast<hw_device_t*>(&sdevice);
  return 0;
}

static hw_module_methods_t smethods;

static gralloc_module_t smodule;

int hw_get_module(const char*, const struct hw_module_t** module) {
  smodule.registerBuffer = local_registerBuffer;
  smodule.unregisterBuffer = local_unregisterBuffer;
  smodule.lock = local_lock;
  smodule.unlock = local_unlock;
  smethods.open = local_open;
  smodule.common.methods = &smethods;
  *module = reinterpret_cast<hw_module_t*>(&smodule);
  return 0;
}

int native_handle_close(const native_handle_t* handle) {
  return GrallocMock::staticObject->native_handle_close(handle);
}

int native_handle_delete(native_handle_t* handle) {
  return GrallocMock::staticObject->native_handle_delete(handle);
}

native_handle_t* native_handle_create(int numFds, int numInts) {
  return GrallocMock::staticObject->native_handle_create(numFds, numInts);
}
