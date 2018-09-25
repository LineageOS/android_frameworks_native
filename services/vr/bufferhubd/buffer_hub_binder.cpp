#include <stdio.h>

#include <log/log.h>
#include <private/dvr/buffer_hub_binder.h>

namespace android {
namespace dvr {

status_t BufferHubBinderService::start() {
  ProcessState::self()->startThreadPool();
  IPCThreadState::self()->disableBackgroundScheduling(true);
  status_t result = BinderService<BufferHubBinderService>::publish();
  if (result != OK) {
    ALOGE("Publishing bufferhubd failed with error %d", result);
    return result;
  }

  return result;
}

status_t BufferHubBinderService::dump(int fd, const Vector<String16> & /* args */) {
  // TODO(b/115435506): not implemented yet
  FILE *out = fdopen(dup(fd), "w");

  fprintf(out, "BufferHubBinderService::dump(): Not Implemented.\n");

  fclose(out);
  return NO_ERROR;
}


}  // namespace dvr
}  // namespace android