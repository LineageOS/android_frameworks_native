#include <stdio.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <log/log.h>
#include <private/dvr/buffer_hub_binder.h>

namespace android {
namespace dvr {

status_t BufferHubBinderService::start(
    const std::shared_ptr<BufferHubService>& pdx_service) {
  IPCThreadState::self()->disableBackgroundScheduling(true);

  sp<BufferHubBinderService> service = new BufferHubBinderService();
  service->pdx_service_ = pdx_service;

  // Not using BinderService::publish because need to get an instance of this
  // class (above). Following code is the same as
  // BinderService::publishAndJoinThreadPool
  sp<IServiceManager> sm = defaultServiceManager();
  status_t result = sm->addService(
      String16(getServiceName()), service,
      /*allowIsolated =*/false,
      /*dump flags =*/IServiceManager::DUMP_FLAG_PRIORITY_DEFAULT);
  if (result != NO_ERROR) {
    ALOGE("Publishing bufferhubd failed with error %d", result);
    return result;
  }

  sp<ProcessState> process_self(ProcessState::self());
  process_self->startThreadPool();

  return result;
}

status_t BufferHubBinderService::dump(int fd, const Vector<String16>& args) {
  FILE* out = fdopen(dup(fd), "w");

  // Currently not supporting args, so notify the user.
  if (!args.isEmpty()) {
    fprintf(out,
            "Note: dumpsys bufferhubd currently does not support args."
            "Input arguments are ignored.\n");
  }

  // TODO(b/116526156): output real data in this class once we have it
  if (pdx_service_) {
    // BufferHubService::Dumpstate(size_t) is not actually using the param
    // So just using 0 as the length
    fprintf(out, "%s", pdx_service_->DumpState(0).c_str());
  } else {
    fprintf(out, "PDX service not registered or died.\n");
  }

  fclose(out);
  return NO_ERROR;
}

sp<IBufferHub> BufferHubBinderService::getServiceProxy() {
  sp<IServiceManager> sm = defaultServiceManager();
  sp<IBinder> service = sm->checkService(String16(getServiceName()));

  if (service == nullptr) {
    ALOGE("getServiceProxy(): %s binder service not found!", getServiceName());
    return nullptr;
  }

  sp<IBufferHub> ret = interface_cast<IBufferHub>(service);
  if (ret == nullptr) {
    ALOGE("getServiceProxy(): %s binder service type casting error!",
          getServiceName());
    return nullptr;
  }

  return ret;
}

}  // namespace dvr
}  // namespace android
