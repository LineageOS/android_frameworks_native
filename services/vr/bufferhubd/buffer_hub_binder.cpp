#include <stdio.h>

#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <log/log.h>
#include <private/dvr/buffer_hub_binder.h>
#include <private/dvr/buffer_node.h>

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

  fprintf(out, "Binder service:\n");
  // Active buffers
  fprintf(out, "Active BufferClients: %zu\n", client_list_.size());
  // TODO(b/117790952): print buffer information after BufferNode has it
  // TODO(b/116526156): print more information once we have them

  if (pdx_service_) {
    fprintf(out, "\nPDX service:\n");
    // BufferHubService::Dumpstate(size_t) is not actually using the param
    // So just using 0 as the length
    fprintf(out, "%s", pdx_service_->DumpState(0).c_str());
  } else {
    fprintf(out, "PDX service not registered or died.\n");
  }

  fclose(out);
  return NO_ERROR;
}

status_t BufferHubBinderService::registerToken(
    const std::weak_ptr<BufferNode> node, uint64_t* outToken) {
  do {
    *outToken = token_engine_();
  } while (token_map_.find(*outToken) != token_map_.end());

  token_map_.emplace(*outToken, node);
  return NO_ERROR;
}

sp<IBufferClient> BufferHubBinderService::createBuffer(
    uint32_t width, uint32_t height, uint32_t layer_count, uint32_t format,
    uint64_t usage, uint64_t user_metadata_size) {
  std::shared_ptr<BufferNode> node = std::make_shared<BufferNode>(
      width, height, layer_count, format, usage, user_metadata_size);

  sp<BufferClient> client = new BufferClient(node, this);
  // Add it to list for bookkeeping and dumpsys.
  client_list_.push_back(client);

  return client;
}

status_t BufferHubBinderService::importBuffer(uint64_t token,
                                              sp<IBufferClient>* outClient) {
  auto iter = token_map_.find(token);

  if (iter == token_map_.end()) {  // Not found
    ALOGE("BufferHubBinderService::importBuffer: token %" PRIu64
          "does not exist.",
          token);
    return PERMISSION_DENIED;
  }

  if (iter->second.expired()) {  // Gone
    ALOGW(
        "BufferHubBinderService::importBuffer: the original node of token "
        "%" PRIu64 "has gone.",
        token);
    token_map_.erase(iter);
    return DEAD_OBJECT;
  }

  // Promote the weak_ptr
  std::shared_ptr<BufferNode> node(iter->second);
  if (!node) {
    ALOGE("BufferHubBinderService::importBuffer: promote weak_ptr failed.");
    token_map_.erase(iter);
    return DEAD_OBJECT;
  }

  sp<BufferClient> client = new BufferClient(node, this);
  *outClient = client;

  token_map_.erase(iter);
  client_list_.push_back(client);

  return NO_ERROR;
}

}  // namespace dvr
}  // namespace android
