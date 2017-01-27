#ifndef ANDROID_PDX_UDS_SERVICE_DISPATCHER_H_
#define ANDROID_PDX_UDS_SERVICE_DISPATCHER_H_

#include <list>
#include <memory>
#include <mutex>
#include <unordered_map>

#include <pdx/file_handle.h>
#include <pdx/service_dispatcher.h>

namespace android {
namespace pdx {
namespace uds {

class ServiceDispatcher : public pdx::ServiceDispatcher {
 public:
  // Get a new instance of ServiceDispatcher, or return nullptr if init failed.
  static std::unique_ptr<pdx::ServiceDispatcher> Create();

  ~ServiceDispatcher() override;
  int AddService(const std::shared_ptr<Service>& service) override;
  int RemoveService(const std::shared_ptr<Service>& service) override;
  int ReceiveAndDispatch() override;
  int ReceiveAndDispatch(int timeout) override;
  int EnterDispatchLoop() override;
  void SetCanceled(bool cancel) override;
  bool IsCanceled() const override;

 private:
  ServiceDispatcher();

  // Internal thread accounting.
  int ThreadEnter();
  void ThreadExit();

  std::mutex mutex_;
  std::condition_variable condition_;
  std::atomic<bool> canceled_{false};

  std::list<std::shared_ptr<Service>> services_;

  int thread_count_ = 0;
  LocalHandle event_fd_;
  LocalHandle epoll_fd_;

  ServiceDispatcher(const ServiceDispatcher&) = delete;
  void operator=(const ServiceDispatcher&) = delete;
};

}  // namespace uds
}  // namespace pdx
}  // namespace android

#endif  // ANDROID_PDX_UDS_SERVICE_DISPATCHER_H_
