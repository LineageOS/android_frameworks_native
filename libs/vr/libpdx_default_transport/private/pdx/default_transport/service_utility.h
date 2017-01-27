#ifndef ANDROID_PDX_DEFAULT_TRANSPORT_SERVICE_UTILITY_H_
#define ANDROID_PDX_DEFAULT_TRANSPORT_SERVICE_UTILITY_H_

#include <pdx/client.h>
#include <pdx/default_transport/client_channel_factory.h>
#include <pdx/service.h>
#include <pdx/status.h>

namespace android {
namespace pdx {
namespace default_transport {

class ServiceUtility : public ClientBase<ServiceUtility> {
 public:
  Status<int> ReloadSystemProperties() {
    Transaction transaction{*this};
    return ReturnStatusOrError(
        transaction.Send<int>(opcodes::REPORT_SYSPROP_CHANGE));
  }

  static std::string GetRootEndpointPath() {
    return ClientChannelFactory::GetRootEndpointPath();
  }
  static std::string GetEndpointPath(const std::string& endpoint_path) {
    return ClientChannelFactory::GetEndpointPath(endpoint_path);
  }

 private:
  friend BASE;

  ServiceUtility(const std::string& endpoint_path, int* error = nullptr)
      : BASE(ClientChannelFactory::Create(endpoint_path)) {
    if (error)
      *error = Client::error();
  }

  ServiceUtility(const ServiceUtility&) = delete;
  void operator=(const ServiceUtility&) = delete;
};

}  // namespace default_transport
}  // namespace pdx
}  // namespace android

#endif  // ANDROID_PDX_DEFAULT_TRANSPORT_SERVICE_UTILITY_H_
