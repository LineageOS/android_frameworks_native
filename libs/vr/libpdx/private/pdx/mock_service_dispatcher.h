#ifndef ANDROID_PDX_MOCK_SERVICE_DISPATCHER_H_
#define ANDROID_PDX_MOCK_SERVICE_DISPATCHER_H_

#include <gmock/gmock.h>
#include <pdx/service_dispatcher.h>

namespace android {
namespace pdx {

class MockServiceDispatcher : public ServiceDispatcher {
 public:
  MOCK_METHOD1(AddService, int(const std::shared_ptr<Service>& service));
  MOCK_METHOD1(RemoveService, int(const std::shared_ptr<Service>& service));
  MOCK_METHOD0(ReceiveAndDispatch, int());
  MOCK_METHOD1(ReceiveAndDispatch, int(int timeout));
  MOCK_METHOD0(EnterDispatchLoop, int());
  MOCK_METHOD1(SetCanceled, void(bool cancel));
  MOCK_CONST_METHOD0(IsCanceled, bool());
};

}  // namespace pdx
}  // namespace android

#endif  // ANDROID_PDX_MOCK_SERVICE_DISPATCHER_H_
