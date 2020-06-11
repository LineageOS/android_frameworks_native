/*
 * Copyright 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Authors: corbin.souffrant@leviathansecurity.com
//          brian.balling@leviathansecurity.com

#include <fuzzer/FuzzedDataProvider.h>
#include <helpers.h>
#include <pdx/client_channel.h>
#include <pdx/service.h>
#include <pdx/service_dispatcher.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/eventfd.h>
#include <thread>

using namespace android::pdx;

// Dispatch fuzzer entry point. This fuzzer creates a ServiceDispatcher
// and creates an endpoint that returns fuzzed messages that are passed
// to the ReceiveAndDispatch and DispatchLoop functions.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  eventfd_t wakeup_val = 1;
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);

  // Endpoint is only used to be immediately wrapped as a unique_ptr,
  // so it is ok to be using a raw ptr and new here without freeing.
  FuzzEndpoint* endpoint = new FuzzEndpoint(&fdp);
  std::unique_ptr<ServiceDispatcher> dispatcher = ServiceDispatcher::Create();
  std::shared_ptr<Channel> channel(nullptr);
  std::shared_ptr<Client> client(nullptr);
  std::shared_ptr<Service> service(
      new Service("FuzzService", std::unique_ptr<Endpoint>(endpoint)));

  service->SetChannel(0, std::shared_ptr<Channel>(channel));
  dispatcher->AddService(service);

  // Dispatcher blocks, so needs to run in its own thread.
  std::thread run_dispatcher([&]() {
    uint8_t opt = 0;

    // Right now the only operations block, so the while loop is pointless
    // but leaving it in, just in case that ever changes.
    while (fdp.remaining_bytes() > sizeof(MessageInfo)) {
      opt = fdp.ConsumeIntegral<uint8_t>() % dispatcher_operations.size();
      dispatcher_operations[opt](dispatcher, &fdp);
    }
  });

  // Continuously wake up the epoll so the dispatcher can run.
  while (fdp.remaining_bytes() > sizeof(MessageInfo)) {
    eventfd_write(endpoint->epoll_fd(), wakeup_val);
  }

  // Cleanup the dispatcher and thread.
  dispatcher->SetCanceled(true);
  if (run_dispatcher.joinable())
    run_dispatcher.join();
  dispatcher->RemoveService(service);

  return 0;
}
