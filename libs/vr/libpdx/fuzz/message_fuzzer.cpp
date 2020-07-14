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

// Fuzzer for Message object functions.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);

  FuzzEndpoint* endpoint = new FuzzEndpoint(&fdp);
  std::shared_ptr<Service> service(
      new Service("FuzzService", std::unique_ptr<Endpoint>(endpoint)));
  std::shared_ptr<Channel> channel(nullptr);

  // Generate a random Message object to call functions in.
  MessageInfo info;
  info.pid = fdp.ConsumeIntegral<int>();
  info.tid = fdp.ConsumeIntegral<int>();
  info.cid = fdp.ConsumeIntegral<int>();
  info.mid = fdp.ConsumeIntegral<int>();
  info.euid = fdp.ConsumeIntegral<int>();
  info.egid = fdp.ConsumeIntegral<int>();
  info.op = fdp.ConsumeIntegral<int32_t>();
  info.flags = fdp.ConsumeIntegral<uint32_t>();
  info.service = service.get();
  info.channel = channel.get();
  info.send_len = fdp.ConsumeIntegral<size_t>();
  info.recv_len = fdp.ConsumeIntegral<size_t>();
  info.fd_count = fdp.ConsumeIntegral<size_t>();
  if (fdp.remaining_bytes() >= 32) {
    std::vector<uint8_t> impulse_vec = fdp.ConsumeBytes<uint8_t>(32);
    memcpy(info.impulse, impulse_vec.data(), 32);
  }

  Message message = Message(info);

  // A bunch of getters that probably won't do much, but might as well
  // get coverage, while we are here.
  message.GetProcessId();
  message.GetThreadId();
  message.GetEffectiveUserId();
  message.GetEffectiveGroupId();
  message.GetChannelId();
  message.GetMessageId();
  message.GetOp();
  message.GetFlags();
  message.GetSendLength();
  message.GetReceiveLength();
  message.GetFileDescriptorCount();
  message.ImpulseEnd();
  message.replied();
  message.IsChannelExpired();
  message.IsServiceExpired();
  message.GetState();
  message.GetState();

  // Some misc. functions.
  unsigned int fd = fdp.ConsumeIntegral<unsigned int>();
  int clear_mask = fdp.ConsumeIntegral<int>();
  int set_mask = fdp.ConsumeIntegral<int>();
  Status<void> status = {};
  message.ModifyChannelEvents(clear_mask, set_mask);

  // Fuzz the handle functions.
  LocalHandle l_handle = {};
  BorrowedHandle b_handle = {};
  RemoteHandle r_handle = {};
  LocalChannelHandle lc_handle = {};
  BorrowedChannelHandle bc_handle = {};
  RemoteChannelHandle rc_handle = {};
  FileReference f_ref = fdp.ConsumeIntegral<int32_t>();
  ChannelReference c_ref = fdp.ConsumeIntegral<int32_t>();

  // These don't actually modify any state in the Message or params.
  // They can be called in any order.
  message.PushFileHandle(b_handle);
  message.PushFileHandle(r_handle);
  message.PushChannelHandle(lc_handle);
  message.PushChannelHandle(bc_handle);
  message.PushChannelHandle(rc_handle);
  message.GetFileHandle(f_ref, &l_handle);
  message.GetChannelHandle(c_ref, &lc_handle);

  // Can only reply once, pick at random.
  switch (fdp.ConsumeIntegral<uint8_t>()) {
    case 0:
      message.ReplyFileDescriptor(fd);
      break;
    case 1:
      message.Reply(status);
      break;
    case 2:
      message.Reply(l_handle);
      break;
    case 3:
      message.Reply(b_handle);
      break;
    case 4:
      message.Reply(r_handle);
      break;
    case 5:
      message.Reply(lc_handle);
      break;
    case 6:
      message.Reply(bc_handle);
      break;
    case 7:
      message.Reply(rc_handle);
  }

  // Fuzz the channel functions.
  int flags = fdp.ConsumeIntegral<int>();
  int channel_id = 0;
  message.PushChannel(flags, channel, &channel_id);
  message.CheckChannel(service.get(), c_ref, &channel);
  message.CheckChannel(c_ref, &channel);
  message.PushChannel(service.get(), flags, channel, &channel_id);
  size_t iovec_size = sizeof(iovec);
  struct iovec* iovecs = nullptr;

  // Fuzz the read/write functions. Needs at least one iovec, plus one byte.
  if (fdp.remaining_bytes() >= iovec_size + 1) {
    std::vector<uint8_t> tmp_vec = fdp.ConsumeBytes<uint8_t>(iovec_size);
    struct iovec* vector = reinterpret_cast<struct iovec*>(tmp_vec.data());
    std::vector<uint8_t> tmp_buf =
        fdp.ConsumeBytes<uint8_t>(fdp.remaining_bytes());
    void* buf = reinterpret_cast<void*>(tmp_buf.data());
    size_t buf_size = fdp.ConsumeIntegral<size_t>();

    // Capping num_vecs to 1024 so it doesn't allocate too much memory.
    size_t num_vecs = fdp.ConsumeIntegralInRange<size_t>(0, 1024);

    if (num_vecs > 0)
      iovecs = new struct iovec[num_vecs];
    for (size_t i = 0; i < num_vecs; i++) {
      iovecs[i] = *vector;
    }

    message.ReadAll(vector, buf_size);
    message.WriteAll(buf, buf_size);
    message.ReadVectorAll(vector, num_vecs);
    message.WriteVectorAll(vector, num_vecs);
    message.ReadVector(vector, buf_size);
    message.WriteVector(vector, buf_size);
  }

  if (iovecs != nullptr)
    delete[] iovecs;
  return 0;
}
