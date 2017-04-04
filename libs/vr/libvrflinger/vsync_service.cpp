#include "vsync_service.h"

#include <log/log.h>
#include <hardware/hwcomposer.h>
#include <poll.h>
#include <sys/prctl.h>
#include <time.h>
#include <utils/Trace.h>

#include <pdx/default_transport/service_endpoint.h>
#include <private/dvr/clock_ns.h>
#include <private/dvr/display_rpc.h>
#include <private/dvr/display_types.h>

using android::pdx::Channel;
using android::pdx::Message;
using android::pdx::MessageInfo;
using android::pdx::default_transport::Endpoint;
using android::pdx::rpc::DispatchRemoteMethod;

namespace android {
namespace dvr {

VSyncService::VSyncService()
    : BASE("VSyncService", Endpoint::Create(DisplayVSyncRPC::kClientPath)),
      last_vsync_(0),
      current_vsync_(0),
      compositor_time_ns_(0),
      current_vsync_count_(0) {}

VSyncService::~VSyncService() {}

void VSyncService::VSyncEvent(int display, int64_t timestamp_ns,
                              int64_t compositor_time_ns,
                              uint32_t vsync_count) {
  ATRACE_NAME("VSyncService::VSyncEvent");
  std::lock_guard<std::mutex> autolock(mutex_);

  if (display == HWC_DISPLAY_PRIMARY) {
    last_vsync_ = current_vsync_;
    current_vsync_ = timestamp_ns;
    compositor_time_ns_ = compositor_time_ns;
    current_vsync_count_ = vsync_count;

    NotifyWaiters();
    UpdateClients();
  }
}

std::shared_ptr<Channel> VSyncService::OnChannelOpen(pdx::Message& message) {
  const MessageInfo& info = message.GetInfo();

  auto client = std::make_shared<VSyncChannel>(*this, info.pid, info.cid);
  AddClient(client);

  return client;
}

void VSyncService::OnChannelClose(pdx::Message& /*message*/,
                                  const std::shared_ptr<Channel>& channel) {
  auto client = std::static_pointer_cast<VSyncChannel>(channel);
  if (!client) {
    ALOGW("WARNING: VSyncChannel was NULL!!!\n");
    return;
  }

  RemoveClient(client);
}

void VSyncService::AddWaiter(pdx::Message& message) {
  std::lock_guard<std::mutex> autolock(mutex_);
  std::unique_ptr<VSyncWaiter> waiter(new VSyncWaiter(message));
  waiters_.push_back(std::move(waiter));
}

void VSyncService::AddClient(const std::shared_ptr<VSyncChannel>& client) {
  std::lock_guard<std::mutex> autolock(mutex_);
  clients_.push_back(client);
}

void VSyncService::RemoveClient(const std::shared_ptr<VSyncChannel>& client) {
  std::lock_guard<std::mutex> autolock(mutex_);
  clients_.remove(client);
}

// Private. Assumes mutex is held.
void VSyncService::NotifyWaiters() {
  ATRACE_NAME("VSyncService::NotifyWaiters");
  auto first = waiters_.begin();
  auto last = waiters_.end();

  while (first != last) {
    (*first)->Notify(current_vsync_);
    waiters_.erase(first++);
  }
}

// Private. Assumes mutex is held.
void VSyncService::UpdateClients() {
  ATRACE_NAME("VSyncService::UpdateClients");
  auto first = clients_.begin();
  auto last = clients_.end();

  while (first != last) {
    (*first)->Signal();
    first++;
  }
}

pdx::Status<void> VSyncService::HandleMessage(pdx::Message& message) {
  switch (message.GetOp()) {
    case DisplayVSyncRPC::Wait::Opcode:
      AddWaiter(message);
      return {};

    case DisplayVSyncRPC::GetLastTimestamp::Opcode:
      DispatchRemoteMethod<DisplayVSyncRPC::GetLastTimestamp>(
          *this, &VSyncService::OnGetLastTimestamp, message);
      return {};

    case DisplayVSyncRPC::GetSchedInfo::Opcode:
      DispatchRemoteMethod<DisplayVSyncRPC::GetSchedInfo>(
          *this, &VSyncService::OnGetSchedInfo, message);
      return {};

    case DisplayVSyncRPC::Acknowledge::Opcode:
      DispatchRemoteMethod<DisplayVSyncRPC::Acknowledge>(
          *this, &VSyncService::OnAcknowledge, message);
      return {};

    default:
      return Service::HandleMessage(message);
  }
}

int64_t VSyncService::OnGetLastTimestamp(pdx::Message& message) {
  auto client = std::static_pointer_cast<VSyncChannel>(message.GetChannel());
  std::lock_guard<std::mutex> autolock(mutex_);

  // Getting the timestamp has the side effect of ACKing.
  client->Ack();
  return current_vsync_;
}

VSyncSchedInfo VSyncService::OnGetSchedInfo(pdx::Message& message) {
  auto client = std::static_pointer_cast<VSyncChannel>(message.GetChannel());
  std::lock_guard<std::mutex> autolock(mutex_);

  // Getting the timestamp has the side effect of ACKing.
  client->Ack();

  uint32_t next_vsync_count = current_vsync_count_ + 1;
  int64_t current_time = GetSystemClockNs();
  int64_t vsync_period_ns = 0;
  int64_t next_warp;
  if (current_vsync_ == 0 || last_vsync_ == 0) {
    // Handle startup when current_vsync_ or last_vsync_ are 0.
    // Normally should not happen because vsync_service is running before
    // applications, but in case it does a sane time prevents applications
    // from malfunctioning.
    vsync_period_ns = 20000000;
    next_warp = current_time;
  } else {
    // TODO(jbates) When we have an accurate reading of the true vsync
    // period, use that instead of this estimated value.
    vsync_period_ns = current_vsync_ - last_vsync_;
    // Clamp the period, because when there are no surfaces the last_vsync_
    // value will get stale. Note this is temporary and goes away as soon
    // as we have an accurate vsync period reported by the system.
    vsync_period_ns = std::min(vsync_period_ns, INT64_C(20000000));
    next_warp = current_vsync_ + vsync_period_ns - compositor_time_ns_;
    // If the request missed the present window, move up to the next vsync.
    if (current_time > next_warp) {
      next_warp += vsync_period_ns;
      ++next_vsync_count;
    }
  }

  return {vsync_period_ns, next_warp, next_vsync_count};
}

int VSyncService::OnAcknowledge(pdx::Message& message) {
  auto client = std::static_pointer_cast<VSyncChannel>(message.GetChannel());
  std::lock_guard<std::mutex> autolock(mutex_);
  client->Ack();
  return 0;
}

void VSyncWaiter::Notify(int64_t timestamp) {
  timestamp_ = timestamp;
  DispatchRemoteMethod<DisplayVSyncRPC::Wait>(*this, &VSyncWaiter::OnWait,
                                              message_);
}

int64_t VSyncWaiter::OnWait(pdx::Message& /*message*/) { return timestamp_; }

void VSyncChannel::Ack() {
  ALOGD_IF(TRACE, "VSyncChannel::Ack: pid=%d cid=%d\n", pid_, cid_);
  service_.ModifyChannelEvents(cid_, POLLPRI, 0);
}

void VSyncChannel::Signal() {
  ALOGD_IF(TRACE, "VSyncChannel::Signal: pid=%d cid=%d\n", pid_, cid_);
  service_.ModifyChannelEvents(cid_, 0, POLLPRI);
}

}  // namespace dvr
}  // namespace android
