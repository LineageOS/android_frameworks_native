#include <uds/channel_manager.h>

#include <log/log.h>

namespace android {
namespace pdx {
namespace uds {

ChannelManager& ChannelManager::Get() {
  static ChannelManager instance;
  return instance;
}

void ChannelManager::CloseHandle(int32_t handle) {
  std::lock_guard<std::mutex> autolock(mutex_);
  auto channel = channels_.find(handle);
  if (channel == channels_.end()) {
    ALOGE("Invalid channel handle: %d", handle);
  } else {
    channels_.erase(channel);
  }
}

LocalChannelHandle ChannelManager::CreateHandle(LocalHandle data_fd,
                                                LocalHandle event_fd) {
  if (data_fd && event_fd) {
    std::lock_guard<std::mutex> autolock(mutex_);
    int32_t handle = data_fd.Get();
    channels_.emplace(handle,
                      ChannelData{std::move(data_fd), std::move(event_fd)});
    return LocalChannelHandle(this, handle);
  }
  return LocalChannelHandle(nullptr, -1);
}

ChannelManager::ChannelData* ChannelManager::GetChannelData(int32_t handle) {
  std::lock_guard<std::mutex> autolock(mutex_);
  auto channel = channels_.find(handle);
  return channel != channels_.end() ? &channel->second : nullptr;
}

}  // namespace uds
}  // namespace pdx
}  // namespace android
