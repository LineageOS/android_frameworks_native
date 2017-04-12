#include "display_manager_service.h"

#include <pdx/channel_handle.h>
#include <pdx/default_transport/service_endpoint.h>
#include <private/android_filesystem_config.h>
#include <private/dvr/display_rpc.h>
#include <private/dvr/trusted_uids.h>
#include <sys/poll.h>

#include <array>

using android::pdx::Channel;
using android::pdx::LocalChannelHandle;
using android::pdx::Message;
using android::pdx::default_transport::Endpoint;
using android::pdx::rpc::DispatchRemoteMethod;
using android::pdx::rpc::IfAnyOf;

namespace {

// As a first line of defense, the display manager endpoint is only accessible
// to the user and group.

// TODO(dnicoara): Remove read/write permission for others. This is in here just
// to allow us to experiment with cast functionality from a plain old app.
constexpr mode_t kDisplayManagerEndpointFileMode =
    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

constexpr size_t kMaxSurfacesPerRequest = 32;

}  // anonymous namespace

namespace android {
namespace dvr {

void DisplayManager::SetNotificationsPending(bool pending) {
  auto status = service_->ModifyChannelEvents(channel_id_, pending ? 0 : POLLIN,
                                              pending ? POLLIN : 0);
  ALOGE_IF(!status,
           "DisplayManager::SetNotificationPending: Failed to modify channel "
           "events: %s",
           status.GetErrorMessage().c_str());
}

DisplayManagerService::DisplayManagerService(
    const std::shared_ptr<DisplayService>& display_service)
    : BASE("DisplayManagerService",
           Endpoint::Create(DisplayManagerRPC::kClientPath,
                            kDisplayManagerEndpointFileMode)),
      display_service_(display_service) {
  display_service_->SetDisplayConfigurationUpdateNotifier(
      std::bind(&DisplayManagerService::OnDisplaySurfaceChange, this));
}

std::shared_ptr<pdx::Channel> DisplayManagerService::OnChannelOpen(
    pdx::Message& message) {
  // Prevent more than one display manager from registering at a time.
  if (display_manager_)
    REPLY_ERROR_RETURN(message, EPERM, nullptr);

  display_manager_ =
      std::make_shared<DisplayManager>(this, message.GetChannelId());
  return display_manager_;
}

void DisplayManagerService::OnChannelClose(
    pdx::Message& /*message*/, const std::shared_ptr<pdx::Channel>& channel) {
  // Unregister the display manager when the channel closes.
  if (display_manager_ == channel)
    display_manager_ = nullptr;
}

pdx::Status<void> DisplayManagerService::HandleMessage(pdx::Message& message) {
  auto channel = std::static_pointer_cast<DisplayManager>(message.GetChannel());

  switch (message.GetOp()) {
    case DisplayManagerRPC::GetSurfaceList::Opcode:
      DispatchRemoteMethod<DisplayManagerRPC::GetSurfaceList>(
          *this, &DisplayManagerService::OnGetSurfaceList, message);
      return {};

    case DisplayManagerRPC::UpdateSurfaces::Opcode:
      DispatchRemoteMethod<DisplayManagerRPC::UpdateSurfaces>(
          *this, &DisplayManagerService::OnUpdateSurfaces, message);
      return {};

    case DisplayManagerRPC::SetupNamedBuffer::Opcode:
      DispatchRemoteMethod<DisplayManagerRPC::SetupNamedBuffer>(
          *this, &DisplayManagerService::OnSetupNamedBuffer, message);
      return {};

    default:
      return Service::DefaultHandleMessage(message);
  }
}

std::vector<DisplaySurfaceInfo> DisplayManagerService::OnGetSurfaceList(
    pdx::Message& /*message*/) {
  std::vector<DisplaySurfaceInfo> items;

  display_service_->ForEachDisplaySurface(
      [&items](const std::shared_ptr<DisplaySurface>& surface) mutable {
        DisplaySurfaceInfo item;

        item.surface_id = surface->surface_id();
        item.process_id = surface->process_id();
        item.type = surface->type();
        item.flags = 0;  // TODO(eieio)
        item.client_attributes = DisplaySurfaceAttributes{
            {DisplaySurfaceAttributeEnum::Visible,
             DisplaySurfaceAttributeValue{surface->client_visible()}},
            {DisplaySurfaceAttributeEnum::ZOrder,
             DisplaySurfaceAttributeValue{surface->client_z_order()}},
            {DisplaySurfaceAttributeEnum::Blur,
             DisplaySurfaceAttributeValue{0.f}}};
        item.manager_attributes = DisplaySurfaceAttributes{
            {DisplaySurfaceAttributeEnum::Visible,
             DisplaySurfaceAttributeValue{surface->manager_visible()}},
            {DisplaySurfaceAttributeEnum::ZOrder,
             DisplaySurfaceAttributeValue{surface->manager_z_order()}},
            {DisplaySurfaceAttributeEnum::Blur,
             DisplaySurfaceAttributeValue{surface->manager_blur()}}};

        items.push_back(item);
      });

  // The fact that we're in the message handler implies that display_manager_ is
  // not nullptr. No check required, unless this service becomes multi-threaded.
  display_manager_->SetNotificationsPending(false);

  return items;
}

int DisplayManagerService::OnUpdateSurfaces(
    pdx::Message& /*message*/,
    const std::map<int, DisplaySurfaceAttributes>& updates) {
  for (const auto& surface_update : updates) {
    const int surface_id = surface_update.first;
    const DisplaySurfaceAttributes& attributes = surface_update.second;

    std::shared_ptr<DisplaySurface> surface =
        display_service_->GetDisplaySurface(surface_id);

    if (!surface)
      return -ENOENT;

    for (const auto& attribute : attributes) {
      const auto& key = attribute.first;
      const auto* variant = &attribute.second;
      bool invalid_value = false;
      switch (key) {
        case DisplaySurfaceAttributeEnum::ZOrder:
          invalid_value =
              !IfAnyOf<int32_t>::Call(variant, [&surface](const auto& value) {
                surface->ManagerSetZOrder(value);
              });
          break;
        case DisplaySurfaceAttributeEnum::Visible:
          invalid_value = !IfAnyOf<int32_t, int64_t, bool>::Call(
              variant, [&surface](const auto& value) {
                surface->ManagerSetVisible(value);
              });
          break;
        case DisplaySurfaceAttributeEnum::Blur:
          invalid_value = !IfAnyOf<int32_t, int64_t, float>::Call(
              variant, [&surface](const auto& value) {
                surface->ManagerSetBlur(value);
              });
          break;
        default:
          ALOGW(
              "DisplayManagerService::OnUpdateSurfaces: Attempt to set invalid "
              "attribute %u on surface %d",
              key, surface_id);
          break;
      }

      if (invalid_value) {
        ALOGW(
            "DisplayManagerService::OnUpdateSurfaces: Failed to set display "
            "surface attribute '%s' because of incompatible type: %d",
            DisplaySurfaceAttributeEnum::ToString(key).c_str(),
            variant->index());
      }
    }
  }

  // Reconfigure the display layers for any active surface changes.
  display_service_->UpdateActiveDisplaySurfaces();
  return 0;
}

pdx::Status<BorrowedNativeBufferHandle>
DisplayManagerService::OnSetupNamedBuffer(pdx::Message& message,
                                          const std::string& name, size_t size,
                                          uint64_t producer_usage,
                                          uint64_t consumer_usage) {
  if (message.GetEffectiveUserId() != AID_ROOT &&
      !IsTrustedUid(message.GetEffectiveUserId())) {
    // Only trusted users can setup named buffers.
    ALOGE("DisplayService::SetupNamedBuffer: Called by untrusted user: uid=%d.",
          message.GetEffectiveUserId());
    return {};
  }
  return display_service_->SetupNamedBuffer(name, size, producer_usage,
                                            consumer_usage);
}

void DisplayManagerService::OnDisplaySurfaceChange() {
  if (display_manager_) {
    display_manager_->SetNotificationsPending(true);
  } else {
    // If there isn't a display manager registered, default all display surfaces
    // to visible.
    display_service_->ForEachDisplaySurface(
        [](const std::shared_ptr<DisplaySurface>& surface) {
          surface->ManagerSetVisible(true);
        });
    display_service_->UpdateActiveDisplaySurfaces();
  }
}

}  // namespace dvr
}  // namespace android
