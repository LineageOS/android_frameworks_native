#define LOG_TAG "PoseClient"
#include <dvr/pose_client.h>

#include <stdint.h>

#include <log/log.h>
#include <pdx/client.h>
#include <pdx/default_transport/client_channel_factory.h>
#include <pdx/file_handle.h>
#include <private/dvr/buffer_hub_client.h>
#include <private/dvr/pose-ipc.h>
#include <private/dvr/pose_client_internal.h>
#include <private/dvr/sensor_constants.h>

using android::pdx::LocalHandle;
using android::pdx::LocalChannelHandle;
using android::pdx::Status;
using android::pdx::Transaction;

#define arraysize(x) (static_cast<int32_t>(std::extent<decltype(x)>::value))

namespace android {
namespace dvr {

// PoseClient is a remote interface to the pose service in sensord.
class PoseClient : public pdx::ClientBase<PoseClient> {
 public:
  ~PoseClient() override {}

  // Casts C handle into an instance of this class.
  static PoseClient* FromC(DvrPose* client) {
    return reinterpret_cast<PoseClient*>(client);
  }

  // Polls the pose service for the current state and stores it in *state.
  // Returns zero on success, a negative error code otherwise.
  int Poll(DvrPoseState* state) {
    Transaction trans{*this};
    Status<int> status =
        trans.Send<int>(DVR_POSE_POLL, nullptr, 0, state, sizeof(*state));
    ALOGE_IF(!status, "Pose poll() failed because: %s\n",
             status.GetErrorMessage().c_str());
    return ReturnStatusOrError(status);
  }

  int GetPose(uint32_t vsync_count, DvrPoseAsync* out_pose) {
    if (!mapped_pose_buffer_) {
      int ret = GetRingBuffer(nullptr);
      if (ret < 0)
        return ret;
    }
    *out_pose =
        mapped_pose_buffer_->ring[vsync_count & kPoseAsyncBufferIndexMask];
    return 0;
  }

  uint32_t GetVsyncCount() {
    if (!mapped_pose_buffer_) {
      int ret = GetRingBuffer(nullptr);
      if (ret < 0)
        return 0;
    }
    return mapped_pose_buffer_->vsync_count;
  }

  int GetControllerPose(int32_t controller_id, uint32_t vsync_count,
                        DvrPoseAsync* out_pose) {
    if (controller_id < 0 || controller_id >= arraysize(controllers_)) {
      return -EINVAL;
    }
    if (!controllers_[controller_id].mapped_pose_buffer) {
      int ret = GetControllerRingBuffer(controller_id);
      if (ret < 0)
        return ret;
    }
    *out_pose =
        controllers_[controller_id]
            .mapped_pose_buffer[vsync_count & kPoseAsyncBufferIndexMask];
    return 0;
  }

  int LogController(bool enable) {
    Transaction trans{*this};
    Status<int> status = trans.Send<int>(DVR_POSE_LOG_CONTROLLER, &enable,
                                         sizeof(enable), nullptr, 0);
    ALOGE_IF(!status, "Pose LogController() failed because: %s",
             status.GetErrorMessage().c_str());
    return ReturnStatusOrError(status);
  }

  // Freezes the pose to the provided state. Future poll operations will return
  // this state until a different state is frozen or SetMode() is called with a
  // different mode.
  // Returns zero on success, a negative error code otherwise.
  int Freeze(const DvrPoseState& frozen_state) {
    Transaction trans{*this};
    Status<int> status = trans.Send<int>(DVR_POSE_FREEZE, &frozen_state,
                                         sizeof(frozen_state), nullptr, 0);
    ALOGE_IF(!status, "Pose Freeze() failed because: %s\n",
             status.GetErrorMessage().c_str());
    return ReturnStatusOrError(status);
  }

  // Sets the data mode for the pose service.
  int SetMode(DvrPoseMode mode) {
    Transaction trans{*this};
    Status<int> status =
        trans.Send<int>(DVR_POSE_SET_MODE, &mode, sizeof(mode), nullptr, 0);
    ALOGE_IF(!status, "Pose SetPoseMode() failed because: %s",
             status.GetErrorMessage().c_str());
    return ReturnStatusOrError(status);
  }

  // Gets the data mode for the pose service.
  int GetMode(DvrPoseMode* out_mode) {
    int mode;
    Transaction trans{*this};
    Status<int> status =
        trans.Send<int>(DVR_POSE_GET_MODE, nullptr, 0, &mode, sizeof(mode));
    ALOGE_IF(!status, "Pose GetPoseMode() failed because: %s",
             status.GetErrorMessage().c_str());
    if (status)
      *out_mode = DvrPoseMode(mode);
    return ReturnStatusOrError(status);
  }

  int GetRingBuffer(DvrPoseRingBufferInfo* out_info) {
    if (pose_buffer_.get()) {
      if (out_info) {
        GetPoseRingBufferInfo(out_info);
      }
      return 0;
    }

    Transaction trans{*this};
    Status<LocalChannelHandle> status =
        trans.Send<LocalChannelHandle>(DVR_POSE_GET_RING_BUFFER);
    if (!status) {
      ALOGE("Pose GetRingBuffer() failed because: %s",
            status.GetErrorMessage().c_str());
      return -status.error();
    }

    auto buffer = BufferConsumer::Import(status.take());
    if (!buffer) {
      ALOGE("Pose failed to import ring buffer");
      return -EIO;
    }
    void* addr = nullptr;
    int ret = buffer->GetBlobReadOnlyPointer(sizeof(DvrPoseRingBuffer), &addr);
    if (ret < 0 || !addr) {
      ALOGE("Pose failed to map ring buffer: ret:%d, addr:%p", ret, addr);
      return -EIO;
    }
    pose_buffer_.swap(buffer);
    mapped_pose_buffer_ = static_cast<const DvrPoseRingBuffer*>(addr);
    ALOGI("Mapped pose data translation %f,%f,%f quat %f,%f,%f,%f",
          mapped_pose_buffer_->ring[0].translation[0],
          mapped_pose_buffer_->ring[0].translation[1],
          mapped_pose_buffer_->ring[0].translation[2],
          mapped_pose_buffer_->ring[0].orientation[0],
          mapped_pose_buffer_->ring[0].orientation[1],
          mapped_pose_buffer_->ring[0].orientation[2],
          mapped_pose_buffer_->ring[0].orientation[3]);
    if (out_info) {
      GetPoseRingBufferInfo(out_info);
    }
    return 0;
  }

  int GetControllerRingBuffer(int32_t controller_id) {
    if (controller_id < 0 || controller_id >= arraysize(controllers_)) {
      return -EINVAL;
    }
    ControllerClientState& client_state = controllers_[controller_id];
    if (client_state.pose_buffer.get()) {
      return 0;
    }

    Transaction trans{*this};
    Status<LocalChannelHandle> status = trans.Send<LocalChannelHandle>(
        DVR_POSE_GET_CONTROLLER_RING_BUFFER, &controller_id,
        sizeof(controller_id), nullptr, 0);
    if (!status) {
      return -status.error();
    }

    auto buffer = BufferConsumer::Import(status.take());
    if (!buffer) {
      ALOGE("Pose failed to import ring buffer");
      return -EIO;
    }
    constexpr size_t size = kPoseAsyncBufferTotalCount * sizeof(DvrPoseAsync);
    void* addr = nullptr;
    int ret = buffer->GetBlobReadOnlyPointer(size, &addr);
    if (ret < 0 || !addr) {
      ALOGE("Pose failed to map ring buffer: ret:%d, addr:%p", ret, addr);
      return -EIO;
    }
    client_state.pose_buffer.swap(buffer);
    client_state.mapped_pose_buffer = static_cast<const DvrPoseAsync*>(addr);
    ALOGI(
        "Mapped controller %d pose data translation %f,%f,%f quat %f,%f,%f,%f",
        controller_id, client_state.mapped_pose_buffer[0].translation[0],
        client_state.mapped_pose_buffer[0].translation[1],
        client_state.mapped_pose_buffer[0].translation[2],
        client_state.mapped_pose_buffer[0].orientation[0],
        client_state.mapped_pose_buffer[0].orientation[1],
        client_state.mapped_pose_buffer[0].orientation[2],
        client_state.mapped_pose_buffer[0].orientation[3]);
    return 0;
  }

  int NotifyVsync(uint32_t vsync_count, int64_t display_timestamp,
                  int64_t display_period_ns,
                  int64_t right_eye_photon_offset_ns) {
    const struct iovec data[] = {
        {.iov_base = &vsync_count, .iov_len = sizeof(vsync_count)},
        {.iov_base = &display_timestamp, .iov_len = sizeof(display_timestamp)},
        {.iov_base = &display_period_ns, .iov_len = sizeof(display_period_ns)},
        {.iov_base = &right_eye_photon_offset_ns,
         .iov_len = sizeof(right_eye_photon_offset_ns)},
    };
    Transaction trans{*this};
    Status<int> status =
        trans.SendVector<int>(DVR_POSE_NOTIFY_VSYNC, data, nullptr);
    ALOGE_IF(!status, "Pose NotifyVsync() failed because: %s\n",
             status.GetErrorMessage().c_str());
    return ReturnStatusOrError(status);
  }

  int GetRingBufferFd(LocalHandle* fd) {
    int ret = GetRingBuffer(nullptr);
    if (ret < 0)
      return ret;
    *fd = pose_buffer_->GetBlobFd();
    return 0;
  }

 private:
  friend BASE;

  // Set up a channel to the pose service.
  PoseClient()
      : BASE(pdx::default_transport::ClientChannelFactory::Create(
            DVR_POSE_SERVICE_CLIENT)) {
    // TODO(eieio): Cache the pose and make timeout 0 so that the API doesn't
    // block while waiting for the pose service to come back up.
    EnableAutoReconnect(kInfiniteTimeout);
  }

  PoseClient(const PoseClient&) = delete;
  PoseClient& operator=(const PoseClient&) = delete;

  void GetPoseRingBufferInfo(DvrPoseRingBufferInfo* out_info) const {
    out_info->min_future_count = kPoseAsyncBufferMinFutureCount;
    out_info->total_count = kPoseAsyncBufferTotalCount;
    out_info->buffer = mapped_pose_buffer_->ring;
  }

  std::unique_ptr<BufferConsumer> pose_buffer_;
  const DvrPoseRingBuffer* mapped_pose_buffer_ = nullptr;

  struct ControllerClientState {
    std::unique_ptr<BufferConsumer> pose_buffer;
    const DvrPoseAsync* mapped_pose_buffer = nullptr;
  };
  ControllerClientState controllers_[2];
};

}  // namespace dvr
}  // namespace android

using android::dvr::PoseClient;

struct DvrPose {};

extern "C" {

DvrPose* dvrPoseCreate() {
  PoseClient* client = PoseClient::Create().release();
  return reinterpret_cast<DvrPose*>(client);
}

void dvrPoseDestroy(DvrPose* client) { delete PoseClient::FromC(client); }

int dvrPoseGet(DvrPose* client, uint32_t vsync_count, DvrPoseAsync* out_pose) {
  return PoseClient::FromC(client)->GetPose(vsync_count, out_pose);
}

uint32_t dvrPoseGetVsyncCount(DvrPose* client) {
  return PoseClient::FromC(client)->GetVsyncCount();
}

int dvrPoseGetController(DvrPose* client, int32_t controller_id,
                         uint32_t vsync_count, DvrPoseAsync* out_pose) {
  return PoseClient::FromC(client)->GetControllerPose(controller_id,
                                                      vsync_count, out_pose);
}

int dvrPoseLogController(DvrPose* client, bool enable) {
  return PoseClient::FromC(client)->LogController(enable);
}

int dvrPosePoll(DvrPose* client, DvrPoseState* state) {
  return PoseClient::FromC(client)->Poll(state);
}

int dvrPoseFreeze(DvrPose* client, const DvrPoseState* frozen_state) {
  return PoseClient::FromC(client)->Freeze(*frozen_state);
}

int dvrPoseSetMode(DvrPose* client, DvrPoseMode mode) {
  return PoseClient::FromC(client)->SetMode(mode);
}

int dvrPoseGetMode(DvrPose* client, DvrPoseMode* mode) {
  return PoseClient::FromC(client)->GetMode(mode);
}

int dvrPoseGetRingBuffer(DvrPose* client, DvrPoseRingBufferInfo* out_info) {
  return PoseClient::FromC(client)->GetRingBuffer(out_info);
}

int privateDvrPoseNotifyVsync(DvrPose* client, uint32_t vsync_count,
                              int64_t display_timestamp,
                              int64_t display_period_ns,
                              int64_t right_eye_photon_offset_ns) {
  return PoseClient::FromC(client)->NotifyVsync(vsync_count, display_timestamp,
                                                display_period_ns,
                                                right_eye_photon_offset_ns);
}

int privateDvrPoseGetRingBufferFd(DvrPose* client, LocalHandle* fd) {
  return PoseClient::FromC(client)->GetRingBufferFd(fd);
}

}  // extern "C"
