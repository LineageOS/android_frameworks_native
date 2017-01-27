#include "include/private/dvr/cpu_thread_pose_updater.h"

#include <sys/prctl.h>
#include <unistd.h>

#define ATRACE_TAG ATRACE_TAG_INPUT
#include <utils/Trace.h>

#include <private/dvr/clock_ns.h>
#include <private/dvr/debug.h>

namespace android {
namespace dvr {

CpuThreadPoseUpdater::CpuThreadPoseUpdater()
    : stop_request_(false), update_period_us_(0), count_(0) {}

CpuThreadPoseUpdater::~CpuThreadPoseUpdater() { StopAndJoin(); }

void CpuThreadPoseUpdater::Start(volatile RawPosePair* mapped_pose_buffer,
                                 int period_us) {
  mapped_pose_buffer_ = mapped_pose_buffer;
  update_period_us_ = period_us;
  stop_request_ = false;

  // First buffer is odd (starts at 1), second is even (starts at 2).
  count_ = 0;
  mapped_pose_buffer_->pose1.Reset(++count_);
  mapped_pose_buffer_->pose2.Reset(++count_);

  update_thread_ = std::thread(&CpuThreadPoseUpdater::UpdateThread, this);
}

void CpuThreadPoseUpdater::StopAndJoin() {
  stop_request_ = true;
  if (update_thread_.joinable()) {
    update_thread_.join();
  }
}

void CpuThreadPoseUpdater::UpdateThread() {
  prctl(PR_SET_NAME, reinterpret_cast<intptr_t>("CpuPoseUpdater"),
        0, 0, 0);

  ATRACE_NAME(__PRETTY_FUNCTION__);
  for (;;) {
    if (stop_request_) {
      break;
    }

    ++count_;

    // Choose the writable pose based on whether count is odd or even.
    volatile RawPose* out_pose = nullptr;
    if (count_ & 1) {
      out_pose = &mapped_pose_buffer_->pose1;
    } else {
      out_pose = &mapped_pose_buffer_->pose2;
    }

    {
      ATRACE_NAME("GetPose");
      Posef pose = pose_tracker_.GetPose(GetSystemClockNs());
      out_pose->qx = pose.GetRotation().x();
      out_pose->qy = pose.GetRotation().y();
      out_pose->qz = pose.GetRotation().z();
      out_pose->qw = pose.GetRotation().w();
      out_pose->px = pose.GetPosition()[0];
      out_pose->py = pose.GetPosition()[1];
      out_pose->pz = pose.GetPosition()[2];
      // Atomically store the count so that it hits memory last:
      out_pose->count.store(count_, std::memory_order_release);
    }

    // Sleep to simulate the IMU update process.
    usleep(update_period_us_);
    // TODO(jbates) sleep_for returns immediately, we need to fix our toolchain!
    // int64_t c1 = GetSystemClockNs();
    // std::this_thread::sleep_for(std::chrono::milliseconds(10));
    // int64_t c2 = GetSystemClockNs();
    // fprintf(stderr, "%lld us\n", (long long)(c2 - c1) / 1000);
  }
}

}  // namesapce dvr
}  // namesapce android
