#include <private/dvr/frame_history.h>

#include <errno.h>
#include <log/log.h>
#include <sync/sync.h>

#include <pdx/file_handle.h>
#include <private/dvr/clock_ns.h>
#include <private/dvr/sync_util.h>

using android::pdx::LocalHandle;

constexpr int kNumFramesToUseForSchedulePrediction = 10;
constexpr int kDefaultVsyncIntervalPrediction = 1;
constexpr int kMaxVsyncIntervalPrediction = 4;
constexpr int kDefaultPendingFrameBufferSize = 10;

namespace android {
namespace dvr {

FrameHistory::PendingFrame::PendingFrame()
    : start_ns(0), scheduled_vsync(0), scheduled_finish_ns(0) {}

FrameHistory::PendingFrame::PendingFrame(int64_t start_ns,
                                         uint32_t scheduled_vsync,
                                         int64_t scheduled_finish_ns,
                                         LocalHandle&& fence)
    : start_ns(start_ns), scheduled_vsync(scheduled_vsync),
      scheduled_finish_ns(scheduled_finish_ns), fence(std::move(fence)) {}

FrameHistory::FrameHistory() : FrameHistory(kDefaultPendingFrameBufferSize) {}

FrameHistory::FrameHistory(int pending_frame_buffer_size)
    : pending_frames_(pending_frame_buffer_size),
      finished_frames_(pending_frame_buffer_size),
      frame_duration_history_(kNumFramesToUseForSchedulePrediction) {}

void FrameHistory::Reset(int pending_frame_buffer_size) {
  pending_frames_.Reset(pending_frame_buffer_size);
  finished_frames_.Reset(pending_frame_buffer_size);
  frame_duration_history_.Clear();
}

void FrameHistory::OnFrameStart(uint32_t scheduled_vsync,
                                int64_t scheduled_finish_ns) {
  if (!pending_frames_.IsEmpty() && !pending_frames_.Back().fence) {
    // If we don't have a fence set for the previous frame it's because
    // OnFrameStart() was called twice in a row with no OnFrameSubmit() call. In
    // that case throw out the pending frame data for the last frame.
    pending_frames_.PopBack();
  }

  if (pending_frames_.IsFull()) {
    ALOGW("Pending frames buffer is full. Discarding pending frame data.");
  }

  pending_frames_.Append(PendingFrame(GetSystemClockNs(), scheduled_vsync,
                                      scheduled_finish_ns, LocalHandle()));
}

void FrameHistory::OnFrameSubmit(LocalHandle&& fence) {
  // Add the fence to the previous frame data in pending_frames so we can
  // track when it finishes.
  if (!pending_frames_.IsEmpty() && !pending_frames_.Back().fence) {
    if (fence && pending_frames_.Back().scheduled_vsync != UINT32_MAX)
      pending_frames_.Back().fence = std::move(fence);
    else
      pending_frames_.PopBack();
  }
}

void FrameHistory::CheckForFinishedFrames() {
  if (pending_frames_.IsEmpty())
    return;

  android::dvr::FenceInfoBuffer fence_info_buffer;
  while (!pending_frames_.IsEmpty()) {
    const auto& pending_frame = pending_frames_.Front();
    if (!pending_frame.fence) {
      // The frame hasn't been submitted yet, so there's nothing more to do
      break;
    }

    int64_t fence_signaled_time = -1;
    int fence = pending_frame.fence.Get();
    int sync_result = sync_wait(fence, 0);
    if (sync_result == 0) {
      int fence_signaled_result =
          GetFenceSignaledTimestamp(fence, &fence_info_buffer,
                                    &fence_signaled_time);
      if (fence_signaled_result < 0) {
        ALOGE("Failed getting signaled timestamp from fence");
      } else {
        // The frame is finished. Record the duration and move the frame data
        // from pending_frames_ to finished_frames_.
        DvrFrameScheduleResult schedule_result = {};
        schedule_result.vsync_count = pending_frame.scheduled_vsync;
        schedule_result.scheduled_frame_finish_ns =
            pending_frame.scheduled_finish_ns;
        schedule_result.frame_finish_offset_ns =
            fence_signaled_time - pending_frame.scheduled_finish_ns;
        finished_frames_.Append(schedule_result);
        frame_duration_history_.Append(
            fence_signaled_time - pending_frame.start_ns);
      }
      pending_frames_.PopFront();
    } else {
      if (errno != ETIME) {
        ALOGE("sync_wait on frame fence failed. fence=%d errno=%d (%s).",
              fence, errno, strerror(errno));
      }
      break;
    }
  }
}

int FrameHistory::PredictNextFrameVsyncInterval(int64_t vsync_period_ns) const {
  if (frame_duration_history_.IsEmpty())
    return kDefaultVsyncIntervalPrediction;

  double total = 0;
  for (size_t i = 0; i < frame_duration_history_.GetSize(); ++i)
    total += frame_duration_history_.Get(i);
  double avg_duration = total / frame_duration_history_.GetSize();

  return std::min(kMaxVsyncIntervalPrediction,
                  static_cast<int>(avg_duration / vsync_period_ns) + 1);
}

int FrameHistory::GetPreviousFrameResults(DvrFrameScheduleResult* results,
                                          int in_result_count) {
  int out_result_count =
      std::min(in_result_count, static_cast<int>(finished_frames_.GetSize()));
  for (int i = 0; i < out_result_count; ++i) {
    results[i] = finished_frames_.Get(0);
    finished_frames_.PopFront();
  }
  return out_result_count;
}

uint32_t FrameHistory::GetCurrentFrameVsync() const {
  return pending_frames_.IsEmpty() ?
      UINT32_MAX : pending_frames_.Back().scheduled_vsync;
}

}  // namespace dvr
}  // namespace android
