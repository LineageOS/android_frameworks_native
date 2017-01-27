#ifndef ANDROID_DVR_FRAME_HISTORY_H_
#define ANDROID_DVR_FRAME_HISTORY_H_

#include <dvr/graphics.h>
#include <pdx/file_handle.h>
#include <private/dvr/ring_buffer.h>

namespace android {
namespace dvr {

// FrameHistory tracks frame times from the start of rendering commands to when
// the buffer is ready.
class FrameHistory {
 public:
  FrameHistory();
  explicit FrameHistory(int pending_frame_buffer_size);

  void Reset(int pending_frame_buffer_size);

  // Call when starting rendering commands (i.e. dvrBeginRenderFrame).
  void OnFrameStart(uint32_t scheduled_vsync, int64_t scheduled_finish_ns);

  // Call when rendering commands are finished (i.e. dvrPresent).
  void OnFrameSubmit(android::pdx::LocalHandle&& fence);

  // Call once per frame to see if any pending frames have finished.
  void CheckForFinishedFrames();

  // Uses the recently completed frame render times to predict how long the next
  // frame will take, in vsync intervals. For example if the predicted frame
  // time is 10ms and the vsync interval is 11ms, this will return 1. If the
  // predicted frame time is 12ms and the vsync interval is 11ms, this will
  // return 2.
  int PredictNextFrameVsyncInterval(int64_t vsync_period_ns) const;

  // Returns results for recently completed frames. Each frame's result is
  // returned only once.
  int GetPreviousFrameResults(DvrFrameScheduleResult* results,
                              int result_count);

  // Gets the vsync count for the most recently started frame. If there are no
  // started frames this will return UINT32_MAX.
  uint32_t GetCurrentFrameVsync() const;

 private:
  struct PendingFrame {
    int64_t start_ns;
    uint32_t scheduled_vsync;
    int64_t scheduled_finish_ns;
    android::pdx::LocalHandle fence;

    PendingFrame();
    PendingFrame(int64_t start_ns, uint32_t scheduled_vsync,
                 int64_t scheduled_finish_ns,
                 android::pdx::LocalHandle&& fence);

    PendingFrame(PendingFrame&&) = default;
    PendingFrame& operator=(PendingFrame&&) = default;
    PendingFrame(const PendingFrame&) = delete;
    PendingFrame& operator=(const PendingFrame&) = delete;
  };

  RingBuffer<PendingFrame> pending_frames_;
  RingBuffer<DvrFrameScheduleResult> finished_frames_;
  RingBuffer<int64_t> frame_duration_history_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_FRAME_HISTORY_H_
