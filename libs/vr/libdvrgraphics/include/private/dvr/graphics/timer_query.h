#ifndef ANDROID_DVR_GRAPHICS_TIMER_QUERY_H_
#define ANDROID_DVR_GRAPHICS_TIMER_QUERY_H_

#include <GLES3/gl3.h>

namespace android {
namespace dvr {

// Class used to asynchronously query time between draw calls on gpu.
class TimerQuery {
 public:
  TimerQuery();
  ~TimerQuery();

  // Marks the start of the timer on gpu.
  void Begin();

  // Marks the end of the timer on gpu.
  void End();

  // Gets the time that has passed from call to Begin to End.
  // Should be called only after the frame has been presented (after the call to
  // swapbuffers).
  double GetTimeInMS();

 private:
  // Generates OpenGL query object.
  void Init();
  // Deletes OpenGL query object.
  void Delete();

  GLuint query_ = 0;

  friend class SyncTimerQuery;
};

// Simplification of TimerQuery that allows to synchronously query time used
// for draw calls on gpu by doing glFlush and stalling cpu.
class SyncTimerQuery {
 public:
  SyncTimerQuery();

  double FlushAndGetTimeInMS();  // Note: This WILL cause a glFlush()

 private:
  TimerQuery timer_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_GRAPHICS_TIMER_QUERY_H_
