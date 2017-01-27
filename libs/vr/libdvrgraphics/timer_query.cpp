#include "include/private/dvr/graphics/timer_query.h"

#include <GLES2/gl2ext.h>
#include <base/logging.h>

namespace android {
namespace dvr {

TimerQuery::TimerQuery() {}

TimerQuery::~TimerQuery() { Delete(); }

void TimerQuery::Init() { glGenQueriesEXT(1, &query_); }

void TimerQuery::Delete() {
  if (query_) {
    glDeleteQueriesEXT(1, &query_);
    query_ = 0;
  }
}

void TimerQuery::Begin() {
  if (query_ == 0) {
    Init();
  }
  glBeginQueryEXT(GL_TIME_ELAPSED_EXT, query_);
}

void TimerQuery::End() { glEndQueryEXT(GL_TIME_ELAPSED_EXT); }

double TimerQuery::GetTimeInMS() {
  GLuint64 elapsed_time = 0;
  glGetQueryObjectui64vEXT(query_, GL_QUERY_RESULT, &elapsed_time);
  return static_cast<double>(elapsed_time) / 1000000.0;
}

SyncTimerQuery::SyncTimerQuery() { timer_.Begin(); }

double SyncTimerQuery::FlushAndGetTimeInMS() {
  if (timer_.query_ == 0) {
    LOG(ERROR) << "Error: Only call FlushAndGetTimeInMS() once.";
    return 0.0;
  }
  timer_.End();
  glFlush();
  GLint done = 0;
  while (!done) {
    glGetQueryObjectivEXT(timer_.query_, GL_QUERY_RESULT_AVAILABLE, &done);
  }

  GLint disjoint_occurred = 0;
  glGetIntegerv(GL_GPU_DISJOINT_EXT, &disjoint_occurred);
  if (disjoint_occurred) {
    LOG(ERROR) << "Disjoint occurred.";
    timer_.Delete();
    return 0.0;
  }

  double elapsed_time = timer_.GetTimeInMS();
  timer_.Delete();
  return elapsed_time;
}

}  // namespace dvr
}  // namespace android
