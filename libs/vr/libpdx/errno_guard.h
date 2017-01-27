#ifndef ANDROID_PDX_ERRNO_GUARD_H_
#define ANDROID_PDX_ERRNO_GUARD_H_

#include <errno.h>

namespace android {
namespace pdx {

// Automatically saves and restores the system errno for API implementations to
// prevent internal use errno from affecting API callers.
class ErrnoGuard {
 public:
  ErrnoGuard() : saved_errno_(errno) {}
  ~ErrnoGuard() { errno = saved_errno_; }

  int saved_errno() const { return saved_errno_; }

 private:
  int saved_errno_;

  ErrnoGuard(const ErrnoGuard&) = delete;
  void operator=(const ErrnoGuard&) = delete;
};

// Checks |return_code| and returns either it or the negated system errno based
// on the return code value.
inline int ReturnCodeOrError(int return_code) {
  return return_code < 0 ? -errno : return_code;
}

}  // namespace pdx
}  // namespace android

#endif  // ANDROID_PDX_ERRNO_GUARD_H_
