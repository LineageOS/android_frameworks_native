#ifndef VR_WINDOW_MANAGER_TEXTURE_H_
#define VR_WINDOW_MANAGER_TEXTURE_H_

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <GLES/gl.h>

struct ANativeWindowBuffer;

namespace android {
namespace dvr {

class Texture {
 public:
  explicit Texture();
  ~Texture();

  bool Initialize(ANativeWindowBuffer* buffer);

  GLuint id() const { return id_; }
  int width() const { return width_; }
  int height() const { return height_; }

 private:
  EGLImageKHR image_ = nullptr;
  GLuint id_ = 0;
  int width_ = 0;
  int height_ = 0;

  Texture(const Texture&) = delete;
  void operator=(const Texture&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_TEXTURE_H_
