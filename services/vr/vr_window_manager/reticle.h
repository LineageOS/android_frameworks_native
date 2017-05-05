#ifndef VR_WINDOW_MANAGER_SHELL_RETICLE_H_
#define VR_WINDOW_MANAGER_SHELL_RETICLE_H_

#include <private/dvr/graphics/shader_program.h>
#include <private/dvr/types.h>

namespace android {
namespace dvr {

class Reticle {
 public:
  Reticle();
  ~Reticle();

  bool Initialize();

  void ShowAt(const mat4& hit_transform, const vec3& color);
  void Hide() { shown_ = false; }

  void Draw(const mat4& perspective, const mat4& eye_matrix,
            const mat4& head_matrix);

 private:
  bool shown_ = false;
  ShaderProgram program_;
  mat4 transform_;

  Reticle(const Reticle&) = delete;
  void operator=(const Reticle&) = delete;
};

}  // namespace dvr
}  // namespace android

#endif  // VR_WINDOW_MANAGER_SHELL_RETICLE_H_
