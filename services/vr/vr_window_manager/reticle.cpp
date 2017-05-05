#include "reticle.h"

#include <GLES/gl.h>
#include <GLES/glext.h>

namespace android {
namespace dvr {

namespace {

const std::string kVertexShader = SHADER0([]() {
  layout(location = 0) in vec4 aPosition;
  layout(location = 1) in vec4 aTexCoord;
  uniform mat4 uViewProjection;
  uniform mat4 uTransform;

  out vec2 vTexCoord;
  void main() {
    gl_Position = uViewProjection * uTransform * aPosition;
    vTexCoord = aTexCoord.xy;
  }
});

const std::string kFragmentShader = SHADER0([]() {
  precision mediump float;

  in vec2 vTexCoord;
  uniform vec3 uColor;

  out vec4 fragColor;
  void main() {
    float alpha = smoothstep(1.0, 0.0, length(vTexCoord));
    fragColor = vec4(uColor, alpha);
  }
});

}  // namespace

Reticle::Reticle() {}

Reticle::~Reticle() {}

bool Reticle::Initialize() {
  program_.Link(kVertexShader, kFragmentShader);
  if (!program_)
    return false;

  return true;
}

void Reticle::ShowAt(const mat4& hit_transform, const vec3& color) {
  transform_ = hit_transform;
  shown_ = true;

  GLint view_projection_location =
      glGetUniformLocation(program_.GetProgram(), "uColor");
  glProgramUniform3f(program_.GetProgram(), view_projection_location, color.x(),
                     color.y(), color.z());
}

void Reticle::Draw(const mat4& perspective, const mat4& eye_matrix,
                   const mat4& head_matrix) {
  if (!shown_)
    return;

  glEnable(GL_BLEND);
  glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

  program_.Use();

  const float kRadius = 0.015;
  GLfloat vertices[] = {
      -kRadius, -kRadius, 0, kRadius, -kRadius, 0,
      -kRadius, kRadius,  0, kRadius, kRadius,  0,
  };
  GLfloat texture_vertices[] = {
      -1, 1, 1, 1, -1, -1, 1, -1,
  };

  mat4 mvp = perspective * eye_matrix * head_matrix;
  GLint view_projection_location =
      glGetUniformLocation(program_.GetProgram(), "uViewProjection");
  glUniformMatrix4fv(view_projection_location, 1, 0, mvp.data());

  GLint transform_location =
      glGetUniformLocation(program_.GetProgram(), "uTransform");
  glUniformMatrix4fv(transform_location, 1, 0, transform_.data());

  glEnableVertexAttribArray(0);
  glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, 0, vertices);
  glEnableVertexAttribArray(1);
  glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, 0, texture_vertices);

  glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);

  glDisable(GL_BLEND);
}

}  // namespace dvr
}  // namespace android
