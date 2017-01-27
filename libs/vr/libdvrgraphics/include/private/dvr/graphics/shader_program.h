#ifndef ANDROID_DVR_SHADER_PROGRAM_H_
#define ANDROID_DVR_SHADER_PROGRAM_H_

#include <EGL/egl.h>
#include <GLES3/gl31.h>
#include <sys/cdefs.h>
#include <string>
#include <vector>

namespace android {
namespace dvr {

// Helper function that allows you to write a shader as a Lambda.  This allows
// an IDE to syntax highlight the contents of a shader, as well as preventing
// quotations on each line. Usage: std::string vs = SHADER0([]() { ... });
template <size_t size>
std::string StripLambda(const char (&shader)[size]) {
  return std::string(shader + 6, shader + size - 2);
}

#define SHADER0(Src) ::android::dvr::StripLambda(#Src)

// Helper function that takes a shader source string containing %0, %1, %n,
// tokens and replaces them with replacements[0], replacements[1],
// replacements[n].  For example:
// shader = "{
//   uniform vec2 %0;
//   %1
//   ...
//     %0.x = 1.0; ...
//     %1(%0);
// }"
// -> %0 = "myVarName", %1 = "void f(vec2 v) { ... }"
std::string ComposeShader(const std::string& shader_code,
                          const std::vector<std::string>& replacements);

class ShaderProgram {
 public:
  ShaderProgram();
  ShaderProgram(const std::string& vertext_source,
                const std::string& fragment_source);
  ShaderProgram(ShaderProgram&&);
  ~ShaderProgram();

  ShaderProgram& operator=(ShaderProgram&&);

  void Link(const std::string& vertext_source,
            const std::string& fragment_source);

  void Link(const std::string& compute_source);

  void Use() const;

  GLuint GetProgram() const { return program_; }
  GLuint GetUniformLocation(const GLchar* name) const {
    return glGetUniformLocation(program_, name);
  }
  GLuint GetAttribLocation(const GLchar* name) const {
    return glGetAttribLocation(program_, name);
  }

  bool IsUsable() const { return program_ != 0; }
  explicit operator bool() const { return IsUsable(); }

 private:
  ShaderProgram(const ShaderProgram&) = delete;
  ShaderProgram& operator=(const ShaderProgram&) = delete;

  GLuint program_;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_SHADER_PROGRAM_H_
