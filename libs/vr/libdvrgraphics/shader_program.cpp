#include "include/private/dvr/graphics/shader_program.h"

#include <regex>
#include <sstream>

#include <base/logging.h>
#include <base/strings/string_util.h>

namespace {

static bool CompileShader(GLuint shader, const std::string& shader_string) {
  std::string prefix = "";
  if (!base::StartsWith(shader_string, "#version",
                        base::CompareCase::SENSITIVE)) {
    prefix = "#version 310 es\n";
  }
  std::string string_with_prefix = prefix + shader_string;
  const char* shader_str[] = {string_with_prefix.data()};
  glShaderSource(shader, 1, shader_str, nullptr);
  glCompileShader(shader);

  GLint success;
  glGetShaderiv(shader, GL_COMPILE_STATUS, &success);
  if (!success) {
    GLchar infoLog[512];
    glGetShaderInfoLog(shader, 512, nullptr, infoLog);
    LOG(ERROR) << "Shader Failed to compile: " << *shader_str << " -- "
               << infoLog;
    return false;
  }
  return true;
}

static bool LinkProgram(GLuint program, GLuint vertex_shader,
                        GLuint fragment_shader) {
  glAttachShader(program, vertex_shader);
  glAttachShader(program, fragment_shader);
  glLinkProgram(program);

  // Check for linking errors
  GLint success;
  glGetProgramiv(program, GL_LINK_STATUS, &success);
  if (!success) {
    GLchar infoLog[512];
    glGetProgramInfoLog(program, 512, nullptr, infoLog);
    LOG(ERROR) << "Shader failed to link: " << infoLog;
    return false;
  }

  return true;
}

static bool LinkProgram(GLuint program, GLuint compute_shader) {
  glAttachShader(program, compute_shader);
  glLinkProgram(program);

  // Check for linking errors
  GLint success;
  glGetProgramiv(program, GL_LINK_STATUS, &success);
  if (!success) {
    GLchar infoLog[512];
    glGetProgramInfoLog(program, 512, nullptr, infoLog);
    LOG(ERROR) << "Shader failed to link: " << infoLog;
    return false;
  }

  return true;
}

}  // anonymous namespace

namespace android {
namespace dvr {

ShaderProgram::ShaderProgram() : program_(0) {}

ShaderProgram::ShaderProgram(const std::string& vertext_source,
                             const std::string& fragment_source)
    : program_(0) {
  Link(vertext_source, fragment_source);
}

ShaderProgram::ShaderProgram(ShaderProgram&& to_move) {
  std::swap(program_, to_move.program_);
}

ShaderProgram::~ShaderProgram() {
  if (program_)
    glDeleteProgram(program_);
}

ShaderProgram& ShaderProgram::operator=(ShaderProgram&& to_move) {
  std::swap(program_, to_move.program_);
  return *this;
}

void ShaderProgram::Link(const std::string& vertext_source,
                         const std::string& fragment_source) {
  if (program_)
    glDeleteProgram(program_);
  program_ = glCreateProgram();
  GLuint vertex_shader = glCreateShader(GL_VERTEX_SHADER);
  GLuint fragment_shader = glCreateShader(GL_FRAGMENT_SHADER);

  bool success = CompileShader(vertex_shader, vertext_source) &&
                 CompileShader(fragment_shader, fragment_source) &&
                 LinkProgram(program_, vertex_shader, fragment_shader);

  glDeleteShader(vertex_shader);
  glDeleteShader(fragment_shader);

  if (!success) {
    glDeleteProgram(program_);
    program_ = 0;
  }
}

void ShaderProgram::Link(const std::string& compute_source) {
  if (program_)
    glDeleteProgram(program_);
  program_ = glCreateProgram();
  GLuint shader = glCreateShader(GL_COMPUTE_SHADER);

  bool success =
      CompileShader(shader, compute_source) && LinkProgram(program_, shader);

  glDeleteShader(shader);

  if (!success) {
    glDeleteProgram(program_);
    program_ = 0;
  }
}

void ShaderProgram::Use() const { glUseProgram(program_); }

std::string ComposeShader(const std::string& shader_code,
                          const std::vector<std::string>& variables) {
  std::stringstream result_stream;
  std::regex expression("%([0-9]*)");
  using reg_iter = std::regex_token_iterator<std::string::const_iterator>;
  reg_iter rend;
  // match the string and number (drop the %)
  std::vector<int> submatches = {-1, 1};
  reg_iter reg(shader_code.begin(), shader_code.end(), expression, submatches);
  bool is_even = true;
  while (reg != rend) {
    if (is_even) {
      // even entries is the code between the %n's
      result_stream << *reg;
    } else {
      // odd entries are the index into the passed in variables.
      size_t i = static_cast<size_t>(std::stoi(*reg));
      if (i < variables.size()) {
        result_stream << variables[i];
      }
    }
    is_even = !is_even;
    ++reg;
  }
  return result_stream.str();
}

}  // namespace dvr
}  // namespace android
