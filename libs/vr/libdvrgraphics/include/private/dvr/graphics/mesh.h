#ifndef ANDROID_DVR_GRAPHICS_MESH_H_
#define ANDROID_DVR_GRAPHICS_MESH_H_

#include <private/dvr/graphics/vertex_attributes.h>
#include <private/dvr/types.h>

#include <EGL/egl.h>
#include <GLES3/gl3.h>
#include <tuple>

namespace android {
namespace dvr {

template <typename... Attributes>
class Mesh {
 public:
  static const int attribute_size = sizeof(std::tuple<Attributes...>);

  Mesh() {}

  Mesh(uint32_t number_of_vertices, const void* vertices) {
    SetVertices(number_of_vertices, vertices);
  }

  Mesh(uint32_t number_of_vertices, const void* vertices, GLenum element_type) {
    SetVertices(number_of_vertices, vertices, element_type);
  }

  Mesh(Mesh&& to_move) { Swap(to_move); }

  ~Mesh() { DeleteGLData(); }

  Mesh& operator=(const Mesh&& to_move) {
    Swap(to_move);
    return *this;
  }

  operator bool() const { return mesh_vbo_ != 0; }

  void Swap(Mesh& to_swap) {
    std::swap(mesh_vbo_, to_swap.mesh_vbo_);
    std::swap(mesh_vao_, to_swap.mesh_vao_);
    std::swap(number_of_vertices_, to_swap.number_of_vertices_);
    std::swap(element_type_, to_swap.element_type_);
  }

  void Draw(uint32_t number_of_vertices) {
    if (!mesh_vbo_)
      return;

    glBindVertexArray(mesh_vao_);
    glDrawArrays(element_type_, 0, number_of_vertices);
    glBindVertexArray(0);
  }

  void Draw() { Draw(number_of_vertices_); }

  void SetVertices(uint32_t number_of_vertices, const void* vertices,
                   GLenum element_type, GLenum usage) {
    DeleteGLData();
    element_type_ = element_type;
    number_of_vertices_ = number_of_vertices;
    glGenBuffers(1, &mesh_vbo_);
    glGenVertexArrays(1, &mesh_vao_);
    glBindVertexArray(mesh_vao_);

    glBindBuffer(GL_ARRAY_BUFFER, mesh_vbo_);
    glBufferData(GL_ARRAY_BUFFER, attribute_size * number_of_vertices, vertices,
                 usage);

    SetupAttributes();

    glBindBuffer(GL_ARRAY_BUFFER, 0);
    glBindVertexArray(0);
  }

  void SetVertices(uint32_t number_of_vertices, const void* vertices) {
    SetVertices(number_of_vertices, vertices, element_type_, GL_STATIC_DRAW);
  }

  void SetVertices(uint32_t number_of_vertices, const void* vertices,
                   GLenum element_type) {
    SetVertices(number_of_vertices, vertices, element_type, GL_STATIC_DRAW);
  }

  std::tuple<Attributes...>* Map(GLbitfield access, int num_vertices) {
    glBindBuffer(GL_ARRAY_BUFFER, mesh_vbo_);
    void* ptr = glMapBufferRange(GL_ARRAY_BUFFER, 0,
                                 attribute_size * num_vertices, access);
    return static_cast<std::tuple<Attributes...>*>(ptr);
  }

  void Unmap() {
    glUnmapBuffer(GL_ARRAY_BUFFER);
    glBindBuffer(GL_ARRAY_BUFFER, 0);
  }

 private:
  Mesh(const Mesh&) = delete;
  Mesh& operator=(const Mesh&) = delete;

  void DeleteGLData() {
    if (mesh_vbo_) {
      glDeleteBuffers(1, &mesh_vbo_);
      glDeleteVertexArrays(1, &mesh_vao_);
      mesh_vbo_ = 0;
      mesh_vao_ = 0;
      number_of_vertices_ = 0;
    }
  }

  void SetupAttributes() {
    const auto size = std::tuple_size<std::tuple<Attributes...>>::value;
    Details::VertexAttribHelper<size - 1, Attributes...>{}();
  }

 private:
  GLuint mesh_vbo_ = 0;
  GLuint mesh_vao_ = 0;
  uint32_t number_of_vertices_ = 0;

  GLenum element_type_ = GL_TRIANGLES;
};

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_GRAPHICS_MESH_H_
