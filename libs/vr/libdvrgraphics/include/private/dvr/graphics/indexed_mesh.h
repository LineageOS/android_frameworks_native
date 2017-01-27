#ifndef ANDROID_DVR_GRAPHICS_INDEXED_MESH_H_
#define ANDROID_DVR_GRAPHICS_INDEXED_MESH_H_

#include <private/dvr/graphics/vertex_attributes.h>
#include <private/dvr/types.h>

#include <EGL/egl.h>
#include <GLES3/gl3.h>
#include <tuple>

namespace android {
namespace dvr {

namespace Details {

// We can have 16 and 32bit indices.
template <typename T>
GLenum GetIndexType();
template <>
inline GLenum GetIndexType<uint16_t>() {
  return GL_UNSIGNED_SHORT;
}
template <>
inline GLenum GetIndexType<uint32_t>() {
  return GL_UNSIGNED_INT;
}

}  // namespace Details

template <typename INDEX_TYPE, typename... Attributes>
class IndexedMesh {
 public:
  static const int attribute_size = sizeof(std::tuple<Attributes...>);

  IndexedMesh() {}
  IndexedMesh(INDEX_TYPE number_of_vertices, const void* vertices,
              INDEX_TYPE number_of_indices, const void* indices) {
    SetVertices(number_of_vertices, vertices, number_of_indices, indices);
  }

  IndexedMesh(INDEX_TYPE number_of_vertices, const void* vertices,
              INDEX_TYPE number_of_indices, const void* indices,
              GLenum element_type) {
    SetVertices(number_of_vertices, vertices, number_of_indices, indices,
                element_type);
  }

  IndexedMesh(IndexedMesh&& to_move) { Swap(to_move); }

  ~IndexedMesh() { DeleteGLData(); }

  IndexedMesh& operator=(IndexedMesh&& to_move) {
    Swap(to_move);
    return *this;
  }

  operator bool() const { return mesh_vbo_ != 0; }

  void Swap(IndexedMesh& to_swap) {
    std::swap(mesh_vbo_, to_swap.mesh_vbo_);
    std::swap(mesh_vao_, to_swap.mesh_vao_);
    std::swap(mesh_ibo_, to_swap.mesh_ibo_);
    std::swap(number_of_indices_, to_swap.number_of_indices_);
    std::swap(element_type_, to_swap.element_type_);
  }

  void Draw() {
    if (!mesh_vbo_)
      return;

    glBindVertexArray(mesh_vao_);
    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, mesh_ibo_);

    glDrawElements(element_type_, number_of_indices_,
                   Details::GetIndexType<INDEX_TYPE>(), nullptr);

    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, 0);
    glBindVertexArray(0);
  }

  void SetVertices(INDEX_TYPE number_of_vertices, const void* vertices,
                   INDEX_TYPE number_of_indices, const void* indices,
                   GLenum element_type) {
    element_type_ = element_type;
    SetVertices(number_of_vertices, vertices, number_of_indices, indices);
  }

  void SetVertices(INDEX_TYPE number_of_vertices, const void* vertices,
                   INDEX_TYPE number_of_indices, const void* indices) {
    DeleteGLData();
    number_of_indices_ = number_of_indices;
    glGenBuffers(1, &mesh_vbo_);
    glGenVertexArrays(1, &mesh_vao_);
    glGenBuffers(1, &mesh_ibo_);
    glBindVertexArray(mesh_vao_);

    glBindBuffer(GL_ARRAY_BUFFER, mesh_vbo_);
    glBufferData(GL_ARRAY_BUFFER, attribute_size * number_of_vertices, vertices,
                 GL_STATIC_DRAW);

    SetupAttributes();

    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, mesh_ibo_);
    glBufferData(GL_ELEMENT_ARRAY_BUFFER,
                 sizeof(INDEX_TYPE) * number_of_indices_, indices,
                 GL_STATIC_DRAW);

    glBindBuffer(GL_ELEMENT_ARRAY_BUFFER, 0);
    glBindBuffer(GL_ARRAY_BUFFER, 0);
    glBindVertexArray(0);
  }

  size_t GetAttributesSize() const { return attribute_size; }

 private:
  IndexedMesh(const IndexedMesh&) = delete;
  IndexedMesh& operator=(const IndexedMesh&) = delete;

  void DeleteGLData() {
    if (mesh_vbo_) {
      glDeleteBuffers(1, &mesh_vbo_);
      glDeleteVertexArrays(1, &mesh_vao_);
      glDeleteBuffers(1, &mesh_ibo_);
      mesh_vbo_ = 0;
      mesh_vao_ = 0;
      mesh_ibo_ = 0;
      number_of_indices_ = 0;
    }
  }

  void SetupAttributes() {
    const auto size = std::tuple_size<std::tuple<Attributes...>>::value;
    Details::VertexAttribHelper<size - 1, Attributes...>{}();
  }

 private:
  GLuint mesh_vbo_ = 0;
  GLuint mesh_vao_ = 0;
  GLuint mesh_ibo_ = 0;
  INDEX_TYPE number_of_indices_ = 0;

  GLenum element_type_ = GL_TRIANGLES;
};

template <typename... Attributes>
using Indexed16Mesh = IndexedMesh<uint16_t, Attributes...>;

template <typename... Attributes>
using Indexed32Mesh = IndexedMesh<uint32_t, Attributes...>;

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_GRAPHICS_INDEXED_MESH_H_
