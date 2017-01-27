#ifndef ANDROID_DVR_GRAPHICS_VERTEX_ATTRIBUTES_H_
#define ANDROID_DVR_GRAPHICS_VERTEX_ATTRIBUTES_H_

#include <private/dvr/types.h>

#include <EGL/egl.h>
#include <GLES3/gl3.h>
#include <tuple>

namespace android {
namespace dvr {

namespace Details {

// Set up the vertex attributes by iterating over the variadic template
// parameters.  The supported attributes are the GetSize and GetType
// specializations.
// clang-format off
template<typename T> GLint GetSize();
template<> inline GLint GetSize<vec2>() { return 2; }
template<> inline GLint GetSize<vec3>() { return 3; }
template<> inline GLint GetSize<vec4>() { return 4; }

template<typename T> GLenum GetType();
template<> inline GLenum GetType<vec2>() { return GL_FLOAT; }
template<> inline GLenum GetType<vec3>() { return GL_FLOAT; }
template<> inline GLenum GetType<vec4>() { return GL_FLOAT; }
// clang-format on

template <typename T>
void VertexAttrib(GLuint index, GLsizei stride, const GLvoid* pointer) {
  glVertexAttribPointer(index, GetSize<T>(), GetType<T>(), GL_FALSE, stride,
                        pointer);
  glEnableVertexAttribArray(index);
}

// Recursion variadic template parameter iterator.
template <int index, typename... Ts>
struct VertexAttribHelper {
  using tuple = std::tuple<Ts...>;
  size_t operator()() {
    size_t offset = VertexAttribHelper<index - 1, Ts...>{}();
    using type = typename std::tuple_element<index, tuple>::type;
    VertexAttrib<type>(index, sizeof(tuple), reinterpret_cast<void*>(offset));
    return offset + sizeof(type);
  }
};

// Recursion stop point.
template <typename... Ts>
struct VertexAttribHelper<0, Ts...> {
  using tuple = std::tuple<Ts...>;
  size_t operator()() {
    using type = typename std::tuple_element<0, tuple>::type;
    VertexAttrib<type>(0, sizeof(tuple), nullptr);
    return sizeof(type);
  }
};
}  // namespace Details

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_GRAPHICS_VERTEX_ATTRIBUTES_H_
