#include "include/private/dvr/eds_mesh.h"

#include <math.h>

#include <base/logging.h>
#include <private/dvr/types.h>

namespace {

using android::dvr::EdsVertex;
using android::dvr::EyeType;
using android::dvr::DistortionFunction;
using android::dvr::vec2;

// Computes the vertices for a distortion mesh with resolution |resolution| and
// distortion provided by |hmd| and stores them in |vertices|.
static void ComputeDistortionMeshVertices(
    EdsVertex* vertices, int resolution,
    const DistortionFunction& distortion_function, EyeType eye) {
  for (int row = 0; row < resolution; row++) {
    for (int col = 0; col < resolution; col++) {
      const float x_norm =
          static_cast<float>(col) / (static_cast<float>(resolution - 1U));
      const float y_norm =
          static_cast<float>(row) / (static_cast<float>(resolution - 1U));

      const vec2 xy_norm(x_norm, y_norm);
      const size_t index = col * resolution + row;

      // Evaluate distortion function to get the new coordinates for each color
      // channel. The distortion function returns the new coordinates relative
      // to a full viewport with 0 <= x <= 1 for each eye.
      vec2 coords[3];
      distortion_function(eye, xy_norm, &vertices[index].position, coords);

      // Store distortion mapping in texture coordinates.
      vertices[index].red_viewport_coords = coords[0];
      vertices[index].green_viewport_coords = coords[1];
      vertices[index].blue_viewport_coords = coords[2];
    }
  }
}

// Computes the triangle strip indices for a distortion mesh with resolution
// |resolution| and stores them in |indices|.
static void ComputeDistortionMeshIndices(uint16_t* indices, int resolution) {
  // The following strip method has been used in the Cardboard SDK
  // (java/com/google/vrtoolkit/cardboard/DistortionRenderer.java) and has
  // originally been described at:
  //
  // http://dan.lecocq.us/wordpress/2009/12/25/triangle-strip-for-grids-a-construction/
  //
  // For a grid with 4 rows and 4 columns of vertices, the strip would
  // look like:
  //                             ↻
  //         0    -    4    -    8    -   12
  //         ↓    ↗    ↓    ↗    ↓    ↗    ↓
  //         1    -    5    -    9    -   13
  //         ↓    ↖    ↓    ↖    ↓    ↖    ↓
  //         2    -    6    -   10    -   14
  //         ↓    ↗    ↓    ↗    ↓    ↗    ↓
  //         3    -    7    -   11    -   15
  //                   ↺
  //
  // Note the little circular arrows next to 7 and 8 that indicate
  // repeating that vertex once so as to produce degenerate triangles.
  //
  // To facilitate scanline racing, the vertex order is left to right.

  int16_t index_offset = 0;
  int16_t vertex_offset = 0;
  for (int row = 0; row < resolution - 1; ++row) {
    if (row > 0) {
      indices[index_offset] = indices[index_offset - 1];
      ++index_offset;
    }
    for (int col = 0; col < resolution; ++col) {
      if (col > 0) {
        if (row % 2 == 0) {
          // Move right on even rows.
          ++vertex_offset;
        } else {
          --vertex_offset;
        }
      }
      // A cast to uint16_t is safe here as |vertex_offset| will not drop below
      // zero in this loop. As col is initially equal to zero |vertex_offset| is
      // always incremented before being decremented, is initialized to zero and
      // is only incremented outside of the loop.
      indices[index_offset++] = static_cast<uint16_t>(vertex_offset);
      indices[index_offset++] = static_cast<uint16_t>(
          vertex_offset + static_cast<int16_t>(resolution));
    }
    vertex_offset =
        static_cast<int16_t>(static_cast<int>(resolution) + vertex_offset);
  }
}

}  // anonymous namespace

namespace android {
namespace dvr {

// Builds a distortion mesh of resolution |resolution| using the distortion
// provided by |hmd| for |eye|.
EdsMesh BuildDistortionMesh(EyeType eye, int resolution,
                            const DistortionFunction& distortion_function) {
  CHECK_GT(resolution, 2);

  // Number of indices produced by the strip method
  // (see comment in ComputeDistortionMeshIndices):
  //
  //     1 vertex per triangle
  //     2 triangles per quad, (rows - 1) * (cols - 1) quads
  //     2 vertices at the start of each row for the first triangle
  //     1 extra vertex per row (except first and last) for a
  //       degenerate triangle
  //
  const uint16_t index_count =
      static_cast<uint16_t>(resolution * (2 * resolution - 1U) - 2U);
  const uint16_t vertex_count = static_cast<uint16_t>(resolution * resolution);

  EdsMesh mesh;
  mesh.vertices.resize(vertex_count);
  mesh.indices.resize(index_count);

  // Populate vertex and index buffer.
  ComputeDistortionMeshVertices(&mesh.vertices[0], resolution,
                                distortion_function, eye);
  ComputeDistortionMeshIndices(&mesh.indices[0], resolution);

  return mesh;
}

}  // namespace dvr
}  // namespace android
