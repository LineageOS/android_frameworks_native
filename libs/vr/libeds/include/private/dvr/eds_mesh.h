#ifndef ANDROID_DVR_EDS_MESH_H_
#define ANDROID_DVR_EDS_MESH_H_

#include <stdint.h>
#include <functional>
#include <vector>

#include <private/dvr/types.h>

namespace android {
namespace dvr {

struct EdsVertex {
  vec2 position;
  vec2 red_viewport_coords;
  vec2 green_viewport_coords;
  vec2 blue_viewport_coords;
};

struct EdsMesh {
  std::vector<EdsVertex> vertices;
  std::vector<uint16_t> indices;
};

// Distortion function takes in a point in the range [0..1, 0..1] and returns
// the vertex position and the three distorted points for separate R, G and B
// channels.
typedef std::function<void(EyeType, vec2, vec2*, vec2*)> DistortionFunction;

// Builds a distortion mesh of resolution |resolution| using
// the distortion provided by |hmd| for |eye|.
EdsMesh BuildDistortionMesh(EyeType eye, int resolution,
                            const DistortionFunction& distortion_function);

}  // namespace dvr
}  // namespace android

#endif  // ANDROID_DVR_EDS_MESH_H_
