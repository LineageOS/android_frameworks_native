/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <layerproto/LayerProtoHeader.h>

#include <math/vec4.h>

#include <android-base/stringprintf.h>
#include <ui/DebugUtils.h>
#include <unordered_map>
#include <vector>

using android::base::StringAppendF;
using android::base::StringPrintf;

namespace android {
namespace surfaceflinger {

class LayerProtoParser {
public:
    class ActiveBuffer {
    public:
        uint32_t width;
        uint32_t height;
        uint32_t stride;
        int32_t format;

        std::string to_string() const {
            return StringPrintf("[%4ux%4u:%4u,%s]", width, height, stride,
                                decodePixelFormat(format).c_str());
        }
    };

    class Transform {
    public:
        float dsdx;
        float dtdx;
        float dsdy;
        float dtdy;

        std::string to_string() const {
            return StringPrintf("[%.2f, %.2f][%.2f, %.2f]", static_cast<double>(dsdx),
                                static_cast<double>(dtdx), static_cast<double>(dsdy),
                                static_cast<double>(dtdy));
        }
    };

    class Rect {
    public:
        int32_t left;
        int32_t top;
        int32_t right;
        int32_t bottom;

        std::string to_string() const {
            return StringPrintf("[%3d, %3d, %3d, %3d]", left, top, right, bottom);
        }
    };

    class Region {
    public:
        uint64_t id;
        std::vector<Rect> rects;

        std::string to_string(const char* what) const {
            std::string result =
                    StringPrintf("  Region %s (this=%lx count=%d)\n", what,
                                 static_cast<unsigned long>(id), static_cast<int>(rects.size()));

            for (auto& rect : rects) {
                StringAppendF(&result, "    %s\n", rect.to_string().c_str());
            }

            return result;
        }
    };

    class Layer {
    public:
        int32_t id;
        std::string name;
        std::vector<const Layer*> children;
        std::vector<const Layer*> relatives;
        std::string type;
        LayerProtoParser::Region transparentRegion;
        LayerProtoParser::Region visibleRegion;
        LayerProtoParser::Region damageRegion;
        uint32_t layerStack;
        int32_t z;
        float2 position;
        float2 requestedPosition;
        int2 size;
        LayerProtoParser::Rect crop;
        LayerProtoParser::Rect finalCrop;
        bool isOpaque;
        bool invalidate;
        std::string dataspace;
        std::string pixelFormat;
        half4 color;
        half4 requestedColor;
        uint32_t flags;
        Transform transform;
        Transform requestedTransform;
        Layer* parent = 0;
        Layer* zOrderRelativeOf = 0;
        LayerProtoParser::ActiveBuffer activeBuffer;
        int32_t queuedFrames;
        bool refreshPending;

        std::string to_string() const {
            std::string result;
            StringAppendF(&result, "+ %s (%s)\n", type.c_str(), name.c_str());
            result.append(transparentRegion.to_string("TransparentRegion").c_str());
            result.append(visibleRegion.to_string("VisibleRegion").c_str());
            result.append(damageRegion.to_string("SurfaceDamageRegion").c_str());

            StringAppendF(&result, "      layerStack=%4d, z=%9d, pos=(%g,%g), size=(%4d,%4d), ",
                          layerStack, z, static_cast<double>(position.x),
                          static_cast<double>(position.y), size.x, size.y);

            StringAppendF(&result, "crop=%s, finalCrop=%s, ", crop.to_string().c_str(),
                          finalCrop.to_string().c_str());
            StringAppendF(&result, "isOpaque=%1d, invalidate=%1d, ", isOpaque, invalidate);
            StringAppendF(&result, "dataspace=%s, ", dataspace.c_str());
            StringAppendF(&result, "pixelformat=%s, ", pixelFormat.c_str());
            StringAppendF(&result, "color=(%.3f,%.3f,%.3f,%.3f), flags=0x%08x, ",
                          static_cast<double>(color.r), static_cast<double>(color.g),
                          static_cast<double>(color.b), static_cast<double>(color.a), flags);
            StringAppendF(&result, "tr=%s", transform.to_string().c_str());
            result.append("\n");
            StringAppendF(&result, "      parent=%s\n",
                          parent == nullptr ? "none" : parent->name.c_str());
            StringAppendF(&result, "      zOrderRelativeOf=%s\n",
                          zOrderRelativeOf == nullptr ? "none" : zOrderRelativeOf->name.c_str());
            StringAppendF(&result, "      activeBuffer=%s,", activeBuffer.to_string().c_str());
            StringAppendF(&result, " queued-frames=%d, mRefreshPending=%d", queuedFrames,
                          refreshPending);

            return result;
        }
    };

    static std::vector<const Layer*> generateLayerTree(const LayersProto& layersProto);
    static std::string layersToString(const std::vector<const LayerProtoParser::Layer*> layers);

private:
    static std::unordered_map<int32_t, Layer*> generateMap(const LayersProto& layersProto);
    static LayerProtoParser::Layer* generateLayer(const LayerProto& layerProto);
    static LayerProtoParser::Region generateRegion(const RegionProto& regionProto);
    static LayerProtoParser::Rect generateRect(const RectProto& rectProto);
    static LayerProtoParser::Transform generateTransform(const TransformProto& transformProto);
    static LayerProtoParser::ActiveBuffer generateActiveBuffer(
            const ActiveBufferProto& activeBufferProto);
    static void updateChildrenAndRelative(const LayerProto& layerProto,
                                          std::unordered_map<int32_t, Layer*>& layerMap);

    static std::string layerToString(const LayerProtoParser::Layer* layer);
};

} // namespace surfaceflinger
} // namespace android
