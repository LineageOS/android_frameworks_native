/*
 * Copyright 2020 The Android Open Source Project
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

#include <system/graphics.h>
#include <ui/FloatRect.h>
#include <ui/Point.h>
#include <ui/Rect.h>
#include <ui/Size.h>

#include <gtest/gtest.h>

namespace android::ui {

TEST(RectTest, constructDefault) {
    const Rect rect;
    EXPECT_FALSE(rect.isValid());
    EXPECT_TRUE(rect.isEmpty());
}

TEST(RectTest, constructFromWidthAndHeight) {
    const Rect rect(100, 200);
    EXPECT_TRUE(rect.isValid());
    EXPECT_FALSE(rect.isEmpty());
    EXPECT_EQ(0, rect.top);
    EXPECT_EQ(0, rect.left);
    EXPECT_EQ(100, rect.right);
    EXPECT_EQ(200, rect.bottom);
    EXPECT_EQ(100, rect.getWidth());
    EXPECT_EQ(200, rect.getHeight());
}

TEST(RectTest, constructFromSize) {
    const Rect rect(Size(100, 200));
    EXPECT_TRUE(rect.isValid());
    EXPECT_FALSE(rect.isEmpty());
    EXPECT_EQ(0, rect.top);
    EXPECT_EQ(0, rect.left);
    EXPECT_EQ(100, rect.right);
    EXPECT_EQ(200, rect.bottom);
    EXPECT_EQ(100, rect.getWidth());
    EXPECT_EQ(200, rect.getHeight());
}

TEST(RectTest, constructFromLTRB) {
    const Rect rect(11, 12, 14, 14);
    EXPECT_TRUE(rect.isValid());
    EXPECT_FALSE(rect.isEmpty());
    EXPECT_EQ(11, rect.left);
    EXPECT_EQ(12, rect.top);
    EXPECT_EQ(14, rect.right);
    EXPECT_EQ(14, rect.bottom);
    EXPECT_EQ(3, rect.getWidth());
    EXPECT_EQ(2, rect.getHeight());
}

TEST(RectTest, constructFromPoints) {
    const Rect rect(Point(11, 12), Point(14, 14));
    EXPECT_TRUE(rect.isValid());
    EXPECT_FALSE(rect.isEmpty());
    EXPECT_EQ(11, rect.left);
    EXPECT_EQ(12, rect.top);
    EXPECT_EQ(14, rect.right);
    EXPECT_EQ(14, rect.bottom);
    EXPECT_EQ(3, rect.getWidth());
    EXPECT_EQ(2, rect.getHeight());
}

TEST(RectTest, constructFromFloatRect) {
    {
        const Rect rect(FloatRect(10, 20, 30, 40));
        EXPECT_TRUE(rect.isValid());
        EXPECT_FALSE(rect.isEmpty());
        EXPECT_EQ(10, rect.left);
        EXPECT_EQ(20, rect.top);
        EXPECT_EQ(30, rect.right);
        EXPECT_EQ(40, rect.bottom);
    }
    // Construct with floating point error
    {
        constexpr float kError = 1e-3;
        const Rect rect(FloatRect(10 - kError, 20 - kError, 30 - kError, 40 - kError));
        EXPECT_TRUE(rect.isValid());
        EXPECT_FALSE(rect.isEmpty());
        EXPECT_EQ(10, rect.left);
        EXPECT_EQ(20, rect.top);
        EXPECT_EQ(30, rect.right);
        EXPECT_EQ(40, rect.bottom);
    }
}

TEST(RectTest, makeInvalid) {
    Rect rect(10, 20, 60, 60);
    EXPECT_TRUE(rect.isValid());
    rect.makeInvalid();
    EXPECT_FALSE(rect.isValid());
}

TEST(RectTest, clear) {
    Rect rect(10, 20, 60, 60);
    EXPECT_FALSE(rect.isEmpty());
    rect.clear();
    EXPECT_TRUE(rect.isEmpty());
}

TEST(RectTest, getSize) {
    const Rect rect(10, 20, 60, 60);
    EXPECT_EQ(Size(50, 40), rect.getSize());
}

TEST(RectTest, getBounds) {
    const Rect rect(10, 20, 60, 60);
    const Rect bounds = rect.getBounds();
    EXPECT_EQ(0, bounds.left);
    EXPECT_EQ(0, bounds.top);
    EXPECT_EQ(50, bounds.right);
    EXPECT_EQ(40, bounds.bottom);
    EXPECT_EQ(rect.getSize(), bounds.getSize());
}

TEST(RectTest, getCornerPoints) {
    const Rect rect(10, 20, 50, 60);
    EXPECT_EQ(Point(10, 20), rect.leftTop());
    EXPECT_EQ(Point(10, 60), rect.leftBottom());
    EXPECT_EQ(Point(50, 20), rect.rightTop());
    EXPECT_EQ(Point(50, 60), rect.rightBottom());
}

TEST(RectTest, operatorEquals) {
    const Rect rect(10, 20, 50, 60);
    EXPECT_EQ(rect, rect);
    EXPECT_NE(Rect(0, 20, 50, 60), rect);
    EXPECT_NE(Rect(10, 0, 50, 60), rect);
    EXPECT_NE(Rect(10, 20, 0, 60), rect);
    EXPECT_NE(Rect(10, 20, 50, 0), rect);
}

TEST(RectTest, operatorsPlusMinus) {
    Rect rect = Rect(10, 20, 50, 60) + Point(1, 2);
    EXPECT_EQ(Rect(11, 22, 51, 62), rect);
    rect -= Point(1, 2);
    EXPECT_EQ(Rect(10, 20, 50, 60), rect);

    rect = Rect(10, 20, 50, 60) - Point(1, 2);
    EXPECT_EQ(Rect(9, 18, 49, 58), rect);
    rect += Point(1, 2);
    EXPECT_EQ(Rect(10, 20, 50, 60), rect);
}

TEST(RectTest, scale) {
    Rect rect(10, 20, 50, 60);
    EXPECT_EQ(Rect(20, 60, 100, 180), rect.scale(2.f, 3.f));
    rect.scaleSelf(2.f, 3.f);
    EXPECT_EQ(Rect(20, 60, 100, 180), rect);

    rect = Rect(10, 20, 50, 60);
    constexpr float kError = 1e-3;
    EXPECT_EQ(Rect(20, 60, 100, 180), rect.scale(2.f - kError, 3.f - kError));
    rect.scaleSelf(2.f - kError, 3.f - kError);
    EXPECT_EQ(Rect(20, 60, 100, 180), rect);
}

TEST(RectTest, inset) {
    Rect rect(10, 20, 50, 60);
    rect.inset(0, 0, 0, 0);
    EXPECT_EQ(Rect(10, 20, 50, 60), rect);
    rect.inset(1, 2, 3, 4);
    EXPECT_EQ(Rect(11, 22, 47, 56), rect);
}

TEST(RectTest, intersect) {
    const Rect rect(10, 20, 50, 60);
    Rect intersection;

    // Intersect with self is self
    intersection.makeInvalid();
    EXPECT_TRUE(rect.intersect(rect, &intersection));
    EXPECT_EQ(Rect(10, 20, 50, 60), intersection);

    // Intersect with rect contained in us
    const Rect insideRect(11, 21, 45, 55);
    intersection.makeInvalid();
    EXPECT_TRUE(rect.intersect(insideRect, &intersection));
    EXPECT_EQ(insideRect, intersection);

    // Intersect with rect we are contained in
    intersection.makeInvalid();
    EXPECT_TRUE(insideRect.intersect(rect, &intersection));
    EXPECT_EQ(insideRect, intersection);

    // Empty intersection
    intersection.makeInvalid();
    EXPECT_FALSE(rect.intersect(Rect(100, 202, 150, 260), &intersection));
    EXPECT_TRUE(intersection.isEmpty());

    // Partial intersection
    const Rect other(30, 40, 70, 80);
    intersection.makeInvalid();
    EXPECT_TRUE(rect.intersect(other, &intersection));
    EXPECT_EQ(Rect(30, 40, 50, 60), intersection);

    // Intersetion is commutative
    intersection.makeInvalid();
    EXPECT_TRUE(other.intersect(rect, &intersection));
    EXPECT_EQ(Rect(30, 40, 50, 60), intersection);
}

TEST(RectTest, reduce) {
    const Rect rect(10, 20, 50, 60);

    // Reduce with self is empty
    EXPECT_TRUE(rect.reduce(rect).isEmpty());

    // Reduce with rect entirely inside is a noop
    const Rect insideRect(11, 21, 45, 55);
    EXPECT_EQ(rect, rect.reduce(insideRect));

    // Reduce with rect entirely outside is empty
    EXPECT_TRUE(insideRect.reduce(rect).isEmpty());

    // Reduce with rect on the right
    EXPECT_EQ(Rect(10, 20, 20, 60), rect.reduce(Rect(20, 0, 60, 70)));

    // Reduce with rect on the left
    EXPECT_EQ(Rect(40, 20, 50, 60), rect.reduce(Rect(0, 0, 40, 70)));

    // Reduce with rect at the top
    EXPECT_EQ(Rect(10, 40, 50, 60), rect.reduce(Rect(0, 0, 70, 40)));

    // Reduce with rect at the bottom
    EXPECT_EQ(Rect(10, 20, 50, 40), rect.reduce(Rect(0, 40, 70, 70)));
}

TEST(RectTest, transform) {
    const int32_t width = 100, height = 200;
    const Rect rect(1, 1, 2, 3);
    EXPECT_EQ(Rect(98, 1, 99, 3), rect.transform(HAL_TRANSFORM_FLIP_H, width, height));
    EXPECT_EQ(Rect(1, 197, 2, 199), rect.transform(HAL_TRANSFORM_FLIP_V, width, height));
    EXPECT_EQ(Rect(197, 1, 199, 2), rect.transform(HAL_TRANSFORM_ROT_90, width, height));
    EXPECT_EQ(Rect(98, 197, 99, 199), rect.transform(HAL_TRANSFORM_ROT_180, width, height));
    EXPECT_EQ(Rect(1, 98, 3, 99), rect.transform(HAL_TRANSFORM_ROT_270, width, height));
}

TEST(RectTest, toFloatRect) {
    const Rect rect(10, 20, 50, 60);
    const FloatRect floatRect = rect.toFloatRect();
    EXPECT_EQ(FloatRect(10.f, 20.f, 50.f, 60.f), floatRect);
}

TEST(RectTest, RectHash) {
    const std::vector<Rect> rects = {
            Rect(10, 20, 50, 60), Rect(11, 20, 50, 60), Rect(11, 21, 50, 60),
            Rect(11, 21, 51, 60), Rect(11, 21, 51, 61),
    };

    for (const auto& a : rects) {
        for (const auto& b : rects) {
            const bool hashEq = std::hash<Rect>{}(a) == std::hash<Rect>{}(b);
            EXPECT_EQ(a == b, hashEq);
        }
    }
}

TEST(RectTest, FloatRectHash) {
    const std::vector<FloatRect> floatRects = {
            Rect(10, 20, 50, 60).toFloatRect(), Rect(11, 20, 50, 60).toFloatRect(),
            Rect(11, 21, 50, 60).toFloatRect(), Rect(11, 21, 51, 60).toFloatRect(),
            Rect(11, 21, 51, 61).toFloatRect(),
    };

    for (const auto& a : floatRects) {
        for (const auto& b : floatRects) {
            const bool hashEq = std::hash<FloatRect>{}(a) == std::hash<FloatRect>{}(b);
            EXPECT_EQ(a == b, hashEq);
        }
    }
}

} // namespace android::ui
