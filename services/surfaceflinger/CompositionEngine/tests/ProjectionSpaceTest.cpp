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
#include <compositionengine/ProjectionSpace.h>
#include <gtest/gtest.h>

namespace android::compositionengine {
namespace {

// Returns a rectangular strip along the side of the given rect pointed by
// rotation. E.g. if rotation is ROTATION_0, the srip will be along the top
// side, if it is ROTATION_90 the stip will be along the right wall.
// One of the dimensions of the strip will be 0 and the other one will match
// the length of the corresponding side.
// The strip will be contained inside the given rect.
Rect getSideStrip(const Rect& rect, ui::Rotation rotation) {
    int width, height;
    if (rotation == ui::ROTATION_90 || rotation == ui::ROTATION_270) {
        width = 0;
        height = rect.height();
    } else {
        width = rect.width();
        height = 0;
    }

    if (rotation == ui::ROTATION_0 || rotation == ui::ROTATION_270) {
        return Rect(rect.left, rect.top, rect.left + width, rect.top + height);
    }

    if (rotation == ui::ROTATION_90) {
        return Rect(rect.right, rect.top, rect.right + width, rect.top + height);
    }

    if (rotation == ui::ROTATION_180) {
        return Rect(rect.left, rect.bottom, rect.left + width, rect.bottom + height);
    }

    return Rect::INVALID_RECT;
}
} // namespace

TEST(ProjectionSpaceTest, getTransformToSelfIsIdentity) {
    ProjectionSpace space;
    space.setContent(Rect(100, 200));
    space.setBounds(ui::Size(100, 200));

    const ui::Transform identity;
    for (int rotation = 0; rotation <= 3; rotation++) {
        space.setOrientation(ui::Rotation(rotation));
        EXPECT_EQ(space.getTransform(space), identity);
    }
}

TEST(ProjectionSpaceTest, getTransformWhenTranslationIsNeeded) {
    ProjectionSpace source;
    source.setContent(Rect(10, 10, 20, 20));
    source.setBounds(ui::Size(100, 200));

    ProjectionSpace dest;
    dest.setContent(Rect(10, 20, 30, 20));
    dest.setBounds(source.getBounds());

    const auto transform = source.getTransform(dest);
    EXPECT_EQ(transform.transform(source.getContent()), dest.getContent());
}

TEST(ProjectionSpaceTest, getTransformWhenScaleIsNeeded) {
    ProjectionSpace source;
    source.setContent(Rect(0, 0, 20, 20));
    source.setBounds(ui::Size(100, 200));

    ProjectionSpace dest;
    dest.setContent(Rect(0, 0, 40, 30));
    dest.setBounds(source.getBounds());

    const auto transform = source.getTransform(dest);
    EXPECT_EQ(transform.transform(source.getContent()), dest.getContent());
}

TEST(ProjectionSpaceTest, getSideStripTest) {
    const Rect rect(10, 20, 40, 100);
    EXPECT_EQ(getSideStrip(rect, ui::ROTATION_0), Rect(10, 20, 40, 20));
    EXPECT_EQ(getSideStrip(rect, ui::ROTATION_90), Rect(40, 20, 40, 100));
    EXPECT_EQ(getSideStrip(rect, ui::ROTATION_180), Rect(10, 100, 40, 100));
    EXPECT_EQ(getSideStrip(rect, ui::ROTATION_270), Rect(10, 20, 10, 100));
}

void testTransform(const ProjectionSpace& source, const ProjectionSpace& dest) {
    const auto transform = source.getTransform(dest);
    EXPECT_EQ(transform.transform(source.getContent()), dest.getContent())
            << "Source content doesn't map to dest content when projecting " << to_string(source)
            << " onto " << to_string(dest);

    // We take a strip at the top (according to the orientation) of each
    // content rect and verify that transform maps between them. This way we
    // verify that the transform is rotating properly.
    // In the following example the strip is marked with asterisks:
    //
    //      *******                +-------*
    //      |     |                |       *
    //      |     |                |       *
    //      +-----+                +-------*
    // source(ROTATION_0)      dest (ROTATION_90)
    const auto sourceStrip = getSideStrip(source.getContent(), source.getOrientation());
    const auto destStrip = getSideStrip(dest.getContent(), dest.getOrientation());
    ASSERT_NE(sourceStrip, Rect::INVALID_RECT);
    ASSERT_NE(destStrip, Rect::INVALID_RECT);
    const auto mappedStrip = transform.transform(sourceStrip);
    EXPECT_EQ(mappedStrip, destStrip)
            << to_string(sourceStrip) << " maps to " << to_string(mappedStrip) << " instead of "
            << to_string(destStrip) << " when projecting " << to_string(source) << " onto "
            << to_string(dest);
}

TEST(ProjectionSpaceTest, getTransformWithOrienations) {
    ProjectionSpace source;
    source.setBounds(ui::Size(666, 776));
    source.setContent(Rect(40, 50, 234, 343));
    ProjectionSpace dest;
    dest.setBounds(ui::Size(862, 546));
    dest.setContent(Rect(43, 52, 432, 213));

    for (int sourceRot = 0; sourceRot <= 3; sourceRot++) {
        source.setOrientation(ui::Rotation(sourceRot));
        for (int destRot = 0; destRot <= 3; destRot++) {
            dest.setOrientation(ui::Rotation(destRot));
            testTransform(source, dest);
        }
    }
}

} // namespace android::compositionengine
