/*
 * Copyright (C) 2014 The Android Open Source Project
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

#pragma once

#include <input/DisplayViewport.h>
#include <input/Input.h>
#include <utils/BitSet.h>

namespace android {

struct SpriteIcon;

struct FloatPoint {
    float x;
    float y;

    inline FloatPoint(float x, float y) : x(x), y(y) {}

    inline explicit FloatPoint(vec2 p) : x(p.x), y(p.y) {}

    template <typename T, typename U>
    operator std::tuple<T, U>() {
        return {x, y};
    }
};

/**
 * Interface for tracking a mouse / touch pad pointer and touch pad spots.
 *
 * The spots are sprites on screen that visually represent the positions of
 * fingers
 *
 * The pointer controller is responsible for providing synchronization and for tracking
 * display orientation changes if needed. It works in the display panel's coordinate space, which
 * is the same coordinate space used by InputReader.
 */
class PointerControllerInterface {
protected:
    PointerControllerInterface() {}
    virtual ~PointerControllerInterface() {}

public:
    /**
     * Enum used to differentiate various types of PointerControllers for the transition to
     * using PointerChoreographer.
     *
     * TODO(b/293587049): Refactor the PointerController class into different controller types.
     */
    enum class ControllerType {
        // The PointerController that is responsible for drawing all icons.
        LEGACY,
        // Represents a single mouse pointer.
        MOUSE,
        // Represents multiple touch spots.
        TOUCH,
        // Represents a single stylus pointer.
        STYLUS,
    };

    /* Dumps the state of the pointer controller. */
    virtual std::string dump() = 0;

    /* Gets the bounds of the region that the pointer can traverse.
     * Returns true if the bounds are available. */
    virtual std::optional<FloatRect> getBounds() const = 0;

    /* Move the pointer. */
    virtual void move(float deltaX, float deltaY) = 0;

    /* Sets the absolute location of the pointer. */
    virtual void setPosition(float x, float y) = 0;

    /* Gets the absolute location of the pointer. */
    virtual FloatPoint getPosition() const = 0;

    enum class Transition {
        // Fade/unfade immediately.
        IMMEDIATE,
        // Fade/unfade gradually.
        GRADUAL,
    };

    /* Fades the pointer out now. */
    virtual void fade(Transition transition) = 0;

    /* Makes the pointer visible if it has faded out.
     * The pointer never unfades itself automatically.  This method must be called
     * by the client whenever the pointer is moved or a button is pressed and it
     * wants to ensure that the pointer becomes visible again. */
    virtual void unfade(Transition transition) = 0;

    enum class Presentation {
        // Show the mouse pointer.
        POINTER,
        // Show spots and a spot anchor in place of the mouse pointer.
        SPOT,
        // Show the stylus hover pointer.
        STYLUS_HOVER,

        ftl_last = STYLUS_HOVER,
    };

    /* Sets the mode of the pointer controller. */
    virtual void setPresentation(Presentation presentation) = 0;

    /* Sets the spots for the current gesture.
     * The spots are not subject to the inactivity timeout like the pointer
     * itself it since they are expected to remain visible for so long as
     * the fingers are on the touch pad.
     *
     * The values of the AMOTION_EVENT_AXIS_PRESSURE axis is significant.
     * For spotCoords, pressure != 0 indicates that the spot's location is being
     * pressed (not hovering).
     */
    virtual void setSpots(const PointerCoords* spotCoords, const uint32_t* spotIdToIndex,
                          BitSet32 spotIdBits, int32_t displayId) = 0;

    /* Removes all spots. */
    virtual void clearSpots() = 0;

    /* Gets the id of the display where the pointer should be shown. */
    virtual int32_t getDisplayId() const = 0;

    /* Sets the associated display of this pointer. Pointer should show on that display. */
    virtual void setDisplayViewport(const DisplayViewport& displayViewport) = 0;

    /* Sets the pointer icon type for mice or styluses. */
    virtual void updatePointerIcon(PointerIconStyle iconId) = 0;

    /* Sets the custom pointer icon for mice or styluses. */
    virtual void setCustomPointerIcon(const SpriteIcon& icon) = 0;
};

} // namespace android
