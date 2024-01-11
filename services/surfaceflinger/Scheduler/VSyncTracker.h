/*
 * Copyright 2019 The Android Open Source Project
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

#include <ui/DisplayId.h>
#include <utils/Timers.h>

#include <scheduler/Fps.h>
#include <scheduler/FrameRateMode.h>

#include "VSyncDispatch.h"

namespace android::scheduler {

/*
 * VSyncTracker is an interface for providing estimates on future Vsync signal times based on
 * historical vsync timing data.
 */
class VSyncTracker {
public:
    virtual ~VSyncTracker();

    /*
     * Adds a known timestamp from a vsync timing source (HWVsync signal, present fence)
     * to the model.
     *
     * \param [in] timestamp    The timestamp when the vsync signal was.
     * \return                  True if the timestamp was consistent with the internal model,
     *                          False otherwise
     */
    virtual bool addVsyncTimestamp(nsecs_t timestamp) = 0;

    /*
     * Access the next anticipated vsync time such that the anticipated time >= timePoint.
     * This will always give the best accurate at the time of calling; multiple
     * calls with the same timePoint might give differing values if the internal model
     * is updated.
     *
     * \param [in] timePoint    The point in time after which to estimate a vsync event.
     * \param [in] lastVsyncOpt The last vsync time used by the client. If provided, the tracker
     *                          should use that as a reference point when generating the new vsync
     *                          and avoid crossing the minimal frame period of a VRR display.
     * \return                  A prediction of the timestamp of a vsync event.
     */
    virtual nsecs_t nextAnticipatedVSyncTimeFrom(
            nsecs_t timePoint, std::optional<nsecs_t> lastVsyncOpt = {}) const = 0;

    /*
     * The current period of the vsync signal.
     *
     * \return  The current period of the vsync signal
     */
    virtual nsecs_t currentPeriod() const = 0;

    /*
     * The minimal period frames can be displayed.
     */
    virtual Period minFramePeriod() const = 0;

    /* Inform the tracker that the samples it has are not accurate for prediction. */
    virtual void resetModel() = 0;

    virtual bool needsMoreSamples() const = 0;

    /*
     * Checks if a vsync timestamp is in phase for a frame rate
     *
     * \param [in] timePoint  A vsync timestamp
     * \param [in] frameRate  The frame rate to check for
     */
    virtual bool isVSyncInPhase(nsecs_t timePoint, Fps frameRate) const = 0;

    /*
     * Sets the active mode of the display which includes the vsync period and other VRR attributes.
     * This will inform the tracker that the period is changing and the tracker needs to recalibrate
     * itself.
     *
     * \param [in] DisplayModePtr The display mode the tracker will use.
     */
    virtual void setDisplayModePtr(ftl::NonNull<DisplayModePtr>) = 0;

    /*
     * Sets a render rate on the tracker. If the render rate is not a divisor
     * of the period, the render rate is ignored until the period changes.
     * The tracker will continue to track the vsync timeline and expect it
     * to match the current period, however, nextAnticipatedVSyncTimeFrom will
     * return vsyncs according to the render rate set. Setting a render rate is useful
     * when a display is running at 120Hz but the render frame rate is 60Hz.
     *
     * \param [in] Fps   The render rate the tracker should operate at.
     */
    virtual void setRenderRate(Fps) = 0;

    virtual void onFrameBegin(TimePoint expectedPresentTime,
                              TimePoint lastConfirmedPresentTime) = 0;

    virtual void onFrameMissed(TimePoint expectedPresentTime) = 0;

    virtual void dump(std::string& result) const = 0;

protected:
    VSyncTracker(VSyncTracker const&) = delete;
    VSyncTracker& operator=(VSyncTracker const&) = delete;
    VSyncTracker() = default;
};

} // namespace android::scheduler
