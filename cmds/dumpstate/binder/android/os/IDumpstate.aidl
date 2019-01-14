/**
 * Copyright (c) 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.os;

import android.os.IDumpstateListener;
import android.os.IDumpstateToken;
import android.os.DumpstateOptions;

/**
  * Binder interface for the currently running dumpstate process.
  * {@hide}
  */
interface IDumpstate {
    // TODO: remove method once startBugReport is used by Shell.
    /*
     * Sets the listener for this dumpstate progress.
     *
     * Returns a token used to monitor dumpstate death, or `nullptr` if the listener was already
     * set (the listener behaves like a Highlander: There Can be Only One).
     * Set {@code getSectionDetails} to true in order to receive callbacks with per section
     * progress details
     */
    IDumpstateToken setListener(@utf8InCpp String name, IDumpstateListener listener,
                                boolean getSectionDetails);

    // These modes encapsulate a set of run time options for generating bugreports.
    // Takes a bugreport without user interference.
    const int BUGREPORT_MODE_FULL = 0;

    // Interactive bugreport, i.e. triggered by the user.
    const int BUGREPORT_MODE_INTERACTIVE = 1;

    // Remote bugreport triggered by DevicePolicyManager, for e.g.
    const int BUGREPORT_MODE_REMOTE = 2;

    // Bugreport triggered on a wear device.
    const int BUGREPORT_MODE_WEAR = 3;

    // Bugreport limited to only telephony info.
    const int BUGREPORT_MODE_TELEPHONY = 4;

    // Bugreport limited to only wifi info.
    const int BUGREPORT_MODE_WIFI = 5;

    // Default mode.
    const int BUGREPORT_MODE_DEFAULT = 6;

    /*
     * Starts a bugreport in the background.
     *
     * @param bugreportFd the file to which the zipped bugreport should be written
     * @param screenshotFd the file to which screenshot should be written; optional
     * @param bugreportMode the mode that specifies other run time options; must be one of above
     * @param listener callback for updates; optional
     */
    void startBugreport(FileDescriptor bugreportFd, FileDescriptor screenshotFd, int bugreportMode,
                        IDumpstateListener listener);
}
