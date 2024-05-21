/*
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

/**
 * Binder interface for the currently running dumpstate process.
 * {@hide}
 */
interface IDumpstate {

    // NOTE: If you add to or change these modes, please also change the corresponding enums
    // in system server, in BugreportParams.java.

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

    // Bugreport taken for onboarding related flows.
    const int BUGREPORT_MODE_ONBOARDING = 7;

    // Use pre-dumped data.
    const int BUGREPORT_FLAG_USE_PREDUMPED_UI_DATA = 0x1;

    // Defer user consent.
    const int BUGREPORT_FLAG_DEFER_CONSENT = 0x2;

    // Keep bugreport stored after retrieval.
    const int BUGREPORT_FLAG_KEEP_BUGREPORT_ON_RETRIEVAL = 0x4;

    /**
     * Speculatively pre-dumps UI data for a bugreport request that might come later.
     *
     * <p>Triggers the dump of certain critical UI data, e.g. traces stored in short
     * ring buffers that might get lost by the time the actual bugreport is requested.
     *
     * <p>{@code startBugreport} will then pick the pre-dumped data if:
     * - {@link BUGREPORT_FLAG_USE_PREDUMPED_UI_DATA} is specified.
     * - {@code preDumpUiData} and {@code startBugreport} were called by the same UID.
     *
     * @param callingPackage package of the original application that requested the report.
     */
    void preDumpUiData(@utf8InCpp String callingPackage);

    /**
     * Starts a bugreport in the background.
     *
     * <p>Shows the user a dialog to get consent for sharing the bugreport with the calling
     * application. If they deny {@link IDumpstateListener#onError} will be called. If they
     * consent and bugreport generation is successful artifacts will be copied to the given fds and
     * {@link IDumpstateListener#onFinished} will be called. If there
     * are errors in bugreport generation {@link IDumpstateListener#onError} will be called.
     *
     * @param callingUid UID of the original application that requested the report.
     * @param callingPackage package of the original application that requested the report.
     * @param bugreportFd the file to which the zipped bugreport should be written
     * @param screenshotFd the file to which screenshot should be written
     * @param bugreportMode the mode that specifies other run time options; must be one of above
     * @param bugreportFlags flags to customize the bugreport generation
     * @param listener callback for updates; optional
     * @param isScreenshotRequested indicates screenshot is requested or not
     */
    void startBugreport(int callingUid, @utf8InCpp String callingPackage,
                        FileDescriptor bugreportFd, FileDescriptor screenshotFd,
                        int bugreportMode, int bugreportFlags,
                        IDumpstateListener listener, boolean isScreenshotRequested,
                        boolean skipUserConsent);

    /**
     * Cancels the bugreport currently in progress.
     *
     * <p>The caller must match the original caller of {@link #startBugreport} in order for the
     * report to actually be cancelled. A {@link SecurityException} is reported if a mismatch is
     * detected.
     *
     * @param callingUid UID of the original application that requested the cancellation.
     * @param callingPackage package of the original application that requested the cancellation.
     */
    void cancelBugreport(int callingUid, @utf8InCpp String callingPackage);

    /**
     * Retrieves a previously generated bugreport.
     *
     * <p>The caller must have previously generated a bugreport using
     * {@link #startBugreport} with the {@link BUGREPORT_FLAG_DEFER_CONSENT}
     * flag set.
     *
     * @param callingUid UID of the original application that requested the report.
     * @param callingPackage package of the original application that requested the report.
     * @param userId user Id of the original package that requested the report.
     * @param bugreportFd the file to which the zipped bugreport should be written
     * @param bugreportFile the path of the bugreport file
     * @param keepBugreportOnRetrieval boolean to indicate if the bugreport should be kept in the
     * platform after it has been retrieved by the caller.
     * @param listener callback for updates; optional
     */
    void retrieveBugreport(int callingUid, @utf8InCpp String callingPackage, int userId,
                           FileDescriptor bugreportFd,
                           @utf8InCpp String bugreportFile,
                           boolean keepBugreportOnRetrieval,
                           boolean skipUserConsent,
                           IDumpstateListener listener);
}
