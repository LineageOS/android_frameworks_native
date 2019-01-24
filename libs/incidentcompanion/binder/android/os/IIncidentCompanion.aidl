/**
 * Copyright (c) 2018, The Android Open Source Project
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

import android.os.IIncidentAuthListener;

/**
 * Helper service for incidentd and dumpstated to provide user feedback
 * and authorization for bug and inicdent reports to be taken.
 *
 * @hide
 */
interface IIncidentCompanion {
    /**
     * Request an authorization for an incident or bug report.
     * // TODO(b/111441001): Add the permission
     * <p>
     * This function requires the ___ permission.
     *
     * @param callingUid The original application that requested the report.  This function
     *      returns via the callback whether the application should be trusted.  It is up
     *      to the caller to actually implement the restriction to take or not take
     *      the incident or bug report.
     * @param flags FLAG_CONFIRMATION_DIALOG (0x1) - to show this as a dialog.  Otherwise
     *      a dialog will be shown as a notification.
     * @param callback Interface to receive results.  The results may not come back for
     *      a long (user's choice) time, or ever (if they never respond to the notification).
     *      Authorization requests are not persisted across reboot.  It is up to the calling
     *      service to request another authorization after reboot if they still would like
     *      to send their report.
     */
    oneway void authorizeReport(int callingUid, String callingPackage,
            int flags, IIncidentAuthListener callback);

    /**
     * Cancel an authorization.
     */
    oneway void cancelAuthorization(IIncidentAuthListener callback);

    /**
     * Return the list of pending approvals.
     */
    List<String> getPendingReports();

    /**
     * The user has authorized the report to be shared.
     *
     * @param uri the report.
     */
    void approveReport(String uri);

    /**
     * The user has denied the report from being shared.
     *
     * @param uri the report.
     */
    void denyReport(String uri);
}
