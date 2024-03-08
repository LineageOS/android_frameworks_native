/*
 * Copyright (C) 2023 The Android Open Source Project
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

use fakeservicemanager_bindgen::{clearFakeServiceManager, setupFakeServiceManager};
// Setup FakeServiceManager for testing and fuzzing purposes
pub fn setup_fake_service_manager() {
    unsafe {
        // Safety: This API creates a new FakeSm object which will be always valid and sets up
        // defaultServiceManager
        setupFakeServiceManager();
    }
}

// Setup FakeServiceManager for testing and fuzzing purposes
pub fn clear_fake_service_manager() {
    unsafe {
        // Safety: This API clears all registered services with Fake SM. This should be only used
        // setupFakeServiceManager is already called.
        clearFakeServiceManager();
    }
}
