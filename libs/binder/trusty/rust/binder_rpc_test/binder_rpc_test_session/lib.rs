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

use binder::{Interface, ParcelFileDescriptor, SpIBinder, Status, StatusCode, Strong};
use binder_rpc_test_aidl::aidl::IBinderRpcCallback::IBinderRpcCallback;
use binder_rpc_test_aidl::aidl::IBinderRpcSession::IBinderRpcSession;
use binder_rpc_test_aidl::aidl::IBinderRpcTest::IBinderRpcTest;
use std::sync::Mutex;

static G_NUM: Mutex<i32> = Mutex::new(0);

#[derive(Debug, Default)]
pub struct MyBinderRpcSession {
    name: String,
}

impl MyBinderRpcSession {
    pub fn new(name: &str) -> Self {
        Self::increment_instance_count();
        Self { name: name.to_string() }
    }

    pub fn get_instance_count() -> i32 {
        *G_NUM.lock().unwrap()
    }

    fn increment_instance_count() {
        *G_NUM.lock().unwrap() += 1;
    }

    fn decrement_instance_count() {
        *G_NUM.lock().unwrap() -= 1;
    }
}

impl Drop for MyBinderRpcSession {
    fn drop(&mut self) {
        MyBinderRpcSession::decrement_instance_count();
    }
}

impl Interface for MyBinderRpcSession {}

impl IBinderRpcSession for MyBinderRpcSession {
    fn getName(&self) -> Result<String, Status> {
        Ok(self.name.clone())
    }
}

impl IBinderRpcTest for MyBinderRpcSession {
    fn sendString(&self, _: &str) -> Result<(), Status> {
        todo!()
    }
    fn doubleString(&self, _s: &str) -> Result<String, Status> {
        todo!()
    }
    fn getClientPort(&self) -> Result<i32, Status> {
        todo!()
    }
    fn countBinders(&self) -> Result<Vec<i32>, Status> {
        todo!()
    }
    fn getNullBinder(&self) -> Result<SpIBinder, Status> {
        todo!()
    }
    fn pingMe(&self, _binder: &SpIBinder) -> Result<i32, Status> {
        todo!()
    }
    fn repeatBinder(&self, _binder: Option<&SpIBinder>) -> Result<Option<SpIBinder>, Status> {
        todo!()
    }
    fn holdBinder(&self, _binder: Option<&SpIBinder>) -> Result<(), Status> {
        todo!()
    }
    fn getHeldBinder(&self) -> Result<Option<SpIBinder>, Status> {
        todo!()
    }
    fn nestMe(
        &self,
        binder: &Strong<(dyn IBinderRpcTest + 'static)>,
        count: i32,
    ) -> Result<(), Status> {
        if count < 0 {
            Ok(())
        } else {
            binder.nestMe(binder, count - 1)
        }
    }
    fn alwaysGiveMeTheSameBinder(&self) -> Result<SpIBinder, Status> {
        todo!()
    }
    fn openSession(
        &self,
        _name: &str,
    ) -> Result<Strong<(dyn IBinderRpcSession + 'static)>, Status> {
        todo!()
    }
    fn getNumOpenSessions(&self) -> Result<i32, Status> {
        todo!()
    }
    fn lock(&self) -> Result<(), Status> {
        todo!()
    }
    fn unlockInMsAsync(&self, _: i32) -> Result<(), Status> {
        todo!()
    }
    fn lockUnlock(&self) -> Result<(), Status> {
        todo!()
    }
    fn sleepMs(&self, _: i32) -> Result<(), Status> {
        todo!()
    }
    fn sleepMsAsync(&self, _: i32) -> Result<(), Status> {
        todo!()
    }
    fn doCallback(
        &self,
        _: &Strong<(dyn IBinderRpcCallback + 'static)>,
        _: bool,
        _: bool,
        _: &str,
    ) -> Result<(), Status> {
        todo!()
    }
    fn doCallbackAsync(
        &self,
        _: &Strong<(dyn IBinderRpcCallback + 'static)>,
        _: bool,
        _: bool,
        _: &str,
    ) -> Result<(), Status> {
        todo!()
    }
    fn die(&self, _: bool) -> Result<(), Status> {
        Err(Status::from(StatusCode::UNKNOWN_TRANSACTION))
    }
    fn scheduleShutdown(&self) -> Result<(), Status> {
        todo!()
    }
    fn useKernelBinderCallingId(&self) -> Result<(), Status> {
        todo!()
    }
    fn echoAsFile(&self, _: &str) -> Result<ParcelFileDescriptor, Status> {
        todo!()
    }
    fn concatFiles(&self, _: &[ParcelFileDescriptor]) -> Result<ParcelFileDescriptor, Status> {
        todo!()
    }
    fn blockingSendFdOneway(&self, _: &ParcelFileDescriptor) -> Result<(), Status> {
        todo!()
    }
    fn blockingRecvFd(&self) -> Result<ParcelFileDescriptor, Status> {
        todo!()
    }
    fn blockingSendIntOneway(&self, _: i32) -> Result<(), Status> {
        todo!()
    }
    fn blockingRecvInt(&self) -> Result<i32, Status> {
        todo!()
    }
}
