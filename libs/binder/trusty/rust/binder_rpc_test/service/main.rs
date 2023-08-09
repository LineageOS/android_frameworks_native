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

use binder::{BinderFeatures, Interface, ParcelFileDescriptor, SpIBinder, Status, Strong};
use binder_rpc_test_aidl::aidl::IBinderRpcCallback::IBinderRpcCallback;
use binder_rpc_test_aidl::aidl::IBinderRpcSession::IBinderRpcSession;
use binder_rpc_test_aidl::aidl::IBinderRpcTest::{BnBinderRpcTest, IBinderRpcTest};
use rpcbinder::RpcServer;
use std::rc::Rc;
use tipc::{service_dispatcher, wrap_service, Manager, PortCfg};

const RUST_SERVICE_PORT: &str = "com.android.trusty.rust.binderRpcTestService.V1";

#[derive(Debug, Default)]
struct TestService;

impl Interface for TestService {}

impl IBinderRpcTest for TestService {
    fn sendString(&self, _: &str) -> Result<(), Status> {
        todo!()
    }
    fn doubleString(&self, _: &str) -> Result<String, Status> {
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
    fn pingMe(&self, _: &SpIBinder) -> Result<i32, Status> {
        todo!()
    }
    fn repeatBinder(&self, _: Option<&SpIBinder>) -> Result<Option<SpIBinder>, Status> {
        todo!()
    }
    fn holdBinder(&self, _: Option<&SpIBinder>) -> Result<(), Status> {
        todo!()
    }
    fn getHeldBinder(&self) -> Result<Option<SpIBinder>, Status> {
        todo!()
    }
    fn nestMe(&self, _: &Strong<(dyn IBinderRpcTest + 'static)>, _: i32) -> Result<(), Status> {
        todo!()
    }
    fn alwaysGiveMeTheSameBinder(&self) -> Result<SpIBinder, Status> {
        todo!()
    }
    fn openSession(&self, _: &str) -> Result<Strong<(dyn IBinderRpcSession + 'static)>, Status> {
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
        todo!()
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

wrap_service!(TestRpcServer(RpcServer: UnbufferedService));

service_dispatcher! {
    enum TestDispatcher {
        TestRpcServer,
    }
}

fn main() {
    let mut dispatcher = TestDispatcher::<1>::new().expect("Could not create test dispatcher");

    let service = BnBinderRpcTest::new_binder(TestService::default(), BinderFeatures::default());
    let rpc_server =
        TestRpcServer::new(RpcServer::new_per_session(move |_uuid| Some(service.as_binder())));

    let cfg = PortCfg::new(RUST_SERVICE_PORT)
        .expect("Could not create port config")
        .allow_ta_connect()
        .allow_ns_connect();
    dispatcher.add_service(Rc::new(rpc_server), cfg).expect("Could not add service to dispatcher");

    Manager::<_, _, 1, 4>::new_with_dispatcher(dispatcher, [])
        .expect("Could not create service manager")
        .run_event_loop()
        .expect("Test event loop failed");
}
