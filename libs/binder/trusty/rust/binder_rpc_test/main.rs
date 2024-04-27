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
#![cfg(test)]

use binder::{BinderFeatures, IBinder, Status, StatusCode, Strong};
use binder_rpc_test_aidl::aidl::IBinderRpcSession::{BnBinderRpcSession, IBinderRpcSession};
use binder_rpc_test_aidl::aidl::IBinderRpcTest::{BnBinderRpcTest, IBinderRpcTest};
use binder_rpc_test_session::MyBinderRpcSession;
use libc::{clock_gettime, CLOCK_REALTIME};
use rpcbinder::RpcSession;
use trusty_std::ffi::{CString, FallibleCString};

test::init!();

const SERVICE_PORT: &str = "com.android.trusty.binderRpcTestService.V1";
const RUST_SERVICE_PORT: &str = "com.android.trusty.rust.binderRpcTestService.V1";

macro_rules! service_test {
    ($c_name:ident, $rust_name:ident, $body:expr) => {
        #[test]
        fn $c_name() {
            $body(get_service(SERVICE_PORT))
        }
        #[test]
        fn $rust_name() {
            $body(get_service(RUST_SERVICE_PORT))
        }
    };
}

fn get_service(port: &str) -> Strong<dyn IBinderRpcTest> {
    let port = CString::try_new(port).expect("Failed to allocate port name");
    RpcSession::new().setup_trusty_client(port.as_c_str()).expect("Failed to create session")
}

fn expect_sessions(expected: i32, srv: &Strong<dyn IBinderRpcTest>) {
    let count = srv.getNumOpenSessions();
    assert!(count.is_ok());
    assert_eq!(expected, count.unwrap());
}

fn get_time_ns() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };

    // Safety: Passing valid pointer to variable ts which lives past end of call
    assert_eq!(unsafe { clock_gettime(CLOCK_REALTIME, &mut ts) }, 0);

    ts.tv_sec as u64 * 1_000_000_000u64 + ts.tv_nsec as u64
}

fn get_time_ms() -> u64 {
    get_time_ns() / 1_000_000u64
}

// ----------

service_test! {ping, ping_rust, |srv: Strong<dyn IBinderRpcTest>| {
    assert_eq!(srv.as_binder().ping_binder(), Ok(()));
}}

service_test! {send_something_oneway, send_something_oneway_rust, |srv: Strong<dyn IBinderRpcTest>| {
    assert_eq!(srv.sendString("Foo"), Ok(()));
}}

service_test! {send_and_get_result_back, send_and_get_result_back_rust, |srv: Strong<dyn IBinderRpcTest>| {
    assert_eq!(srv.doubleString("Foo"), Ok(String::from("FooFoo")));
}}

service_test! {send_and_get_result_back_big, send_and_get_result_back_big_rust, |srv: Strong<dyn IBinderRpcTest>| {
    let single_len = 512;
    let single = "a".repeat(single_len);
    assert_eq!(srv.doubleString(&single), Ok(String::from(single.clone() + &single)));
}}

service_test! {invalid_null_binder_return, invalid_null_binder_return_rust, |srv: Strong<dyn IBinderRpcTest>| {
    let binder = srv.getNullBinder();
    assert!(binder == Err(Status::from(StatusCode::UNEXPECTED_NULL)) || binder == Err(Status::from(StatusCode::UNKNOWN_TRANSACTION)));
}}

service_test! {call_me_back, call_me_back_rust, |srv: Strong<dyn IBinderRpcTest>| {
    let binder =
        BnBinderRpcSession::new_binder(MyBinderRpcSession::new("Foo"), BinderFeatures::default())
            .as_binder();
    let result = srv.pingMe(&binder);
    assert_eq!(result, Ok(0));
}}

service_test! {repeat_binder, repeat_binder_rust, |srv: Strong<dyn IBinderRpcTest>| {
    let in_binder =
        BnBinderRpcSession::new_binder(MyBinderRpcSession::new("Foo"), BinderFeatures::default())
            .as_binder();
    let result = srv.repeatBinder(Some(&in_binder));
    assert_eq!(result.unwrap().unwrap(), in_binder);
}}

service_test! {repeat_their_binder, repeat_their_binder_rust, |srv: Strong<dyn IBinderRpcTest>| {
    let session = srv.openSession("Test");
    assert!(session.is_ok());

    let in_binder = session.unwrap().as_binder();
    let out_binder = srv.repeatBinder(Some(&in_binder));
    assert_eq!(out_binder.unwrap().unwrap(), in_binder);
}}

service_test! {hold_binder, hold_binder_rust, |srv: Strong<dyn IBinderRpcTest>| {
    let name = "Foo";

    let binder =
        BnBinderRpcSession::new_binder(MyBinderRpcSession::new(name), BinderFeatures::default())
            .as_binder();
    assert!(srv.holdBinder(Some(&binder)).is_ok());

    let held = srv.getHeldBinder();
    assert!(held.is_ok());
    let held = held.unwrap();
    assert!(held.is_some());
    let held = held.unwrap();
    assert_eq!(binder, held);

    let session = held.into_interface::<dyn IBinderRpcSession>();
    assert!(session.is_ok());

    let session_name = session.unwrap().getName();
    assert!(session_name.is_ok());
    let session_name = session_name.unwrap();
    assert_eq!(session_name, name);

    assert!(srv.holdBinder(None).is_ok());
}}

service_test! {nested_transactions, nested_transactions_rust, |srv: Strong<dyn IBinderRpcTest>| {
    let binder =
        BnBinderRpcTest::new_binder(MyBinderRpcSession::new("Nest"), BinderFeatures::default());
    assert!(srv.nestMe(&binder, 10).is_ok());
}}

service_test! {same_binder_equality, same_binder_equality_rust, |srv: Strong<dyn IBinderRpcTest>| {
    let a = srv.alwaysGiveMeTheSameBinder();
    assert!(a.is_ok());

    let b = srv.alwaysGiveMeTheSameBinder();
    assert!(b.is_ok());

    assert_eq!(a.unwrap(), b.unwrap());
}}

service_test! {single_session, single_session_rust, |srv: Strong<dyn IBinderRpcTest>| {
    let session = srv.openSession("aoeu");
    assert!(session.is_ok());
    let session = session.unwrap();
    let name = session.getName();
    assert!(name.is_ok());
    assert_eq!(name.unwrap(), "aoeu");

    let count = srv.getNumOpenSessions();
    assert!(count.is_ok());
    assert_eq!(count.unwrap(), 1);

    drop(session);
    let count = srv.getNumOpenSessions();
    assert!(count.is_ok());
    assert_eq!(count.unwrap(), 0);
}}

service_test! {many_session, many_session_rust, |srv: Strong<dyn IBinderRpcTest>| {
    let mut sessions = Vec::new();

    for i in 0..15 {
        expect_sessions(i, &srv);

        let session = srv.openSession(&(i.to_string()));
        assert!(session.is_ok());
        sessions.push(session.unwrap());
    }

    expect_sessions(sessions.len() as i32, &srv);

    for i in 0..sessions.len() {
        let name = sessions[i].getName();
        assert!(name.is_ok());
        assert_eq!(name.unwrap(), i.to_string());
    }

    expect_sessions(sessions.len() as i32, &srv);

    while !sessions.is_empty() {
        sessions.pop();

        expect_sessions(sessions.len() as i32, &srv);
    }

    expect_sessions(0, &srv);
}}

service_test! {one_way_call_does_not_wait, one_way_call_does_not_wait_rust, |srv: Strong<dyn IBinderRpcTest>| {
    let really_long_time_ms = 100;
    let sleep_ms = really_long_time_ms * 5;

    let before = get_time_ms();
    let _ = srv.sleepMsAsync(sleep_ms);
    let after = get_time_ms();

    assert!(after < before + really_long_time_ms as u64);
}}
