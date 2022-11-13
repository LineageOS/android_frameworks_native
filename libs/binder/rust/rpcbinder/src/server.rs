/*
 * Copyright (C) 2022 The Android Open Source Project
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

use binder::{
    unstable_api::{AIBinder, AsNative},
    SpIBinder,
};
use std::{ffi::CString, os::raw, ptr::null_mut};

/// Runs a binder RPC server, serving the supplied binder service implementation on the given vsock
/// port.
///
/// If and when the server is ready for connections (it is listening on the port), `on_ready` is
/// called to allow appropriate action to be taken - e.g. to notify clients that they may now
/// attempt to connect.
///
/// The current thread is joined to the binder thread pool to handle incoming messages.
///
/// Returns true if the server has shutdown normally, false if it failed in some way.
pub fn run_vsock_rpc_server<F>(service: SpIBinder, port: u32, on_ready: F) -> bool
where
    F: FnOnce(),
{
    let mut ready_notifier = ReadyNotifier(Some(on_ready));
    ready_notifier.run_vsock_server(service, port)
}

/// Runs a binder RPC server, serving the supplied binder service implementation on the given
/// socket file name. The socket should be initialized in init.rc with the same name.
///
/// If and when the server is ready for connections, `on_ready` is called to allow appropriate
/// action to be taken - e.g. to notify clients that they may now attempt to connect.
///
/// The current thread is joined to the binder thread pool to handle incoming messages.
///
/// Returns true if the server has shutdown normally, false if it failed in some way.
pub fn run_init_unix_domain_rpc_server<F>(
    service: SpIBinder,
    socket_name: &str,
    on_ready: F,
) -> bool
where
    F: FnOnce(),
{
    let mut ready_notifier = ReadyNotifier(Some(on_ready));
    ready_notifier.run_init_unix_domain_server(service, socket_name)
}

struct ReadyNotifier<F>(Option<F>)
where
    F: FnOnce();

impl<F> ReadyNotifier<F>
where
    F: FnOnce(),
{
    fn run_vsock_server(&mut self, mut service: SpIBinder, port: u32) -> bool {
        let service = service.as_native_mut();
        let param = self.as_void_ptr();

        // SAFETY: Service ownership is transferring to the server and won't be valid afterward.
        // Plus the binder objects are threadsafe.
        // RunVsockRpcServerCallback does not retain a reference to `ready_callback` or `param`; it only
        // uses them before it returns, which is during the lifetime of `self`.
        unsafe {
            binder_rpc_unstable_bindgen::RunVsockRpcServerCallback(
                service,
                port,
                Some(Self::ready_callback),
                param,
            )
        }
    }

    fn run_init_unix_domain_server(&mut self, mut service: SpIBinder, socket_name: &str) -> bool {
        let socket_name = match CString::new(socket_name) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Cannot convert {} to CString. Error: {:?}", socket_name, e);
                return false;
            }
        };
        let service = service.as_native_mut();
        let param = self.as_void_ptr();

        // SAFETY: Service ownership is transferring to the server and won't be valid afterward.
        // Plus the binder objects are threadsafe.
        // RunInitUnixDomainRpcServer does not retain a reference to `ready_callback` or `param`;
        // it only uses them before it returns, which is during the lifetime of `self`.
        unsafe {
            binder_rpc_unstable_bindgen::RunInitUnixDomainRpcServer(
                service,
                socket_name.as_ptr(),
                Some(Self::ready_callback),
                param,
            )
        }
    }

    fn as_void_ptr(&mut self) -> *mut raw::c_void {
        self as *mut _ as *mut raw::c_void
    }

    unsafe extern "C" fn ready_callback(param: *mut raw::c_void) {
        // SAFETY: This is only ever called by `RunVsockRpcServerCallback`, within the lifetime of the
        // `ReadyNotifier`, with `param` taking the value returned by `as_void_ptr` (so a properly
        // aligned non-null pointer to an initialized instance).
        let ready_notifier = param as *mut Self;
        ready_notifier.as_mut().unwrap().notify()
    }

    fn notify(&mut self) {
        if let Some(on_ready) = self.0.take() {
            on_ready();
        }
    }
}

type RpcServerFactoryRef<'a> = &'a mut (dyn FnMut(u32) -> Option<SpIBinder> + Send + Sync);

/// Runs a binder RPC server, using the given factory function to construct a binder service
/// implementation for each connection.
///
/// The current thread is joined to the binder thread pool to handle incoming messages.
///
/// Returns true if the server has shutdown normally, false if it failed in some way.
pub fn run_vsock_rpc_server_with_factory(
    port: u32,
    mut factory: impl FnMut(u32) -> Option<SpIBinder> + Send + Sync,
) -> bool {
    // Double reference the factory because trait objects aren't FFI safe.
    // NB: The type annotation is necessary to ensure that we have a `dyn` rather than an `impl`.
    let mut factory_ref: RpcServerFactoryRef = &mut factory;
    let context = &mut factory_ref as *mut RpcServerFactoryRef as *mut raw::c_void;

    // SAFETY: `factory_wrapper` is only ever called by `RunVsockRpcServerWithFactory`, with context
    // taking the pointer value above (so a properly aligned non-null pointer to an initialized
    // `RpcServerFactoryRef`), within the lifetime of `factory_ref` (i.e. no more calls will be made
    // after `RunVsockRpcServerWithFactory` returns).
    unsafe {
        binder_rpc_unstable_bindgen::RunVsockRpcServerWithFactory(
            Some(factory_wrapper),
            context,
            port,
        )
    }
}

unsafe extern "C" fn factory_wrapper(cid: u32, context: *mut raw::c_void) -> *mut AIBinder {
    // SAFETY: `context` was created from an `&mut RpcServerFactoryRef` by
    // `run_vsock_rpc_server_with_factory`, and we are still within the lifetime of the value it is
    // pointing to.
    let factory_ptr = context as *mut RpcServerFactoryRef;
    let factory = factory_ptr.as_mut().unwrap();

    if let Some(mut service) = factory(cid) {
        service.as_native_mut()
    } else {
        null_mut()
    }
}
