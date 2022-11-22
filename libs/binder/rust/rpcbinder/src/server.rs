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
use binder_rpc_unstable_bindgen::ARpcServer;
use foreign_types::{foreign_type, ForeignType, ForeignTypeRef};
use std::io::{Error, ErrorKind};
use std::{ffi::CString, os::raw, ptr::null_mut};

foreign_type! {
    type CType = binder_rpc_unstable_bindgen::ARpcServer;
    fn drop = binder_rpc_unstable_bindgen::ARpcServer_free;

    /// A type that represents a foreign instance of RpcServer.
    #[derive(Debug)]
    pub struct RpcServer;
    /// A borrowed RpcServer.
    pub struct RpcServerRef;
}

/// SAFETY - The opaque handle can be cloned freely.
unsafe impl Send for RpcServer {}
/// SAFETY - The underlying C++ RpcServer class is thread-safe.
unsafe impl Sync for RpcServer {}

impl RpcServer {
    /// Creates a binder RPC server, serving the supplied binder service implementation on the given
    /// vsock port. Only connections from the given CID are accepted.
    ///
    // Set `cid` to libc::VMADDR_CID_ANY to accept connections from any client.
    // Set `cid` to libc::VMADDR_CID_LOCAL to only bind to the local vsock interface.
    pub fn new_vsock(mut service: SpIBinder, cid: u32, port: u32) -> Result<RpcServer, Error> {
        let service = service.as_native_mut();

        // SAFETY: Service ownership is transferring to the server and won't be valid afterward.
        // Plus the binder objects are threadsafe.
        unsafe {
            Self::checked_from_ptr(binder_rpc_unstable_bindgen::ARpcServer_newVsock(
                service, cid, port,
            ))
        }
    }

    /// Creates a binder RPC server, serving the supplied binder service implementation on the given
    /// socket file name. The socket should be initialized in init.rc with the same name.
    pub fn new_init_unix_domain(
        mut service: SpIBinder,
        socket_name: &str,
    ) -> Result<RpcServer, Error> {
        let socket_name = match CString::new(socket_name) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Cannot convert {} to CString. Error: {:?}", socket_name, e);
                return Err(Error::from(ErrorKind::InvalidInput));
            }
        };
        let service = service.as_native_mut();

        // SAFETY: Service ownership is transferring to the server and won't be valid afterward.
        // Plus the binder objects are threadsafe.
        unsafe {
            Self::checked_from_ptr(binder_rpc_unstable_bindgen::ARpcServer_newInitUnixDomain(
                service,
                socket_name.as_ptr(),
            ))
        }
    }

    unsafe fn checked_from_ptr(ptr: *mut ARpcServer) -> Result<RpcServer, Error> {
        if ptr.is_null() {
            return Err(Error::new(ErrorKind::Other, "Failed to start server"));
        }
        Ok(RpcServer::from_ptr(ptr))
    }
}

impl RpcServerRef {
    /// Starts a new background thread and calls join(). Returns immediately.
    pub fn start(&self) {
        unsafe { binder_rpc_unstable_bindgen::ARpcServer_start(self.as_ptr()) };
    }

    /// Joins the RpcServer thread. The call blocks until the server terminates.
    /// This must be called from exactly one thread.
    pub fn join(&self) {
        unsafe { binder_rpc_unstable_bindgen::ARpcServer_join(self.as_ptr()) };
    }

    /// Shuts down the running RpcServer. Can be called multiple times and from
    /// multiple threads. Called automatically during drop().
    pub fn shutdown(&self) {
        unsafe { binder_rpc_unstable_bindgen::ARpcServer_shutdown(self.as_ptr()) };
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
