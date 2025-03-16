// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::{
    ffi::{QUIC_API_TABLE, QUIC_STATUS},
    Status,
};
use std::sync::Once;

//
// APITABLE will be initialized via MsQuicOpenVersion() when we first initialize Api or Registration.
//
pub(crate) static mut APITABLE: *const QUIC_API_TABLE = std::ptr::null();
static START_MSQUIC: Once = Once::new();

/// Initializes the global static api table.
/// This is used in registration creation, or in user getting raw ffi.
pub(crate) fn once_init_api() {
    // initialization is done exactly once.
    unsafe {
        START_MSQUIC.call_once(|| {
            let mut table: *const QUIC_API_TABLE = std::ptr::null();
            let status = global_fn::MsQuicOpenVersion(2, std::ptr::addr_of_mut!(table));
            if let Err(err) = Status::ok_from_raw(status as QUIC_STATUS) {
                panic!("Failed to open MsQuic: {}", err);
            }
            APITABLE = table;
        });
    }
}

#[cfg(not(feature = "load"))]
mod global_fn {
    #[link(name = "msquic")]
    unsafe extern "C" {
        unsafe fn MsQuicOpenVersion(
            version: u32,
            api: *mut *const crate::ffi::QUIC_API_TABLE,
        ) -> u32;
        unsafe fn MsQuicClose(api: *const crate::ffi::QUIC_API_TABLE);
    }
}

#[allow(non_snake_case, static_mut_refs)]
#[cfg(feature = "load")]
mod global_fn {

    static LOAD_LIB_ONCE: std::sync::Once = std::sync::Once::new();

    /// Once lib is loaded it needs to be present for the entire lifetime
    /// of the process.
    static mut LIB: Option<libloading::Library> = None;

    pub(crate) unsafe fn MsQuicOpenVersion(
        version: u32,
        api: *mut *const crate::ffi::QUIC_API_TABLE,
    ) -> u32 {
        // load the lib
        init_global_once();
        // find the function and call it.
        let open_fn = load_fn::<
            unsafe extern "C" fn(version: u32, api: *mut *const crate::ffi::QUIC_API_TABLE) -> u32,
        >(LIB.as_ref().unwrap(), "MsQuicOpenVersion");
        open_fn(version, api)
    }
    pub(crate) unsafe fn MsQuicClose(api: *const crate::ffi::QUIC_API_TABLE) {
        // find the function and call it.
        // assumes global lib is already loaded.
        let close_fn = load_fn::<unsafe extern "C" fn(api: *const crate::ffi::QUIC_API_TABLE)>(
            LIB.as_ref().unwrap(),
            "MsQuicClose",
        );
        close_fn(api)
    }

    /// load the lib of a name.
    fn load_lib(name: &str) -> libloading::Library {
        unsafe { libloading::Library::new(libloading::library_filename(name)) }
            .unwrap_or_else(|e| panic!("cannot load lib {name} :{e}"))
    }

    /// load the function from lib.
    fn load_fn<T>(lib: &'static libloading::Library, name: &str) -> libloading::Symbol<'static, T> {
        unsafe { lib.get(name.as_bytes()) }.unwrap_or_else(|e| panic!("cannot load fn {name} :{e}"))
    }

    fn init_global_once() {
        LOAD_LIB_ONCE.call_once(|| {
            let lib = load_lib("msquic");
            unsafe { LIB = Some(lib) };
        });
    }

    /// unload the lib from the process.
    pub(crate) fn uninit_global() {
        // unsafe { LIB = None };
    }
}

#[ctor::dtor]
fn close_msquic() {
    unsafe {
        if !APITABLE.is_null() {
            global_fn::MsQuicClose(APITABLE);
            APITABLE = std::ptr::null();
        }
    }
    #[cfg(feature = "load")]
    global_fn::uninit_global();
}
