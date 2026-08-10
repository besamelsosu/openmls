//! C ABI for the dynamic library build.
//!
//! Strings returned by this API contain JSON and must be released with
//! [`openmls_cli_string_free`]. A successful response has the shape
//! `{"ok":true,"value":...}`; failures are `{"ok":false,"error":"..."}`.

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};

use serde::Serialize;
use serde_json::{json, Value};

use crate::Client;

fn response<T: Serialize>(result: Result<T, String>) -> *mut c_char {
    let value = match result {
        Ok(value) => json!({ "ok": true, "value": value }),
        Err(error) => json!({ "ok": false, "error": error }),
    };
    CString::new(value.to_string()).unwrap().into_raw()
}

unsafe fn text(ptr: *const c_char, name: &str) -> Result<String, String> {
    if ptr.is_null() {
        return Err(format!("{name} must not be null"));
    }
    // SAFETY: The caller promises a valid, NUL-terminated string for every
    // input pointer, as required by this C API.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| format!("{name} must be valid UTF-8"))
}

unsafe fn call<T: Serialize>(
    client: *mut Client,
    operation: impl FnOnce(&mut Client) -> Result<T, String>,
) -> *mut c_char {
    if client.is_null() {
        return response::<Value>(Err("client must not be null".to_string()));
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: Handles originate from openmls_cli_new and the caller must
        // serialize access to each handle and not use it after free.
        operation(unsafe { &mut *client })
    }))
    .unwrap_or_else(|_| Err("OpenMLS operation panicked".to_string()));
    response(result)
}

/// Allocate an empty client handle.
#[no_mangle]
pub extern "C" fn openmls_cli_new() -> *mut Client {
    Box::into_raw(Box::new(Client::new()))
}

/// Release a client handle. Passing null is allowed.
///
/// # Safety
/// `client` must have been returned by [`openmls_cli_new`] and not previously freed.
#[no_mangle]
pub unsafe extern "C" fn openmls_cli_free(client: *mut Client) {
    if !client.is_null() {
        // SAFETY: Guaranteed by the function contract.
        drop(unsafe { Box::from_raw(client) });
    }
}

/// Release a response returned by this API. Passing null is allowed.
///
/// # Safety
/// `value` must be a pointer returned by this API and not previously freed.
#[no_mangle]
pub unsafe extern "C" fn openmls_cli_string_free(value: *mut c_char) {
    if !value.is_null() {
        // SAFETY: Guaranteed by the function contract.
        drop(unsafe { CString::from_raw(value) });
    }
}

macro_rules! name_operation {
    ($fn_name:ident, $method:ident) => {
        #[no_mangle]
        pub unsafe extern "C" fn $fn_name(client: *mut Client, name: *const c_char) -> *mut c_char {
            let name = match unsafe { text(name, "name") } {
                Ok(name) => name,
                Err(error) => return response::<Value>(Err(error)),
            };
            unsafe { call(client, |client| client.$method(name)) }
        }
    };
}

name_operation!(openmls_cli_register, register);
name_operation!(openmls_cli_load, load);

#[no_mangle]
pub unsafe extern "C" fn openmls_cli_create_key_package(client: *mut Client) -> *mut c_char {
    unsafe { call(client, Client::create_key_package) }
}

#[no_mangle]
pub unsafe extern "C" fn openmls_cli_create_group(client: *mut Client) -> *mut c_char {
    unsafe { call(client, Client::create_group) }
}

#[no_mangle]
pub unsafe extern "C" fn openmls_cli_update(client: *mut Client) -> *mut c_char {
    unsafe { call(client, |client| client.update(None)) }
}

#[no_mangle]
pub unsafe extern "C" fn openmls_cli_info(client: *mut Client) -> *mut c_char {
    unsafe { call(client, |client| client.info()) }
}

macro_rules! group_operation {
    ($fn_name:ident, $method:ident) => {
        #[no_mangle]
        pub unsafe extern "C" fn $fn_name(
            client: *mut Client,
            group: *const c_char,
        ) -> *mut c_char {
            let group = match unsafe { text(group, "group") } {
                Ok(group) => group,
                Err(error) => return response::<Value>(Err(error)),
            };
            unsafe { call(client, |client| client.$method(group)) }
        }
    };
}

group_operation!(openmls_cli_leave, leave);
group_operation!(openmls_cli_self_update, self_update);
group_operation!(openmls_cli_read, read);

#[no_mangle]
pub unsafe extern "C" fn openmls_cli_update_group(
    client: *mut Client,
    group: *const c_char,
) -> *mut c_char {
    let group = match unsafe { text(group, "group") } {
        Ok(group) => group,
        Err(error) => return response::<Value>(Err(error)),
    };
    unsafe { call(client, |client| client.update(Some(group))) }
}

#[no_mangle]
pub unsafe extern "C" fn openmls_cli_group_info(
    client: *mut Client,
    group: *const c_char,
) -> *mut c_char {
    let group = match unsafe { text(group, "group") } {
        Ok(group) => group,
        Err(error) => return response::<Value>(Err(error)),
    };
    unsafe { call(client, |client| client.group_info(&group)) }
}

#[no_mangle]
pub unsafe extern "C" fn openmls_cli_resolve_group(
    client: *mut Client,
    prefix: *const c_char,
) -> *mut c_char {
    let prefix = match unsafe { text(prefix, "prefix") } {
        Ok(prefix) => prefix,
        Err(error) => return response::<Value>(Err(error)),
    };
    unsafe { call(client, |client| client.resolve_group(&prefix)) }
}

macro_rules! group_user_operation {
    ($fn_name:ident, $method:ident) => {
        #[no_mangle]
        pub unsafe extern "C" fn $fn_name(
            client: *mut Client,
            group: *const c_char,
            user: *const c_char,
        ) -> *mut c_char {
            let group = match unsafe { text(group, "group") } {
                Ok(value) => value,
                Err(error) => return response::<Value>(Err(error)),
            };
            let user = match unsafe { text(user, "user") } {
                Ok(value) => value,
                Err(error) => return response::<Value>(Err(error)),
            };
            unsafe { call(client, |client| client.$method(group, user)) }
        }
    };
}

group_user_operation!(openmls_cli_invite, invite);
group_user_operation!(openmls_cli_remove, remove);
group_user_operation!(openmls_cli_promote, promote);
group_user_operation!(openmls_cli_demote, demote);

#[no_mangle]
pub unsafe extern "C" fn openmls_cli_send(
    client: *mut Client,
    group: *const c_char,
    message: *const c_char,
) -> *mut c_char {
    let group = match unsafe { text(group, "group") } {
        Ok(value) => value,
        Err(error) => return response::<Value>(Err(error)),
    };
    let message = match unsafe { text(message, "message") } {
        Ok(value) => value,
        Err(error) => return response::<Value>(Err(error)),
    };
    unsafe { call(client, |client| client.send(group, &message)) }
}

#[no_mangle]
pub unsafe extern "C" fn openmls_cli_reset(client: *mut Client) -> *mut c_char {
    unsafe {
        call(client, |client| {
            client.reset();
            Ok(())
        })
    }
}
