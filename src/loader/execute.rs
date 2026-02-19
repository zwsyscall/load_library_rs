use crate::loader::DataDirectory;
use std::{ffi::c_void, ptr::null_mut};

#[repr(C)]
pub struct ImageTlsDirectory {
    pub start_address_of_raw_data: u64,
    pub end_address_of_raw_data: u64,
    pub address_of_index: u64,
    pub address_of_call_backs: u64,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
}

type DllMain = unsafe extern "system" fn(
    hinst_dll: *mut c_void,
    fdw_reason: u32,
    lpv_reserved: *mut c_void,
) -> i32;

type TlsCallback =
    unsafe extern "system" fn(hinst_dll: *mut c_void, fdw_reason: u32, lpv_reserved: *mut c_void);

pub fn run_dll_main(base_addr: usize, entry_point: usize) -> i32 {
    unsafe {
        let dll_main: DllMain = std::mem::transmute(base_addr + entry_point as usize);
        dll_main(base_addr as *mut c_void, 1, null_mut())
    }
}

pub fn tls_callbacks(base_addr: usize, tls_directory_info: &DataDirectory) {
    let tls_directory = unsafe {
        let dir_ptr =
            (base_addr + tls_directory_info.virtual_address as usize) as *const ImageTlsDirectory;
        if dir_ptr.is_null() {
            return;
        }
        &*dir_ptr
    };

    if tls_directory.address_of_call_backs == 0 {
        return;
    }

    let mut callback_ptr = (tls_directory.address_of_call_backs as usize) as *const usize;

    unsafe {
        while *callback_ptr != 0 {
            let callback: TlsCallback = std::mem::transmute(*callback_ptr);
            callback(base_addr as *mut c_void, 1, std::ptr::null_mut());
            callback_ptr = callback_ptr.add(1);
        }
    }
}
