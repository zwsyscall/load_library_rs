use crate::loader::Section;
use std::ffi::c_void;
use std::ptr;

// Section types
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;

// Mem protection types
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_READONLY: u32 = 0x02;
const PAGE_NOACCESS: u32 = 0x01;

unsafe extern "system" {
    fn VirtualProtect(
        address: *const c_void,
        size: usize,
        new_protect: u32,
        old_protect: *mut u32,
    ) -> i32;
}

// todo: fix zeroing out based on charasteristics
// base addr is the start of the allocated buffer for the mapped DLL
pub fn map_section(base_addr: usize, section: &Section, bytes: &[u8]) {
    let target_addr = base_addr + section.virtual_address;

    unsafe {
        if section.size_of_raw_data > 0 {
            ptr::copy_nonoverlapping(
                bytes.as_ptr().add(section.pointer_to_raw_data),
                target_addr as _,
                section.size_of_raw_data,
            )
        }

        // Zero out the rest of the section in case we are hollowing out another DLL
        if section.size_of_raw_data < section.virtual_size {
            ptr::write_bytes(
                (target_addr + section.size_of_raw_data) as *mut u8,
                0,
                section.virtual_size - section.size_of_raw_data,
            )
        }
    }
}

pub fn map_headers(base_addr: usize, size_of_headers: usize, data: &[u8]) {
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), base_addr as *mut u8, size_of_headers);
    }
}

pub fn apply_characteristics(base_addr: usize, section: &Section) {
    let protections = get_mem_protections(section.characteristics);
    let section_destination = base_addr + section.virtual_address;
    let mut _old_protect: u32 = 0;

    unsafe {
        if VirtualProtect(
            section_destination as *const c_void,
            section.virtual_size,
            protections,
            &mut _old_protect as *mut _,
        ) != 1
        {
            panic!("VirtualProtect failed!")
        }
    }
}

fn get_mem_protections(characteristics: u32) -> u32 {
    let r = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    let w = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    let x = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;

    match (r, w, x) {
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (true, false, true) => PAGE_EXECUTE_READ,
        (false, false, true) => PAGE_EXECUTE,
        (true, true, false) => PAGE_READWRITE,
        (true, false, false) => PAGE_READONLY,
        _ => PAGE_NOACCESS,
    }
}
