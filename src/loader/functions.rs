#![allow(unused_unsafe)]
use std::ffi::CStr;

#[cfg(feature = "log")]
use log::debug;

macro_rules! ptr_at {
    ($base:expr, $rva:expr) => {
        unsafe { ($base as *const u8).add($rva as usize).cast() }
    };
}

macro_rules! deref {
    ($base:expr) => {
        unsafe { &*$base }
    };
}

#[repr(C, packed(2))]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
pub struct ImageNtHeaders {
    pub signature: u32,
    pub file_header: [u8; 20],
    pub optional_header: ImageOptionalHeader,
}

#[repr(C, packed(4))]
pub struct ImageOptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
#[derive(Debug)]
pub struct ImageExportDirectory {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

fn fetch_module_functions(
    base_address: *mut u8,
    image_export_dir: &ImageExportDirectory,
    target: &str,
) -> Option<*const u8> {
    // Set up required offsets
    let function_name_offset: *const u32 = ptr_at!(base_address, image_export_dir.address_of_names);
    let function_ordinal_offset: *const u16 =
        ptr_at!(base_address, image_export_dir.address_of_name_ordinals);

    let function_address_offset: *const u32 =
        ptr_at!(base_address, image_export_dir.address_of_functions);

    for idx in 0..image_export_dir.number_of_names {
        // Math is the [function_name_offset] where we move by size_of<function_name_offset> * n
        let c_str = unsafe {
            CStr::from_ptr(ptr_at!(
                base_address,
                *function_name_offset.add(idx as usize)
            ))
        };
        let Ok(name) = c_str.to_str() else { continue };

        // Match the name to a function
        let function_address: *const u8 = {
            let function_index = deref!(function_ordinal_offset.add(idx as usize));
            let function_rva =
                *deref!(function_address_offset.byte_offset((function_index * 4) as isize));

            ptr_at!(base_address, function_rva)
        };

        if name == target {
            #[cfg(feature = "log")]
            debug!("Found function at {:#X}", function_address as usize);
            return Some(function_address);
        }
    }
    None
}

pub(crate) fn find_function(module_base_address: usize, name: &str) -> Option<*const u8> {
    let dos_header = module_base_address as *const ImageDosHeader;
    let e_lfanew = deref!(dos_header).e_lfanew;

    // Offset with the RVA as the e_lfanew is image offset
    let nt_headers: *const ImageNtHeaders = ptr_at!(module_base_address, e_lfanew);
    let optional_header = &deref!(nt_headers).optional_header;

    // Calculate the Export directory RVA
    let export_dir_entry: &ImageDataDirectory = &optional_header.data_directory[0];
    let export_rva = export_dir_entry.virtual_address;

    // No exports available
    if export_rva == 0 {
        return None;
    }

    let export_ptr: *const ImageExportDirectory = ptr_at!(module_base_address, export_rva);
    let image_export_dir: &ImageExportDirectory = deref!(export_ptr);

    return fetch_module_functions(module_base_address as *mut u8, image_export_dir, name);
}
