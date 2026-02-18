use crate::loader::DataDirectory;
use std::ffi::{CStr, c_void};

unsafe extern "system" {
    fn LoadLibraryA(name: *const i8) -> *const c_void;
    fn GetProcAddress(module: *const c_void, name: *const i8) -> *const c_void;
}

#[repr(C)]
pub struct ImageImportDescriptor {
    pub original_first_thunk: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
    pub name: u32, // RVA to the DLL name string (e.g., "KERNEL32.dll")
    pub first_thunk: u32,
}

#[repr(C)]
pub struct ImageImportByName {
    pub hint: u16,
    pub name: i8,
}

pub fn resolve_iat(base_addr: usize, import_dir: &DataDirectory) {
    let import_table_base = (base_addr + import_dir.virtual_address as usize) as *const u8;
    let mut descriptor_offset = 0;

    loop {
        unsafe {
            let descriptor_ptr =
                import_table_base.add(descriptor_offset) as *const ImageImportDescriptor;
            let descriptor = &*descriptor_ptr;

            // Check sentinel descriptor (EOL)
            if descriptor.name == 0 && descriptor.first_thunk == 0 {
                break;
            }

            let dll_name_ptr = CStr::from_ptr((base_addr + descriptor.name as usize) as _);
            println!("Importing {:#?}", &dll_name_ptr);

            // Using loadlibraryA here because of redirected imports (type beat)
            let l_handle = LoadLibraryA(dll_name_ptr.as_ptr());
            if l_handle.is_null() {
                panic!("Failed to load dependency library");
            }

            let mut thunk_rva = descriptor.original_first_thunk;
            if thunk_rva == 0 {
                thunk_rva = descriptor.first_thunk;
            }

            // We are checking what the IAT wants from the ILT and writing the target address to the IAT
            let mut ilt_ptr = (base_addr + thunk_rva as usize) as *const u64; // src
            let mut iat_ptr = (base_addr + descriptor.first_thunk as usize) as *mut u64; // dst

            loop {
                let thunk_val = *ilt_ptr;

                // EOL
                if thunk_val == 0 {
                    break;
                }

                let import_address: u64;
                let name: String;

                // Ordinal import
                match (thunk_val >> 63) & 0x1 {
                    0 => {
                        let name_struct_ptr =
                            (base_addr + thunk_val as usize) as *const ImageImportByName;

                        import_address =
                            GetProcAddress(l_handle, &((*name_struct_ptr).name) as _) as u64;
                        let name_data = CStr::from_ptr(&((*name_struct_ptr).name) as _);
                        name = name_data.to_str().unwrap().to_string();
                    }
                    _ => {
                        let ordinal = thunk_val & 0xFFFF;
                        import_address = GetProcAddress(l_handle, ordinal as *const i8) as u64;
                        name = format!("ordinal {}", ordinal);
                    }
                }

                if import_address == 0 {
                    panic!(
                        "Failed to resolve import: {}->{}",
                        dll_name_ptr.to_str().unwrap(),
                        name
                    );
                }

                // Finally write the function address to the IAT
                *iat_ptr = import_address;

                // Advance pointers for loop to continue
                ilt_ptr = ilt_ptr.add(1);
                iat_ptr = iat_ptr.add(1);
            }

            descriptor_offset += std::mem::size_of::<ImageImportDescriptor>();
        }
    }
}
