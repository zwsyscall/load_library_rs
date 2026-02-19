#[cfg(feature = "log")]
use log::{debug, info};
use std::{ffi::c_void, ptr::null_mut};

use crate::{
    error::MappingError,
    loader::{self, DllInformation},
    options::{Allocator, Resolver},
    parser,
};

unsafe extern "system" {
    fn VirtualAlloc(
        address: *mut std::ffi::c_void,
        size: usize,
        alloc_type: u32,
        protect_flags: u32,
    ) -> *const c_void;
}

pub struct Library {
    pub(crate) base_address: Option<usize>,
    allocator: Allocator,
    resolver: Resolver,
    data: Option<Vec<u8>>,
}

// Construction
impl Library {
    fn internal_map(
        base_addr: usize,
        allocated_region_size: usize,
        dll: DllInformation,
        data: &[u8],
    ) -> Result<(), MappingError> {
        // If there isn't enough space, error out
        if dll.size_of_image > allocated_region_size {
            return Err(MappingError::NotEnoughSpace);
        }

        // Early return if the passed address is 0
        if base_addr == 0 {
            return Err(MappingError::InvalidMappingAddress);
        }

        #[cfg(feature = "log")]
        debug!("Mapping {} sections", dll.sections.len());
        for section in &dll.sections {
            loader::mmap::map_section(base_addr, &section, &data);
        }

        #[cfg(feature = "log")]
        debug!("Fixing reloctions");
        if let Some(relocations) = &dll.reloc_dir {
            loader::reloc::fix_relocations(base_addr, &relocations, dll.image_base);
        }

        #[cfg(feature = "log")]
        debug!("Resolving IAT");
        if let Some(imports) = &dll.import_dir {
            loader::iat::resolve_iat(base_addr, &imports);
        }

        #[cfg(feature = "log")]
        debug!("Map headers");
        loader::mmap::map_headers(base_addr, dll.size_of_headers, &data);

        #[cfg(feature = "log")]
        debug!("Applying characteristics");
        for section in &dll.sections {
            loader::mmap::apply_characteristics(base_addr, section);
        }

        #[cfg(feature = "log")]
        debug!("Running TLS callbacks");
        if let Some(callbacks) = &dll.tls_callbacks {
            loader::execute::tls_callbacks(base_addr, callbacks);
        }

        #[cfg(feature = "log")]
        debug!("Running DllMain");
        loader::execute::run_dll_main(base_addr, dll.entry_point_rva as usize);

        Ok(())
    }

    pub fn map(mut self) -> Result<Self, MappingError> {
        let data = &self.data.take().ok_or(MappingError::MissingData)?;
        let dll = parser::parse_header(&data)?;

        let (base_address, allocation_size) = match self.allocator {
            Allocator::Native => unsafe {
                #[cfg(feature = "log")]
                debug!(
                    "Calling VirtualAlloc(0x0, {:#X}, {:#X}, {:#X});",
                    dll.size_of_image,
                    0x1000 | 0x2000,
                    0x04
                );

                let addr = VirtualAlloc(null_mut(), dll.size_of_image, 0x1000 | 0x2000, 0x04);
                if addr.is_null() {
                    return Err(MappingError::AllocatorFailure);
                }
                (addr as usize, dll.size_of_image)
            },
            Allocator::PreAllocated(address, size) => (address, size),
            Allocator::Custom(alloc) => {
                #[cfg(feature = "log")]
                debug!("Calling allocator for size {:#X}", dll.size_of_image);
                match alloc(dll.size_of_image) {
                    Some(addr) => (addr, dll.size_of_image),
                    None => return Err(MappingError::AllocatorFailure),
                }
            }
        };

        #[cfg(feature = "log")]
        info!(
            "Beginning to map library with size {:#X} at offset {:#X}",
            allocation_size, base_address
        );

        self.base_address = Some(base_address);
        Self::internal_map(base_address, allocation_size, dll, data)?;
        Ok(self)
    }

    pub fn from_file(path: &str) -> Result<Self, std::io::Error> {
        let data = std::fs::read(path)?;
        #[cfg(feature = "log")]
        info!("Read library file {}", path);

        Ok(Self {
            base_address: None,
            allocator: Allocator::default(),
            resolver: Resolver::default(),
            data: Some(data),
        })
    }

    pub fn from_raw<T: Into<Vec<u8>>>(bytes: T) -> Self {
        let data: Vec<u8> = bytes.into();
        Self {
            base_address: None,
            allocator: Allocator::default(),
            resolver: Resolver::default(),
            data: Some(data),
        }
    }

    pub fn allocator(mut self, alloc: Allocator) -> Self {
        self.allocator = alloc;
        self
    }

    pub fn function_resolver(mut self, resolver: Resolver) -> Self {
        self.resolver = resolver;
        self
    }
}

// Usage
impl Library {
    pub fn function<T>(&self, name: &str) -> Option<T> {
        if let Some(addr) = self.base_address {
            let fn_ptr = match self.resolver {
                Resolver::Native => loader::functions::find_function(addr, name),
                Resolver::Custom(resolv) => resolv(addr, name),
            };
            unsafe {
                return fn_ptr.map(|address| std::mem::transmute_copy(&address));
            }
        }
        None
    }
    pub fn find(&self, name: &str) -> Option<*const u8> {
        if let Some(addr) = self.base_address {
            return loader::functions::find_function(addr, name);
        }
        None
    }
}
