#[cfg(feature = "log")]
use log::{debug, info};

use crate::{
    allocators::{self, Allocator},
    error::MappingError,
    loader::{self, DllInformation},
    parser,
    resolvers::{self, Resolver},
};

pub struct Library<
    A: Allocator = allocators::DefaultAllocator,
    R: Resolver = resolvers::DefaultResolver,
> {
    pub base_address: Option<usize>,
    allocator: A,
    resolver: R,
    data: Option<Vec<u8>>,
}

impl Library {
    pub fn from(data: &[u8]) -> Self {
        Self {
            base_address: None,
            allocator: allocators::DefaultAllocator {},
            resolver: resolvers::DefaultResolver {},
            data: Some(data.to_owned()),
        }
    }
}

impl<A: Allocator> Library<A> {
    pub fn from_with_allocator(data: &[u8], allocator: A) -> Self {
        Self {
            base_address: None,
            allocator: allocator,
            resolver: resolvers::DefaultResolver {},
            data: Some(data.to_owned()),
        }
    }
}

// Construction
impl<A: Allocator, R: Resolver> Library<A, R> {
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

        let (base_address, allocation_size) = self
            .allocator
            .allocate(dll.image_base)
            .ok_or(MappingError::AllocatorFailure)?;

        #[cfg(feature = "log")]
        info!(
            "Beginning to map library with size {:#X} at offset {:#X}",
            allocation_size, base_address
        );

        self.base_address = Some(base_address);
        Self::internal_map(base_address, allocation_size, dll, data)?;
        Ok(self)
    }
}

// Usage
impl<A: Allocator, R: Resolver> Library<A, R> {
    pub fn function<T>(&self, name: &str) -> Option<T> {
        if let Some(addr) = self.base_address {
            let fn_ptr = self.resolver.resolve(addr, name);
            unsafe {
                return fn_ptr.map(|address| std::mem::transmute_copy(&address));
            }
        }
        None
    }
}
