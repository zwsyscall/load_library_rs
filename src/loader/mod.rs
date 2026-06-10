pub(crate) mod execute;
pub(crate) mod iat;
pub(crate) mod mmap;
pub(crate) mod reloc;

pub struct DllInformation {
    pub image_base: usize,
    pub entry_point_rva: u32,
    pub size_of_image: usize,
    pub size_of_headers: usize,
    pub sections: Vec<Section>,
    pub tls_callbacks: Option<DataDirectory>,
    // The Virtual Address and Size of the Import Directory
    pub import_dir: Option<DataDirectory>,
    // The Virtual Address and Size of the Base Relocation Table
    pub reloc_dir: Option<DataDirectory>,
}

pub struct DataDirectory {
    pub virtual_address: usize,
    pub size: usize,
}

pub struct Section {
    pub name: String,
    pub virtual_size: usize,
    pub virtual_address: usize,
    pub size_of_raw_data: usize,
    pub pointer_to_raw_data: usize,
    pub characteristics: u32,
}

impl std::fmt::Display for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} | 0x{:x} 0x{:x}",
            self.name, self.virtual_address, self.virtual_size
        )
    }
}
