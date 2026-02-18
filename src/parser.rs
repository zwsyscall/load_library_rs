use goblin::pe::PE;

use crate::{
    error::MappingError,
    loader::{DataDirectory, DllInformation, Section},
};

pub fn parse_header(data: &[u8]) -> Result<DllInformation, MappingError> {
    let pe = PE::parse(data).map_err(|e| MappingError::GoblinError(e))?;

    let sections: Vec<Section> = pe
        .sections
        .iter()
        .map(|s| Section {
            name: String::from_utf8_lossy(&s.name)
                .trim_matches('\0')
                .to_string(),
            virtual_size: s.virtual_size as usize,
            virtual_address: s.virtual_address as usize,
            size_of_raw_data: s.size_of_raw_data as usize,
            pointer_to_raw_data: s.pointer_to_raw_data as usize,
            characteristics: s.characteristics,
        })
        .collect();
    let optional_header = pe
        .header
        .optional_header
        .ok_or(MappingError::MissingOptionalHeader)?;

    // Import Table
    let import_dir = optional_header
        .data_directories
        .get_import_table()
        .map(|d| DataDirectory {
            virtual_address: d.virtual_address as usize,
            size: d.size as usize,
        });

    // Base Relocation Table
    let reloc_dir = optional_header
        .data_directories
        .get_base_relocation_table()
        .map(|d| DataDirectory {
            virtual_address: d.virtual_address as usize,
            size: d.size as usize,
        });

    let callbacks_dir = optional_header
        .data_directories
        .get_tls_table()
        .map(|d| DataDirectory {
            virtual_address: d.virtual_address as usize,
            size: d.size as usize,
        });

    Ok(DllInformation {
        image_base: pe.image_base as usize,
        entry_point_rva: pe.entry,
        size_of_image: optional_header.windows_fields.size_of_image as usize,
        sections,
        size_of_headers: optional_header.windows_fields.size_of_headers as usize,
        import_dir,
        reloc_dir,
        tls_callbacks: callbacks_dir,
    })
}
