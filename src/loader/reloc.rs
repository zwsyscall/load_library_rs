use crate::loader::DataDirectory;

#[repr(C)]
struct BaseRelocationBlock {
    pub page_rva: u32,
    pub block_size: u32,
}

pub fn fix_relocations(base_addr: usize, reloc_dir: &DataDirectory, image_base: usize) {
    // no underflow
    let delta = (base_addr as i64) - (image_base as i64);
    // at preferred base
    if delta == 0 {
        return;
    }

    let mut current_offset: usize = 0;
    let reloc_table_base = (base_addr + reloc_dir.virtual_address) as *const u8;
    unsafe {
        while current_offset < reloc_dir.size {
            let block_ptr = reloc_table_base.add(current_offset) as *const BaseRelocationBlock;
            let block = &*block_ptr;

            // Something broke check
            if block.block_size == 0 {
                break;
            }

            // offset from the header
            let entries_ptr = block_ptr.add(1) as *const u16;
            let entries_count = (block.block_size - 8) / 2;

            for i in 0..entries_count {
                // deref and offset to get the type and offset
                let (rel_type, rel_offset) = {
                    let entry = *entries_ptr.add(i as usize);
                    ((entry >> 12) as u8, (entry & 0x0FFF) as usize)
                };

                // IMAGE_REL_BASED_DIR64
                if rel_type == 10 {
                    // wicked maths
                    let patch_location =
                        (base_addr + block.page_rva as usize + rel_offset) as *mut i64;

                    *patch_location += delta;
                }
            }

            current_offset += block.block_size as usize;
        }
    }
}
