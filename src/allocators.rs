use std::{ffi::c_void, ptr::null_mut};

pub trait Allocator {
    /// Returns address and real size of allocation
    fn allocate(&mut self, size: usize) -> Option<(usize, usize)>;
}

unsafe extern "system" {
    fn VirtualAlloc(
        address: *mut std::ffi::c_void,
        size: usize,
        alloc_type: u32,
        protect_flags: u32,
    ) -> *const c_void;
}

pub struct PreAllocated {
    target: usize,
}

impl PreAllocated {
    pub fn new(target: *const c_void) -> Self {
        Self {
            target: target as usize,
        }
    }
}

impl Allocator for PreAllocated {
    fn allocate(&mut self, size: usize) -> Option<(usize, usize)> {
        return Some((self.target, size));
    }
}

pub struct DefaultAllocator {}
impl Allocator for DefaultAllocator {
    fn allocate(&mut self, size: usize) -> Option<(usize, usize)> {
        #[cfg(feature = "log")]
        debug!(
            "Calling VirtualAlloc(0x0, {:#X}, {:#X}, {:#X});",
            size,
            0x1000 | 0x2000,
            0x04
        );

        unsafe {
            let addr = VirtualAlloc(null_mut(), size, 0x1000 | 0x2000, 0x04);
            if addr.is_null() {
                return None;
            } else {
                return Some((addr as usize, size));
            }
        }
    }
}
