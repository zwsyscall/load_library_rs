type AllocatorSignature = fn(size: usize) -> Option<usize>;
type ResolverSignature = fn(base_address: usize, name: &str) -> Option<*const u8>;

pub enum Allocator {
    Native,
    PreAllocated(usize, usize),
    Custom(AllocatorSignature),
}

impl Default for Allocator {
    fn default() -> Self {
        Self::Native
    }
}

pub enum Resolver {
    Native,
    Custom(ResolverSignature),
}

impl Default for Resolver {
    fn default() -> Self {
        Self::Native
    }
}
