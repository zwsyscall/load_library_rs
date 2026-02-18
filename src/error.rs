#[derive(Debug)]
pub enum MappingError {
    NotEnoughSpace,
    NotValidLibrary,
    MissingOptionalHeader,
    InvalidMappingAddress,
    MissingData,
    AllocatorFailure,
    IoError(std::io::Error),
    GoblinError(goblin::error::Error),
}
