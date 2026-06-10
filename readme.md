# In-Memory PE/DLL Loader

Rust native library for manually mapping dynamically linked libraries. Supports mapping libraries from memory.

## Notes

This library does not recursively call itself for library dependencies as windows libraries utilize proxied loading and as such, it's easier to just call `GetProcAddress` and `LoadLibraryA` for dependencies.

## Architecture

The core of the crate revolves around the `Library` struct, which orchestrates the loading process.

* **`Library`**: The main orchestrator that parses headers (using `goblin`), allocates memory, maps sections, fixes IAT/Relocations, and executes the entry point.
* **`Allocator`**: A trait controlling how memory is allocated. By default, `DefaultAllocator` uses `VirtualAlloc`.
* **`Resolver`**: A trait controlling how exported functions are dynamically found. `DefaultResolver` implements custom export directory parsing.

## Example Usage

Below is an example of how to load a DLL entirely from a memory buffer and execute an exported function.

### 1. Basic Execution

```rust
use your_crate::Library; 
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dll_bytes = fs::read("library.dll")?;

    // Calling new() on the Library struct maps the library into memory.
    // in short, this allocates memory, maps sections, resolves IAT, fixes relocations,
    // runs TLS callbacks, and executes the entrypoint.
    let mapped_lib = Library::new(dll_bytes).map()?;

    // Define function signature of an exported function in the library
    type CalculateSumFn = unsafe extern "C" fn(i32, i32) -> i32;

    // Resolve and cast the function automagically
    if let Some(calculate_sum) = mapped_lib.function::<CalculateSumFn>("calculate_sum") {
        unsafe {
            let result = calculate_sum(10, 20);
            println!("Result from loaded DLL: {}", result);
        }
    }

    Ok(())
}

```

### 2. Using Custom Allocators

If you want to avoid standard `VirtualAlloc` calls (for instance, to implement Module Stomping), you can implement the `Allocator` trait.

```rust
use your_crate::allocators::Allocator;
use your_crate::Library;

pub struct MyCustomAllocator;

impl Allocator for MyCustomAllocator {
    fn allocate(&mut self, size: usize) -> Option<(usize, usize)> {
        // Return Some((address, allocated_size))
        todo!()
    }
}

fn main() {
    let dll_bytes = vec![/* ... */];
    
    // Construct the library with your custom allocator
    let lib = Library::<MyCustomAllocator, _>::with_allocator(dll_bytes, MyCustomAllocator);
    let mapped_lib = lib.map().unwrap();
}

```

## Dependencies

* `goblin`: Used to parse the PE headers.
* `log`: Used for internal debug and trace logging. Enable the `log` feature to see detailed mapping steps.