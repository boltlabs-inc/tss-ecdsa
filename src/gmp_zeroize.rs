//! This module is used to clean up secrets from memory when they are no longer
//! used.
//!
//! We use the crates unknown_order / rug / GMP. Secrets are ultimately stored
//! in arrays on the heap managed by malloc. GMP is a C library which frequently
//! allocates and copies buffers, and this is not visible to the Rust code. GMP
//! accepts a custom implementation of memory management (alloc / realloc /
//! free). We override these functions with wrappers that erase all buffers
//! whenever they are released.

use gmp_mpfr_sys::gmp::{
    allocate_function, free_function, get_memory_functions, reallocate_function,
    set_memory_functions,
};
use std::{ffi::c_void, ptr::addr_of_mut, slice, sync::Once};
use zeroize::Zeroize;

static ONCE: Once = Once::new();

/// Enable zeroization of GMP memory allocations.
///
/// This should be called on startup before any protocol.
pub fn enable_zeroize() {
    ONCE.call_once(do_setup_gmp_zeroize);
}

fn do_setup_gmp_zeroize() {
    unsafe {
        // SAFETY: Calling a C API documented here: https://gmplib.org/manual/Custom-Allocation
        get_memory_functions(
            addr_of_mut!(GMP_ALLOC),
            addr_of_mut!(GMP_REALLOC),
            addr_of_mut!(GMP_FREE),
        );

        // Check that we received the memory functions from GMP.
        // SAFETY: There are no documented error conditions.
        assert!(
            GMP_ALLOC.and(GMP_REALLOC).and(GMP_FREE).is_some(),
            "GMP should return its memory functions."
        );

        set_memory_functions(
            None, // alloc stays the same.
            Some(realloc_and_zeroize),
            Some(free_and_zeroize),
        );
    }
}

static mut GMP_ALLOC: allocate_function = None;
static mut GMP_REALLOC: reallocate_function = None;
static mut GMP_FREE: free_function = None;

extern "C" fn realloc_and_zeroize(
    old_ptr: *mut c_void,
    old_size: usize,
    new_size: usize,
) -> *mut c_void {
    // We cannot use realloc, because it will take ownership of the buffer and it
    // will be too late to zeroize it. So we have to allocate a new buffer, copy
    // the data, and free the old buffer.

    unsafe {
        // SAFETY: this function can only be called after GMP_ALLOC is set.
        let new_ptr = GMP_ALLOC.unwrap()(new_size);

        // Copy the data from the old buffer to the new buffer.
        // SAFETY: Per GMP doc, "ptr is never NULL, it’s always a previously allocated
        // block."
        {
            let min_size = old_size.min(new_size);
            let old_data = slice::from_raw_parts(old_ptr as *const u8, min_size);
            let new_data = slice::from_raw_parts_mut(new_ptr as *mut u8, min_size);
            new_data.copy_from_slice(old_data);
        }

        // Zeroize and free the old buffer.
        free_and_zeroize(old_ptr, old_size);

        new_ptr
    }
}

extern "C" fn free_and_zeroize(ptr: *mut c_void, size: usize) {
    unsafe {
        // SAFETY: Per GMP doc, "ptr is never NULL, it’s always a previously allocated
        // block of size bytes."
        let data = slice::from_raw_parts_mut(ptr as *mut u8, size);

        data.zeroize();

        // SAFETY: this function can only be called after GMP_FREE is set.
        GMP_FREE.unwrap()(ptr, size);
    }
}
