use gmp_mpfr_sys::gmp::{
    allocate_function, free_function, get_memory_functions, reallocate_function,
    set_memory_functions,
};
use std::{ffi::c_void, ptr::addr_of_mut, slice, sync::Once};
use zeroize::Zeroize;

static ONCE: Once = Once::new();

pub fn setup_zeroize() {
    ONCE.call_once(do_setup_gmp_zeroize);
}

fn do_setup_gmp_zeroize() {
    unsafe {
        get_memory_functions(
            addr_of_mut!(GMP_ALLOC),
            addr_of_mut!(GMP_REALLOC),
            addr_of_mut!(GMP_FREE),
        );

        // Check that we received the memory functions from GMP.
        assert!(
            GMP_ALLOC.and(GMP_REALLOC).and(GMP_FREE).is_some(),
            "GMP should return its memory functions."
        );

        // Check that Option<fn> is a nullable function pointer in this environment.
        assert_eq!(
            addr_of_mut!(GMP_ALLOC) as *mut c_void,
            GMP_ALLOC.as_mut().unwrap() as *mut _ as *mut c_void,
            "This version of gmp_mpfr_sys requires that Option<fn> be implemented as a nullable function pointer."
        );

        set_memory_functions(None, Some(realloc_and_zeroize), Some(free_and_zeroize));
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
        let new_ptr = GMP_ALLOC.unwrap()(new_size);

        // Copy the data from the old buffer to the new buffer.
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
        let data = slice::from_raw_parts_mut(ptr as *mut u8, size);

        data.zeroize();

        GMP_FREE.unwrap()(ptr, size);
    }
}
