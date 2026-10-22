use std::process::id;
use std::ptr;
use std::thread;
use std::time::Duration;

fn main() {
    let pid = id();
    println!("{pid}");
    eprintln!(
        "every 500 ms: leak 4096 bytes from malloc, leak 4096 bytes from calloc, and grow one realloc buffer. Ctrl-C stops."
    );

    let mut grown: *mut libc::c_void = ptr::null_mut();
    let mut grown_size = 0usize;
    loop {
        leak(unsafe { libc::malloc(4096) }, "malloc");
        leak(unsafe { libc::calloc(1, 4096) }, "calloc");

        grown_size += 4096;
        let next = unsafe { libc::realloc(grown, grown_size) };
        if next.is_null() {
            eprintln!("error: realloc returned NULL.");
            std::process::exit(1);
        }
        grown = next;
        unsafe { ptr::write(grown.cast::<u8>(), 1) };

        thread::sleep(Duration::from_millis(500));
    }
}

fn leak(ptr: *mut libc::c_void, name: &str) {
    if ptr.is_null() {
        eprintln!("error: {name} returned NULL.");
        std::process::exit(1);
    }
    unsafe { std::ptr::write(ptr.cast::<u8>(), 1) };
}
