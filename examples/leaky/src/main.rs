use std::process::id;
use std::thread;
use std::time::Duration;

fn main() {
    let pid = id();
    println!("{pid}");
    eprintln!("allocating 4096 bytes every 500 ms and never freeing them. Ctrl-C stops.");
    loop {
        let ptr = unsafe { libc::malloc(4096) };
        if ptr.is_null() {
            eprintln!("error: malloc returned NULL.");
            std::process::exit(1);
        }
        unsafe { std::ptr::write(ptr.cast::<u8>(), 1) };
        thread::sleep(Duration::from_millis(500));
    }
}
