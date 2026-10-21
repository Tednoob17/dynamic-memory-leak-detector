#![no_std]
#![no_main]

use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::macros::{map, uprobe, uretprobe};
use aya_ebpf::maps::{HashMap, PerCpuArray};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use dmld_common::{ALLOCS_MAX_ENTRIES, Counters, PENDING_MAX_ENTRIES};

/// Requested size, keyed by kernel thread id, between `malloc` entry and return.
#[map]
static PENDING: HashMap<u32, u64> = HashMap::with_max_entries(PENDING_MAX_ENTRIES, 0);

/// Block address to requested size, for allocations observed after attach.
#[map]
static ALLOCS: HashMap<u64, u64> = HashMap::with_max_entries(ALLOCS_MAX_ENTRIES, 0);

#[map]
static COUNTERS: PerCpuArray<Counters> = PerCpuArray::with_max_entries(1, 0);

#[uprobe]
pub fn malloc_enter(ctx: ProbeContext) -> u32 {
    try_malloc_enter(ctx);
    0
}

#[inline(always)]
fn try_malloc_enter(ctx: ProbeContext) {
    let size: u64 = ctx.arg(0).unwrap_or(0);
    // `pid()` in the kernel sense is the thread id. Two threads can be inside
    // malloc at once; one thread cannot, unless a signal handler calls malloc.
    let tid = bpf_get_current_pid_tgid() as u32;
    if PENDING.insert(&tid, &size, 0).is_err() {
        add_dropped();
    }
}

#[uretprobe]
pub fn malloc_exit(ctx: RetProbeContext) -> u32 {
    try_malloc_exit(ctx);
    0
}

#[inline(always)]
fn try_malloc_exit(ctx: RetProbeContext) {
    let tid = bpf_get_current_pid_tgid() as u32;
    let Some(size) = copy_u64(PENDING.get_ptr(&tid)) else {
        return;
    };
    let _ = PENDING.remove(&tid);

    let addr: u64 = ctx.ret();
    if addr == 0 {
        return;
    }
    let Some(tracked) = i64::try_from(size).ok() else {
        add_dropped();
        return;
    };
    if ALLOCS.insert(&addr, &size, 0).is_err() {
        add_dropped();
        return;
    }
    if let Some(ptr) = COUNTERS.get_ptr_mut(0u32) {
        unsafe {
            (*ptr).allocs += 1;
            (*ptr).live_bytes += tracked;
        }
    }
}

#[uprobe]
pub fn free_enter(ctx: ProbeContext) -> u32 {
    try_free_enter(ctx);
    0
}

#[inline(always)]
fn try_free_enter(ctx: ProbeContext) {
    let addr: u64 = ctx.arg(0).unwrap_or(0);
    // free(NULL) is a no-op in the allocator.
    if addr == 0 {
        return;
    }
    let Some(size) = copy_u64(ALLOCS.get_ptr(&addr)) else {
        // Allocated before dmld attached, or never recorded.
        if let Some(ptr) = COUNTERS.get_ptr_mut(0u32) {
            unsafe { (*ptr).ignored_frees += 1 }
        }
        return;
    };
    let _ = ALLOCS.remove(&addr);
    let Some(size) = i64::try_from(size).ok() else {
        return;
    };
    if let Some(ptr) = COUNTERS.get_ptr_mut(0u32) {
        unsafe {
            (*ptr).frees += 1;
            (*ptr).live_bytes -= size;
        }
    }
}

#[inline(always)]
fn copy_u64(ptr: Option<*const u64>) -> Option<u64> {
    match ptr {
        Some(ptr) => Some(unsafe { *ptr }),
        None => None,
    }
}

#[inline(always)]
fn add_dropped() {
    if let Some(ptr) = COUNTERS.get_ptr_mut(0u32) {
        unsafe { (*ptr).dropped_allocs += 1 }
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
