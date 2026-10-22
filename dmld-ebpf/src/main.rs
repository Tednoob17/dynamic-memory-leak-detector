#![no_std]
#![no_main]

use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::macros::{map, uprobe, uretprobe};
use aya_ebpf::maps::{HashMap, PerCpuArray};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use dmld_common::{ALLOCS_MAX_ENTRIES, Counters, PENDING_MAX_ENTRIES, Pending, allocation_outcome};

/// Request remembered between the entry and the return of one allocator call.
/// Keyed by kernel thread id.
#[map]
static PENDING: HashMap<u32, Pending> = HashMap::with_max_entries(PENDING_MAX_ENTRIES, 0);

/// Block address to requested size, for allocations observed after attach.
#[map]
static ALLOCS: HashMap<u64, u64> = HashMap::with_max_entries(ALLOCS_MAX_ENTRIES, 0);

#[map]
static COUNTERS: PerCpuArray<Counters> = PerCpuArray::with_max_entries(1, 0);

#[uprobe]
pub fn malloc_enter(ctx: ProbeContext) -> u32 {
    let size: u64 = ctx.arg(0).unwrap_or(0);
    remember(size, 0);
    0
}

#[uretprobe]
pub fn malloc_exit(ctx: RetProbeContext) -> u32 {
    on_return(ctx.ret());
    0
}

#[uprobe]
pub fn calloc_enter(ctx: ProbeContext) -> u32 {
    let count: u64 = ctx.arg(0).unwrap_or(0);
    let size: u64 = ctx.arg(1).unwrap_or(0);
    // An overflowing product does not allocate. The return is NULL.
    if let Some(total) = count.checked_mul(size) {
        remember(total, 0);
    }
    0
}

#[uretprobe]
pub fn calloc_exit(ctx: RetProbeContext) -> u32 {
    on_return(ctx.ret());
    0
}

#[uprobe]
pub fn realloc_enter(ctx: ProbeContext) -> u32 {
    let old_addr: u64 = ctx.arg(0).unwrap_or(0);
    let size: u64 = ctx.arg(1).unwrap_or(0);
    remember(size, old_addr);
    0
}

#[uretprobe]
pub fn realloc_exit(ctx: RetProbeContext) -> u32 {
    on_return(ctx.ret());
    0
}

#[uprobe]
pub fn free_enter(ctx: ProbeContext) -> u32 {
    release(ctx.arg(0).unwrap_or(0));
    0
}

#[inline(always)]
fn on_return(returned: u64) {
    let Some(pending) = take_pending() else {
        return;
    };
    let outcome = allocation_outcome(pending, returned);
    if outcome.release != 0 {
        release(outcome.release);
    }
    if outcome.record_addr == 0 {
        return;
    }
    if outcome.resize {
        resize(outcome.record_addr, outcome.record_size);
    } else {
        record_new(outcome.record_addr, outcome.record_size);
    }
}

/// `pid()` in the kernel sense is the thread id. Two threads can be inside
/// the allocator at once. One thread cannot, unless a signal handler calls it.
#[inline(always)]
fn remember(size: u64, old_addr: u64) {
    let tid = bpf_get_current_pid_tgid() as u32;
    let pending = Pending { size, old_addr };
    if PENDING.insert(&tid, &pending, 0).is_err() {
        add_dropped();
    }
}

#[inline(always)]
fn take_pending() -> Option<Pending> {
    let tid = bpf_get_current_pid_tgid() as u32;
    let ptr = PENDING.get_ptr(&tid)?;
    let pending = unsafe { *ptr };
    let _ = PENDING.remove(&tid);
    Some(pending)
}

#[inline(always)]
fn record_new(addr: u64, size: u64) {
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

/// Grow or shrink a block that stayed at the same address.
///
/// A block allocated before dmld attached is left alone. Its previous size is
/// unknown, so counting the new size would invent bytes.
#[inline(always)]
fn resize(addr: u64, size: u64) {
    let Some(old) = copy_u64(ALLOCS.get_ptr(&addr)) else {
        return;
    };
    let Some(old) = i64::try_from(old).ok() else {
        return;
    };
    let Some(new) = i64::try_from(size).ok() else {
        add_dropped();
        return;
    };
    if ALLOCS.insert(&addr, &size, 0).is_err() {
        add_dropped();
        return;
    }
    if let Some(ptr) = COUNTERS.get_ptr_mut(0u32) {
        unsafe { (*ptr).live_bytes += new - old }
    }
}

#[inline(always)]
fn release(addr: u64) {
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
