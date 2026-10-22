//! Types shared by the eBPF programs and the userspace daemon.
//!
//! The `std` feature adds parsing and formatting for the daemon. The `pod`
//! feature also marks [`Counters`] as plain data for aya. The eBPF crate
//! leaves both features off and stays `no_std`.

#![cfg_attr(not(feature = "std"), no_std)]

mod alloc;

pub use alloc::{Outcome, Pending, allocation_outcome};

/// Threads that can be inside the allocator at the same time.
pub const PENDING_MAX_ENTRIES: u32 = 8_192;

/// Live blocks tracked at once. A full map drops new allocations instead of
/// evicting old ones, so a leak already recorded stays recorded.
pub const ALLOCS_MAX_ENTRIES: u32 = 131_072;

/// Per-CPU counters. Userspace sums every CPU.
///
/// `live_bytes` is signed because an allocation and its `free` can run on
/// different CPUs. One CPU can go negative. The sum across CPUs is the total.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Counters {
    pub allocs: i64,
    pub frees: i64,
    pub live_bytes: i64,
    pub ignored_frees: i64,
    pub dropped_allocs: i64,
}

// Safety: the fields are `i64` only, so the layout has no padding.
#[cfg(feature = "pod")]
unsafe impl aya::Pod for Counters {}

#[cfg(feature = "std")]
mod maps;
#[cfg(feature = "std")]
mod sample;

#[cfg(feature = "std")]
pub use maps::{AllocatorKind, MapChoice, classify_maps};
#[cfg(feature = "std")]
pub use sample::{format_json, format_plain, format_terminal};
