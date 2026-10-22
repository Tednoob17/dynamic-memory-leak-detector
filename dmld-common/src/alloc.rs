//! What an allocator return should do to the tracked set.
//!
//! The eBPF probes only see the arguments and the returned address. This
//! function turns that pair into the bookkeeping change. It does not know
//! whether an address was already tracked.

/// Size requested by the call, and the block `realloc` was asked to replace.
///
/// `old_addr` is zero for `malloc` and `calloc`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    pub size: u64,
    pub old_addr: u64,
}

/// Bookkeeping for one allocator return.
///
/// A zero address means "nothing". `resize` is set only when `record_addr` is
/// the same block as the one `realloc` was given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub release: u64,
    pub record_addr: u64,
    pub record_size: u64,
    pub resize: bool,
}

impl Outcome {
    const fn none() -> Self {
        Self {
            release: 0,
            record_addr: 0,
            record_size: 0,
            resize: false,
        }
    }
}

/// Decide how to update tracked blocks when an allocator call returns.
///
/// `returned` is the address the function returned. Zero means it returned NULL.
#[inline(always)]
pub fn allocation_outcome(pending: Pending, returned: u64) -> Outcome {
    let Pending { size, old_addr } = pending;

    // realloc failed. The old block is still the caller's.
    if returned == 0 && size != 0 && old_addr != 0 {
        return Outcome::none();
    }
    // malloc or calloc failed, or realloc(NULL, 0) returned NULL.
    if returned == 0 && old_addr == 0 {
        return Outcome::none();
    }
    // The block stayed where it was. Only its size may have changed.
    if returned != 0 && returned == old_addr {
        return Outcome {
            release: 0,
            record_addr: returned,
            record_size: size,
            resize: true,
        };
    }

    // A different address, or a NULL return after realloc(ptr, 0): the old
    // block is gone. A non-NULL return is a new block.
    Outcome {
        release: old_addr,
        record_addr: returned,
        record_size: size,
        resize: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(size: u64, old_addr: u64) -> Pending {
        Pending { size, old_addr }
    }

    #[test]
    fn malloc_success_records_a_new_block() {
        assert_eq!(
            allocation_outcome(pending(32, 0), 0x1000),
            Outcome {
                release: 0,
                record_addr: 0x1000,
                record_size: 32,
                resize: false,
            }
        );
    }

    #[test]
    fn malloc_failure_records_nothing() {
        assert_eq!(allocation_outcome(pending(32, 0), 0), Outcome::none());
    }

    #[test]
    fn realloc_failure_keeps_the_old_block() {
        assert_eq!(allocation_outcome(pending(64, 0x1000), 0), Outcome::none());
    }

    #[test]
    fn realloc_in_place_is_a_resize() {
        assert_eq!(
            allocation_outcome(pending(128, 0x1000), 0x1000),
            Outcome {
                release: 0,
                record_addr: 0x1000,
                record_size: 128,
                resize: true,
            }
        );
    }

    #[test]
    fn realloc_that_moves_releases_the_old_block_and_records_the_new_one() {
        assert_eq!(
            allocation_outcome(pending(128, 0x1000), 0x2000),
            Outcome {
                release: 0x1000,
                record_addr: 0x2000,
                record_size: 128,
                resize: false,
            }
        );
    }

    #[test]
    fn realloc_of_null_is_a_new_block() {
        assert_eq!(
            allocation_outcome(pending(16, 0), 0x3000),
            Outcome {
                release: 0,
                record_addr: 0x3000,
                record_size: 16,
                resize: false,
            }
        );
    }

    #[test]
    fn realloc_to_zero_releases_the_old_block() {
        assert_eq!(
            allocation_outcome(pending(0, 0x1000), 0),
            Outcome {
                release: 0x1000,
                record_addr: 0,
                record_size: 0,
                resize: false,
            }
        );
    }

    #[test]
    fn realloc_null_to_zero_does_nothing() {
        assert_eq!(allocation_outcome(pending(0, 0), 0), Outcome::none());
    }
}
