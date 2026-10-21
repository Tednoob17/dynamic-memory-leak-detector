//! This file exists so the package has a library target. Cargo then rebuilds
//! the userspace daemon when these sources change, without compiling the
//! eBPF binary for the host.

#![no_std]
