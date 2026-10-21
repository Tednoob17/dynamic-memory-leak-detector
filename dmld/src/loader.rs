use std::num::NonZeroU32;
use std::path::Path;

use anyhow::{Context as _, anyhow};
use aya::Ebpf;
use aya::programs::UProbe;
use aya::programs::uprobe::UProbeScope;

use crate::allocator::Detected;

pub fn load_and_attach(detected: &Detected, pid: NonZeroU32) -> anyhow::Result<Ebpf> {
    raise_memlock();
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dmld"
    )))?;
    attach(&mut ebpf, &detected.host_path, pid)?;
    Ok(ebpf)
}

fn attach(ebpf: &mut Ebpf, target: &Path, pid: NonZeroU32) -> anyhow::Result<()> {
    let scope = UProbeScope::OneProcess(pid);
    for (program, symbol) in [
        ("malloc_enter", "malloc"),
        ("malloc_exit", "malloc"),
        ("free_enter", "free"),
    ] {
        let prog: &mut UProbe = ebpf
            .program_mut(program)
            .ok_or_else(|| anyhow!("the embedded eBPF object has no program named {program}"))?
            .try_into()
            .with_context(|| format!("{program} is not a uprobe"))?;
        prog.load().with_context(|| format!("loading {program}"))?;
        prog.attach(symbol, target, scope)
            .with_context(|| format!("attaching {symbol} in {}", target.display()))?;
    }
    Ok(())
}

fn raise_memlock() {
    let limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) };
}
