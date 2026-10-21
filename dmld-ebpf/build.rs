use which::which;

/// Building the eBPF binary depends on `bpf-linker`. Cargo cannot express that
/// dependency, so this script rebuilds the crate when that binary changes.
fn main() {
    match which("bpf-linker") {
        Ok(bpf_linker) => {
            println!("cargo:rerun-if-changed={}", bpf_linker.display());
        }
        Err(_) => {
            println!(
                "cargo:warning=bpf-linker was not found on PATH. Install nightly with rust-src (`rustup toolchain install nightly --component rust-src`), then `cargo install bpf-linker`. On macOS, install LLVM first and run `cargo install bpf-linker --no-default-features`."
            );
        }
    }
}
