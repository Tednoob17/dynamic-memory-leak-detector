use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("reading the workspace metadata")?;
    let ebpf_package = packages
        .into_iter()
        .find(|package| package.name.as_str() == "dmld-ebpf")
        .ok_or_else(|| anyhow!("dmld-ebpf package not found"))?;
    let manifest_path = ebpf_package.manifest_path;
    let root_dir = manifest_path
        .parent()
        .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?;
    let package = aya_build::Package {
        name: ebpf_package.name.as_str(),
        root_dir: root_dir.as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([package], Toolchain::default())?;

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").context("OUT_DIR is not set")?);
    let object = out_dir.join("dmld");
    if !object.exists() {
        if std::env::var_os("AYA_BUILD_SKIP").is_some() {
            std::fs::write(&object, []).context("writing a placeholder eBPF object")?;
            println!(
                "cargo:warning=AYA_BUILD_SKIP is set, so the embedded eBPF object is empty and dmld cannot attach probes"
            );
        } else {
            anyhow::bail!("eBPF object {} was not produced", object.display());
        }
    }
    Ok(())
}
