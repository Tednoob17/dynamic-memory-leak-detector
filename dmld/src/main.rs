mod allocator;
mod loader;

use std::io::{self, IsTerminal as _, Write as _};
use std::num::NonZeroU32;
use std::path::Path;
use std::time::Duration;

use aya::Ebpf;
use aya::maps::PerCpuArray;
use clap::Parser;
use dmld_common::{Counters, format_json, format_plain, format_terminal};

use crate::allocator::{DetectError, detect};

const BEFORE_HELP: &str = "\
Examples:
  sudo dmld --pid 4242
  sudo dmld --pid 4242 --json

Prints one sample per second. Ctrl-C removes the probes.";

const AFTER_HELP: &str = "\
Stdout is the sample stream. Status and errors go to stderr.

  terminal         allocs N  frees N  live_bytes N  ignored_frees N  dropped_allocs N
  pipe or --plain  allocs frees live_bytes ignored_frees dropped_allocs
  --json           one JSON object per line

Live bytes count memory allocated after dmld attaches. free of an older block
is counted in ignored_frees, not in frees.

Scripts should pass --plain or --json. The terminal lines may change.

Exit codes:
  0  stopped by Ctrl-C, or the traced process exited
  1  unexpected error
  2  the process does not exist, or its maps cannot be read
  3  malloc and free could not be found
  4  the kernel rejected the eBPF program

Issues: https://github.com/ValyonBJ/dynamic-memory-leak-detector/issues";

/// Count malloc and free calls in one running process.
#[derive(Debug, Parser)]
#[command(
    name = "dmld",
    version,
    about,
    before_help = BEFORE_HELP,
    after_help = AFTER_HELP,
    arg_required_else_help = true,
    disable_help_subcommand = true
)]
struct Opt {
    /// Process to trace.
    #[arg(short, long, value_name = "PID", value_parser = parse_pid)]
    pid: NonZeroU32,

    /// Print each sample as one JSON object per line.
    #[arg(long, conflicts_with = "plain")]
    json: bool,

    /// Print five numbers per line, with no labels.
    ///
    /// The columns are allocs, frees, live_bytes, ignored_frees, dropped_allocs.
    #[arg(long, conflicts_with = "json")]
    plain: bool,

    /// Do not print the attachment banner.
    #[arg(short, long)]
    quiet: bool,

    /// Print the probe names and how many live blocks can be tracked.
    #[arg(short = 'd', long)]
    debug: bool,
}

fn parse_pid(raw: &str) -> Result<NonZeroU32, String> {
    let pid: u32 = raw
        .parse()
        .map_err(|_| format!("{raw:?} is not a pid. A pid is a positive number."))?;
    NonZeroU32::new(pid).ok_or_else(|| "pid must be greater than 0.".to_string())
}

enum Exit {
    NotLinux,
    Detect(DetectError),
    Probe(anyhow::Error),
    Unexpected(anyhow::Error),
}

impl Exit {
    fn report_and_code(self) -> i32 {
        match self {
            Self::NotLinux => {
                eprintln!("error: dmld only runs on Linux.");
                eprintln!(
                    "eBPF probes are installed by the Linux kernel. Copy this binary to a Linux machine and run it there."
                );
                1
            }
            Self::Detect(error) => {
                error.report();
                error.code()
            }
            Self::Probe(error) => {
                eprintln!("error: {error:#}.");
                eprintln!();
                eprintln!("{}", probe_remedy(&error));
                4
            }
            Self::Unexpected(error) => {
                eprintln!("error: {error:#}.");
                eprintln!(
                    "This was not an expected failure. Report it, with the text above, at https://github.com/ValyonBJ/dynamic-memory-leak-detector/issues."
                );
                1
            }
        }
    }
}

fn probe_remedy(error: &anyhow::Error) -> &'static str {
    let text = format!("{error:#}").to_lowercase();
    if text.contains("symbol") {
        "The library has no malloc or free symbol. It may be stripped, or this process may use another allocator."
    } else if text.contains("not permitted")
        || text.contains("eperm")
        || text.contains("permission")
    {
        "Run dmld as root, or grant CAP_BPF and CAP_PERFMON. Linux 5.8 or newer is required."
    } else {
        "dmld needs Linux 5.8 or newer, and CAP_BPF plus CAP_PERFMON. Running as root is enough."
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let code = match run().await {
        Ok(()) => 0,
        Err(exit) => exit.report_and_code(),
    };
    std::process::exit(code);
}

async fn run() -> Result<(), Exit> {
    let opt = Opt::parse();
    if !cfg!(target_os = "linux") {
        return Err(Exit::NotLinux);
    }

    let pid = opt.pid.get();
    let detected = detect(pid).map_err(Exit::Detect)?;
    if !opt.quiet {
        eprintln!(
            "Attaching malloc and free probes to pid {pid}, {}, {}.",
            detected.kind.as_str(),
            detected.host_path.display()
        );
    }
    if opt.debug {
        eprintln!(
            "debug: probes malloc_enter (uprobe), malloc_exit (uretprobe), free_enter (uprobe)."
        );
        eprintln!(
            "debug: tracking up to {} live blocks.",
            dmld_common::ALLOCS_MAX_ENTRIES
        );
    }

    let mut ebpf = loader::load_and_attach(&detected, opt.pid).map_err(Exit::Probe)?;
    if !opt.quiet {
        eprintln!("Attached. Ctrl-C removes the probes.");
    }
    sample(&mut ebpf, &opt).await
}

async fn sample(ebpf: &mut Ebpf, opt: &Opt) -> Result<(), Exit> {
    let pid = opt.pid.get();
    let mode = output_mode(opt);
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut warned_dropped = false;

    loop {
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    return Err(Exit::Unexpected(error.into()));
                }
                eprintln!("stopped");
                return Ok(());
            }
            _ = interval.tick() => {
                if !Path::new(&format!("/proc/{pid}")).exists() {
                    eprintln!("pid {pid} exited.");
                    return Ok(());
                }
                let counters = read_counters(ebpf).map_err(Exit::Unexpected)?;
                if !warned_dropped && counters.dropped_allocs > 0 {
                    warned_dropped = true;
                    eprintln!(
                        "warning: some malloc calls were not recorded. The tracking map is full, so later frees of those blocks show up in ignored_frees."
                    );
                }
                let line = match mode {
                    Output::Terminal => format_terminal(&counters),
                    Output::Plain => format_plain(&counters),
                    Output::Json => format_json(&counters),
                };
                println!("{line}");
                let _ = io::stdout().flush();
            }
        }
    }
}

enum Output {
    Terminal,
    Plain,
    Json,
}

fn output_mode(opt: &Opt) -> Output {
    if opt.json {
        Output::Json
    } else if opt.plain || !io::stdout().is_terminal() {
        Output::Plain
    } else {
        Output::Terminal
    }
}

fn read_counters(ebpf: &mut Ebpf) -> anyhow::Result<Counters> {
    let map = ebpf
        .map_mut("COUNTERS")
        .ok_or_else(|| anyhow::anyhow!("the eBPF object has no COUNTERS map"))?;
    let counters = PerCpuArray::<_, Counters>::try_from(map)?;
    let index = 0u32;
    let per_cpu = counters.get(&index, 0)?;
    let mut total = Counters::default();
    for cpu in per_cpu.iter() {
        total.allocs += cpu.allocs;
        total.frees += cpu.frees;
        total.live_bytes += cpu.live_bytes;
        total.ignored_frees += cpu.ignored_frees;
        total.dropped_allocs += cpu.dropped_allocs;
    }
    Ok(total)
}
