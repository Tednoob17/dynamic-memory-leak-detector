use std::fs::File;
use std::io;
use std::path::PathBuf;

use dmld_common::{AllocatorKind, MapChoice, classify_maps};

pub struct Detected {
    pub kind: AllocatorKind,
    pub host_path: PathBuf,
}

pub enum DetectError {
    NoProcess {
        pid: u32,
    },
    Maps {
        pid: u32,
        source: io::Error,
    },
    Unsupported {
        pid: u32,
        library: String,
    },
    NotFound {
        pid: u32,
    },
    Unreadable {
        pid: u32,
        mapped: String,
        host: PathBuf,
        source: io::Error,
    },
}

impl DetectError {
    pub fn code(&self) -> i32 {
        match self {
            Self::NoProcess { .. } | Self::Maps { .. } => 2,
            Self::Unsupported { .. } | Self::NotFound { .. } | Self::Unreadable { .. } => 3,
        }
    }

    pub fn report(&self) {
        match self {
            Self::NoProcess { pid } => {
                eprintln!("error: no process with pid {pid}.");
                eprintln!("Find a pid with `ps -eo pid,comm`.");
            }
            Self::Maps { pid, source } => {
                eprintln!("error: cannot read /proc/{pid}/maps: {source}.");
                if source.kind() == io::ErrorKind::PermissionDenied {
                    eprintln!(
                        "Reading another user's process needs CAP_SYS_PTRACE. Running as root is enough."
                    );
                }
            }
            Self::Unsupported { pid, library } => {
                eprintln!(
                    "error: pid {pid} loads {library}, and dmld does not trace that allocator yet."
                );
                eprintln!("dmld traces malloc and free in glibc and musl.");
            }
            Self::NotFound { pid } => {
                eprintln!("error: pid {pid} has no glibc or musl library to probe.");
                eprintln!("A malloc linked into the executable itself is not handled yet.");
            }
            Self::Unreadable {
                pid,
                mapped,
                host,
                source,
            } => {
                eprintln!(
                    "error: pid {pid} maps {mapped}, but {} cannot be opened: {source}.",
                    host.display()
                );
                eprintln!(
                    "dmld reads that file to place the probes. In a container the path goes through /proc/{pid}/root."
                );
            }
        }
    }
}

pub fn detect(pid: u32) -> Result<Detected, DetectError> {
    let maps_path = format!("/proc/{pid}/maps");
    let maps = match std::fs::read_to_string(&maps_path) {
        Ok(maps) => maps,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(DetectError::NoProcess { pid });
        }
        Err(source) => return Err(DetectError::Maps { pid, source }),
    };

    match classify_maps(&maps) {
        MapChoice::Unsupported { library } => Err(DetectError::Unsupported { pid, library }),
        MapChoice::NotFound => Err(DetectError::NotFound { pid }),
        MapChoice::Probe { kind, mapped_path } => {
            let host_path = host_path(pid, &mapped_path);
            match File::open(&host_path) {
                Ok(_) => Ok(Detected { kind, host_path }),
                Err(source) => Err(DetectError::Unreadable {
                    pid,
                    mapped: mapped_path,
                    host: host_path,
                    source,
                }),
            }
        }
    }
}

fn host_path(pid: u32, mapped: &str) -> PathBuf {
    let mut path = PathBuf::from(format!("/proc/{pid}/root"));
    path.push(mapped.trim_start_matches('/'));
    path
}
