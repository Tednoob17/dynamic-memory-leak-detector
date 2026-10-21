//! Read `/proc/<pid>/maps` text and decide which file provides `malloc`.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocatorKind {
    Glibc,
    Musl,
}

impl AllocatorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Glibc => "glibc",
            Self::Musl => "musl",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapChoice {
    Probe {
        kind: AllocatorKind,
        mapped_path: String,
    },
    /// A supported library may also be mapped. Its `malloc` is not the one in use.
    Unsupported {
        library: String,
    },
    NotFound,
}

pub fn classify_maps(maps: &str) -> MapChoice {
    let mut libc = None;
    let mut unsupported = None;

    for line in maps.lines() {
        let Some(path) = pathname(line) else {
            continue;
        };
        if !path.starts_with('/') {
            continue;
        }
        let path = path.strip_suffix(" (deleted)").unwrap_or(path);
        let base = basename(path);

        if unsupported.is_none()
            && (base.starts_with("libjemalloc")
                || base.starts_with("libtcmalloc")
                || base.starts_with("libmimalloc"))
        {
            unsupported = Some(base.to_string());
            continue;
        }

        if libc.is_none() {
            let kind = if base.starts_with("libc.so") || base.starts_with("libc-") {
                Some(AllocatorKind::Glibc)
            } else if base.starts_with("ld-musl") {
                Some(AllocatorKind::Musl)
            } else {
                None
            };
            if let Some(kind) = kind {
                libc = Some((kind, path.to_string()));
            }
        }
    }

    if let Some(library) = unsupported {
        return MapChoice::Unsupported { library };
    }
    match libc {
        Some((kind, mapped_path)) => MapChoice::Probe { kind, mapped_path },
        None => MapChoice::NotFound,
    }
}

fn pathname(line: &str) -> Option<&str> {
    let mut rest = line.trim();
    for _ in 0..5 {
        let split = rest.find(char::is_whitespace)?;
        rest = rest[split..].trim_start();
        if rest.is_empty() {
            return None;
        }
    }
    Some(rest)
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glibc_mapping_is_selected() {
        let maps = "\
7f000000-7f021000 r-xp 00000000 08:01 1 /usr/lib/x86_64-linux-gnu/libc.so.6\n\
7f021000-7f022000 r--p 00021000 08:01 1 /usr/lib/x86_64-linux-gnu/libc.so.6\n\
55a000-55b000 rw-p 00000000 00:00 0 [heap]\n";
        assert_eq!(
            classify_maps(maps),
            MapChoice::Probe {
                kind: AllocatorKind::Glibc,
                mapped_path: "/usr/lib/x86_64-linux-gnu/libc.so.6".to_string(),
            }
        );
    }

    #[test]
    fn musl_loader_is_selected() {
        let maps = "7f000-7f100 r-xp 00000000 08:01 2 /lib/ld-musl-x86_64.so.1\n";
        assert_eq!(
            classify_maps(maps),
            MapChoice::Probe {
                kind: AllocatorKind::Musl,
                mapped_path: "/lib/ld-musl-x86_64.so.1".to_string(),
            }
        );
    }

    #[test]
    fn versioned_glibc_name_is_selected() {
        let maps = "7f000-7f100 r-xp 00000000 08:01 2 /lib/libc-2.39.so\n";
        assert_eq!(
            classify_maps(maps),
            MapChoice::Probe {
                kind: AllocatorKind::Glibc,
                mapped_path: "/lib/libc-2.39.so".to_string(),
            }
        );
    }

    #[test]
    fn jemalloc_wins_over_libc() {
        let maps = "\
7f000-7f100 r-xp 00000000 08:01 1 /usr/lib/libc.so.6\n\
7f200-7f300 r-xp 00000000 08:01 9 /usr/lib/libjemalloc.so.2\n";
        assert_eq!(
            classify_maps(maps),
            MapChoice::Unsupported {
                library: "libjemalloc.so.2".to_string(),
            }
        );
    }

    #[test]
    fn heap_and_libcplusplus_are_not_allocators() {
        let maps = "\
55a000-55b000 rw-p 00000000 00:00 0 [heap]\n\
7f000-7f100 r-xp 00000000 08:01 3 /usr/lib/libc++.so.1\n";
        assert_eq!(classify_maps(maps), MapChoice::NotFound);
    }

    #[test]
    fn pathname_may_contain_spaces() {
        let maps = "7f000-7f100 r-xp 00000000 08:01 4 /opt/my libc/libc.so.6 (deleted)\n";
        assert_eq!(
            classify_maps(maps),
            MapChoice::Probe {
                kind: AllocatorKind::Glibc,
                mapped_path: "/opt/my libc/libc.so.6".to_string(),
            }
        );
    }
}
