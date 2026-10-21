//! One sample of the counters, in the shapes the CLI prints.

use crate::Counters;

pub fn format_terminal(counters: &Counters) -> String {
    format!(
        "allocs {}  frees {}  live_bytes {}  ignored_frees {}  dropped_allocs {}",
        counters.allocs,
        counters.frees,
        counters.live_bytes,
        counters.ignored_frees,
        counters.dropped_allocs
    )
}

pub fn format_plain(counters: &Counters) -> String {
    format!(
        "{} {} {} {} {}",
        counters.allocs,
        counters.frees,
        counters.live_bytes,
        counters.ignored_frees,
        counters.dropped_allocs
    )
}

pub fn format_json(counters: &Counters) -> String {
    format!(
        "{{\"allocs\":{},\"frees\":{},\"live_bytes\":{},\"ignored_frees\":{},\"dropped_allocs\":{}}}",
        counters.allocs,
        counters.frees,
        counters.live_bytes,
        counters.ignored_frees,
        counters.dropped_allocs
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Counters {
        Counters {
            allocs: 12,
            frees: 3,
            live_bytes: 36_864,
            ignored_frees: 1,
            dropped_allocs: 0,
        }
    }

    #[test]
    fn plain_is_five_columns() {
        assert_eq!(format_plain(&sample()), "12 3 36864 1 0");
    }

    #[test]
    fn json_is_one_object() {
        assert_eq!(
            format_json(&sample()),
            "{\"allocs\":12,\"frees\":3,\"live_bytes\":36864,\"ignored_frees\":1,\"dropped_allocs\":0}"
        );
    }

    #[test]
    fn terminal_names_each_field() {
        assert_eq!(
            format_terminal(&sample()),
            "allocs 12  frees 3  live_bytes 36864  ignored_frees 1  dropped_allocs 0"
        );
    }
}
