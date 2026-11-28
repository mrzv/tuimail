//! Opt-in latency measurements. No mailbox, message or server data is logged.

use std::io::{IsTerminal as _, Write as _};
use std::sync::LazyLock;
use std::time::Instant;

static ENABLED: LazyLock<bool> = LazyLock::new(|| {
    std::env::var_os("TM_IMAP_TIMINGS").is_some_and(|v| v == "1")
        && !std::io::stderr().is_terminal()
});

pub(crate) fn start() -> Option<Instant> {
    (*ENABLED).then(Instant::now)
}

pub(crate) fn finish(started: Option<Instant>, stage: &'static str, bytes: Option<usize>) {
    let Some(started) = started else { return };
    let ms = started.elapsed().as_secs_f64() * 1_000.0;
    let mut log = std::io::stderr().lock();
    let _ = match bytes {
        Some(n) => writeln!(log, "tuimail imap {stage}: {ms:.1} ms, {n} bytes"),
        None => writeln!(log, "tuimail imap {stage}: {ms:.1} ms"),
    };
}
