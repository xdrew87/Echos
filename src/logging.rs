use std::path::Path;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

fn make_filter(verbose: bool, quiet: bool) -> EnvFilter {
    let level = if verbose { "debug" } else if quiet { "warn" } else { "info" };
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level))
}

fn file_appender(path: &Path) -> tracing_appender::rolling::RollingFileAppender {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let fname = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("echos.log"));
    tracing_appender::rolling::never(dir, fname)
}

pub fn init(
    verbose: bool,
    quiet: bool,
    json: bool,
    log_file: Option<&Path>,
) -> Option<tracing_appender::non_blocking::WorkerGuard> {
    match (json, log_file) {
        (false, None) => {
            tracing_subscriber::registry()
                .with(make_filter(verbose, quiet))
                .with(fmt::layer().with_target(false))
                .init();
            None
        }
        (true, None) => {
            tracing_subscriber::registry()
                .with(make_filter(verbose, quiet))
                .with(fmt::layer().json())
                .init();
            None
        }
        (false, Some(p)) => {
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender(p));
            tracing_subscriber::registry()
                .with(make_filter(verbose, quiet))
                .with(fmt::layer().with_target(false))
                .with(fmt::layer().json().with_ansi(false).with_writer(non_blocking))
                .init();
            Some(guard)
        }
        (true, Some(p)) => {
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender(p));
            tracing_subscriber::registry()
                .with(make_filter(verbose, quiet))
                .with(fmt::layer().json())
                .with(fmt::layer().json().with_ansi(false).with_writer(non_blocking))
                .init();
            Some(guard)
        }
    }
}
