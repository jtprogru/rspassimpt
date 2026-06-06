use std::path::PathBuf;

use clap::Parser;

/// CLI structure for clap derive. `about`/`help` texts are swapped in `main`
/// via `mut_arg` once the active language is known — see `i18n.rs`.
#[derive(Debug, Parser)]
#[command(name = "rspassimpt", version)]
pub struct Cli {
    pub csv_file: PathBuf,

    #[arg(long, default_value = "")]
    pub prefix: String,

    #[arg(long)]
    pub force: bool,

    #[arg(long)]
    pub dry_run: bool,

    #[arg(long)]
    pub skip_existing: bool,

    #[arg(long)]
    pub store_dir: Option<PathBuf>,

    #[arg(long, short = 'j')]
    pub jobs: Option<usize>,

    #[arg(long)]
    pub no_progress: bool,
}
