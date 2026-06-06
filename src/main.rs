use std::process::ExitCode;

use clap::{CommandFactory, FromArgMatches};
use rspassimpt::{cli, i18n, pipeline};

fn main() -> ExitCode {
    i18n::detect();

    let cmd = cli::Cli::command()
        .about(i18n::about())
        .long_about(i18n::long_about())
        .mut_arg("csv_file", |a| a.help(i18n::help_csv_file()))
        .mut_arg("prefix", |a| a.help(i18n::help_prefix()))
        .mut_arg("force", |a| a.help(i18n::help_force()))
        .mut_arg("dry_run", |a| a.help(i18n::help_dry_run()))
        .mut_arg("skip_existing", |a| a.help(i18n::help_skip_existing()))
        .mut_arg("store_dir", |a| a.help(i18n::help_store_dir()))
        .mut_arg("jobs", |a| a.help(i18n::help_jobs()))
        .mut_arg("no_progress", |a| a.help(i18n::help_no_progress()));

    let matches = cmd.get_matches();
    let args = match cli::Cli::from_arg_matches(&matches) {
        Ok(a) => a,
        Err(e) => {
            e.print().ok();
            return ExitCode::from(2);
        }
    };

    match pipeline::run(args) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("{}", i18n::fatal(&e));
            ExitCode::from(2)
        }
    }
}
