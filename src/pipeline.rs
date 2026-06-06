use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, bail};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use rayon::prelude::*;

use crate::cli::Cli;
use crate::gpg;
use crate::i18n;
use crate::sanitize::{RawRow, build_entry, sanitize_path};
use crate::store::{RecipientCache, build_entry_path, resolve_store_dir};

const REQUIRED_COLUMNS: &[&str] = &["Title", "Password"];

pub fn run(args: Cli) -> Result<u8> {
    if !args.csv_file.is_file() {
        bail!(i18n::err_file_not_found(&args.csv_file));
    }
    if !args.dry_run {
        gpg::ensure_gpg_available()?;
    }

    let store_dir = resolve_store_dir(args.store_dir.clone())?;
    if !args.dry_run && !store_dir.is_dir() {
        bail!(i18n::err_store_dir_missing(&store_dir));
    }
    let recipients = Arc::new(RecipientCache::new(store_dir.clone()));

    if let Some(jobs) = args.jobs {
        rayon::ThreadPoolBuilder::new()
            .num_threads(jobs.max(1))
            .build_global()
            .context(i18n::err_rayon_pool())?;
    }

    let file =
        std::fs::File::open(&args.csv_file).with_context(|| i18n::err_open(&args.csv_file))?;
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(std::io::BufReader::with_capacity(1 << 20, file));

    let headers = reader.headers().context(i18n::err_csv_header())?.clone();
    let header_set: std::collections::HashSet<&str> = headers.iter().collect();
    let missing: Vec<&str> = REQUIRED_COLUMNS
        .iter()
        .copied()
        .filter(|c| !header_set.contains(c))
        .collect();
    if !missing.is_empty() {
        bail!(i18n::err_missing_columns(&missing));
    }

    let prefix = args.prefix.trim_matches('/').to_string();
    let pb = make_progress(args.no_progress);

    let counters = Counters::default();
    let force = args.force;
    let dry_run = args.dry_run;
    let skip_existing = args.skip_existing;
    let store_dir_ref: &Path = &store_dir;

    let handle_outcome = |outcome: Outcome| {
        match outcome {
            Outcome::Imported => counters.imported.fetch_add(1, Ordering::Relaxed),
            Outcome::Skipped => counters.skipped.fetch_add(1, Ordering::Relaxed),
            Outcome::Failed => counters.failed.fetch_add(1, Ordering::Relaxed),
        };
        pb.inc(1);
    };

    // dry-run does no I/O, so parallelism buys nothing and only garbles stdout.
    if dry_run {
        for (idx, parse_res) in reader.deserialize::<RawRow>().enumerate() {
            handle_outcome(process_row(
                parse_res,
                idx + 2,
                &prefix,
                store_dir_ref,
                &recipients,
                force,
                true,
                skip_existing,
            ));
        }
    } else {
        reader
            .deserialize::<RawRow>()
            .enumerate()
            .par_bridge()
            .for_each(|(idx, parse_res)| {
                let lineno = idx + 2; // line 1 is the header
                handle_outcome(process_row(
                    parse_res,
                    lineno,
                    &prefix,
                    store_dir_ref,
                    &recipients,
                    force,
                    false,
                    skip_existing,
                ));
            });
    }

    pb.finish_and_clear();

    let imported = counters.imported.load(Ordering::Relaxed);
    let skipped = counters.skipped.load(Ordering::Relaxed);
    let failed = counters.failed.load(Ordering::Relaxed);
    eprintln!("{}", i18n::final_summary(imported, skipped, failed));

    Ok(if failed == 0 { 0 } else { 1 })
}

#[derive(Default)]
struct Counters {
    imported: AtomicU64,
    skipped: AtomicU64,
    failed: AtomicU64,
}

enum Outcome {
    Imported,
    Skipped,
    Failed,
}

#[allow(clippy::too_many_arguments)]
fn process_row(
    parse_res: csv::Result<RawRow>,
    lineno: usize,
    prefix: &str,
    store_dir: &Path,
    recipients: &RecipientCache,
    force: bool,
    dry_run: bool,
    skip_existing: bool,
) -> Outcome {
    let mut row = match parse_res {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", i18n::parse_error(lineno, &e));
            return Outcome::Failed;
        }
    };

    let title = sanitize_path(&row.title);
    if title.is_empty() {
        row.zeroize_in_place();
        return Outcome::Skipped;
    }
    if row.password.trim().is_empty() {
        eprintln!("{}", i18n::skip_no_password(lineno, &title));
        row.zeroize_in_place();
        return Outcome::Skipped;
    }

    let out_path = match build_entry_path(store_dir, prefix, &title) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", i18n::row_error(lineno, &title, &e));
            row.zeroize_in_place();
            return Outcome::Failed;
        }
    };

    if dry_run {
        let plaintext = build_entry(&row);
        let pw_len = row.password.trim().len();
        let body = String::from_utf8_lossy(&plaintext);
        let mut lines = body.lines();
        let _ = lines.next();
        println!("--- {} ---", out_path.display());
        println!("{}", i18n::dry_password_label(pw_len));
        for l in lines {
            println!("{l}");
        }
        println!();
        // plaintext (Zeroizing) is wiped now, row follows right after.
        row.zeroize_in_place();
        return Outcome::Imported;
    }

    if !force && out_path.exists() {
        if !skip_existing {
            eprintln!("{}", i18n::skip_exists(&out_path));
        }
        row.zeroize_in_place();
        return Outcome::Skipped;
    }

    let parent = out_path.parent().expect("entry has a parent directory");
    let recps = match recipients.recipients_for(parent) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", i18n::row_error(lineno, &title, &e));
            row.zeroize_in_place();
            return Outcome::Failed;
        }
    };

    let plaintext = build_entry(&row);
    let res = gpg::encrypt_to_file(&recps, &plaintext, &out_path);
    // plaintext is wiped by Zeroizing's drop impl.
    drop(plaintext);
    row.zeroize_in_place();

    match res {
        Ok(()) => Outcome::Imported,
        Err(e) => {
            eprintln!("{}", i18n::row_error(lineno, &title, &e));
            Outcome::Failed
        }
    }
}

fn make_progress(no_progress: bool) -> ProgressBar {
    if no_progress {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new_spinner();
    pb.set_draw_target(ProgressDrawTarget::stderr_with_hz(8));
    pb.set_style(ProgressStyle::with_template(i18n::progress_template()).unwrap());
    pb
}
