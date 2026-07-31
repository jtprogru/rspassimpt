use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use rayon::prelude::*;

use crate::cli::Cli;
use crate::gpg::{self, Written};
use crate::i18n;
use crate::sanitize::{RawRow, build_entry, password_has_line_break, sanitize_path};
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
    let dry_run = args.dry_run;

    let ctx = Ctx {
        prefix: &prefix,
        store_dir: &store_dir,
        recipients: &recipients,
        force: args.force,
        dry_run,
        skip_existing: args.skip_existing,
        // A real run detects collisions atomically at rename time, which costs
        // nothing on the hot path. dry-run has no rename to lean on, so it
        // tracks the paths it has emitted in order to predict the same result.
        seen: dry_run.then(|| Mutex::new(HashSet::new())),
    };

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
            handle_outcome(process_row(parse_res, idx + 2, &ctx));
        }
    } else {
        reader
            .deserialize::<RawRow>()
            .enumerate()
            .par_bridge()
            .for_each(|(idx, parse_res)| {
                let lineno = idx + 2; // line 1 is the header
                handle_outcome(process_row(parse_res, lineno, &ctx));
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

/// Everything a row needs, shared across rayon workers.
struct Ctx<'a> {
    prefix: &'a str,
    store_dir: &'a Path,
    recipients: &'a RecipientCache,
    force: bool,
    dry_run: bool,
    skip_existing: bool,
    /// Entry paths already emitted. Only populated for dry-run — see `run`.
    seen: Option<Mutex<HashSet<PathBuf>>>,
}

impl Ctx<'_> {
    /// Record `path` and report whether an earlier row already claimed it.
    fn is_duplicate(&self, path: &Path) -> bool {
        match &self.seen {
            Some(seen) => !seen.lock().unwrap().insert(path.to_path_buf()),
            None => false,
        }
    }
}

fn process_row(parse_res: csv::Result<RawRow>, lineno: usize, ctx: &Ctx<'_>) -> Outcome {
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
    // The store format cannot round-trip such a password, and writing it
    // anyway would truncate the secret at the first newline without a word.
    if password_has_line_break(&row.password) {
        eprintln!("{}", i18n::err_password_line_break(lineno, &title));
        row.zeroize_in_place();
        return Outcome::Failed;
    }

    let out_path = match build_entry_path(ctx.store_dir, ctx.prefix, &title) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}", i18n::row_error(lineno, &title, &e));
            row.zeroize_in_place();
            return Outcome::Failed;
        }
    };

    if ctx.dry_run {
        // Mirror what the real run would do with a colliding title.
        if ctx.is_duplicate(&out_path) && !ctx.force {
            eprintln!("{}", i18n::skip_duplicate_title(lineno, &out_path));
            row.zeroize_in_place();
            return Outcome::Skipped;
        }
        let plaintext = build_entry(&row);
        let pw_len = row.password.len();
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

    // Cheap pre-check that saves spawning gpg for entries that already exist.
    // It is *not* what makes overwriting safe — the no-clobber rename below is.
    if !ctx.force && out_path.exists() {
        if !ctx.skip_existing {
            eprintln!("{}", i18n::skip_exists(&out_path));
        }
        row.zeroize_in_place();
        return Outcome::Skipped;
    }

    let parent = out_path.parent().expect("entry has a parent directory");
    let recps = match ctx.recipients.recipients_for(parent) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", i18n::row_error(lineno, &title, &e));
            row.zeroize_in_place();
            return Outcome::Failed;
        }
    };

    let plaintext = build_entry(&row);
    let res = gpg::encrypt_to_file(&recps, &plaintext, &out_path, ctx.force);
    // plaintext is wiped by Zeroizing's drop impl.
    drop(plaintext);
    row.zeroize_in_place();

    match res {
        Ok(Written::Ok) => Outcome::Imported,
        // Another row won the race for this path between the check above and
        // the rename. Report it like any other pre-existing entry.
        Ok(Written::AlreadyExists) => {
            if !ctx.skip_existing {
                eprintln!("{}", i18n::skip_exists(&out_path));
            }
            Outcome::Skipped
        }
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
