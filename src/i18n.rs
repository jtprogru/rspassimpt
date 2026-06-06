//! Minimal in-house localization with no external dependencies.
//!
//! The active language is detected once at startup from the environment
//! variables `LC_ALL` → `LC_MESSAGES` → `LANG` (same order as gettext).
//! A locale starting with `ru` selects Russian; anything else falls back
//! to English.
//!
//! Each message is its own function: either `&'static str` (no parameters)
//! or `String` (parameters via `format!`). This is more type-safe and
//! simpler than a runtime template engine.

use std::path::Path;
use std::sync::OnceLock;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Lang {
    Ru,
    En,
}

static LANG: OnceLock<Lang> = OnceLock::new();

/// Detect the language from environment variables. Called once at startup.
pub fn detect() {
    let raw = std::env::var("LC_ALL")
        .or_else(|_| std::env::var("LC_MESSAGES"))
        .or_else(|_| std::env::var("LANG"))
        .unwrap_or_default()
        .to_ascii_lowercase();
    let lang = if raw.starts_with("ru") {
        Lang::Ru
    } else {
        Lang::En
    };
    let _ = LANG.set(lang);
}

pub fn lang() -> Lang {
    *LANG.get().unwrap_or(&Lang::En)
}

// ============================================================================
// CLI help
// ============================================================================

pub fn about() -> &'static str {
    match lang() {
        Lang::Ru => "Импорт паролей из CSV-экспорта macOS Passwords в `pass` (passwordstore.org)",
        Lang::En => {
            "Import passwords from a macOS Passwords CSV export into `pass` (passwordstore.org)"
        }
    }
}

pub fn long_about() -> &'static str {
    match lang() {
        Lang::Ru => {
            "Импортирует записи из CSV-экспорта macOS Passwords напрямую в хранилище pass.\n\
                     Шифрование выполняется через локальный gpg (только публичным ключом получателя из \
                     $PASSWORD_STORE_DIR/.gpg-id), мастер-пароль для этого не требуется.\n\
                     Записи кладутся в формате passwordstore.org: первая строка — пароль, далее \
                     пары key: value (user/url/otpauth) и опциональный блок notes."
        }
        Lang::En => {
            "Imports records from a macOS Passwords CSV export directly into the pass store.\n\
                     Encryption goes through local gpg using only the recipient public key from \
                     $PASSWORD_STORE_DIR/.gpg-id — no master passphrase is required.\n\
                     Each entry follows the passwordstore.org layout: password on the first line, \
                     then key: value pairs (user/url/otpauth) and an optional notes block."
        }
    }
}

pub fn help_csv_file() -> &'static str {
    match lang() {
        Lang::Ru => "CSV-файл экспорта (колонки: Title, URL, Username, Password, Notes, OTPAuth)",
        Lang::En => "CSV export file (columns: Title, URL, Username, Password, Notes, OTPAuth)",
    }
}

pub fn help_prefix() -> &'static str {
    match lang() {
        Lang::Ru => "Префикс пути в хранилище pass (например, `imported/macos`)",
        Lang::En => "Path prefix inside the pass store (e.g. `imported/macos`)",
    }
}

pub fn help_force() -> &'static str {
    match lang() {
        Lang::Ru => "Перезаписывать существующие entry",
        Lang::En => "Overwrite existing entries",
    }
}

pub fn help_dry_run() -> &'static str {
    match lang() {
        Lang::Ru => {
            "Только показать, что было бы сделано (ничего не пишется, пароли не печатаются)"
        }
        Lang::En => "Only show what would happen (nothing is written, passwords are not printed)",
    }
}

pub fn help_skip_existing() -> &'static str {
    match lang() {
        Lang::Ru => "Тихо пропускать уже существующие entry (вместо ошибки)",
        Lang::En => "Silently skip already-existing entries (instead of erroring)",
    }
}

pub fn help_store_dir() -> &'static str {
    match lang() {
        Lang::Ru => {
            "Каталог хранилища pass (по умолчанию $PASSWORD_STORE_DIR или ~/.password-store)"
        }
        Lang::En => "Pass store directory (defaults to $PASSWORD_STORE_DIR or ~/.password-store)",
    }
}

pub fn help_jobs() -> &'static str {
    match lang() {
        Lang::Ru => "Число параллельных воркеров (по умолчанию = число CPU)",
        Lang::En => "Number of parallel workers (defaults to CPU count)",
    }
}

pub fn help_no_progress() -> &'static str {
    match lang() {
        Lang::Ru => "Не показывать прогресс-бар (полезно для скриптов и CI)",
        Lang::En => "Hide the progress bar (useful for scripts and CI)",
    }
}

// ============================================================================
// Runtime errors / messages
// ============================================================================

pub fn err_file_not_found(p: &Path) -> String {
    match lang() {
        Lang::Ru => format!("файл не найден: {}", p.display()),
        Lang::En => format!("file not found: {}", p.display()),
    }
}

pub fn err_store_dir_missing(p: &Path) -> String {
    match lang() {
        Lang::Ru => format!(
            "каталог хранилища не существует: {} — запустите `pass init`",
            p.display()
        ),
        Lang::En => format!(
            "store directory does not exist: {} — run `pass init`",
            p.display()
        ),
    }
}

pub fn err_no_home() -> &'static str {
    match lang() {
        Lang::Ru => "не удалось определить домашнюю директорию",
        Lang::En => "could not determine the user's home directory",
    }
}

pub fn err_bad_path_component(c: std::path::Component<'_>, combined: &str) -> String {
    match lang() {
        Lang::Ru => format!("недопустимый компонент пути: {c:?} (в {combined:?})"),
        Lang::En => format!("invalid path component: {c:?} (in {combined:?})"),
    }
}

pub fn err_empty_filename(combined: &str) -> String {
    match lang() {
        Lang::Ru => format!("пустое имя файла после санитизации: {combined:?}"),
        Lang::En => format!("empty filename after sanitization: {combined:?}"),
    }
}

pub fn err_read(path: &Path) -> String {
    match lang() {
        Lang::Ru => format!("чтение {}", path.display()),
        Lang::En => format!("reading {}", path.display()),
    }
}

pub fn err_open(path: &Path) -> String {
    match lang() {
        Lang::Ru => format!("открытие {}", path.display()),
        Lang::En => format!("opening {}", path.display()),
    }
}

pub fn err_csv_header() -> &'static str {
    match lang() {
        Lang::Ru => "чтение заголовка CSV",
        Lang::En => "reading CSV header",
    }
}

pub fn err_missing_columns(missing: &[&str]) -> String {
    match lang() {
        Lang::Ru => format!("в CSV нет обязательных колонок: {missing:?}"),
        Lang::En => format!("CSV is missing required columns: {missing:?}"),
    }
}

pub fn err_rayon_pool() -> &'static str {
    match lang() {
        Lang::Ru => "настройка пула rayon",
        Lang::En => "configuring the rayon thread pool",
    }
}

pub fn err_gpg_id_empty(path: &Path) -> String {
    match lang() {
        Lang::Ru => format!("{} пустой — добавьте хотя бы один gpg id", path.display()),
        Lang::En => format!("{} is empty — add at least one gpg id", path.display()),
    }
}

pub fn err_no_gpg_id(store_dir: &Path) -> String {
    match lang() {
        Lang::Ru => format!(
            "не найден .gpg-id в {} и выше — хранилище не инициализировано?\n\
             запустите `pass init <gpg-id>`",
            store_dir.display()
        ),
        Lang::En => format!(
            "no .gpg-id found in {} or its parents — is the store initialised?\n\
             run `pass init <gpg-id>`",
            store_dir.display()
        ),
    }
}

pub fn err_no_gpg_id_fs_root() -> &'static str {
    match lang() {
        Lang::Ru => "не найден .gpg-id (достигнут корень файловой системы)",
        Lang::En => "no .gpg-id found (reached filesystem root)",
    }
}

pub fn err_no_parent(path: &Path) -> String {
    match lang() {
        Lang::Ru => format!("у пути нет родителя: {}", path.display()),
        Lang::En => format!("path has no parent: {}", path.display()),
    }
}

pub fn err_mkdir(path: &Path) -> String {
    match lang() {
        Lang::Ru => format!("создание каталога {}", path.display()),
        Lang::En => format!("creating directory {}", path.display()),
    }
}

pub fn err_spawn_gpg() -> &'static str {
    match lang() {
        Lang::Ru => "не удалось запустить gpg (установлен ли он?)",
        Lang::En => "failed to spawn gpg (is it installed?)",
    }
}

pub fn err_gpg_stdin() -> &'static str {
    match lang() {
        Lang::Ru => "запись plaintext в gpg stdin",
        Lang::En => "writing plaintext to gpg stdin",
    }
}

pub fn err_gpg_wait() -> &'static str {
    match lang() {
        Lang::Ru => "ожидание завершения gpg",
        Lang::En => "waiting for gpg to finish",
    }
}

pub fn err_gpg_failed(status: &std::process::ExitStatus, stderr: &str) -> String {
    match lang() {
        Lang::Ru => format!("gpg --encrypt вернул {status}: {stderr}"),
        Lang::En => format!("gpg --encrypt returned {status}: {stderr}"),
    }
}

pub fn err_mktemp(dir: &Path) -> String {
    match lang() {
        Lang::Ru => format!("создание temp-файла в {}", dir.display()),
        Lang::En => format!("creating temp file in {}", dir.display()),
    }
}

pub fn err_write_blob() -> &'static str {
    match lang() {
        Lang::Ru => "запись зашифрованного блоба в temp-файл",
        Lang::En => "writing encrypted blob to temp file",
    }
}

pub fn err_fsync() -> &'static str {
    match lang() {
        Lang::Ru => "fsync temp-файла",
        Lang::En => "fsync on temp file",
    }
}

pub fn err_chmod() -> &'static str {
    match lang() {
        Lang::Ru => "chmod 0600 для temp-файла",
        Lang::En => "chmod 0600 on temp file",
    }
}

pub fn err_rename(path: &Path, e: &dyn std::fmt::Display) -> String {
    match lang() {
        Lang::Ru => format!("атомарный rename в {}: {e}", path.display()),
        Lang::En => format!("atomic rename to {}: {e}", path.display()),
    }
}

pub fn err_gpg_not_in_path() -> &'static str {
    match lang() {
        Lang::Ru => "утилита `gpg` не найдена в PATH — установите GnuPG",
        Lang::En => "`gpg` not found in PATH — please install GnuPG",
    }
}

// ============================================================================
// Per-row status messages
// ============================================================================

pub fn parse_error(lineno: usize, e: &dyn std::fmt::Display) -> String {
    match lang() {
        Lang::Ru => format!("error: строка {lineno}: парсинг CSV: {e}"),
        Lang::En => format!("error: line {lineno}: CSV parse: {e}"),
    }
}

pub fn skip_no_password(lineno: usize, title: &str) -> String {
    match lang() {
        Lang::Ru => format!("skip (нет пароля, строка {lineno}): {title}"),
        Lang::En => format!("skip (no password, line {lineno}): {title}"),
    }
}

pub fn skip_exists(path: &Path) -> String {
    match lang() {
        Lang::Ru => format!(
            "skip (уже существует): {} — запустите с --force или --skip-existing",
            path.display()
        ),
        Lang::En => format!(
            "skip (already exists): {} — re-run with --force or --skip-existing",
            path.display()
        ),
    }
}

pub fn row_error(lineno: usize, title: &str, e: &dyn std::fmt::Display) -> String {
    match lang() {
        Lang::Ru => format!("error: строка {lineno} ({title}): {e:#}"),
        Lang::En => format!("error: line {lineno} ({title}): {e:#}"),
    }
}

pub fn final_summary(imp: u64, skp: u64, fld: u64) -> String {
    match lang() {
        Lang::Ru => format!("готово: импортировано={imp}, пропущено={skp}, ошибок={fld}"),
        Lang::En => format!("done: imported={imp}, skipped={skp}, errors={fld}"),
    }
}

pub fn progress_template() -> &'static str {
    match lang() {
        Lang::Ru => "{spinner:.green} [{elapsed_precise}] {pos} обработано  ({per_sec})",
        Lang::En => "{spinner:.green} [{elapsed_precise}] {pos} processed  ({per_sec})",
    }
}

pub fn dry_password_label(pw_len: usize) -> String {
    match lang() {
        Lang::Ru => format!("<password: {pw_len} chars>"),
        Lang::En => format!("<password: {pw_len} chars>"),
    }
}

pub fn fatal(e: &dyn std::fmt::Display) -> String {
    match lang() {
        Lang::Ru => format!("error: {e:#}"),
        Lang::En => format!("error: {e:#}"),
    }
}
