use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::i18n;

/// Encrypt `plaintext` for every recipient in `recipients` and atomically
/// write the result to `out_path`.
///
/// Only the public key is used (`gpg --encrypt -r`), so no passphrase is
/// required — bulk import runs without pinentry prompts. When `recipients`
/// contains multiple keys, the file is encrypted to all of them at once
/// (pass convention).
pub fn encrypt_to_file(recipients: &[String], plaintext: &[u8], out_path: &Path) -> Result<()> {
    let parent = out_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!(i18n::err_no_parent(out_path)))?;
    std::fs::create_dir_all(parent).with_context(|| i18n::err_mkdir(parent))?;

    let mut cmd = Command::new("gpg");
    cmd.arg("--batch")
        .arg("--yes")
        .arg("--quiet")
        .arg("--no-tty")
        .arg("--trust-model")
        .arg("always")
        .arg("--encrypt");
    for r in recipients {
        cmd.arg("--recipient").arg(r);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().context(i18n::err_spawn_gpg())?;
    {
        let mut stdin = child.stdin.take().expect("stdin was piped");
        // Feed the secret to gpg via stdin — never argv, never a tmpfile.
        stdin.write_all(plaintext).context(i18n::err_gpg_stdin())?;
        // stdin is closed when this scope ends (drop), giving gpg EOF.
    }
    let output = child.wait_with_output().context(i18n::err_gpg_wait())?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(i18n::err_gpg_failed(&output.status, stderr.trim()));
    }

    // Atomic write: a .tmp file in the same directory, then rename.
    let mut tmp = tempfile::Builder::new()
        .prefix(".rspassimpt-")
        .suffix(".gpg.tmp")
        .tempfile_in(parent)
        .with_context(|| i18n::err_mktemp(parent))?;
    tmp.as_file_mut()
        .write_all(&output.stdout)
        .context(i18n::err_write_blob())?;
    tmp.as_file_mut().sync_all().context(i18n::err_fsync())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(tmp.path(), perms).context(i18n::err_chmod())?;
    }

    tmp.persist(out_path)
        .map_err(|e| anyhow::anyhow!(i18n::err_rename(out_path, &e.error)))?;
    Ok(())
}

/// Check that the `gpg` binary is available on PATH (without running it).
pub fn ensure_gpg_available() -> Result<()> {
    if which_gpg().is_some() {
        return Ok(());
    }
    bail!(i18n::err_gpg_not_in_path());
}

fn which_gpg() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("gpg");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
