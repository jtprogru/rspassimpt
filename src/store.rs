use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::RwLock;

use anyhow::{Context, Result, anyhow, bail};

use crate::i18n;

/// Pass store directory: the explicit one, $PASSWORD_STORE_DIR, or ~/.password-store.
pub fn resolve_store_dir(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if let Ok(v) = std::env::var("PASSWORD_STORE_DIR")
        && !v.is_empty()
    {
        return Ok(PathBuf::from(v));
    }
    let home = dirs::home_dir().ok_or_else(|| anyhow!(i18n::err_no_home()))?;
    Ok(home.join(".password-store"))
}

/// Safely join the prefix and entry's relative path inside the store.
///
/// Guarantees the resulting path stays under `store_dir` (defense against
/// `..` in Title).
pub fn build_entry_path(store_dir: &Path, prefix: &str, rel: &str) -> Result<PathBuf> {
    let prefix = prefix.trim_matches('/');
    let combined = if prefix.is_empty() {
        rel.to_string()
    } else {
        format!("{prefix}/{rel}")
    };

    // Reject any component that could escape the store.
    let rel_path = PathBuf::from(&combined);
    for c in rel_path.components() {
        match c {
            Component::Normal(_) => {}
            _ => bail!(i18n::err_bad_path_component(c, &combined)),
        }
    }

    let mut out = store_dir.join(&rel_path);
    let new_name = match out.file_name() {
        Some(name) => {
            let mut s = name.to_os_string();
            s.push(".gpg");
            s
        }
        None => bail!(i18n::err_empty_filename(&combined)),
    };
    out.set_file_name(new_name);
    Ok(out)
}

/// Recipients cache: directory → recipients.
///
/// pass supports hierarchical .gpg-id files — for each entry we walk up
/// from its directory to the store root and pick the closest `.gpg-id`.
pub struct RecipientCache {
    store_dir: PathBuf,
    map: RwLock<HashMap<PathBuf, Vec<String>>>,
}

impl RecipientCache {
    pub fn new(store_dir: PathBuf) -> Self {
        Self {
            store_dir,
            map: RwLock::new(HashMap::new()),
        }
    }

    /// Return the recipients for an entry located in `entry_dir` (absolute path).
    pub fn recipients_for(&self, entry_dir: &Path) -> Result<Vec<String>> {
        if let Some(cached) = self.map.read().unwrap().get(entry_dir) {
            return Ok(cached.clone());
        }
        let recipients = self.lookup(entry_dir)?;
        self.map
            .write()
            .unwrap()
            .insert(entry_dir.to_path_buf(), recipients.clone());
        Ok(recipients)
    }

    fn lookup(&self, entry_dir: &Path) -> Result<Vec<String>> {
        let mut cur = entry_dir.to_path_buf();
        loop {
            let candidate = cur.join(".gpg-id");
            if candidate.is_file() {
                let content = std::fs::read_to_string(&candidate)
                    .with_context(|| i18n::err_read(&candidate))?;
                let recipients: Vec<String> = content
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect();
                if recipients.is_empty() {
                    bail!(i18n::err_gpg_id_empty(&candidate));
                }
                return Ok(recipients);
            }
            if cur == self.store_dir {
                bail!(i18n::err_no_gpg_id(&self.store_dir));
            }
            match cur.parent() {
                Some(p) => cur = p.to_path_buf(),
                None => bail!(i18n::err_no_gpg_id_fs_root()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_entry_path_basic() {
        let store = Path::new("/store");
        let p = build_entry_path(store, "", "a/b").unwrap();
        assert_eq!(p, PathBuf::from("/store/a/b.gpg"));
    }

    #[test]
    fn build_entry_path_with_prefix() {
        let store = Path::new("/store");
        let p = build_entry_path(store, "imported/macos", "site").unwrap();
        assert_eq!(p, PathBuf::from("/store/imported/macos/site.gpg"));
    }

    #[test]
    fn build_entry_path_rejects_traversal() {
        let store = Path::new("/store");
        assert!(build_entry_path(store, "", "../etc/passwd").is_err());
        assert!(build_entry_path(store, "..", "a").is_err());
        assert!(build_entry_path(store, "", "/abs").is_err());
    }
}
