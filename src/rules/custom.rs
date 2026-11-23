//! The client's own rules (ADR-0057): the folder a scan reads them from.
//! The rules themselves are loaded with the catalog's
//! (`rules::catalog::load_rules`, origin `Client`) and shown in the
//! report's "Custom rules" section.
//!
//! Shared by both builds since ADR-0057: before it, the private build
//! alone read this folder (ADR-0041).

use std::path::PathBuf;

/// Custom rules folder of a scan (ticket #84): `--custom-rules-dir`, else
/// [`default_custom_rules_dir`]. `None` with an explicit `--rules <PATH>`:
/// an isolated test catalog must never see the custom rules slip in. The
/// folder does not need to exist: the scan checks `is_dir()` before any
/// read, a missing default is silent.
pub fn resolve_custom_rules_dir(
    explicit_rules: bool,
    custom_rules_dir: Option<PathBuf>,
) -> Option<PathBuf> {
    if explicit_rules {
        return None;
    }
    custom_rules_dir.or_else(default_custom_rules_dir)
}

/// Default custom rules folder: `.codefixture-audit/custom-rules` in the
/// user's home (`~` on macOS and Linux, `%USERPROFILE%` on Windows).
/// Deliberate deviation from Python's `{SCRIPT_DIR}/custom-rules/` and from
/// the former default next to the executable (ADR-0039): next to a binary
/// built from source, the folder sat in `target/`, which `cargo clean`
/// deletes. The client's own rules must never be deleted by a build, an
/// update or a reinstall. `None` only when no home folder is known.
pub fn default_custom_rules_dir() -> Option<PathBuf> {
    std::env::home_dir().map(|home| home.join(".codefixture-audit").join("custom-rules"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ticket #84: custom rules are never mixed into an explicit
    /// `--rules <PATH>`; otherwise the given folder, else
    /// `~/.codefixture-audit/custom-rules` (ADR-0039, kept by ADR-0040).
    #[test]
    fn test_resolve_custom_rules_dir_ignored_with_explicit_rules() {
        let given = Some(PathBuf::from("/tmp/my-rules"));
        assert_eq!(resolve_custom_rules_dir(true, given.clone()), None);
        assert_eq!(resolve_custom_rules_dir(false, given.clone()), given);
        let default = resolve_custom_rules_dir(false, None).expect("home is known");
        assert!(
            default.ends_with(".codefixture-audit/custom-rules"),
            "{}",
            default.display()
        );
        assert!(
            !default.starts_with(std::env::current_exe().unwrap().parent().unwrap()),
            "never next to the binary, where a build can delete it"
        );
    }
}
