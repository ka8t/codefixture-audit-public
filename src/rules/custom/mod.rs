//! The client's own rules (ADR-0057): the folder a scan reads them from,
//! and the tools that write them there.
//! The rules themselves are loaded with the catalog's
//! (`rules::catalog::load_rules`, origin `Client`) and shown in the
//! report's "Custom rules" section.
//!
//! Shared by both builds since ADR-0057: before it, the private build
//! alone read this folder (ADR-0041).
//!
//! - [`create`]: the wizard that writes a rule into this folder
//!   (`custom-rules create`, ticket #275);
//! - [`skeleton`]: the test cases it adds for each rule, kept in
//!   `cases/` of this folder (ticket #276);
//! - [`try_rule`]: one rule run alone on a project (`custom-rules try`,
//!   ticket #276).
//!
//! The folder is `--custom-rules-dir`, else `CODEFIXTURE_AUDIT_CUSTOM_RULES`,
//! else `~/.codefixture-audit/custom-rules` ([`locate_custom_rules_dir`]);
//! a scan names on the console what it did with it ([`scan_custom_rules`],
//! ticket #292).

pub mod create;
pub mod skeleton;
pub mod try_rule;

use std::ffi::OsString;
use std::path::PathBuf;

/// Environment variable naming the custom rules folder for every scan and
/// every `custom-rules` command of a machine (ticket #292), on the model
/// of `CODEFIXTURE_AUDIT_CPU`: a CI server usually runs under another
/// account than the one whose home holds the rules, so the default folder
/// is not there.
pub const CUSTOM_RULES_VARIABLE: &str = "CODEFIXTURE_AUDIT_CUSTOM_RULES";

/// Where the custom rules folder was named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomRulesOrigin {
    /// `--custom-rules-dir`.
    Option,
    /// [`CUSTOM_RULES_VARIABLE`].
    Environment,
    /// [`default_custom_rules_dir`]: nothing was given.
    Default,
}

/// The custom rules folder and where it was named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomRulesDir {
    /// The folder, as given (or the default one).
    pub path: PathBuf,
    /// Where it was named.
    pub origin: CustomRulesOrigin,
}

/// Why no custom rules folder could be named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomRulesLocationError {
    /// [`CUSTOM_RULES_VARIABLE`] is set but empty: a variable set by
    /// mistake is shown, never passed over (as for `CODEFIXTURE_AUDIT_CPU`).
    EmptyVariable,
    /// Neither the option nor the variable is given, and no home folder is
    /// known for the default one.
    NoHome,
}

/// The custom rules folder from its sources, first given first taken:
/// `option` (`--custom-rules-dir`), else `environment` (the value of
/// [`CUSTOM_RULES_VARIABLE`] as the system gives it, `None` when unset),
/// else the default folder under `home`. Nothing is read on disk: the
/// `custom-rules` commands may name a folder that `create` makes.
pub fn locate_custom_rules_dir(
    option: Option<PathBuf>,
    environment: Option<OsString>,
    home: Option<PathBuf>,
) -> Result<CustomRulesDir, CustomRulesLocationError> {
    if let Some(path) = option {
        return Ok(CustomRulesDir {
            path,
            origin: CustomRulesOrigin::Option,
        });
    }
    if let Some(value) = environment {
        if value.is_empty() {
            return Err(CustomRulesLocationError::EmptyVariable);
        }
        return Ok(CustomRulesDir {
            path: PathBuf::from(value),
            origin: CustomRulesOrigin::Environment,
        });
    }
    home.map(|home| CustomRulesDir {
        path: home_custom_rules_dir(home),
        origin: CustomRulesOrigin::Default,
    })
    .ok_or(CustomRulesLocationError::NoHome)
}

/// [`locate_custom_rules_dir`] with this process's sources: the variable
/// from the environment and the user's home folder.
pub fn locate_custom_rules_dir_here(
    option: Option<PathBuf>,
) -> Result<CustomRulesDir, CustomRulesLocationError> {
    locate_custom_rules_dir(
        option,
        std::env::var_os(CUSTOM_RULES_VARIABLE),
        std::env::home_dir(),
    )
}

/// What a scan does with the client's rules (ticket #292). Every case is
/// named on the console, so that a scan without the client's rules, a CI
/// job under another account for instance, never passes for one with them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanCustomRules {
    /// The folder exists: its rules are read.
    Read(CustomRulesDir),
    /// The default folder does not exist: the client wrote no rule on this
    /// account, which is the usual case and not an error.
    DefaultMissing(PathBuf),
    /// `--rules <PATH>` was given: an isolated catalog never sees the
    /// client's rules slip in (ticket #84).
    NotRead,
    /// No folder could be named: no option, no variable, no home folder.
    NoHome,
}

/// Why a scan stops on the client's rules folder (exit code 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanCustomRulesError {
    /// [`CUSTOM_RULES_VARIABLE`] is set but empty.
    EmptyVariable,
    /// The folder given with `--custom-rules-dir` or the variable does not
    /// exist. Given explicitly, it is expected: scanning without it would
    /// leave the client's rules out without a word.
    Missing(CustomRulesDir),
    /// The path exists but is not a folder.
    NotAFolder(CustomRulesDir),
}

/// What a scan does with the client's rules, from `--rules` being given
/// (`explicit_rules`) and the located folder. Before 2026-11-25, a folder
/// that was absent, whoever named it, was skipped without a word.
pub fn scan_custom_rules(
    explicit_rules: bool,
    located: Result<CustomRulesDir, CustomRulesLocationError>,
) -> Result<ScanCustomRules, ScanCustomRulesError> {
    if explicit_rules {
        return Ok(ScanCustomRules::NotRead);
    }
    let dir = match located {
        Ok(dir) => dir,
        Err(CustomRulesLocationError::EmptyVariable) => {
            return Err(ScanCustomRulesError::EmptyVariable);
        }
        Err(CustomRulesLocationError::NoHome) => return Ok(ScanCustomRules::NoHome),
    };
    if dir.path.is_dir() {
        Ok(ScanCustomRules::Read(dir))
    } else if dir.path.exists() {
        Err(ScanCustomRulesError::NotAFolder(dir))
    } else if dir.origin == CustomRulesOrigin::Default {
        Ok(ScanCustomRules::DefaultMissing(dir.path))
    } else {
        Err(ScanCustomRulesError::Missing(dir))
    }
}

/// Default custom rules folder: `.codefixture-audit/custom-rules` in the
/// user's home (`~` on macOS and Linux, `%USERPROFILE%` on Windows).
/// Deliberate deviation from Python's `{SCRIPT_DIR}/custom-rules/` and from
/// the former default next to the executable (ADR-0039): next to a binary
/// built from source, the folder sat in `target/`, which `cargo clean`
/// deletes. The client's own rules must never be deleted by a build, an
/// update or a reinstall. `None` only when no home folder is known.
pub fn default_custom_rules_dir() -> Option<PathBuf> {
    std::env::home_dir().map(home_custom_rules_dir)
}

/// The default custom rules folder under the home folder `home`.
fn home_custom_rules_dir(home: PathBuf) -> PathBuf {
    home.join(".codefixture-audit").join("custom-rules")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn located(path: &str, origin: CustomRulesOrigin) -> CustomRulesDir {
        CustomRulesDir {
            path: PathBuf::from(path),
            origin,
        }
    }

    /// Ticket #292: the option first, then the variable, then the default
    /// folder of the home; an empty variable is an error, never skipped.
    #[test]
    fn test_locate_custom_rules_dir_takes_option_then_variable_then_home() {
        let home = Some(PathBuf::from("/home/me"));
        assert_eq!(
            locate_custom_rules_dir(
                Some(PathBuf::from("/opt/rules")),
                Some("/srv/rules".into()),
                home.clone()
            ),
            Ok(located("/opt/rules", CustomRulesOrigin::Option))
        );
        assert_eq!(
            locate_custom_rules_dir(None, Some("/srv/rules".into()), home.clone()),
            Ok(located("/srv/rules", CustomRulesOrigin::Environment))
        );
        let default = locate_custom_rules_dir(None, None, home.clone()).unwrap();
        assert_eq!(default.origin, CustomRulesOrigin::Default);
        assert!(
            default.path.ends_with(".codefixture-audit/custom-rules"),
            "{}",
            default.path.display()
        );
        assert_eq!(
            locate_custom_rules_dir(None, Some(OsString::new()), home),
            Err(CustomRulesLocationError::EmptyVariable)
        );
        assert_eq!(
            locate_custom_rules_dir(None, None, None),
            Err(CustomRulesLocationError::NoHome)
        );
    }

    /// The default folder is never next to the binary, where a build can
    /// delete it (ADR-0039, kept by ADR-0040).
    #[test]
    fn test_default_custom_rules_dir_is_not_next_to_the_binary() {
        let default = default_custom_rules_dir().expect("home is known");
        assert!(
            !default.starts_with(std::env::current_exe().unwrap().parent().unwrap()),
            "never next to the binary, where a build can delete it"
        );
    }

    /// Ticket #292: what a scan does with each kind of folder. A missing
    /// default folder is the usual case; a missing folder that was named
    /// explicitly, or a path that is not a folder, stops the scan.
    #[test]
    fn test_scan_custom_rules_names_every_case() {
        let dir = std::env::temp_dir().join(format!("sast-custom-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("rules")).unwrap();
        std::fs::write(dir.join("file"), "").unwrap();
        let at = |name: &str, origin| CustomRulesDir {
            path: dir.join(name),
            origin,
        };

        assert_eq!(
            scan_custom_rules(true, Ok(at("rules", CustomRulesOrigin::Option))),
            Ok(ScanCustomRules::NotRead),
            "--rules: never read (ticket #84)"
        );
        assert_eq!(
            scan_custom_rules(false, Ok(at("rules", CustomRulesOrigin::Environment))),
            Ok(ScanCustomRules::Read(at(
                "rules",
                CustomRulesOrigin::Environment
            )))
        );
        assert_eq!(
            scan_custom_rules(false, Ok(at("absent", CustomRulesOrigin::Default))),
            Ok(ScanCustomRules::DefaultMissing(dir.join("absent")))
        );
        for origin in [CustomRulesOrigin::Option, CustomRulesOrigin::Environment] {
            assert_eq!(
                scan_custom_rules(false, Ok(at("absent", origin))),
                Err(ScanCustomRulesError::Missing(at("absent", origin)))
            );
        }
        assert_eq!(
            scan_custom_rules(false, Ok(at("file", CustomRulesOrigin::Default))),
            Err(ScanCustomRulesError::NotAFolder(at(
                "file",
                CustomRulesOrigin::Default
            )))
        );
        assert_eq!(
            scan_custom_rules(false, Err(CustomRulesLocationError::EmptyVariable)),
            Err(ScanCustomRulesError::EmptyVariable)
        );
        assert_eq!(
            scan_custom_rules(false, Err(CustomRulesLocationError::NoHome)),
            Ok(ScanCustomRules::NoHome)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
