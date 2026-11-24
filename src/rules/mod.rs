//! Where rules come from (ADR-0040): the catalog pack `rules.cfpack`
//! next to the binary (or `--rules <PATH>`), plus the client's own rules
//! (`custom`, ADR-0057). The rule sources themselves live in
//! `rules/builtin` of the private repository. Rule test cases
//! (`cases`) and the rule wizard (`wizard`) serve both the catalog and
//! the client's rules.

pub mod cases;
pub mod catalog;
pub mod custom;
pub mod identity;
pub mod pack_format;
pub mod rules_crypto;
pub mod wizard;

/// A number of a `pack_format::PackError` (a size, a count, a format
/// number) as the console of `script_locale` writes it: `1,073,741,824`,
/// `1 073 741 824`, `1.073.741.824`. `pack_format` reaches it as
/// `super::pack_number_text`; `build.rs`, which compiles `pack_format`
/// without i18n, defines its own with the plain digits.
pub(crate) fn pack_number_text(script_locale: &serde_json::Value, n: u64) -> String {
    crate::report::locale_format::LocaleFormat::of_console(script_locale).int(n)
}
