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
