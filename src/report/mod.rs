//! HTML/JSON report generation — port of `Audit/sca/report.py`.

pub mod audit_params;
pub mod brand;
pub mod category_examples;
pub mod comparison;
pub mod comparison_html;
pub mod compliance;
pub mod compliance_html;
pub mod cwe_catalog;
pub mod data;
pub mod export_json;
pub mod exports;
pub mod findings_html;
pub mod fix_proposal;
pub mod html;
#[cfg(test)]
mod html_languages;
pub mod locale_format;
pub mod playbook;
pub mod priorities;
pub mod report_assets;
pub mod successes;
pub mod summary_html;
pub mod system_html;
pub mod text;
