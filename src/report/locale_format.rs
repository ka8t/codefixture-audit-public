//! Dates, times and numbers of the HTML report in the report's language.
//!
//! Each report locale owns its formats (`formats` block of
//! `resources/locales/report/<lang>.json`): the date-and-time pattern of
//! the header and of the baseline, the short pattern of the trend chart's
//! axis, the digit group separator, the decimal separator and the percent
//! pattern. The report used to write every date the French way
//! (`24/11/2026 à 09:47` in an English report, found on 2026-11-24) and
//! every number with a dot and no group separator. No code here knows a
//! language: a fifth locale only needs its own `formats` block.
//!
//! The separators match what the browser's `Intl.NumberFormat` gives for
//! the locale code (`charts.js` formats the charts' numbers with it), so a
//! number reads the same in the text and in the charts: a narrow
//! no-break space for French groups, no group under five digits in
//! Spanish.
//!
//! Deliberate deviation from Audit (`report.py`), which writes the date
//! with one French pattern (`%d/%m/%Y à %H:%M`) whatever the language.

use chrono::NaiveDateTime;
use serde_json::Value;

use crate::i18n::get_nested;

/// The number and date formats of one report language, read once from its
/// locale and used by every renderer of the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocaleFormat {
    /// `strftime` pattern of a full date and time (`November 24, 2026 at
    /// 9:47 AM`, `24/11/2026 à 09:47`).
    datetime: String,
    /// `strftime` pattern of a short date and time, for chart axes.
    datetime_short: String,
    /// Separator between groups of three digits.
    group: String,
    /// Fewest digits a number needs before its groups are separated
    /// beyond the first one: 1 groups from 1 000 on, 2 from 10 000 on
    /// (Spanish usage, as `Intl.NumberFormat("es")`).
    group_min_digits: usize,
    /// Decimal separator.
    decimal: String,
    /// Pattern of a percentage, `{n}` standing for the number.
    percent: String,
    /// What follows a label before its value (`": "`, French `" : "`).
    colon: String,
}

impl LocaleFormat {
    /// The formats of `report_locale`. A locale without a `formats` block
    /// is an error of the embedded files, caught by the tests: every
    /// field then falls back to the English form rather than to nothing.
    pub fn of(report_locale: &Value) -> Self {
        let text = |key: &str, default: &str| -> String {
            get_nested(report_locale, &format!("formats.{key}"))
                .and_then(Value::as_str)
                .unwrap_or(default)
                .to_string()
        };
        let group_min_digits = get_nested(report_locale, "formats.number_group_min_digits")
            .and_then(Value::as_u64)
            .unwrap_or(1) as usize;
        let colon = get_nested(report_locale, "label_colon")
            .and_then(Value::as_str)
            .unwrap_or(": ")
            .to_string();
        LocaleFormat {
            datetime: text("datetime", "%Y-%m-%d %H:%M"),
            datetime_short: text("datetime_short", "%m-%d %H:%M"),
            group: text("number_group", ","),
            group_min_digits,
            decimal: text("decimal", "."),
            percent: text("percent", "{n}%"),
            colon,
        }
    }

    /// A whole number with its digit groups: `11,126`, `11 126`,
    /// `11.126`; `1234` stays whole in Spanish.
    pub fn int(&self, n: impl Into<i128>) -> String {
        let n: i128 = n.into();
        let digits = n.unsigned_abs().to_string();
        let sign = if n < 0 { "-" } else { "" };
        // Groups are separated only when the number has more digits than
        // one group plus the minimum (4 digits with a minimum of 1, 5 with
        // a minimum of 2).
        if digits.len() < 4 + self.group_min_digits - 1 {
            return format!("{sign}{digits}");
        }
        let mut out = String::new();
        for (i, c) in digits.chars().enumerate() {
            if i > 0 && (digits.len() - i).is_multiple_of(3) {
                out.push_str(&self.group);
            }
            out.push(c);
        }
        format!("{sign}{out}")
    }

    /// `x` with `places` decimal places, its trailing zeros removed
    /// (`43.70` → `43,7`), its whole part grouped like [`Self::int`].
    pub fn decimal(&self, x: f64, places: usize) -> String {
        let fixed = format!("{:.*}", places, x.abs());
        let (whole, frac) = match fixed.split_once('.') {
            Some((w, f)) => (w.to_string(), f.trim_end_matches('0').to_string()),
            None => (fixed, String::new()),
        };
        let whole: i128 = whole.parse().unwrap_or(0);
        let sign = if x < 0.0 && (whole != 0 || !frac.is_empty()) {
            "-"
        } else {
            ""
        };
        if frac.is_empty() {
            format!("{sign}{}", self.int(whole))
        } else {
            format!("{sign}{}{}{frac}", self.int(whole), self.decimal)
        }
    }

    /// A percentage from an already formatted number: `45%`, `45 %`.
    pub fn percent_of(&self, number: &str) -> String {
        self.percent.replace("{n}", number)
    }

    /// A whole percentage: `45%`, `45 %`.
    pub fn percent(&self, n: impl Into<i128>) -> String {
        self.percent_of(&self.int(n))
    }

    /// The percent pattern itself (`{n}%`), for the charts.
    pub fn percent_pattern(&self) -> &str {
        &self.percent
    }

    /// The separator between a label and its value.
    pub fn colon(&self) -> &str {
        &self.colon
    }

    /// A date and time in full: `November 24, 2026 at 9:47 AM`.
    pub fn datetime(&self, at: &NaiveDateTime) -> String {
        at.format(&self.datetime).to_string()
    }

    /// A short date and time, for the trend chart: `Nov 18, 9:18 AM`.
    pub fn datetime_short(&self, at: &NaiveDateTime) -> String {
        at.format(&self.datetime_short).to_string()
    }

    /// A scan timestamp as the engine names its files (`2026-11-23-15-47`,
    /// `audit-datas/SCA-DATA-<timestamp>.json`) in full, or the timestamp
    /// itself when it has another shape: it is then shown as it was
    /// written rather than dropped.
    pub fn scan_timestamp(&self, timestamp: &str) -> String {
        match parse_scan_timestamp(timestamp) {
            Some(at) => self.datetime(&at),
            None => timestamp.to_string(),
        }
    }
}

/// Reads a scan timestamp `YYYY-MM-DD-HH-MM`, `None` for another shape.
pub fn parse_scan_timestamp(timestamp: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(timestamp, "%Y-%m-%d-%H-%M").ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::load_report_locale;

    fn fmt(lang: &str) -> LocaleFormat {
        LocaleFormat::of(&load_report_locale(lang))
    }

    fn at(s: &str) -> NaiveDateTime {
        parse_scan_timestamp(s).expect("valid timestamp")
    }

    /// The header date in each language, with its own words and order:
    /// the English report wrote `24/11/2026 à 09:47` (2026-11-24).
    #[test]
    fn test_datetime_in_each_language() {
        let morning = at("2026-11-24-09-47");
        assert_eq!(fmt("en").datetime(&morning), "November 24, 2026 at 9:47 AM");
        assert_eq!(fmt("fr").datetime(&morning), "24/11/2026 à 09:47");
        assert_eq!(fmt("es").datetime(&morning), "24/11/2026 a las 09:47");
        assert_eq!(fmt("de").datetime(&morning), "24.11.2026 um 09:47");
        let evening = at("2026-03-05-18-05");
        assert_eq!(fmt("en").datetime(&evening), "March 5, 2026 at 6:05 PM");
        assert_eq!(fmt("en").datetime_short(&evening), "Mar 5, 6:05 PM");
        assert_eq!(fmt("fr").datetime_short(&evening), "05/03 18:05");
        assert_eq!(fmt("de").datetime_short(&evening), "05.03. 18:05");
    }

    /// Digit groups as `Intl.NumberFormat` writes them for the locale, so
    /// the text and the charts agree.
    #[test]
    fn test_int_groups_digits_per_language() {
        assert_eq!(fmt("en").int(11126u32), "11,126");
        assert_eq!(fmt("fr").int(11126u32), "11\u{202f}126");
        assert_eq!(fmt("es").int(11126u32), "11.126");
        assert_eq!(fmt("de").int(1234567u32), "1.234.567");
        assert_eq!(fmt("en").int(999u32), "999");
        assert_eq!(fmt("en").int(1000u32), "1,000");
        // Spanish leaves a four-digit number whole.
        assert_eq!(fmt("es").int(1234u32), "1234");
        assert_eq!(fmt("en").int(-1234i64), "-1,234");
        assert_eq!(fmt("en").int(0u8), "0");
    }

    #[test]
    fn test_decimal_and_percent_per_language() {
        assert_eq!(fmt("en").decimal(43.7, 1), "43.7");
        assert_eq!(fmt("fr").decimal(43.7, 1), "43,7");
        assert_eq!(fmt("de").decimal(43.0, 1), "43");
        assert_eq!(fmt("en").decimal(1234.5, 1), "1,234.5");
        assert_eq!(fmt("en").decimal(-0.04, 1), "0");
        assert_eq!(fmt("en").percent(45u8), "45%");
        assert_eq!(fmt("fr").percent(45u8), "45\u{202f}%");
        assert_eq!(fmt("es").percent(45u8), "45\u{a0}%");
        assert_eq!(
            fmt("de").percent_of(&fmt("de").decimal(43.7, 1)),
            "43,7\u{a0}%"
        );
    }

    /// The baseline is named by its scan timestamp, shown as a date; a
    /// timestamp of another shape is shown as it is.
    #[test]
    fn test_scan_timestamp_shown_as_a_date() {
        assert_eq!(
            fmt("en").scan_timestamp("2026-11-23-15-47"),
            "November 23, 2026 at 3:47 PM"
        );
        assert_eq!(
            fmt("de").scan_timestamp("2026-11-23-15-47"),
            "23.11.2026 um 15:47"
        );
        assert_eq!(fmt("fr").scan_timestamp("2026-08-01"), "2026-08-01");
    }

    /// Every report locale has its formats block and its label colon: a
    /// missing one would silently fall back to English forms.
    #[test]
    fn test_every_locale_has_its_formats() {
        for lang in ["en", "fr", "es", "de"] {
            let locale = load_report_locale(lang);
            for key in [
                "formats.datetime",
                "formats.datetime_short",
                "formats.number_group",
                "formats.number_group_min_digits",
                "formats.decimal",
                "formats.percent",
                "label_colon",
            ] {
                assert!(get_nested(&locale, key).is_some(), "{lang}: {key}");
            }
        }
        assert_eq!(fmt("fr").colon(), "\u{a0}: ");
        assert_eq!(fmt("en").colon(), ": ");
    }
}
