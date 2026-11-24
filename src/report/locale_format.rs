//! Dates, times and numbers in the language of the HTML report and of
//! the console.
//!
//! Each locale owns its formats (`formats` block of
//! `resources/locales/report/<lang>.json`): the date-and-time pattern of
//! the header and of the baseline, the short pattern of the trend chart's
//! axis, the date pattern, the digit group separator, the decimal
//! separator and the percent pattern. The report used to write every date
//! the French way (`24/11/2026 à 09:47` in an English report, found on
//! 2026-11-24) and every number with a dot and no group separator. No
//! code here knows a language: a fifth locale only needs its own `formats`
//! block.
//!
//! The console reads the same formats ([`LocaleFormat::of_console`]): its
//! locale (`resources/locales/script/<lang>.json`) names its language in
//! `locale_code`, and the formats of that language's report locale apply.
//! One block per language, so the console and the report never write a
//! number two ways. The console used to write `Durée totale : 12.7 s` and
//! `11126 ligne(s)` in French (2026-11-24). Machine outputs (SARIF, JSON
//! export, SBOM, `--json`, the fields of `--log-format json`, the debug
//! log) never go through here: they keep their neutral numbers.
//!
//! The separators match what the browser's `Intl.NumberFormat` gives for
//! the locale code (`charts.js` formats the charts' numbers with it), so a
//! number reads the same in the text and in the charts: a narrow
//! no-break space for French groups, no group under five digits in
//! Spanish.
//!
//! Deliberate deviation from Audit (`report.py`), which writes the date
//! with one French pattern (`%d/%m/%Y à %H:%M`) whatever the language,
//! and whose console (`runner.py`) writes Python's neutral `{:.1f}`.

use std::sync::OnceLock;
use std::time::Duration;

use chrono::{NaiveDate, NaiveDateTime};
use serde_json::Value;

use crate::i18n::{get_nested, load_report_locale};

/// The languages that have their own formats; any other code gets the
/// English ones, as `i18n::load_report_locale` gives the English locale.
const LANGUAGES: [&str; 4] = ["en", "fr", "es", "de"];

/// The number and date formats of one report language, read once from its
/// locale and used by every renderer of the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocaleFormat {
    /// `strftime` pattern of a full date and time (`November 24, 2026 at
    /// 9:47 AM`, `24/11/2026 à 09:47`).
    datetime: String,
    /// `strftime` pattern of a short date and time, for chart axes.
    datetime_short: String,
    /// `strftime` pattern of a date without time (`November 24, 2026`,
    /// `24/11/2026`), for the console's dates.
    date: String,
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
            date: text("date", "%Y-%m-%d"),
            group: text("number_group", ","),
            group_min_digits,
            decimal: text("decimal", "."),
            percent: text("percent", "{n}%"),
            colon,
        }
    }

    /// The formats of language `lang` (`en`, `fr`, `es`, `de`; any other
    /// code gets the English ones), read once per process from its report
    /// locale: the console formats every progress line with them, and
    /// parsing the locale for each line would cost more than the line.
    pub fn for_language(lang: &str) -> &'static LocaleFormat {
        static FORMATS: [OnceLock<LocaleFormat>; 4] = [
            OnceLock::new(),
            OnceLock::new(),
            OnceLock::new(),
            OnceLock::new(),
        ];
        let index = LANGUAGES.iter().position(|l| *l == lang).unwrap_or(0);
        FORMATS[index].get_or_init(|| LocaleFormat::of(&load_report_locale(LANGUAGES[index])))
    }

    /// The formats of the console whose locale is `script_locale`
    /// (`i18n::load_script_locale`): those of the language it names in
    /// `locale_code`, English when it names none (a test checks that the
    /// four console locales name theirs).
    pub fn of_console(script_locale: &Value) -> &'static LocaleFormat {
        let lang = get_nested(script_locale, "locale_code")
            .and_then(Value::as_str)
            .unwrap_or("en");
        LocaleFormat::for_language(lang)
    }

    /// A count (files, lines, findings) with its digit groups, as
    /// [`Self::int`]: the engine's counts are `usize`, which has no
    /// `Into<i128>` conversion.
    pub fn count(&self, n: usize) -> String {
        self.int(n as u64)
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
        self.with_places(x, places, true)
    }

    /// `x` with exactly `places` decimal places, trailing zeros kept
    /// (`32.0` → `32,0`): the console's sizes in GB keep their one
    /// decimal, as they had before they were localised.
    pub fn fixed(&self, x: f64, places: usize) -> String {
        self.with_places(x, places, false)
    }

    /// [`Self::decimal`] and [`Self::fixed`]: `x` rounded to `places`
    /// decimals by `format!`, then written with the locale's separators,
    /// its trailing zeros removed when `trim_zeros`.
    fn with_places(&self, x: f64, places: usize, trim_zeros: bool) -> String {
        let fixed = format!("{:.*}", places, x.abs());
        let (whole, frac) = match fixed.split_once('.') {
            Some((w, f)) if trim_zeros => (w.to_string(), f.trim_end_matches('0').to_string()),
            Some((w, f)) => (w.to_string(), f.to_string()),
            None => (fixed, String::new()),
        };
        let whole: i128 = whole.parse().unwrap_or(0);
        // No `-0` (nor `-0,0`): a negative value rounded to zero is zero.
        let sign = if x < 0.0 && (whole != 0 || frac.chars().any(|c| c != '0')) {
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

    /// A duration for the console (ticket #135): `850 ms` under a second,
    /// `12.4 s` (`12,4 s`) under a minute, `1 min 12 s` under an hour,
    /// `1 h 02 min` beyond. The unit symbols are the SI ones in the four
    /// languages; the decimal separator is the locale's. Truncates rather
    /// than rounds at each level, so a displayed value is never larger
    /// than the real one (`59.99 s` shows `59.9 s`, not `60.0 s`). Moved
    /// here from `main.rs` on 2026-11-24, where it wrote a dot in every
    /// language.
    pub fn duration(&self, d: Duration) -> String {
        let ms = d.as_millis();
        if ms < 1_000 {
            format!("{ms} ms")
        } else if ms < 60_000 {
            format!("{}{}{} s", ms / 1_000, self.decimal, (ms % 1_000) / 100)
        } else if ms < 3_600_000 {
            let secs = ms / 1_000;
            format!("{} min {} s", secs / 60, secs % 60)
        } else {
            let mins = ms / 60_000;
            format!("{} h {:02} min", self.int((mins / 60) as i128), mins % 60)
        }
    }

    /// A date without time: `November 24, 2026`, `24/11/2026`.
    pub fn date(&self, day: &NaiveDate) -> String {
        day.format(&self.date).to_string()
    }

    /// The day of an RFC 3339 instant (`2026-11-11T00:00:00Z`, the date of
    /// the OSV data of a rule pack) as [`Self::date`] writes it, in UTC so
    /// that every machine names the same day; a plain `YYYY-MM-DD` date
    /// is read too. A text of another shape is shown as it was written
    /// rather than dropped.
    pub fn instant_date(&self, instant: &str) -> String {
        let day = chrono::DateTime::parse_from_rfc3339(instant)
            .map(|at| at.with_timezone(&chrono::Utc).date_naive())
            .or_else(|_| NaiveDate::parse_from_str(instant, "%Y-%m-%d"));
        match day {
            Ok(day) => self.date(&day),
            Err(_) => instant.to_string(),
        }
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
                "formats.date",
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

    /// Each console locale names its language, so that the console gets
    /// that language's formats and not the English fallback. The label
    /// colon is not among them: the console keeps its own `label_colon`
    /// (a plain space before the French colon, where the report has a
    /// no-break one).
    #[test]
    fn test_every_console_locale_names_its_language() {
        use crate::i18n::load_script_locale;
        for lang in ["en", "fr", "es", "de"] {
            let script = load_script_locale(lang);
            assert_eq!(
                get_nested(&script, "locale_code").and_then(Value::as_str),
                Some(lang)
            );
            assert_eq!(LocaleFormat::of_console(&script), &fmt(lang));
        }
        assert_eq!(LocaleFormat::for_language("xx"), &fmt("en"));
        assert_eq!(LocaleFormat::of_console(&serde_json::json!({})), &fmt("en"));
    }

    /// The console's durations, with the decimal separator of each
    /// language: the French console wrote `12.7 s` (2026-11-24).
    #[test]
    fn test_duration_per_language() {
        let cases = [
            (Duration::from_millis(31), "31 ms", "31 ms"),
            (Duration::from_millis(999), "999 ms", "999 ms"),
            (Duration::from_millis(12_480), "12.4 s", "12,4 s"),
            (Duration::from_millis(59_990), "59.9 s", "59,9 s"),
            (Duration::from_secs(72), "1 min 12 s", "1 min 12 s"),
            (Duration::from_secs(3_720), "1 h 02 min", "1 h 02 min"),
        ];
        for (duration, en, others) in cases {
            assert_eq!(fmt("en").duration(duration), en);
            for lang in ["fr", "es", "de"] {
                assert_eq!(fmt(lang).duration(duration), others, "{lang}");
            }
        }
    }

    /// Sizes keep their decimal (`32,0`), counts their groups.
    #[test]
    fn test_fixed_and_count() {
        assert_eq!(fmt("en").fixed(32.0, 1), "32.0");
        assert_eq!(fmt("fr").fixed(5.44, 1), "5,4");
        assert_eq!(fmt("de").fixed(1234.56, 1), "1.234,6");
        assert_eq!(fmt("en").fixed(-0.04, 1), "0.0");
        assert_eq!(fmt("fr").count(11126), "11\u{202f}126");
        assert_eq!(fmt("es").count(3042), "3042");
        assert_eq!(fmt("es").count(11126), "11.126");
    }

    /// The OSV date of a rule pack, an RFC 3339 instant, as a date of the
    /// language; any other text as it is.
    #[test]
    fn test_instant_date_per_language() {
        assert_eq!(
            fmt("en").instant_date("2026-11-11T00:00:00Z"),
            "November 11, 2026"
        );
        assert_eq!(
            fmt("fr").instant_date("2026-11-07T10:00:00.5Z"),
            "07/11/2026"
        );
        assert_eq!(fmt("de").instant_date("2026-11-07"), "07.11.2026");
        assert_eq!(fmt("es").instant_date(""), "");
        assert_eq!(fmt("es").instant_date("soon"), "soon");
    }
}
