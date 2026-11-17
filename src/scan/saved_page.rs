//! Detection of web pages saved from a browser, which the scan skips
//! (ADR-0046).
//!
//! "Save page as… > Web page, complete" writes `<name>.html` and puts the
//! page's scripts, styles and images in a `<name>_files/` folder beside
//! it; Chrome, Edge and Internet Explorer also write a
//! `<!-- saved from url=(NNNN)https://… -->` comment at the top of the
//! page. Such a page is a copy of another site (in `bountybench-main`:
//! the write-ups of bug bounty reports), not code the project writes or
//! reviews: on the 13 test projects, 117 files of saved pages gave 1 398
//! findings, all in `bountybench-main` (ticket #193).
//!
//! The engine of reference (`Audit`, Python) has no such detection.
//! Skipping saved pages is a deliberate deviation, decided on 2026-11-17
//! with the measure above, in the line of the minified files
//! (ADR-0045).
//!
//! The rule needs the browser's mark, so that a project's own page with
//! a `<name>_files/` folder (WebGoat keeps the images of a lesson in
//! `ClientSideFiltering_files/`) stays scanned:
//!
//! - an HTML file whose first [`HEAD_BYTES`] bytes hold the mark is a
//!   saved page ([`is_saved_page_text`]);
//! - a file under a `<name>_files/` folder whose sibling `<name>.html` or
//!   `<name>.htm` is a saved page belongs to it ([`SavedPageFolders`]).
//!
//! Phase A applies both before parsing; the skipped files are listed on
//! the console, so that no code is left out without a word.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

/// How far into an HTML file the browser's mark is looked for: browsers
/// write it on the first or second line, after the doctype.
const HEAD_BYTES: usize = 4096;

/// The comment browsers write at the top of a saved page, lower-case.
const SAVED_FROM_MARK: &str = "<!-- saved from url=";

/// Suffix of the folder that holds a saved page's resources.
const RESOURCES_SUFFIX: &str = "_files";

/// True when `text`, the start of an HTML file, carries the browser's
/// "saved from" mark within its first [`HEAD_BYTES`] bytes.
pub(crate) fn is_saved_page_text(text: &str) -> bool {
    let mut end = text.len().min(HEAD_BYTES);
    // Never cut inside a multi-byte character.
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_ascii_lowercase().contains(SAVED_FROM_MARK)
}

/// True when the HTML file at `path` is a saved page: reads its first
/// [`HEAD_BYTES`] bytes only. An unreadable file is not a saved page.
fn is_saved_page_file(path: &Path) -> bool {
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut head = Vec::with_capacity(HEAD_BYTES);
    if file.take(HEAD_BYTES as u64).read_to_end(&mut head).is_err() {
        return false;
    }
    is_saved_page_text(&String::from_utf8_lossy(&head))
}

/// The `<name>_files/` folders of saved pages among the ancestors of a
/// scan's files, found once before phase A: each candidate folder costs
/// one read of the head of its sibling page, whatever the number of
/// files under it.
#[derive(Debug, Default)]
pub(crate) struct SavedPageFolders {
    folders: BTreeSet<PathBuf>,
}

impl SavedPageFolders {
    /// Looks at the folders between `root` and each of `files` (the
    /// discovered files, absolute or relative to the same base as
    /// `root`): a folder `<name>_files` is kept when `<name>.html` or
    /// `<name>.htm` beside it is a saved page.
    pub(crate) fn find(root: &Path, files: &[PathBuf]) -> Self {
        let mut verdicts: BTreeMap<PathBuf, bool> = BTreeMap::new();
        for file in files {
            for folder in file.ancestors().skip(1) {
                if folder == root || !folder.starts_with(root) {
                    break;
                }
                if verdicts.contains_key(folder) {
                    continue;
                }
                let verdict = resources_page_of(folder).is_some_and(|page| page);
                verdicts.insert(folder.to_path_buf(), verdict);
            }
        }
        SavedPageFolders {
            folders: verdicts
                .into_iter()
                .filter_map(|(folder, saved)| saved.then_some(folder))
                .collect(),
        }
    }

    /// True when `file` lies under the resources folder of a saved page.
    pub(crate) fn contains(&self, file: &Path) -> bool {
        !self.folders.is_empty() && file.ancestors().skip(1).any(|a| self.folders.contains(a))
    }
}

/// For a folder `<name>_files`, whether its sibling page `<name>.html` or
/// `<name>.htm` is a saved page; `None` for any other folder name.
fn resources_page_of(folder: &Path) -> Option<bool> {
    let name = folder.file_name()?.to_str()?;
    let page = name.strip_suffix(RESOURCES_SUFFIX).filter(|n| !n.is_empty())?;
    let parent = folder.parent()?;
    Some(
        ["html", "htm"]
            .iter()
            .any(|ext| is_saved_page_file(&parent.join(format!("{page}.{ext}")))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "codefixture_saved_page_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const SAVED: &str = "<!DOCTYPE html>\n<!-- saved from url=(0029)https://example.com/report -->\n<html><body>x</body></html>\n";

    /// The mark of Chrome, Edge and Internet Explorer, whatever its case.
    #[test]
    fn test_browser_mark_makes_a_saved_page() {
        assert!(is_saved_page_text(SAVED));
        assert!(is_saved_page_text("<!-- Saved From URL=(0014)about:internet -->"));
        assert!(!is_saved_page_text("<!DOCTYPE html>\n<html><body>saved from url</body></html>"));
    }

    /// The mark must be at the top: a page that quotes it further down
    /// (a tutorial on saved pages) is the project's own page.
    #[test]
    fn test_mark_after_the_head_is_ignored() {
        let text = format!("<html>{}<!-- saved from url=(0001)x -->", "é".repeat(HEAD_BYTES));
        assert!(!is_saved_page_text(&text));
    }

    /// The resources folder of a saved page is skipped; the folder of a
    /// project page without the mark (WebGoat's lesson images) and the
    /// page's own siblings are not.
    #[test]
    fn test_resources_folder_needs_a_saved_sibling_page() {
        let root = temp_dir();
        std::fs::create_dir_all(root.join("w/report_files")).unwrap();
        std::fs::create_dir_all(root.join("lesson/Filtering_files")).unwrap();
        std::fs::create_dir_all(root.join("exploit_files")).unwrap();
        std::fs::write(root.join("w/report.html"), SAVED).unwrap();
        std::fs::write(root.join("lesson/Filtering.html"), "<html>lesson</html>").unwrap();
        let files: Vec<PathBuf> = [
            "w/report_files/app.js",
            "w/report_files/sub/page.html",
            "w/notes.js",
            "lesson/Filtering_files/demo.js",
            "exploit_files/run.py",
        ]
        .iter()
        .map(|f| root.join(f))
        .collect();
        let folders = SavedPageFolders::find(&root, &files);
        let skipped: Vec<bool> = files.iter().map(|f| folders.contains(f)).collect();
        assert_eq!(skipped, vec![true, true, false, false, false]);
        std::fs::remove_dir_all(&root).ok();
    }
}
