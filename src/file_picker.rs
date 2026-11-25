//! The path field and directory list share a query; only Enter chooses a file.

use std::borrow::Cow;
use std::io;
use std::path::{MAIN_SEPARATOR, Path, PathBuf, is_separator};

use crate::{config, text};

pub(crate) struct Entry {
    pub name: String,
    pub directory: bool,
}

/// Read one directory, without following links encountered in its listing.
pub(crate) fn entries(dir: &Path) -> io::Result<Vec<Entry>> {
    let mut entries = Vec::new();
    if dir.parent().is_some() {
        entries.push(Entry {
            name: "..".into(),
            directory: true,
        });
    }
    let first_file = entries.len();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if let Ok(kind) = entry.file_type()
            && (kind.is_dir() || kind.is_file() || kind.is_symlink())
            && let Ok(name) = entry.file_name().into_string()
            && displayable(&name)
        {
            entries.push(Entry {
                name,
                directory: kind.is_dir(),
            });
        }
    }
    entries[first_file..]
        .sort_unstable_by(|a, b| b.directory.cmp(&a.directory).then(a.name.cmp(&b.name)));
    Ok(entries)
}

pub(crate) fn displayable(value: &str) -> bool {
    !value.chars().any(|c| c.is_control() || text::is_hidden(c))
}

fn quoted(value: &str) -> Option<&str> {
    let quote = value.chars().next().filter(|c| matches!(c, '\'' | '"'))?;
    value.strip_prefix(quote)?.strip_suffix(quote)
}

/// A path as typed or dropped: quotes around it, or `\ ` for spaces on Unix.
pub(crate) fn unquote(value: &str) -> Cow<'_, str> {
    if let Some(path) = quoted(value) {
        Cow::Borrowed(path)
    } else if !cfg!(windows) && value.contains("\\ ") {
        Cow::Owned(value.replace("\\ ", " "))
    } else {
        Cow::Borrowed(value)
    }
}

fn is_local(path: &Path) -> bool {
    path.is_absolute() && !config::maybe_remote(path) && path.to_str().is_some_and(displayable)
}

/// Never look up a network path or a Windows path relative to another drive.
pub(crate) fn local_path(value: &str, base: Option<&Path>) -> Option<PathBuf> {
    if !displayable(value) {
        return None;
    }
    if value == "~" {
        return dirs::home_dir().filter(|path| is_local(path));
    }
    let path = Path::new(value);
    if config::maybe_remote(path) {
        return None;
    }
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    let path = if value.starts_with('~') && value[1..].starts_with(is_separator) {
        let home = dirs::home_dir().filter(|path| is_local(path))?;
        let tail = Path::new(&value[2..]);
        if tail.has_root()
            || matches!(
                tail.components().next(),
                Some(std::path::Component::Prefix(_))
            )
        {
            return None;
        }
        home.join(tail)
    } else {
        base?.join(path)
    };
    is_local(&path).then_some(path)
}

fn split(value: &str) -> (&str, &str) {
    if value == "~" {
        return (value, "");
    }
    value.split_at(value.rfind(is_separator).map_or(0, |at| at + 1))
}

pub(crate) struct FilePicker {
    pub directory: Option<PathBuf>,
    pub selected: Option<usize>,
    pub error: Option<String>,
    base: Option<PathBuf>,
    input_dir: String,
    listing: Option<io::Result<Vec<Entry>>>,
    // Valid only until this picker or its directory changes. The app runs one scan at a time.
    scanning: bool,
    matches: Vec<usize>,
    complete_when_loaded: bool,
}

impl FilePicker {
    pub fn new() -> Self {
        let base = dirs::home_dir()
            .filter(|path| is_local(path))
            .or_else(|| std::env::current_dir().ok().filter(|path| is_local(path)));
        Self {
            directory: base.clone(),
            base,
            input_dir: String::new(),
            listing: None,
            scanning: false,
            matches: Vec::new(),
            selected: None,
            error: None,
            complete_when_loaded: false,
        }
    }

    pub fn enter(&mut self, dir: PathBuf) {
        self.base = Some(dir);
        self.input_dir.clear();
        self.set_directory(self.base.clone());
        self.change("");
    }

    pub fn change(&mut self, input: &str) {
        let value = unquote(input);
        let (dir, prefix) = split(&value);
        if dir != self.input_dir {
            self.input_dir.clear();
            self.input_dir.push_str(dir);
            self.set_directory(local_path(dir, self.base.as_deref()));
        }
        self.error = None;
        self.selected = None;
        self.complete_when_loaded = false;
        self.filter(prefix);
    }

    fn set_directory(&mut self, dir: Option<PathBuf>) {
        if dir != self.directory {
            self.directory = dir;
            self.listing = None;
            self.scanning = false;
        }
    }

    fn filter(&mut self, prefix: &str) {
        self.matches.clear();
        if let Some(Ok(entries)) = &self.listing {
            self.matches
                .extend(entries.iter().enumerate().filter_map(|(i, entry)| {
                    let name = &entry.name;
                    (name.starts_with(prefix)
                        && (!name.starts_with('.') || name == ".." || prefix.starts_with('.')))
                    .then_some(i)
                }));
        }
    }

    pub fn scan(&mut self) -> Option<PathBuf> {
        if self.listing.is_some() {
            return None;
        }
        let dir = self.directory.clone()?;
        self.scanning = true;
        Some(dir)
    }

    pub fn listed(&mut self, listing: io::Result<Vec<Entry>>, input: &str) -> bool {
        if !std::mem::take(&mut self.scanning) {
            return false;
        }
        self.listing = Some(listing);
        self.filter(split(&unquote(input)).1);
        std::mem::take(&mut self.complete_when_loaded)
    }

    pub fn listing_error(&self) -> Option<&io::Error> {
        self.listing.as_ref()?.as_ref().err()
    }

    pub fn loading(&self) -> bool {
        self.directory.is_some() && self.listing.is_none()
    }

    fn entries(&self) -> &[Entry] {
        match &self.listing {
            Some(Ok(entries)) => entries,
            _ => &[],
        }
    }

    pub fn matches(&self) -> impl ExactSizeIterator<Item = &Entry> + '_ {
        self.matches.iter().map(|&i| &self.entries()[i])
    }

    pub fn step(&mut self, down: bool) {
        let Some(last) = self.matches.len().checked_sub(1) else {
            return;
        };
        self.selected = Some(match (self.selected, down) {
            (None, true) => 0,
            (None, false) => last,
            (Some(i), true) => (i + 1).min(last),
            (Some(i), false) => i.saturating_sub(1),
        });
        self.error = None;
    }

    pub fn chosen(&self, input: &str) -> Option<(PathBuf, bool)> {
        if let Some(i) = self.selected {
            let dir = self.directory.as_ref()?;
            let entry = &self.entries()[self.matches[i]];
            // Use the logical parent for a path through a link.
            let path = if entry.name == ".." && !dir.ends_with("..") {
                dir.parent()?.to_path_buf()
            } else {
                dir.join(&entry.name)
            };
            return Some((path, entry.directory));
        }
        let value = unquote(input);
        if value.is_empty() {
            return None;
        }
        let path = local_path(&value, self.base.as_deref())?;
        Some((path, value == "~" || value.ends_with(is_separator)))
    }

    /// Extend a unique match or the common prefix. Never chooses a file.
    pub fn complete(&mut self, input: &str) -> Option<(String, bool)> {
        let value = unquote(input);
        if value == "~" && self.selected.is_none() {
            return Some((format!("~{MAIN_SEPARATOR}"), false));
        }
        if self.loading() {
            self.complete_when_loaded = true;
            return None;
        }
        let (start, prefix) = split(&value);
        let (name, directory) = if let Some(i) = self.selected {
            let entry = &self.entries()[self.matches[i]];
            (entry.name.as_str(), entry.directory)
        } else {
            let mut choices = self.matches().filter(|entry| entry.name != "..");
            let first = choices.next()?;
            let mut common = first.name.as_str();
            let mut unique = true;
            for entry in choices {
                unique = false;
                let bytes = common
                    .chars()
                    .zip(entry.name.chars())
                    .take_while(|(a, b)| a == b)
                    .map(|(c, _)| c.len_utf8())
                    .sum();
                common = &common[..bytes];
                if common == prefix {
                    break;
                }
            }
            (common, unique && first.directory)
        };
        if prefix == name && !directory {
            return None;
        }
        let mut path = if name == ".." && self.selected.is_some() {
            // Completing the parent must lead to the same place as choosing it directly.
            self.chosen(input)?.0.into_os_string().into_string().ok()?
        } else if start == "~" {
            format!("{start}{MAIN_SEPARATOR}{name}")
        } else {
            format!("{start}{name}")
        };
        if start.is_empty() && (path == "~" || config::maybe_remote(Path::new(&path))) {
            path.insert(0, MAIN_SEPARATOR);
            path.insert(0, '.');
        }
        if directory && !path.ends_with(is_separator) {
            path.push(MAIN_SEPARATOR);
        }
        let quote = quoted(&path).is_some() || (!cfg!(windows) && path.contains("\\ "));
        if quote {
            path.insert(0, '"');
            path.push('"');
        }
        Some((path, quote))
    }
}
