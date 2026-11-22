use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};

use crate::text;

/// The local folders for configuration and cached mail.
pub struct Config {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
}

/// Keep source lookups and shared destination staging stable until startup
/// has finished reading or moving the configuration.
#[derive(Default)]
pub struct MigrationLocks {
    _first: Option<std::fs::File>,
    _second: Option<std::fs::File>,
}

#[cfg(unix)]
const CONFIG_FILES: [&str; 2] = ["accounts.toml", "settings.toml"];

impl Config {
    /// Resolve paths without creating folders or migrating files.
    pub fn paths() -> Result<Self> {
        let overridden = var("TM_DATA_DIR");
        let data_dir = data_dir_from(overridden.as_deref())?;
        let config_dir = if cfg!(unix) && overridden.is_none() {
            unix_config_dir(std::env::var_os("XDG_CONFIG_HOME"), dirs::home_dir)?
        } else {
            data_dir.clone()
        };
        Ok(Self {
            config_dir,
            data_dir,
        })
    }

    pub fn load() -> Result<Self> {
        let (config, _locks) = Self::inspect()?;
        #[cfg(unix)]
        if config.config_dir != config.data_dir {
            config.migrate_config()?;
        }
        Ok(config)
    }

    /// Check the folders without moving configuration. Hold the returned
    /// locks while reading legacy files.
    pub fn inspect() -> Result<(Self, MigrationLocks)> {
        Self::paths()?.prepare()
    }

    fn prepare(mut self) -> Result<(Self, MigrationLocks)> {
        let together = self.config_dir == self.data_dir;
        self.data_dir = make_private_dir(&self.data_dir)?;
        if together {
            self.config_dir = self.data_dir.clone();
            return Ok((self, MigrationLocks::default()));
        }
        #[cfg(unix)]
        {
            self.config_dir = protect_dir(&self.config_dir)?;
            use std::os::unix::fs::MetadataExt;

            let identity = |dir: &Path| -> std::io::Result<_> {
                let meta = std::fs::metadata(dir)?;
                Ok((meta.dev(), meta.ino()))
            };
            // Order by filesystem identity, not path: bind mounts can give
            // the same directory different canonical names.
            let (first, second) = match identity(&self.data_dir)?.cmp(&identity(&self.config_dir)?)
            {
                std::cmp::Ordering::Less => (&self.data_dir, &self.config_dir),
                std::cmp::Ordering::Greater => (&self.config_dir, &self.data_dir),
                std::cmp::Ordering::Equal => {
                    self.config_dir = self.data_dir.clone();
                    return Ok((self, MigrationLocks::default()));
                }
            };
            let first = lock_config_dir(first)?;
            let second = lock_config_dir(second)?;
            self.clear_migration_staging()?;
            check_private_entries(&self.config_dir)?;
            Ok((
                self,
                MigrationLocks {
                    _first: Some(first),
                    _second: Some(second),
                },
            ))
        }
        #[cfg(not(unix))]
        unreachable!("config and data share a path on this platform")
    }

    /// `--check` reads the file that startup would use without moving it.
    pub fn inspect_file(&self, name: &str) -> Result<PathBuf> {
        let path = self.config_dir.join(name);
        if self.config_dir != self.data_dir && !exists(&path)? {
            let legacy = self.data_dir.join(name);
            if exists(&legacy)? {
                return Ok(legacy);
            }
        }
        Ok(path)
    }

    #[cfg(unix)]
    fn staging(&self, name: &str) -> PathBuf {
        self.config_dir.join(format!(".tuimail-migrate-{name}"))
    }

    #[cfg(unix)]
    fn clear_migration_staging(&self) -> Result<()> {
        use std::fs;
        use std::io::ErrorKind::NotFound;
        use std::os::unix::fs::MetadataExt;

        for name in CONFIG_FILES {
            let stage = self.staging(name);
            let meta = match fs::symlink_metadata(&stage) {
                Err(e) if e.kind() == NotFound => continue,
                result => result?,
            };
            // A crash can leave both names of our staged file on filesystems
            // where no-replace publication uses link/unlink.
            let is_published = meta.nlink() == 2
                && fs::symlink_metadata(self.config_dir.join(name))
                    .is_ok_and(|to| to.dev() == meta.dev() && to.ino() == meta.ino());
            if !meta.is_file() || meta.uid() != euid() || !(meta.nlink() == 1 || is_published) {
                bail!(
                    "{} isn't a tuimail migration file: move it away",
                    shown(&stage)
                );
            }
            fs::remove_file(stage)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn migrate_config(&self) -> Result<()> {
        use std::fs::{self, File};
        use std::io::ErrorKind::{AlreadyExists, NotFound};
        use std::io::Write;

        if self.config_dir == self.data_dir {
            return Ok(());
        }

        for name in CONFIG_FILES {
            let from = self.data_dir.join(name);
            let to = self.config_dir.join(name);
            if exists(&to)? {
                continue;
            }
            let migrate = || -> std::io::Result<()> {
                let bytes = match read_capped(&from, SMALL_FILE_LIMIT) {
                    Err(e) if e.kind() == NotFound => return Ok(()),
                    result => result?,
                };
                let mut file = tempfile::Builder::new()
                    .prefix(&format!(".tuimail-migrate-{name}"))
                    .rand_bytes(0)
                    .tempfile_in(&self.config_dir)?;
                file.write_all(&bytes)?;
                file.as_file().sync_all()?;
                match file.persist_noclobber(&to) {
                    Ok(_) => {}
                    Err(e) if e.error.kind() == AlreadyExists => return Ok(()),
                    Err(e) => return Err(e.error),
                }
                // tempfile can report success even if its hard-link fallback
                // leaves the staging name behind. Keep the legacy copy until
                // that name is gone, so recovery can still run.
                match fs::remove_file(self.staging(name)) {
                    Ok(()) => {}
                    Err(e) if e.kind() == NotFound => {}
                    Err(e) => return Err(e),
                }
                // Persist the destination and its path before deleting the
                // source. If directory sync is unsupported or forbidden,
                // use the new file but keep the legacy copy.
                for dir in self.config_dir.ancestors() {
                    match File::open(dir).and_then(|dir| dir.sync_all()) {
                        Ok(()) => {}
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::PermissionDenied
                                    | std::io::ErrorKind::Unsupported
                            ) || e.raw_os_error() == Some(libc::EINVAL) =>
                        {
                            return Ok(());
                        }
                        Err(e) => return Err(e),
                    }
                }
                fs::remove_file(&from)
            };
            migrate().with_context(|| format!("cannot move {} to {}", shown(&from), shown(&to)))?;
        }
        Ok(())
    }
}

/// Serialize config read-modify-write operations with startup migration,
/// including when an explicit TM_DATA_DIR points at the legacy folder.
pub fn lock_config_write(path: &Path) -> Result<Option<std::fs::File>> {
    #[cfg(unix)]
    {
        let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
        Ok(Some(lock_config_dir(
            dir.unwrap_or_else(|| Path::new(".")),
        )?))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(None)
    }
}

#[cfg(unix)]
fn lock_config_dir(dir: &Path) -> Result<std::fs::File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let path = dir.join(".tuimail-config.lock");

    // Keep the inode in place for other callers. NFS needs a writable file
    // descriptor for the exclusive lock.
    let guard = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .with_context(|| format!("cannot open {}", shown(&path)))?;
    let meta = guard.metadata()?;
    if !meta.is_file() || meta.uid() != euid() || meta.nlink() != 1 {
        bail!("{} isn't a plain file of yours", shown(&path));
    }
    guard
        .lock()
        .with_context(|| format!("cannot lock {}", shown(&path)))?;
    Ok(guard)
}

fn exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("cannot inspect {}", shown(path))),
    }
}

pub const SMALL_FILE_LIMIT: u64 = 1 << 20;

/// Reads a file tuimail keeps, refusing anything that isn't a plain file of
/// a sane size, so a link to `/dev/zero` or a pipe can't hang the start.
pub fn read_small(path: &Path) -> std::io::Result<String> {
    String::from_utf8(read_capped(path, SMALL_FILE_LIMIT)?).map_err(std::io::Error::other)
}

/// The bytes of `path` if it's a plain file of at most `cap` bytes: checked
/// and read through one open file (nothing can be put in its place between
/// the two), never waiting on a pipe, and never more than `cap` read.
pub fn read_capped(path: &Path, cap: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NONBLOCK);
    let file = options.open(path)?;
    let meta = file.metadata()?;
    let too_big = || std::io::Error::other(format!("not a plain file under {} KB", cap >> 10));
    if !meta.is_file() || meta.len() > cap {
        return Err(too_big());
    }
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(too_big());
    }
    Ok(bytes)
}

/// Makes the data folder, or checks the one that's there, so only you can
/// reach it, and gives its path with links resolved. In this order, so
/// nothing is created or changed somewhere unsafe: the folders above it may
/// be changed only by you or the system ([`private_place`]); it's then
/// made, mode 0700, or found to be a real folder (not a link) that's yours;
/// then set to 0700 again, and on macOS cleared of access rules inherited
/// from above, which would let others in whatever the mode says.
#[cfg(unix)]
fn make_private_dir(dir: &Path) -> Result<PathBuf> {
    let dir = protect_dir(dir)?;
    check_private_entries(&dir)?;
    Ok(dir)
}

#[cfg(unix)]
fn protect_dir(dir: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let shown = shown(dir);
    let (Some(parent), Some(name)) = (dir.parent(), dir.file_name()) else {
        bail!("{shown} isn't a folder tuimail can use");
    };
    std::fs::create_dir_all(parent).with_context(|| format!("cannot create {shown}"))?;
    let parent = std::fs::canonicalize(parent).with_context(|| format!("cannot read {shown}"))?;
    private_place(&parent)?;
    let dir = parent.join(name);
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => {
            return Err(e).with_context(|| format!("cannot create {shown}"));
        }
        _ => {}
    }
    let meta = std::fs::symlink_metadata(&dir).with_context(|| format!("cannot read {shown}"))?;
    if meta.file_type().is_symlink() || !meta.is_dir() || meta.uid() != euid() {
        bail!("{shown} isn't a folder of yours, so it's no place for your data");
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("cannot protect {shown}"))?;
    #[cfg(target_os = "macos")]
    clear_acls(&dir);
    Ok(dir)
}

#[cfg(unix)]
fn check_private_entries(dir: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let shown = shown(dir);
    // What's in it must be yours alone too: a link or file another account
    // left while it could still write here would stay in use (a link at
    // accounts.toml choosing the program that gives your password).
    // So must the agents' sockets: one left there would get every agent's
    // questions, and answer them.
    use std::os::unix::fs::FileTypeExt;
    for (entry, kind) in [
        ("accounts.toml", Entry::File),
        ("settings.toml", Entry::File),
        ("tuimail.db", Entry::File),
        ("tuimail.db-wal", Entry::File),
        ("tuimail.db-shm", Entry::File),
        ("drafts", Entry::Folder),
        ("opened", Entry::Folder),
        (crate::agent::SOCKET, Entry::Socket),
        (crate::agent::DEMO_SOCKET, Entry::Socket),
    ] {
        let Ok(meta) = std::fs::symlink_metadata(dir.join(entry)) else {
            continue;
        };
        let kind = match kind {
            Entry::Folder => meta.is_dir(),
            Entry::File => meta.is_file() && meta.nlink() == 1,
            Entry::Socket => meta.file_type().is_socket() && meta.nlink() == 1,
        };
        if meta.file_type().is_symlink() || !kind || meta.uid() != euid() {
            bail!(
                "{entry} in {shown} isn't yours alone (a link, or another account's): move it away"
            );
        }
    }
    Ok(())
}

/// What an entry of the data folder must be.
#[cfg(unix)]
enum Entry {
    File,
    Folder,
    Socket,
}

/// On Windows, a folder set with `TM_DATA_DIR` must be in your own profile,
/// whose permissions are yours alone; tuimail doesn't set Windows ACLs.
#[cfg(not(unix))]
fn make_private_dir(dir: &Path) -> Result<PathBuf> {
    let shown = shown(dir);
    if var("TM_DATA_DIR").is_some() {
        let mine = ["USERPROFILE", "LOCALAPPDATA"]
            .iter()
            .filter_map(std::env::var_os)
            .any(|base| dir.starts_with(base));
        if !mine {
            bail!("TM_DATA_DIR must be a folder in your user profile ({shown} isn't)");
        }
    }
    std::fs::create_dir_all(dir).with_context(|| format!("cannot create {shown}"))?;
    Ok(dir.to_path_buf())
}

/// Removes access rules (ACLs) from `dir` and everything in it: a folder
/// made inside one with an inherited rule for everyone gets that rule too,
/// and mode 0700 doesn't override it. `/bin/chmod -N` by its full path.
#[cfg(target_os = "macos")]
fn clear_acls(dir: &Path) {
    let _ = std::process::Command::new("/bin/chmod")
        .args(["-R", "-N"])
        .arg(dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// The user tuimail runs as.
#[cfg(unix)]
pub fn euid() -> u32 {
    // SAFETY: geteuid can't fail and touches no memory.
    unsafe { libc::geteuid() }
}

/// `TM_DATA_DIR`, else the platform's place for app data: `~/Library/Application
/// Support/tuimail` on macOS, `~/.local/share/tuimail` on Linux, `%LOCALAPPDATA%\tuimail`
/// on Windows. The same wherever the command is run from.
pub fn open_data_dir() -> Result<PathBuf> {
    make_private_dir(&data_dir_from(var("TM_DATA_DIR").as_deref())?)
}

fn data_dir_from(set: Option<&str>) -> Result<PathBuf> {
    if let Some(dir) = set {
        let dir = PathBuf::from(dir);
        // On Windows even creating a folder on another machine hands that
        // server your login hash. A relative path would depend on where
        // tuimail is started: a cloned folder could hand you its own data.
        let elsewhere = maybe_remote(&dir) || !dir.is_absolute();
        if elsewhere {
            bail!(
                "TM_DATA_DIR must be a full path to a folder on this computer \
                 (with a drive letter on Windows)"
            );
        }
        return Ok(dir);
    }
    let base = dirs::data_local_dir().context("no home directory found; set TM_DATA_DIR")?;
    Ok(base.join("tuimail"))
}

fn unix_config_dir(
    xdg: Option<std::ffi::OsString>,
    home: impl FnOnce() -> Option<PathBuf>,
) -> Result<PathBuf> {
    let base = xdg
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            home()
                .filter(|path| path.is_absolute())
                .map(|path| path.join(".config"))
        })
        .context("no home directory found; set XDG_CONFIG_HOME or TM_DATA_DIR")?;
    Ok(base.join("tuimail"))
}

/// Whether `path` names a file on another machine: `\\server\share\…` (or
/// `//server/share/…`) on Windows. Looking at such a path connects to that
/// server and hands it the user's Windows login hash.
pub fn on_another_machine(path: &Path) -> bool {
    matches!(
        path.as_os_str().as_encoded_bytes(),
        [b'/' | b'\\', b'/' | b'\\', ..]
    )
}

/// Whether `path` may not be on this computer's own drives: on Windows, any
/// path that starts with a separator, since besides `\\server\share` the NT
/// spellings (`\??\UNC\server\…`) reach the network too, and only a drive
/// letter is surely local. Elsewhere, [`on_another_machine`].
pub fn maybe_remote(path: &Path) -> bool {
    on_another_machine(path) || (cfg!(windows) && starts_with_separator(path))
}

fn starts_with_separator(path: &Path) -> bool {
    matches!(path.as_os_str().as_encoded_bytes(), [b'/' | b'\\', ..])
}

/// A path as it can be printed: it may come from the environment.
pub fn shown(path: &Path) -> String {
    text::clean(&path.display().to_string())
}

/// Checks that only you or the system can change `dir` and the folders
/// above it: otherwise another account could rename the data folder away
/// and put its own in its place. Folders anyone may write to, like `/tmp`,
/// are fine when only an entry's owner can move it (the sticky bit) and the
/// system owns them. Owners are compared with the user tuimail runs as,
/// not with the folder's own owner.
#[cfg(unix)]
fn private_place(dir: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let uid = euid();
    // SAFETY: getgid can't fail and touches no memory.
    let gid = unsafe { libc::getgid() };
    let unsafe_place = |what: &Path| {
        anyhow::anyhow!(
            "{} can be changed by other users, so it's no place for your data; \
             set TM_DATA_DIR somewhere in your home folder",
            shown(what)
        )
    };
    for folder in std::fs::canonicalize(dir)?.ancestors() {
        let meta = std::fs::metadata(folder)?;
        let mode = meta.mode();
        // Your own group is only yours on Linux (user private groups); on
        // macOS every account is in `staff`.
        let group_is_others = cfg!(target_os = "macos") || meta.gid() != gid;
        let others_write = mode & 0o002 != 0 || (mode & 0o020 != 0 && group_is_others);
        let sticky = mode & 0o1000 != 0;
        let owner_ok = meta.uid() == uid || meta.uid() == 0;
        if !owner_ok || (others_write && !(sticky && meta.uid() == 0)) {
            return Err(unsafe_place(folder));
        }
    }
    Ok(())
}

/// `TM_*` settings from `.env` in the source folder, for development.
static DOTENV: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Reads `.env` from tuimail's own source folder (where it was built), not
/// the working directory, and keeps only its `TM_*` keys, without touching
/// the process environment. `TM_DATA_DIR` picks where your mail and
/// passwords' settings are kept, so a `.env` in whatever folder tuimail is
/// started from must never count. Only development builds read it.
pub fn load_dotenv() {
    if !cfg!(debug_assertions) {
        let _ = DOTENV.set(HashMap::new());
        return;
    }
    let vars = dotenvy::from_path_iter(concat!(env!("CARGO_MANIFEST_DIR"), "/.env"))
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|(key, _)| key.starts_with("TM_"))
        .collect();
    let _ = DOTENV.set(vars);
}

/// A variable's trimmed value from the environment, else from `.env`, or
/// `None` if it's unset or blank.
pub fn var(name: &str) -> Option<String> {
    let value = std::env::var(name)
        .ok()
        .or_else(|| DOTENV.get()?.get(name).cloned())?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn migration_recovers_interrupted_publication_without_replacing_config() {
        use std::fs;
        use std::os::unix::fs::MetadataExt;

        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let other_data = root.path().join("other-data");
        let config_root = root.path().join("config");
        let config_dir = config_root.join("tuimail");
        fs::create_dir(&data).unwrap();
        fs::create_dir(&other_data).unwrap();
        fs::create_dir_all(&config_dir).unwrap();
        let other_legacy = other_data.join("accounts.toml");
        fs::write(&other_legacy, "# legacy\n").unwrap();
        fs::write(data.join("settings.toml"), "threads = false\n").unwrap();
        let config = Config {
            config_dir,
            data_dir: data,
        };
        let stage = config.staging("accounts.toml");
        let accounts = config.config_dir.join("accounts.toml");
        fs::write(&stage, "# already published\n").unwrap();
        fs::hard_link(&stage, &accounts).unwrap();

        let (config, guard) = config.prepare().unwrap();
        assert_eq!(fs::metadata(&accounts).unwrap().nlink(), 1);
        assert_eq!(
            config.inspect_file("settings.toml").unwrap(),
            config.data_dir.join("settings.toml")
        );
        config.migrate_config().unwrap();
        drop(guard);
        assert_eq!(
            fs::read_to_string(&accounts).unwrap(),
            "# already published\n"
        );
        assert_eq!(fs::read_to_string(other_legacy).unwrap(), "# legacy\n");
        assert!(!config.data_dir.join("settings.toml").exists());
        assert_eq!(
            fs::read_to_string(config.config_dir.join("settings.toml")).unwrap(),
            "threads = false\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn migration_keeps_legacy_when_an_xdg_parent_cannot_be_synced() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        if euid() == 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let data_dir = root.path().join("data");
        let parent = root.path().join("config");
        fs::create_dir(&data_dir).unwrap();
        fs::create_dir(&parent).unwrap();
        let legacy = data_dir.join("settings.toml");
        let text = "threads = false\n";
        fs::write(&legacy, text).unwrap();
        let config_dir = parent.join("tuimail");
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o300)).unwrap();
        let result = Config {
            data_dir,
            config_dir,
        }
        .prepare()
        .and_then(|(config, _guard)| {
            config.migrate_config()?;
            Ok(config)
        });
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let config = result.unwrap();
        assert_eq!(fs::read_to_string(legacy).unwrap(), text);
        let dest = config.inspect_file("settings.toml").unwrap();
        assert_eq!(dest, config.config_dir.join("settings.toml"));
        assert_eq!(fs::read_to_string(dest).unwrap(), text);
    }

    #[test]
    fn small_files_are_read_whole_and_nothing_else() {
        let dir = std::env::temp_dir().join(format!("tuimail-capped-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let small = dir.join("small");
        std::fs::write(&small, b"12345").unwrap();
        assert_eq!(read_capped(&small, 5).unwrap(), b"12345");
        assert!(read_capped(&small, 4).is_err());
        assert!(read_capped(&dir, 1 << 20).is_err());
        // A pipe in a file's place is refused, not waited on.
        #[cfg(unix)]
        {
            let fifo = dir.join("fifo");
            let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            assert!(read_capped(&fifo, 1 << 20).is_err());
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_data_folder_on_another_machine_is_refused() {
        for dir in ["//evil.example/s/tt", "\\\\evil.example\\s\\tt"] {
            assert!(data_dir_from(Some(dir)).is_err(), "{dir}");
        }
        assert!(data_dir_from(Some("./.tuimail")).is_err(), "relative");
        assert!(data_dir_from(Some(".tuimail")).is_err(), "relative");
    }

    #[test]
    fn nt_spellings_of_a_share_count_as_maybe_remote_on_windows() {
        for path in [
            "\\??\\UNC\\evil.example\\s\\subscriptions.csv",
            "\\\\?\\UNC\\evil.example\\s\\x.csv",
            "\\\\evil.example\\s\\x.csv",
            "/??/UNC/evil.example/s/x.csv",
        ] {
            assert!(starts_with_separator(Path::new(path)), "{path}");
        }
        assert!(!starts_with_separator(Path::new("C:\\Users\\me\\x.csv")));
        assert!(!on_another_machine(Path::new("\\??\\UNC\\h\\s\\x.csv")));
        assert_eq!(
            maybe_remote(Path::new("\\??\\UNC\\h\\s\\x.csv")),
            cfg!(windows),
            "refused on Windows, a plain (odd) local path elsewhere"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_data_folder_others_could_swap_out_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        // SAFETY: geteuid can't fail and touches no memory.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let parent = std::env::temp_dir().join(format!("tuimail-place-{}", std::process::id()));
        let dir = parent.join("tt");
        std::fs::create_dir_all(&dir).unwrap();
        let mode = |path: &Path, mode| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        mode(&parent, 0o777);
        assert!(private_place(&dir).is_err(), "anyone could rename it");
        mode(&parent, 0o1777);
        assert!(private_place(&dir).is_err(), "sticky, but not the system's");
        mode(&parent, 0o755);
        private_place(&dir).unwrap();
        // A data folder that's someone else's (the system's here), however
        // safe the folders above it.
        assert!(make_private_dir(Path::new("/usr/share")).is_err());
        let made = make_private_dir(&parent.join("made")).unwrap();
        let mode_of = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode_of(&made), 0o700);
        // A link in its place is refused, not followed.
        let target = parent.join("elsewhere");
        std::fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, parent.join("link")).unwrap();
        assert!(make_private_dir(&parent.join("link")).is_err());
        assert_eq!(mode_of(&target), 0o755, "not changed through the link");
        // What's left in a data folder that was open to others: a link at
        // accounts.toml, a second name for settings.toml.
        let outside = parent.join("outside.toml");
        std::fs::write(&outside, "").unwrap();
        std::os::unix::fs::symlink(&outside, made.join("accounts.toml")).unwrap();
        assert!(make_private_dir(&made).is_err(), "a link is refused");
        std::fs::remove_file(made.join("accounts.toml")).unwrap();
        std::fs::hard_link(&outside, made.join("settings.toml")).unwrap();
        assert!(make_private_dir(&made).is_err(), "a second name is refused");
        std::fs::remove_file(made.join("settings.toml")).unwrap();
        // The agents' sockets: a link to someone else's, or not a socket.
        for socket in [crate::agent::SOCKET, crate::agent::DEMO_SOCKET] {
            std::os::unix::fs::symlink(&outside, made.join(socket)).unwrap();
            assert!(
                make_private_dir(&made).is_err(),
                "a link at {socket} is refused"
            );
            std::fs::remove_file(made.join(socket)).unwrap();
            std::fs::write(made.join(socket), "").unwrap();
            assert!(
                make_private_dir(&made).is_err(),
                "a file at {socket} is refused"
            );
            std::fs::remove_file(made.join(socket)).unwrap();
        }
        std::fs::write(made.join("accounts.toml"), "").unwrap();
        make_private_dir(&made).unwrap();
        std::fs::remove_dir_all(&parent).unwrap();
    }

    #[test]
    fn paths_are_printed_without_control_characters() {
        assert_eq!(shown(Path::new("/tmp/a\u{1b}]0;x\u{7}b")), "/tmp/a]0;xb");
    }
}
