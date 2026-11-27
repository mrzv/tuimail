//! What tuimail keeps between runs, in `tuimail.db` (SQLite) in the data
//! folder: each account's folders, the headers of their messages, the
//! messages opened (so they read offline), and for POP3 accounts the mail
//! itself. It never leaves this computer.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::config;
use crate::mail::{self, Addr, Summary};
use crate::search::{Field, MAX_TERMS, Term, terms};
use crate::{tags, text};

#[path = "store_contacts.rs"]
mod contact_cache;
pub use contact_cache::CachedContact;

pub struct Store {
    db: Connection,
}

/// What a folder is for, from the server's SPECIAL-USE attributes or its
/// name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    Inbox,
    Drafts,
    Sent,
    Archive,
    All,
    Flagged,
    Junk,
    Trash,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Inbox => "inbox",
            Role::Drafts => "drafts",
            Role::Sent => "sent",
            Role::Archive => "archive",
            Role::All => "all",
            Role::Flagged => "flagged",
            Role::Junk => "junk",
            Role::Trash => "trash",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "inbox" => Role::Inbox,
            "drafts" => Role::Drafts,
            "sent" => Role::Sent,
            "archive" => Role::Archive,
            "all" => Role::All,
            "flagged" => Role::Flagged,
            "junk" => Role::Junk,
            "trash" => Role::Trash,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Folder {
    /// The name on the server (modified UTF-7 for IMAP), used in commands.
    pub name: String,
    /// The name as shown.
    pub shown: String,
    pub delimiter: Option<String>,
    pub role: Option<Role>,
    pub selectable: bool,
    pub unread: u32,
    pub total: u32,
}

/// What's kept of a folder's state on the server, for the next sync.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Known {
    pub uidvalidity: u32,
    /// Every message with a UID from `low` to `high` is in the cache.
    pub low: u32,
    pub high: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub seen: bool,
    pub flagged: bool,
    pub answered: bool,
    pub draft: bool,
    /// Its tags ([`tags`]), sorted.
    pub tags: Vec<String>,
}

/// Server-provided Gmail identities and the standard `\Sent` label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gmail {
    pub message_id: u64,
    pub thread_id: u64,
    pub sent: bool,
}

/// A message in the list.
#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub folder: String,
    pub uid: u32,
    pub summary: Summary,
    pub flags: Flags,
    pub size: u32,
    pub gmail: Option<Gmail>,
    /// The start of its text, once it's been downloaded.
    pub preview: String,
}

/// A change made to mail (a star, read or unread, a tag, a move), kept so
/// it can be listed and undone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// 0 until it's kept.
    pub id: i64,
    /// Unix seconds.
    pub at: i64,
    /// Who made it: empty for you, else the program's name.
    pub who: String,
    pub what: What,
    pub messages: Vec<Changed>,
    pub undone: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum What {
    /// Marked read (`true`) or unread.
    Seen(bool),
    /// Starred or not.
    Flagged(bool),
    /// A tag put on (`true`) or taken off.
    Tag(String, bool),
    /// Moved: each message says where to.
    Move,
}

/// A message a [`Change`] changed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Changed {
    pub account: String,
    pub folder: String,
    /// What `uid` meant when it was changed.
    pub uidvalidity: u32,
    pub uid: u32,
    /// Its Message-ID: how a moved message is found again.
    pub message_id: String,
    /// It had the flag or tag before.
    pub had: bool,
    /// Moves: the folder it went to, and its UID there if known (folders
    /// kept here: never given to another message there).
    pub moved_to: String,
    pub new_uid: u32,
    /// Moves on the server: the folder's UIDVALIDITY and UIDNEXT just
    /// before (its UID there is at least that), once the server has made
    /// the move (0 until then), and its size, to know it again there.
    pub moved_uidvalidity: u32,
    pub moved_floor: u32,
    pub size: u32,
}

/// Changes are kept this long (seconds), and at most [`MAX_CHANGES`].
const KEEP_CHANGES_FOR: i64 = 30 * 24 * 3600;
const MAX_CHANGES: i64 = 1000;

/// A message's headers as fetched, to store.
#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    pub uid: u32,
    pub summary: Summary,
    pub flags: Flags,
    pub size: u32,
    pub gmail: Option<Gmail>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS folders (
    account TEXT NOT NULL,
    name TEXT NOT NULL,
    shown TEXT NOT NULL,
    delimiter TEXT,
    role TEXT,
    selectable INTEGER NOT NULL DEFAULT 1,
    uidvalidity INTEGER NOT NULL DEFAULT 0,
    low INTEGER NOT NULL DEFAULT 0,
    high INTEGER NOT NULL DEFAULT 0,
    unread INTEGER NOT NULL DEFAULT 0,
    total INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account, name)
);
CREATE TABLE IF NOT EXISTS messages (
    account TEXT NOT NULL,
    folder TEXT NOT NULL,
    uid INTEGER NOT NULL,
    message_id TEXT NOT NULL,
    in_reply_to TEXT NOT NULL,
    refs TEXT NOT NULL,
    date INTEGER NOT NULL,
    from_name TEXT NOT NULL,
    from_addr TEXT NOT NULL,
    to_list TEXT NOT NULL,
    cc_list TEXT NOT NULL,
    subject TEXT NOT NULL,
    attachments INTEGER NOT NULL DEFAULT 0,
    seen INTEGER NOT NULL DEFAULT 0,
    flagged INTEGER NOT NULL DEFAULT 0,
    answered INTEGER NOT NULL DEFAULT 0,
    draft INTEGER NOT NULL DEFAULT 0,
    size INTEGER NOT NULL DEFAULT 0,
    preview TEXT NOT NULL DEFAULT '',
    pop_id TEXT,
    tags TEXT NOT NULL DEFAULT '',
    gmail_message_id TEXT,
    gmail_thread_id TEXT,
    gmail_sent INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account, folder, uid)
);
CREATE INDEX IF NOT EXISTS messages_by_date ON messages(account, folder, date DESC);
CREATE TABLE IF NOT EXISTS bodies (
    account TEXT NOT NULL,
    folder TEXT NOT NULL,
    uid INTEGER NOT NULL,
    raw BLOB NOT NULL,
    PRIMARY KEY (account, folder, uid)
);
-- Deletes for good asked for and not yet confirmed by the server: made
-- again at the next start, so quitting (or a lost connection) never leaves
-- a message the user deleted on the server, or hidden there but kept.
CREATE TABLE IF NOT EXISTS pending_deletes (
    account TEXT NOT NULL,
    folder TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    PRIMARY KEY (account, folder, uid)
);
CREATE TABLE IF NOT EXISTS pop_seen (
    account TEXT NOT NULL,
    pop_id TEXT NOT NULL,
    remove INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account, pop_id)
);
-- POP3 accounts checked before: only a first check leaves older mail on
-- the server, and `pop_seen` can't tell (it's emptied with the server).
CREATE TABLE IF NOT EXISTS pop_checked (
    account TEXT PRIMARY KEY
);
-- Changes made to mail, so they can be listed and undone: a row per
-- action, and a `changed` row per message. Nothing a message says is kept
-- here: it's looked up in the cache to show.
CREATE TABLE IF NOT EXISTS changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at INTEGER NOT NULL,
    who TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL,
    tag TEXT NOT NULL DEFAULT '',
    turned_on INTEGER NOT NULL DEFAULT 0,
    undone INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS changed (
    change_id INTEGER NOT NULL,
    account TEXT NOT NULL,
    folder TEXT NOT NULL,
    uidvalidity INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    message_id TEXT NOT NULL,
    had INTEGER NOT NULL DEFAULT 0,
    moved_to TEXT NOT NULL DEFAULT '',
    new_uid INTEGER NOT NULL DEFAULT 0,
    moved_uidvalidity INTEGER NOT NULL DEFAULT 0,
    moved_floor INTEGER NOT NULL DEFAULT 0,
    size INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS changed_by_change ON changed(change_id);
-- The last UID each folder kept here has given: never given again, so a
-- UID held (a change, an agent's id, a question) can't come to mean
-- another message.
CREATE TABLE IF NOT EXISTS local_uids (
    account TEXT NOT NULL,
    folder TEXT NOT NULL,
    last INTEGER NOT NULL,
    PRIMARY KEY (account, folder)
);
CREATE TABLE IF NOT EXISTS addresses (
    addr TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    last INTEGER NOT NULL DEFAULT 0,
    normalized_addr TEXT NOT NULL DEFAULT '',
    name_fold TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS contact_sources (
    account TEXT PRIMARY KEY,
    revision INTEGER NOT NULL,
    address_book TEXT NOT NULL,
    sync_token TEXT NOT NULL,
    discovered_at INTEGER NOT NULL,
    last_sync INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS contacts (
    account TEXT NOT NULL,
    id TEXT NOT NULL,
    name TEXT NOT NULL,
    name_fold TEXT NOT NULL,
    phones TEXT NOT NULL,
    organization TEXT NOT NULL,
    search_text TEXT NOT NULL,
    etag TEXT NOT NULL,
    vcard TEXT NOT NULL,
    PRIMARY KEY (account, id)
);
CREATE TABLE IF NOT EXISTS contact_emails (
    account TEXT NOT NULL,
    contact_id TEXT NOT NULL,
    email TEXT NOT NULL,
    normalized_email TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    PRIMARY KEY (account, contact_id, normalized_email)
);
CREATE INDEX IF NOT EXISTS contact_emails_by_address
    ON contact_emails(normalized_email, account);
";

const MESSAGE_COLUMNS: &str = "folder, uid, message_id, in_reply_to, refs, date, from_name, \
     from_addr, to_list, cc_list, subject, attachments, seen, flagged, answered, draft, size, \
     preview, tags, gmail_message_id, gmail_thread_id, gmail_sent";

/// Messages bigger than this aren't kept: they're fetched again to read.
pub const MAX_KEPT_BODY: usize = 25 << 20;

fn message_row(row: &rusqlite::Row) -> rusqlite::Result<Message> {
    // Cleaned again on the way out: the file could have been changed.
    let one = |i: usize, max: usize| -> rusqlite::Result<String> {
        Ok(text::one_line(&row.get::<_, String>(i)?, max))
    };
    // Gmail's unsigned IDs don't fit SQLite's signed integers. Invalid
    // metadata in an edited cache must not invent a conversation.
    let gmail = match (
        row.get::<_, Option<String>>(19)?,
        row.get::<_, Option<String>>(20)?,
    ) {
        (Some(message), Some(thread)) => match (message.parse(), thread.parse()) {
            (Ok(message_id), Ok(thread_id)) => Some(Gmail {
                message_id,
                thread_id,
                sent: row.get(21)?,
            }),
            _ => None,
        },
        _ => None,
    };
    Ok(Message {
        folder: row.get(0)?,
        uid: row.get(1)?,
        summary: Summary {
            message_id: one(2, 300)?,
            in_reply_to: one(3, 300)?,
            references: one(4, 20_000)?,
            date: row.get(5)?,
            from: Addr {
                name: one(6, mail::MAX_NAME)?,
                addr: one(7, mail::MAX_NAME)?,
            },
            to: one(8, mail::MAX_ADDRESSES)?,
            cc: one(9, mail::MAX_ADDRESSES)?,
            subject: one(10, mail::MAX_SUBJECT)?,
            attachments: row.get(11)?,
        },
        flags: Flags {
            seen: row.get(12)?,
            flagged: row.get(13)?,
            answered: row.get(14)?,
            draft: row.get(15)?,
            tags: tags::from_stored(&row.get::<_, String>(18)?),
        },
        size: row.get(16)?,
        gmail,
        preview: one(17, 300)?,
    })
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let shown = config::shown(path);
        // Not through a link: the cache is the file in the data folder.
        let flags = rusqlite::OpenFlags::default() | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let db = Connection::open_with_flags(path, flags)
            .with_context(|| format!("cannot open {shown}"))?;
        // Deleted rows (a message deleted) are overwritten, not left
        // readable in the file's free pages; under WAL once checkpointed,
        // which removals do.
        db.execute_batch("PRAGMA journal_mode = WAL; PRAGMA secure_delete = ON;")?;
        db.execute_batch(SCHEMA)
            .and_then(|()| Self::migrate(&db))
            .with_context(|| format!("cannot set up {shown}"))?;
        Self::protect(path).with_context(|| format!("cannot protect {shown}"))?;
        let store = Self { db };
        store.prune_changes()?;
        Ok(store)
    }

    /// A store that lives only in memory: the demo's, and tests'.
    pub fn in_memory() -> Self {
        let db = Connection::open_in_memory().expect("SQLite opens in memory");
        db.execute_batch(SCHEMA)
            .and_then(|()| Self::migrate(&db))
            .expect("the schema is valid");
        Self { db }
    }

    /// Adds what a cache made by an older tuimail lacks.
    fn migrate(db: &Connection) -> rusqlite::Result<()> {
        let tagged: bool = db.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('messages') WHERE name = 'tags'",
            [],
            |r| r.get(0),
        )?;
        if !tagged {
            db.execute_batch("ALTER TABLE messages ADD COLUMN tags TEXT NOT NULL DEFAULT '';")?;
        }
        for (column, declaration) in [
            ("gmail_message_id", "TEXT"),
            ("gmail_thread_id", "TEXT"),
            ("gmail_sent", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            let there: bool = db.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('messages') WHERE name = ?1",
                [column],
                |r| r.get(0),
            )?;
            if !there {
                db.execute_batch(&format!(
                    "ALTER TABLE messages ADD COLUMN {column} {declaration};"
                ))?;
            }
        }
        // Created after adding the columns: SCHEMA also opens old caches.
        db.execute_batch(
            "CREATE INDEX IF NOT EXISTS messages_by_gmail_thread
             ON messages(account, folder, gmail_thread_id);
             CREATE INDEX IF NOT EXISTS messages_by_gmail_message
             ON messages(account, gmail_message_id);",
        )?;
        for column in ["moved_uidvalidity", "moved_floor", "size"] {
            let there: bool = db.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('changed') WHERE name = ?1",
                [column],
                |r| r.get(0),
            )?;
            if !there {
                db.execute_batch(&format!(
                    "ALTER TABLE changed ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0;"
                ))?;
            }
        }
        Self::migrate_contact_addresses(db)?;
        Ok(())
    }

    /// The database and its journal files readable only by you, whatever
    /// the umask.
    fn protect(path: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for suffix in ["", "-wal", "-shm"] {
                let mut file = path.as_os_str().to_owned();
                file.push(suffix);
                match std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)) {
                    // The journal files come and go with the connection.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound && !suffix.is_empty() => {}
                    result => result?,
                }
            }
        }
        #[cfg(not(unix))]
        let _ = path;
        Ok(())
    }

    /// Writes deleted pages out of the journal, so removed mail is gone
    /// from the file.
    fn scrub(&self) {
        let _ = self.db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);");
    }

    // Folders.

    pub fn folders(&self, account: &str) -> Result<Vec<Folder>> {
        let mut stmt = self.db.prepare(
            "SELECT name, shown, delimiter, role, selectable, unread, total FROM folders
             WHERE account = ?1",
        )?;
        let rows = stmt.query_map(params![account], |row| {
            Ok(Folder {
                name: row.get(0)?,
                shown: text::one_line(&row.get::<_, String>(1)?, 200),
                delimiter: row.get(2)?,
                role: row
                    .get::<_, Option<String>>(3)?
                    .and_then(|r| Role::parse(&r)),
                selectable: row.get(4)?,
                unread: row.get(5)?,
                total: row.get(6)?,
            })
        })?;
        let mut folders = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        sort_folders(&mut folders);
        Ok(folders)
    }

    /// Replaces the account's folder list with `folders`; folders gone from
    /// the server go, with their messages.
    pub fn set_folders(&mut self, account: &str, folders: &[Folder]) -> Result<()> {
        let tx = self.db.transaction()?;
        let names: HashSet<&str> = folders.iter().map(|f| f.name.as_str()).collect();
        let old: Vec<String> = {
            let mut stmt = tx.prepare("SELECT name FROM folders WHERE account = ?1")?;
            let rows = stmt.query_map(params![account], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let mut removed = false;
        for name in old.iter().filter(|n| !names.contains(n.as_str())) {
            for table in ["folders", "messages", "bodies"] {
                let column = if table == "folders" { "name" } else { "folder" };
                tx.execute(
                    &format!("DELETE FROM {table} WHERE account = ?1 AND {column} = ?2"),
                    params![account, name],
                )?;
            }
            removed = true;
        }
        for f in folders {
            tx.execute(
                "INSERT INTO folders (account, name, shown, delimiter, role, selectable)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(account, name) DO UPDATE SET shown = excluded.shown,
                     delimiter = excluded.delimiter, role = excluded.role,
                     selectable = excluded.selectable",
                params![
                    account,
                    f.name,
                    f.shown,
                    f.delimiter,
                    f.role.map(Role::as_str),
                    f.selectable
                ],
            )?;
        }
        tx.commit()?;
        if removed {
            self.scrub();
        }
        Ok(())
    }

    pub fn set_counts(&self, account: &str, folder: &str, unread: u32, total: u32) -> Result<()> {
        self.db.execute(
            "UPDATE folders SET unread = ?3, total = ?4 WHERE account = ?1 AND name = ?2",
            params![account, folder, unread, total],
        )?;
        Ok(())
    }

    /// Counts a folder's unread and total messages from what's cached, for
    /// folders kept here (POP3) and after a change made here.
    pub fn count(&self, account: &str, folder: &str) -> Result<(u32, u32)> {
        Ok(self.db.query_row(
            "SELECT COALESCE(SUM(seen = 0), 0), COUNT(*) FROM messages
             WHERE account = ?1 AND folder = ?2",
            params![account, folder],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?)
    }

    pub fn known(&self, account: &str, folder: &str) -> Result<Known> {
        Ok(self
            .db
            .query_row(
                "SELECT uidvalidity, low, high FROM folders WHERE account = ?1 AND name = ?2",
                params![account, folder],
                |r| {
                    Ok(Known {
                        uidvalidity: r.get(0)?,
                        low: r.get(1)?,
                        high: r.get(2)?,
                    })
                },
            )
            .optional()?
            .unwrap_or_default())
    }

    pub fn set_known(&self, account: &str, folder: &str, known: Known) -> Result<()> {
        self.db.execute(
            "UPDATE folders SET uidvalidity = ?3, low = ?4, high = ?5
             WHERE account = ?1 AND name = ?2",
            params![account, folder, known.uidvalidity, known.low, known.high],
        )?;
        Ok(())
    }

    /// Forgets a folder's messages: its UIDs mean other messages now.
    pub fn reset_folder(&self, account: &str, folder: &str) -> Result<()> {
        for table in ["messages", "bodies"] {
            self.db.execute(
                &format!("DELETE FROM {table} WHERE account = ?1 AND folder = ?2"),
                params![account, folder],
            )?;
        }
        self.db.execute(
            "UPDATE folders SET uidvalidity = 0, low = 0, high = 0
             WHERE account = ?1 AND name = ?2",
            params![account, folder],
        )?;
        self.scrub();
        Ok(())
    }

    // Messages.

    /// A folder's messages, newest first.
    pub fn messages(&self, account: &str, folder: &str, limit: usize) -> Result<Vec<Message>> {
        let mut stmt = self.db.prepare(&format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages WHERE account = ?1 AND folder = ?2
             ORDER BY date DESC, uid DESC LIMIT ?3"
        ))?;
        let rows = stmt.query_map(params![account, folder, limit as i64], message_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn message(&self, account: &str, folder: &str, uid: u32) -> Result<Option<Message>> {
        Ok(self
            .db
            .query_row(
                &format!(
                    "SELECT {MESSAGE_COLUMNS} FROM messages
                     WHERE account = ?1 AND folder = ?2 AND uid = ?3"
                ),
                params![account, folder, uid],
                message_row,
            )
            .optional()?)
    }

    /// The account's cached messages matching every search term, newest
    /// first. Date bounds use the cached timestamp at UTC midnight.
    pub fn search(
        &self,
        account: &str,
        folder: Option<&str>,
        query: &str,
        limit: usize,
    ) -> Result<Vec<Message>> {
        self.search_including(account, folder, query, limit, None)
    }

    /// Include verified server hits even when they match uncached text or
    /// headers. Tag predicates always use the current cached flags.
    pub(crate) fn search_including(
        &self,
        account: &str,
        folder: Option<&str>,
        query: &str,
        limit: usize,
        server_matches: Option<(&str, &[u32])>,
    ) -> Result<Vec<Message>> {
        let mut terms = terms(query).peekable();
        if terms.peek().is_none() {
            return Ok(Vec::new());
        }
        let mut sql = format!("SELECT {MESSAGE_COLUMNS} FROM messages WHERE account = ?1");
        let mut values: Vec<rusqlite::types::Value> = vec![account.to_string().into()];
        if let Some(folder) = folder {
            values.push(folder.to_string().into());
            write!(sql, " AND folder = ?{}", values.len()).unwrap();
        }
        sql.push_str(" AND ((1");
        let mut tag_binds = [0; MAX_TERMS];
        let mut tag_count = 0;
        for term in terms {
            let n = values.len() + 1;
            match term {
                Term::Tag { name, .. } => {
                    values.push(name.into());
                    tag_binds[tag_count] = n;
                    tag_count += 1;
                }
                Term::Since(date) | Term::Before(date) => {
                    let midnight = date.and_time(chrono::NaiveTime::MIN).and_utc().timestamp();
                    values.push(midnight.into());
                    let op = if matches!(term, Term::Since(_)) {
                        ">="
                    } else {
                        "<"
                    };
                    // Zero is the cache's sentinel for an unknown date.
                    write!(sql, " AND date != 0 AND date {op} ?{n}").unwrap();
                }
                Term::Text(field, word) => {
                    // SQLite's LIKE treats NUL as the end of the pattern.
                    // No cached text can match a literal NUL.
                    if word.contains('\0') {
                        return Ok(Vec::new());
                    }
                    let mut pattern = String::with_capacity(word.len() + 2);
                    pattern.push('%');
                    for c in word.chars() {
                        if matches!(c, '\\' | '%' | '_') {
                            pattern.push('\\');
                        }
                        pattern.push(c);
                    }
                    pattern.push('%');
                    values.push(pattern.into());
                    let columns: &[&str] = match field {
                        Field::Any => &[
                            "subject",
                            "from_name",
                            "from_addr",
                            "to_list",
                            "cc_list",
                            "preview",
                        ],
                        Field::From => &["from_name", "from_addr"],
                        Field::To => &["to_list"],
                        Field::Subject => &["subject"],
                    };
                    sql.push_str(" AND (");
                    for (i, column) in columns.iter().enumerate() {
                        if i != 0 {
                            sql.push_str(" OR ");
                        }
                        write!(sql, "{column} LIKE ?{n} ESCAPE '\\'").unwrap();
                    }
                    sql.push(')');
                }
            }
        }
        sql.push(')');
        if let Some((folder, uids)) = server_matches.filter(|(_, uids)| !uids.is_empty()) {
            values.push(folder.to_string().into());
            write!(sql, " OR (folder = ?{} AND uid IN (", values.len()).unwrap();
            for (i, &uid) in uids.iter().enumerate() {
                if i != 0 {
                    sql.push(',');
                }
                sql.push('?');
                values.push(uid.into());
            }
            sql.push_str("))");
        }
        sql.push(')');
        for &n in &tag_binds[..tag_count] {
            write!(
                sql,
                " AND instr(' ' || tags || ' ', ' ' || ?{n} || ' ') > 0"
            )
            .unwrap();
        }
        write!(sql, " ORDER BY date DESC, uid DESC LIMIT {limit}").unwrap();
        let mut stmt = self.db.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(values), message_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Adds fetched headers, keeping downloaded text and any Gmail
    /// identities absent from an ordinary header refresh.
    pub fn add_headers(&mut self, account: &str, folder: &str, headers: &[Header]) -> Result<()> {
        let tx = self.db.transaction()?;
        Self::insert_headers(&tx, account, folder, headers)?;
        tx.commit()?;
        Ok(())
    }

    fn insert_headers<'a>(
        tx: &Transaction<'_>,
        account: &str,
        folder: &str,
        headers: impl IntoIterator<Item = &'a Header>,
    ) -> Result<()> {
        let mut stmt = tx.prepare(
            "INSERT INTO messages (account, folder, uid, message_id, in_reply_to, refs, date,
                 from_name, from_addr, to_list, cc_list, subject, attachments, seen, flagged,
                 answered, draft, size, tags, gmail_message_id, gmail_thread_id, gmail_sent)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                 ?17, ?18, ?19, ?20, ?21, ?22)
             ON CONFLICT(account, folder, uid) DO UPDATE SET
                 seen = excluded.seen, flagged = excluded.flagged,
                 answered = excluded.answered, draft = excluded.draft,
                 tags = excluded.tags,
                 gmail_message_id = COALESCE(excluded.gmail_message_id, messages.gmail_message_id),
                 gmail_thread_id = COALESCE(excluded.gmail_thread_id, messages.gmail_thread_id),
                 gmail_sent = CASE WHEN excluded.gmail_message_id IS NULL THEN messages.gmail_sent
                     ELSE excluded.gmail_sent END",
        )?;
        for h in headers {
            let s = &h.summary;
            stmt.execute(params![
                account,
                folder,
                h.uid,
                s.message_id,
                s.in_reply_to,
                s.references,
                s.date,
                s.from.name,
                s.from.addr,
                s.to,
                s.cc,
                s.subject,
                s.attachments,
                h.flags.seen,
                h.flags.flagged,
                h.flags.answered,
                h.flags.draft,
                h.size,
                tags::to_stored(&h.flags.tags),
                h.gmail.map(|g| g.message_id.to_string()),
                h.gmail.map(|g| g.thread_id.to_string()),
                h.gmail.is_some_and(|g| g.sent)
            ])?;
        }
        Ok(())
    }

    /// Records identities only for UIDs already cached in this folder.
    pub fn set_gmail(
        &mut self,
        account: &str,
        folder: &str,
        messages: &[(u32, Gmail)],
    ) -> Result<()> {
        let tx = self.db.transaction()?;
        {
            let mut stmt = tx.prepare(
                "UPDATE messages SET gmail_message_id = ?4, gmail_thread_id = ?5, gmail_sent = ?6
                 WHERE account = ?1 AND folder = ?2 AND uid = ?3",
            )?;
            for (uid, gmail) in messages {
                stmt.execute(params![
                    account,
                    folder,
                    uid,
                    gmail.message_id.to_string(),
                    gmail.thread_id.to_string(),
                    gmail.sent
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Cached members of these native threads only, newest first.
    pub fn gmail_messages(
        &self,
        account: &str,
        folder: &str,
        thread_ids: &[u64],
    ) -> Result<Vec<Message>> {
        if thread_ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut stmt = self.db.prepare(&format!(
            "SELECT {MESSAGE_COLUMNS} FROM messages
             WHERE account = ?1 AND folder = ?2 AND gmail_thread_id = ?3"
        ))?;
        let mut messages = Vec::new();
        let mut seen = HashSet::new();
        for thread in thread_ids {
            if !seen.insert(*thread) {
                continue;
            }
            let rows = stmt.query_map(params![account, folder, thread.to_string()], message_row)?;
            for row in rows {
                let message = row?;
                if message.gmail.is_some() {
                    messages.push(message);
                }
            }
        }
        messages
            .sort_unstable_by(|a, b| b.summary.date.cmp(&a.summary.date).then(b.uid.cmp(&a.uid)));
        Ok(messages)
    }

    /// Cached label copies of these native messages, including their source
    /// identities, without using sender-supplied Message-ID headers.
    pub fn gmail_copies(
        &self,
        account: &str,
        folder: &str,
        uids: &[u32],
    ) -> Result<Vec<(String, u32)>> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        let mut stmt = self.db.prepare(
            "SELECT copy.folder, copy.uid FROM messages AS source
             JOIN messages AS copy ON copy.account = source.account
                 AND copy.gmail_message_id = source.gmail_message_id
             WHERE source.account = ?1 AND source.folder = ?2 AND source.uid = ?3",
        )?;
        let mut copies = HashSet::new();
        for uid in uids {
            let rows = stmt.query_map(params![account, folder, uid], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, u32>(1)?))
            })?;
            for row in rows {
                copies.insert(row?);
            }
        }
        Ok(copies.into_iter().collect())
    }

    /// Replaces only these complete native threads, retaining surviving
    /// UIDs' bodies and previews. This does not claim a contiguous sync
    /// range or alter the folder's server counts.
    pub fn replace_gmail_threads(
        &mut self,
        account: &str,
        folder: &str,
        thread_ids: &[u64],
        headers: &[Header],
    ) -> Result<()> {
        if thread_ids.is_empty() {
            return Ok(());
        }
        let threads: HashSet<u64> = thread_ids.iter().copied().collect();
        let matching = || {
            headers
                .iter()
                .filter(|h| h.gmail.is_some_and(|g| threads.contains(&g.thread_id)))
        };
        let kept: HashSet<u32> = matching().map(|h| h.uid).collect();
        let tx = self.db.transaction()?;
        let mut gone = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT uid FROM messages
                 WHERE account = ?1 AND folder = ?2 AND gmail_thread_id = ?3",
            )?;
            for thread in &threads {
                let rows = stmt.query_map(params![account, folder, thread.to_string()], |r| {
                    r.get::<_, u32>(0)
                })?;
                for row in rows {
                    let uid = row?;
                    if !kept.contains(&uid) {
                        gone.push(uid);
                    }
                }
            }
        }
        Self::remove_messages(&tx, account, folder, &gone)?;
        Self::insert_headers(&tx, account, folder, matching())?;
        tx.commit()?;
        if !gone.is_empty() {
            self.scrub();
        }
        Ok(())
    }

    /// Sets the flags of messages already cached.
    pub fn set_flags(&mut self, account: &str, folder: &str, flags: &[(u32, Flags)]) -> Result<()> {
        let tx = self.db.transaction()?;
        {
            let mut stmt = tx.prepare(
                "UPDATE messages SET seen = ?4, flagged = ?5, answered = ?6, draft = ?7,
                     tags = ?8
                 WHERE account = ?1 AND folder = ?2 AND uid = ?3",
            )?;
            for (uid, f) in flags {
                stmt.execute(params![
                    account,
                    folder,
                    uid,
                    f.seen,
                    f.flagged,
                    f.answered,
                    f.draft,
                    tags::to_stored(&f.tags)
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Every tag on a cached message of these accounts, sorted: the ones to
    /// offer when tagging.
    pub fn all_tags(&self, accounts: &[&str]) -> Result<Vec<String>> {
        let mut stmt = self.db.prepare(
            "SELECT DISTINCT tags FROM messages WHERE account = ?1 AND tags != '' LIMIT 5000",
        )?;
        let mut all = std::collections::BTreeSet::new();
        for account in accounts {
            let rows = stmt.query_map(params![account], |r| r.get::<_, String>(0))?;
            for row in rows {
                all.extend(tags::from_stored(&row?));
            }
        }
        Ok(all.into_iter().take(500).collect())
    }

    /// The UIDs cached in `folder` from `low` to `high`.
    pub fn uids(&self, account: &str, folder: &str, low: u32, high: u32) -> Result<Vec<u32>> {
        let mut stmt = self.db.prepare(
            "SELECT uid FROM messages WHERE account = ?1 AND folder = ?2 AND uid BETWEEN ?3 AND ?4",
        )?;
        let rows = stmt.query_map(params![account, folder, low, high], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn remove(&mut self, account: &str, folder: &str, uids: &[u32]) -> Result<()> {
        if uids.is_empty() {
            return Ok(());
        }
        let tx = self.db.transaction()?;
        Self::remove_messages(&tx, account, folder, uids)?;
        tx.commit()?;
        self.scrub();
        Ok(())
    }

    fn remove_messages(
        tx: &Transaction<'_>,
        account: &str,
        folder: &str,
        uids: &[u32],
    ) -> Result<()> {
        for table in ["messages", "bodies"] {
            let mut stmt = tx.prepare(&format!(
                "DELETE FROM {table} WHERE account = ?1 AND folder = ?2 AND uid = ?3"
            ))?;
            for uid in uids {
                stmt.execute(params![account, folder, uid])?;
            }
        }
        Ok(())
    }

    pub fn body(&self, account: &str, folder: &str, uid: u32) -> Result<Option<Vec<u8>>> {
        Ok(self
            .db
            .query_row(
                "SELECT raw FROM bodies WHERE account = ?1 AND folder = ?2 AND uid = ?3",
                params![account, folder, uid],
                |r| r.get(0),
            )
            .optional()?)
    }

    /// Disproves a possible copy only when both full messages are cached.
    pub fn cached_bodies_differ(
        &self,
        account: &str,
        first: (&str, u32),
        second: (&str, u32),
    ) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT EXISTS (
                SELECT 1 FROM bodies AS a JOIN bodies AS b ON a.account = b.account
                WHERE a.account = ?1 AND a.folder = ?2 AND a.uid = ?3
                    AND b.folder = ?4 AND b.uid = ?5 AND a.raw <> b.raw
            )",
            params![account, first.0, first.1, second.0, second.1],
            |r| r.get(0),
        )?)
    }

    /// Keeps a downloaded message, and the start of its text for the list.
    /// Keeps a downloaded message, unless it's bigger than [`MAX_KEPT_BODY`]
    /// (then it's downloaded again to read). Its preview for the list comes
    /// later ([`Store::set_preview`]): making one may lay out HTML, which
    /// needs the big stack of a background thread.
    pub fn save_body(&self, account: &str, folder: &str, uid: u32, raw: &[u8]) -> Result<()> {
        if raw.len() <= MAX_KEPT_BODY {
            self.keep_body(account, folder, uid, raw)?;
        }
        Ok(())
    }

    fn keep_body(&self, account: &str, folder: &str, uid: u32, raw: &[u8]) -> Result<()> {
        self.db.execute(
            "INSERT OR REPLACE INTO bodies (account, folder, uid, raw) VALUES (?1, ?2, ?3, ?4)",
            params![account, folder, uid, raw],
        )?;
        Ok(())
    }

    /// The start of a message's text, for the list.
    pub fn set_preview(&self, account: &str, folder: &str, uid: u32, preview: &str) -> Result<()> {
        self.db.execute(
            "UPDATE messages SET preview = ?4 WHERE account = ?1 AND folder = ?2 AND uid = ?3",
            params![account, folder, uid, text::one_line(preview, 200)],
        )?;
        Ok(())
    }

    // Folders kept here: POP3 mail, and its Sent, Drafts and Trash.

    /// Adds a whole message to a folder kept here, under the next UID;
    /// returns that UID.
    pub fn add_local(
        &mut self,
        account: &str,
        folder: &str,
        raw: &[u8],
        flags: Flags,
        pop_id: Option<&str>,
    ) -> Result<u32> {
        // Seen first: a message that can't be kept is never downloaded
        // again and again.
        if let Some(id) = pop_id {
            self.pop_skip(account, id)?;
        }
        // Past every UID the folder has given, not only those it has now:
        // a freed UID given to the next message would make what held it (a
        // change to undo, an agent's id, a question asked) act on that one.
        let uid: u32 = self.db.query_row(
            "SELECT MAX(
                 COALESCE((SELECT MAX(uid) FROM messages WHERE account = ?1 AND folder = ?2), 0),
                 COALESCE((SELECT last FROM local_uids WHERE account = ?1 AND folder = ?2), 0)
             ) + 1",
            params![account, folder],
            |r| r.get(0),
        )?;
        self.db.execute(
            "INSERT INTO local_uids (account, folder, last) VALUES (?1, ?2, ?3)
             ON CONFLICT (account, folder) DO UPDATE SET last = excluded.last",
            params![account, folder, uid],
        )?;
        let header = Header {
            uid,
            summary: mail::summarize(raw),
            flags,
            size: raw.len() as u32,
            gmail: None,
        };
        self.add_headers(account, folder, &[header])?;
        self.db.execute(
            "UPDATE messages SET pop_id = ?4 WHERE account = ?1 AND folder = ?2 AND uid = ?3",
            params![account, folder, uid, pop_id],
        )?;
        // The only copy: kept whatever its size.
        self.keep_body(account, folder, uid, raw)?;
        Ok(uid)
    }

    /// Moves messages between folders kept here; the UIDs of those moved,
    /// before and after.
    pub fn move_local(
        &mut self,
        account: &str,
        from: &str,
        uids: &[u32],
        to: &str,
    ) -> Result<Vec<(u32, u32)>> {
        let mut moved = Vec::new();
        for &uid in uids {
            let Some(raw) = self.body(account, from, uid)? else {
                continue;
            };
            let Some(message) = self.message(account, from, uid)? else {
                continue;
            };
            let pop_id: Option<String> = self.db.query_row(
                "SELECT pop_id FROM messages WHERE account = ?1 AND folder = ?2 AND uid = ?3",
                params![account, from, uid],
                |r| r.get(0),
            )?;
            let new = self.add_local(account, to, &raw, message.flags, None)?;
            if let Some(gmail) = message.gmail {
                self.set_gmail(account, to, &[(new, gmail)])?;
            }
            self.db.execute(
                "UPDATE messages SET pop_id = ?4 WHERE account = ?1 AND folder = ?2 AND uid = ?3",
                params![account, to, new, pop_id],
            )?;
            moved.push((uid, new));
        }
        // Only what was copied goes.
        let gone: Vec<u32> = moved.iter().map(|(old, _)| *old).collect();
        self.remove(account, from, &gone)?;
        Ok(moved)
    }

    /// The POP3 ids of every message ever downloaded for the account, so
    /// none is downloaded twice.
    pub fn pop_seen(&self, account: &str) -> Result<HashSet<String>> {
        let mut stmt = self
            .db
            .prepare("SELECT pop_id FROM pop_seen WHERE account = ?1")?;
        let rows = stmt.query_map(params![account], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Notes deletes for good on their way to the server.
    pub fn add_pending_deletes(
        &mut self,
        account: &str,
        folder: &str,
        uidvalidity: u32,
        uids: &[u32],
    ) -> Result<()> {
        let tx = self.db.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO pending_deletes (account, folder, uidvalidity, uid)
                 VALUES (?1, ?2, ?3, ?4)",
            )?;
            for uid in uids {
                stmt.execute(params![account, folder, uidvalidity, uid])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Deletes the server has made.
    pub fn done_deletes(&mut self, account: &str, folder: &str, uids: &[u32]) -> Result<()> {
        let tx = self.db.transaction()?;
        {
            let mut stmt = tx.prepare(
                "DELETE FROM pending_deletes WHERE account = ?1 AND folder = ?2 AND uid = ?3",
            )?;
            for uid in uids {
                stmt.execute(params![account, folder, uid])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// The deletes still to make, by folder: (folder, UIDVALIDITY, UIDs).
    pub fn pending_deletes(&self, account: &str) -> Result<Vec<(String, u32, Vec<u32>)>> {
        let mut stmt = self.db.prepare(
            "SELECT folder, uidvalidity, uid FROM pending_deletes WHERE account = ?1
             ORDER BY folder, uidvalidity, uid",
        )?;
        let rows = stmt.query_map(params![account], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, u32>(2)?,
            ))
        })?;
        let mut out: Vec<(String, u32, Vec<u32>)> = Vec::new();
        for row in rows {
            let (folder, uidvalidity, uid) = row?;
            match out.last_mut() {
                Some(last) if last.0 == folder && last.1 == uidvalidity => last.2.push(uid),
                _ => out.push((folder, uidvalidity, vec![uid])),
            }
        }
        Ok(out)
    }

    /// Remembers a POP3 id that wasn't downloaded, so it isn't asked about
    /// again.
    pub fn pop_skip(&self, account: &str, pop_id: &str) -> Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO pop_seen (account, pop_id) VALUES (?1, ?2)",
            params![account, pop_id],
        )?;
        Ok(())
    }

    /// [`Store::pop_skip`] for many ids, in one write: a server listing
    /// thousands costs one commit, not one each.
    pub fn pop_skip_all(&mut self, account: &str, pop_ids: &[String]) -> Result<()> {
        let tx = self.db.transaction()?;
        {
            let mut stmt =
                tx.prepare("INSERT OR IGNORE INTO pop_seen (account, pop_id) VALUES (?1, ?2)")?;
            for id in pop_ids {
                stmt.execute(params![account, id])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// The POP3 ids of these messages, marked to be deleted from the server
    /// at the next check.
    pub fn mark_pop_removal(&self, account: &str, folder: &str, uids: &[u32]) -> Result<()> {
        for uid in uids {
            self.db.execute(
                "UPDATE pop_seen SET remove = 1 WHERE account = ?1 AND pop_id =
                     (SELECT pop_id FROM messages WHERE account = ?1 AND folder = ?2 AND uid = ?3)",
                params![account, folder, uid],
            )?;
        }
        Ok(())
    }

    /// The POP3 ids waiting to be deleted from the server.
    pub fn pop_removals(&self, account: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .db
            .prepare("SELECT pop_id FROM pop_seen WHERE account = ?1 AND remove = 1")?;
        let rows = stmt.query_map(params![account], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Forgets POP3 ids the server no longer has: they can't come back.
    pub fn pop_forget(&mut self, account: &str, keep: &HashSet<String>) -> Result<()> {
        let gone: Vec<String> = self
            .pop_seen(account)?
            .into_iter()
            .filter(|id| !keep.contains(id))
            .collect();
        let tx = self.db.transaction()?;
        {
            let mut stmt = tx.prepare("DELETE FROM pop_seen WHERE account = ?1 AND pop_id = ?2")?;
            for id in &gone {
                stmt.execute(params![account, id])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Whether the account's mail has been checked before. A cache from
    /// before this was kept counts if it remembers an id.
    pub fn pop_checked(&self, account: &str) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT EXISTS (SELECT 1 FROM pop_checked WHERE account = ?1)
                 OR EXISTS (SELECT 1 FROM pop_seen WHERE account = ?1)",
            params![account],
            |r| r.get(0),
        )?)
    }

    /// Notes that the account's mail has been checked.
    pub fn set_pop_checked(&self, account: &str) -> Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO pop_checked (account) VALUES (?1)",
            params![account],
        )?;
        Ok(())
    }

    // Addresses, for completing To, Cc and Bcc.

    /// Remembers addresses written to (`used`) or seen. A name seen in mail
    /// never replaces one already known: anyone can put any name on any
    /// address. Nor does a name sent to an address already written to: a
    /// reply-all carries the names its sender chose for everyone on it.
    pub fn remember(&self, addrs: &[Addr], used: bool, now: i64) -> Result<()> {
        for a in addrs.iter().take(100) {
            if !crate::account::valid_address(&a.addr) {
                continue;
            }
            let name = text::one_line(&a.name, mail::MAX_NAME);
            let normalized = a.addr.to_lowercase();
            self.db.execute(
                "INSERT INTO addresses (addr, name, used, last, normalized_addr, name_fold)
                 VALUES (COALESCE(
                     (SELECT addr FROM addresses WHERE normalized_addr=?5
                      ORDER BY used DESC,(name<>'') DESC,last DESC,addr LIMIT 1), lower(?6)),
                     ?1,?2,?3,?5,?4)
                 ON CONFLICT(addr) DO UPDATE SET
                     name = CASE
                         WHEN excluded.name = '' THEN addresses.name
                         WHEN addresses.name = '' THEN excluded.name
                         WHEN excluded.used = 1 AND addresses.used = 0 THEN excluded.name
                         ELSE addresses.name END,
                     name_fold = CASE
                         WHEN excluded.name = '' THEN addresses.name_fold
                         WHEN addresses.name = '' THEN excluded.name_fold
                         WHEN excluded.used = 1 AND addresses.used = 0 THEN excluded.name_fold
                         ELSE addresses.name_fold END,
                     used = addresses.used + excluded.used,
                     last = MAX(addresses.last, excluded.last)",
                params![
                    name,
                    i64::from(used),
                    now,
                    name.to_lowercase(),
                    normalized,
                    a.addr
                ],
            )?;
        }
        Ok(())
    }

    // Changes.

    /// Keeps a change; its id. Changes older than [`KEEP_CHANGES_FOR`], or
    /// past the newest [`MAX_CHANGES`], go.
    pub fn add_change(&mut self, change: &Change, now: i64) -> Result<i64> {
        let (kind, tag, on) = match &change.what {
            What::Seen(on) => ("seen", "", *on),
            What::Flagged(on) => ("flagged", "", *on),
            What::Tag(tag, on) => ("tag", tag.as_str(), *on),
            What::Move => ("move", "", false),
        };
        let tx = self.db.transaction()?;
        tx.execute(
            "INSERT INTO changes (at, who, kind, tag, turned_on, undone)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![change.at, change.who, kind, tag, on, change.undone],
        )?;
        let id = tx.last_insert_rowid();
        {
            let mut stmt = tx.prepare(
                "INSERT INTO changed (change_id, account, folder, uidvalidity, uid, message_id,
                     had, moved_to, new_uid, moved_uidvalidity, moved_floor, size)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            )?;
            for m in &change.messages {
                stmt.execute(params![
                    id,
                    m.account,
                    m.folder,
                    m.uidvalidity,
                    m.uid,
                    m.message_id,
                    m.had,
                    m.moved_to,
                    m.new_uid,
                    m.moved_uidvalidity,
                    m.moved_floor,
                    m.size
                ])?;
            }
        }
        tx.execute(
            "DELETE FROM changes WHERE at < ?1 OR id <= ?2",
            params![now - KEEP_CHANGES_FOR, id - MAX_CHANGES],
        )?;
        tx.execute(
            "DELETE FROM changed WHERE change_id NOT IN (SELECT id FROM changes)",
            [],
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// The newest changes first, at most `limit`, none older than
    /// [`KEEP_CHANGES_FOR`].
    pub fn changes(&self, limit: usize) -> Result<Vec<Change>> {
        self.read_changes("at >= ?1 ORDER BY id DESC LIMIT ?2", limit as i64)
    }

    /// The change with this id, if it's still kept.
    pub fn change(&self, id: i64) -> Result<Option<Change>> {
        Ok(self.read_changes("at >= ?1 AND id = ?2", id)?.pop())
    }

    fn read_changes(&self, filter: &str, arg: i64) -> Result<Vec<Change>> {
        let oldest = chrono::Utc::now().timestamp() - KEEP_CHANGES_FOR;
        let mut stmt = self.db.prepare(&format!(
            "SELECT id, at, who, kind, tag, turned_on, undone FROM changes WHERE {filter}"
        ))?;
        let rows = stmt.query_map(params![oldest, arg], |r| {
            let kind: String = r.get(3)?;
            let on: bool = r.get(5)?;
            let what = match kind.as_str() {
                "seen" => What::Seen(on),
                "flagged" => What::Flagged(on),
                "tag" => What::Tag(r.get(4)?, on),
                _ => What::Move,
            };
            Ok(Change {
                id: r.get(0)?,
                at: r.get(1)?,
                who: text::one_line(&r.get::<_, String>(2)?, 60),
                what,
                messages: Vec::new(),
                undone: r.get(6)?,
            })
        })?;
        let mut changes = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut stmt = self.db.prepare(
            "SELECT account, folder, uidvalidity, uid, message_id, had, moved_to, new_uid,
                 moved_uidvalidity, moved_floor, size
             FROM changed WHERE change_id = ?1",
        )?;
        for change in &mut changes {
            let rows = stmt.query_map(params![change.id], |r| {
                Ok(Changed {
                    account: r.get(0)?,
                    folder: r.get(1)?,
                    uidvalidity: r.get(2)?,
                    uid: r.get(3)?,
                    message_id: r.get(4)?,
                    had: r.get(5)?,
                    moved_to: r.get(6)?,
                    new_uid: r.get(7)?,
                    moved_uidvalidity: r.get(8)?,
                    moved_floor: r.get(9)?,
                    size: r.get(10)?,
                })
            })?;
            change.messages = rows.collect::<rusqlite::Result<_>>()?;
        }
        // A tag changed by hand in the file is no tag.
        changes.retain(
            |c| !matches!(&c.what, What::Tag(tag, _) if tags::normalize(tag).as_ref() != Some(tag)),
        );
        Ok(changes)
    }

    /// Where the server put messages a change moved: `to`'s UIDVALIDITY
    /// and its UIDNEXT just before the move ([`Changed::moved_floor`]).
    #[allow(clippy::too_many_arguments)]
    pub fn set_moved(
        &self,
        account: &str,
        folder: &str,
        uidvalidity: u32,
        uids: &[u32],
        to: &str,
        to_uidvalidity: u32,
        floor: u32,
    ) -> Result<()> {
        let mut stmt = self.db.prepare(
            "UPDATE changed SET moved_uidvalidity = ?6, moved_floor = ?7
             WHERE account = ?1 AND folder = ?2 AND uidvalidity = ?3 AND uid = ?4
                 AND moved_to = ?5 AND moved_floor = 0",
        )?;
        for uid in uids {
            stmt.execute(params![
                account,
                folder,
                uidvalidity,
                uid,
                to,
                to_uidvalidity,
                floor
            ])?;
        }
        Ok(())
    }

    /// Messages deleted for good: their Message-IDs go from the changes
    /// kept about them (where they were, and where a move put them here).
    pub fn forget_changed(&self, account: &str, folder: &str, uids: &[u32]) -> Result<()> {
        let mut stmt = self.db.prepare(
            "UPDATE changed SET message_id = ''
             WHERE account = ?1
                 AND ((folder = ?2 AND uid = ?3) OR (moved_to = ?2 AND new_uid = ?3))",
        )?;
        for uid in uids {
            stmt.execute(params![account, folder, uid])?;
        }
        Ok(())
    }

    /// Drops changes past [`KEEP_CHANGES_FOR`] (they're never shown), and
    /// what they kept about the messages, overwritten.
    fn prune_changes(&self) -> Result<()> {
        let oldest = chrono::Utc::now().timestamp() - KEEP_CHANGES_FOR;
        let gone = self
            .db
            .execute("DELETE FROM changes WHERE at < ?1", params![oldest])?;
        self.db.execute(
            "DELETE FROM changed WHERE change_id NOT IN (SELECT id FROM changes)",
            [],
        )?;
        if gone > 0 {
            self.scrub();
        }
        Ok(())
    }

    pub fn set_undone(&self, id: i64) -> Result<()> {
        self.db
            .execute("UPDATE changes SET undone = 1 WHERE id = ?1", params![id])?;
        Ok(())
    }

    /// A cached message in `folder` with this Message-ID, if there is one
    /// (to show which: the sender writes it, so it needn't be the only one).
    pub fn message_with_id(
        &self,
        account: &str,
        folder: &str,
        message_id: &str,
    ) -> Result<Option<Message>> {
        if message_id.is_empty() {
            return Ok(None);
        }
        let uid: Option<u32> = self
            .db
            .query_row(
                "SELECT uid FROM messages WHERE account = ?1 AND folder = ?2 AND message_id = ?3
                 ORDER BY uid DESC LIMIT 1",
                params![account, folder, message_id],
                |r| r.get(0),
            )
            .optional()?;
        match uid {
            Some(uid) => self.message(account, folder, uid),
            None => Ok(None),
        }
    }

    /// Forgets everything about an account: it was removed.
    pub fn forget_account(&self, account: &str) -> Result<()> {
        // Keep a generation tombstone even if the first sync is still
        // running in another process, so its result cannot revive this account.
        let tx = Transaction::new_unchecked(&self.db, TransactionBehavior::Immediate)?;
        let revision: i64 = tx
            .query_row(
                "SELECT revision FROM contact_sources WHERE account=?1",
                [account],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let revision = revision
            .checked_add(1)
            .context("contacts revision overflow")?;
        tx.execute(
            "INSERT INTO contact_sources
                 (account,revision,address_book,sync_token,discovered_at,last_sync)
             VALUES (?1,?2,'','',0,0)
             ON CONFLICT(account) DO UPDATE SET revision=excluded.revision,
                 address_book='',sync_token='',discovered_at=0,last_sync=0",
            params![account, revision],
        )?;
        for table in [
            "folders",
            "messages",
            "bodies",
            "pop_seen",
            "pop_checked",
            "pending_deletes",
            "changed",
            "local_uids",
            "contact_emails",
            "contacts",
        ] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE account = ?1"),
                params![account],
            )?;
        }
        tx.execute(
            "DELETE FROM changes WHERE id NOT IN (SELECT change_id FROM changed)",
            [],
        )?;
        tx.commit()?;
        self.scrub();
        Ok(())
    }
}

/// The start of a message's text for the list: one line, signature and
/// quotes left out.
pub fn preview(text: &str) -> String {
    let mut out = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line == "--" || line.starts_with("-- ") {
            break;
        }
        if line.is_empty() || line.starts_with('>') {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(line);
        if out.chars().count() > 200 {
            break;
        }
    }
    text::one_line(&out, 200)
}

/// Folders in the order the sidebar shows them: the inbox, then folders
/// with a role in [`Role`]'s order, then the rest by name.
pub fn sort_folders(folders: &mut [Folder]) {
    folders.sort_by(|a, b| {
        let key = |f: &Folder| (f.role.map_or(u8::MAX, |r| r as u8), f.shown.to_lowercase());
        key(a).cmp(&key(b))
    });
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn header(uid: u32, subject: &str, date: i64) -> Header {
        Header {
            uid,
            summary: Summary {
                subject: subject.into(),
                date,
                from: Addr {
                    name: "Alice".into(),
                    addr: "alice@example.com".into(),
                },
                to: "me@example.org".into(),
                ..Summary::default()
            },
            flags: Flags::default(),
            size: 100,
            gmail: None,
        }
    }

    fn folder(name: &str, role: Option<Role>) -> Folder {
        Folder {
            name: name.into(),
            shown: name.into(),
            delimiter: Some("/".into()),
            role,
            selectable: true,
            unread: 0,
            total: 0,
        }
    }

    fn gmail_header(uid: u32, thread_id: u64, sent: bool) -> Header {
        let mut h = header(uid, "Conversation", i64::from(uid));
        h.gmail = Some(Gmail {
            message_id: u64::MAX - u64::from(uid),
            thread_id,
            sent,
        });
        h
    }

    #[test]
    fn gmail_ids_are_unsigned_and_survive_ordinary_header_refreshes() {
        let mut store = Store::in_memory();
        let native = gmail_header(1, u64::MAX, true);
        store
            .add_headers("a", "All", std::slice::from_ref(&native))
            .unwrap();
        store
            .add_headers("b", "All", std::slice::from_ref(&native))
            .unwrap();
        store
            .add_headers("a", "INBOX", std::slice::from_ref(&native))
            .unwrap();
        store.save_body("a", "All", 1, b"kept body").unwrap();
        store.set_preview("a", "All", 1, "kept preview").unwrap();
        let mut ordinary = header(1, "Conversation", 1);
        ordinary.flags.seen = true;
        store.add_headers("a", "All", &[ordinary]).unwrap();
        let message = store.message("a", "All", 1).unwrap().unwrap();
        assert_eq!(message.gmail, native.gmail);
        assert!(message.flags.seen);
        assert_eq!(message.preview, "kept preview");
        assert_eq!(store.body("a", "All", 1).unwrap().unwrap(), b"kept body");
        let text_ids: (String, String) = store
            .db
            .query_row(
                "SELECT gmail_message_id, gmail_thread_id FROM messages
                 WHERE account = 'a' AND folder = 'All'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(text_ids, ((u64::MAX - 1).to_string(), u64::MAX.to_string()));
        assert!(store.gmail_messages("a", "All", &[]).unwrap().is_empty());
        let found = store
            .gmail_messages("a", "All", &[u64::MAX, u64::MAX])
            .unwrap();
        assert_eq!(found.len(), 1, "duplicate queries must not duplicate mail");
        assert_eq!(found[0].gmail, native.gmail);
        let changed = Gmail {
            sent: false,
            ..native.gmail.unwrap()
        };
        store
            .set_gmail("a", "All", &[(1, changed), (99, changed)])
            .unwrap();
        assert_eq!(
            store.message("a", "All", 1).unwrap().unwrap().gmail,
            Some(changed)
        );
        assert!(store.message("a", "All", 99).unwrap().is_none());
        assert_eq!(
            store.message("b", "All", 1).unwrap().unwrap().gmail,
            native.gmail
        );
        assert_eq!(
            store.message("a", "INBOX", 1).unwrap().unwrap().gmail,
            native.gmail
        );
        store
            .db
            .execute(
                "UPDATE messages SET gmail_message_id = '18446744073709551616'
                 WHERE account = 'a' AND folder = 'All'",
                [],
            )
            .unwrap();
        assert!(
            store
                .message("a", "All", 1)
                .unwrap()
                .unwrap()
                .gmail
                .is_none()
        );
        assert!(
            store
                .gmail_messages("a", "All", &[u64::MAX])
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn replacing_gmail_threads_is_targeted_and_keeps_surviving_bodies() {
        let mut store = Store::in_memory();
        store.set_folders("a", &[folder("All", None)]).unwrap();
        let known = Known {
            uidvalidity: 9,
            low: 100,
            high: 200,
        };
        store.set_known("a", "All", known).unwrap();
        store.set_counts("a", "All", 12, 40).unwrap();
        let thread = u64::MAX;
        let original = [
            gmail_header(1, thread, false),
            gmail_header(2, thread, true),
            gmail_header(3, 7, false),
            header(4, "Ordinary", 4),
        ];
        store.add_headers("a", "All", &original).unwrap();
        for uid in 1..=4 {
            store.save_body("a", "All", uid, &[uid as u8]).unwrap();
            store.set_preview("a", "All", uid, "kept").unwrap();
        }
        for (account, folder) in [("b", "All"), ("a", "INBOX")] {
            store.add_headers(account, folder, &original).unwrap();
            store.save_body(account, folder, 1, b"separate").unwrap();
        }
        let mut survivor = gmail_header(2, thread, false);
        survivor.flags.seen = true;
        store
            .replace_gmail_threads(
                "a",
                "All",
                &[thread, thread],
                &[
                    survivor,
                    gmail_header(5, thread, true),
                    gmail_header(1, 99, false),
                    gmail_header(6, 99, false),
                    header(7, "Missing metadata", 7),
                ],
            )
            .unwrap();
        assert!(store.message("a", "All", 1).unwrap().is_none());
        assert!(store.body("a", "All", 1).unwrap().is_none());
        let survived = store.message("a", "All", 2).unwrap().unwrap();
        assert_eq!(survived.gmail, gmail_header(2, thread, false).gmail);
        assert!(survived.flags.seen);
        assert_eq!(survived.preview, "kept");
        for uid in 2..=4 {
            assert_eq!(store.body("a", "All", uid).unwrap().unwrap(), [uid as u8]);
        }
        assert!(store.message("a", "All", 5).unwrap().is_some());
        for uid in [6, 7] {
            assert!(store.message("a", "All", uid).unwrap().is_none());
        }
        assert_eq!(store.known("a", "All").unwrap(), known);
        let folders = store.folders("a").unwrap();
        assert_eq!((folders[0].unread, folders[0].total), (12, 40));
        for (account, folder) in [("b", "All"), ("a", "INBOX")] {
            assert_eq!(
                store.body(account, folder, 1).unwrap().unwrap(),
                b"separate"
            );
            assert_eq!(
                store
                    .gmail_messages(account, folder, &[thread])
                    .unwrap()
                    .len(),
                2
            );
        }
        let found = store.gmail_messages("a", "All", &[7, thread]).unwrap();
        assert_eq!(found.iter().map(|m| m.uid).collect::<Vec<_>>(), [5, 3, 2]);
        store
            .replace_gmail_threads("a", "All", &[], &original)
            .unwrap();
        assert_eq!(store.uids("a", "All", 0, 10).unwrap().len(), 4);
        store
            .replace_gmail_threads("a", "All", &[thread], &[])
            .unwrap();
        assert!(
            store
                .gmail_messages("a", "All", &[thread])
                .unwrap()
                .is_empty()
        );
        assert!(store.body("a", "All", 2).unwrap().is_none());
        assert!(store.message("a", "All", 3).unwrap().is_some());
        assert!(store.message("a", "All", 4).unwrap().is_some());
    }

    #[test]
    fn replacing_gmail_threads_rolls_back_removals_when_insertion_fails() {
        let mut store = Store::in_memory();
        store
            .add_headers("a", "All", &[gmail_header(1, 9, false)])
            .unwrap();
        store.save_body("a", "All", 1, b"kept").unwrap();
        store
            .db
            .execute_batch(
                "CREATE TRIGGER fail_header BEFORE INSERT ON messages WHEN NEW.uid = 5
                 BEGIN SELECT RAISE(ABORT, 'test failure'); END;",
            )
            .unwrap();
        assert!(
            store
                .replace_gmail_threads("a", "All", &[9], &[gmail_header(5, 9, false)])
                .is_err()
        );
        assert!(store.message("a", "All", 1).unwrap().is_some());
        assert_eq!(store.body("a", "All", 1).unwrap().unwrap(), b"kept");
        assert!(store.message("a", "All", 5).unwrap().is_none());
    }

    #[test]
    fn old_caches_gain_gmail_metadata_without_changing_existing_mail() {
        let db = Connection::open_in_memory().unwrap();
        let old = SCHEMA.replace(
            "    gmail_message_id TEXT,\n    gmail_thread_id TEXT,\n    gmail_sent INTEGER NOT NULL DEFAULT 0,\n",
            "",
        );
        assert_ne!(old, SCHEMA);
        db.execute_batch(&old).unwrap();
        db.execute_batch(
            "INSERT INTO messages (account, folder, uid, message_id, in_reply_to, refs, date,
                 from_name, from_addr, to_list, cc_list, subject, preview)
             VALUES ('a', 'All', 1, 'sender@id', '', '', 1, '', 'a@b.c', '', '', 'Old', 'kept');
             INSERT INTO bodies (account, folder, uid, raw) VALUES ('a', 'All', 1, X'6162');",
        )
        .unwrap();
        // Opening an existing cache applies SCHEMA before migration.
        db.execute_batch(SCHEMA).unwrap();
        Store::migrate(&db).unwrap();
        Store::migrate(&db).unwrap();
        let mut store = Store { db };
        let old = store.message("a", "All", 1).unwrap().unwrap();
        assert!(old.gmail.is_none());
        assert_eq!(old.preview, "kept");
        assert_eq!(old.summary.message_id, "sender@id");
        assert_eq!(store.body("a", "All", 1).unwrap().unwrap(), b"ab");
        let gmail = Gmail {
            message_id: u64::MAX,
            thread_id: u64::MAX - 1,
            sent: true,
        };
        store.set_gmail("a", "All", &[(1, gmail)]).unwrap();
        assert_eq!(
            store
                .gmail_messages("a", "All", &[gmail.thread_id])
                .unwrap()[0]
                .gmail,
            Some(gmail)
        );
        let indexed: bool = store
            .db
            .query_row(
                "SELECT COUNT(*) FROM pragma_index_list('messages')
                 WHERE name = 'messages_by_gmail_thread'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(indexed);
    }

    #[test]
    fn local_moves_keep_gmail_identities_and_only_remove_copied_mail() {
        let mut store = Store::in_memory();
        let raw = b"From: a@b.c\r\n\r\nkept\r\n";
        let uid = store
            .add_local("a", "INBOX", raw, Flags::default(), None)
            .unwrap();
        let missing = header(2, "Not downloaded", 2);
        store.add_headers("a", "INBOX", &[missing]).unwrap();
        let gmail = Gmail {
            message_id: u64::MAX,
            thread_id: u64::MAX,
            sent: true,
        };
        store
            .set_gmail("a", "INBOX", &[(uid, gmail), (2, gmail)])
            .unwrap();
        let moved = store.move_local("a", "INBOX", &[uid, 2], "Trash").unwrap();
        assert_eq!(moved, [(uid, 1)]);
        assert_eq!(
            store.message("a", "Trash", 1).unwrap().unwrap().gmail,
            Some(gmail)
        );
        assert_eq!(store.body("a", "Trash", 1).unwrap().unwrap(), raw);
        assert!(store.message("a", "INBOX", uid).unwrap().is_none());
        assert_eq!(
            store.message("a", "INBOX", 2).unwrap().unwrap().gmail,
            Some(gmail)
        );
    }

    fn tagged(uid: u32, subject: &str, tags: &[&str]) -> Header {
        let mut h = header(uid, subject, i64::from(uid));
        h.flags.tags = tags.iter().map(|t| t.to_string()).collect();
        h
    }

    #[test]
    fn tags_are_kept_with_the_flags_and_found_by_tag_words() {
        let mut store = Store::in_memory();
        store
            .add_headers(
                "a",
                "INBOX",
                &[
                    tagged(1, "Invoice March", &["receipts", "work"]),
                    tagged(2, "Invoice April", &["receipts"]),
                    tagged(3, "Lunch", &[]),
                ],
            )
            .unwrap();
        let tags = |store: &Store, uid| {
            store
                .message("a", "INBOX", uid)
                .unwrap()
                .unwrap()
                .flags
                .tags
        };
        assert_eq!(tags(&store, 1), ["receipts", "work"]);
        let found = |store: &Store, q: &str| -> Vec<u32> {
            let found = store.search("a", Some("INBOX"), q, 50).unwrap();
            found.iter().map(|m| m.uid).collect()
        };
        assert_eq!(found(&store, "tag:receipts"), [2, 1]);
        assert_eq!(found(&store, "tag:receipts march"), [1]);
        assert_eq!(found(&store, "tag:work tag:receipts"), [1]);
        assert!(found(&store, "tag:rec").is_empty(), "whole tags only");
        // The next check's flags replace them.
        let flags = Flags {
            tags: vec!["later".into()],
            ..Flags::default()
        };
        store.set_flags("a", "INBOX", &[(1, flags)]).unwrap();
        assert_eq!(tags(&store, 1), ["later"]);
        store
            .add_headers("a", "INBOX", &[tagged(1, "Invoice March", &[])])
            .unwrap();
        assert!(tags(&store, 1).is_empty());
        assert_eq!(store.all_tags(&["a"]).unwrap(), ["receipts"]);
        assert!(
            store.all_tags(&["b"]).unwrap().is_empty(),
            "another account's are its own"
        );
        // Read back checked: a cache changed by hand shows no bad tag.
        store
            .db
            .execute(
                "UPDATE messages SET tags = 'ok Bad \u{1b}x' WHERE uid = 3",
                [],
            )
            .unwrap();
        assert_eq!(tags(&store, 3), ["ok"]);
    }

    #[test]
    fn a_cache_made_before_tags_gets_them() {
        let db = Connection::open_in_memory().unwrap();
        let old = SCHEMA.replace("    tags TEXT NOT NULL DEFAULT '',\n", "");
        assert_ne!(old, SCHEMA);
        db.execute_batch(&old).unwrap();
        Store::migrate(&db).unwrap();
        Store::migrate(&db).unwrap();
        let mut store = Store { db };
        store
            .add_headers("a", "INBOX", &[tagged(1, "Hi", &["work"])])
            .unwrap();
        let m = store.message("a", "INBOX", 1).unwrap().unwrap();
        assert_eq!(m.flags.tags, ["work"]);
    }

    fn a_change(at: i64, account: &str) -> Change {
        Change {
            id: 0,
            at,
            who: String::new(),
            what: What::Tag("work".into(), true),
            messages: vec![Changed {
                account: account.into(),
                folder: "INBOX".into(),
                uidvalidity: 7,
                uid: 1,
                message_id: "a@b".into(),
                ..Changed::default()
            }],
            undone: false,
        }
    }

    #[test]
    fn changes_are_kept_newest_first_for_a_while() {
        let mut store = Store::in_memory();
        let day = 24 * 3600;
        let now = chrono::Utc::now().timestamp();
        let old = store
            .add_change(&a_change(now - 40 * day, "a"), now - 40 * day)
            .unwrap();
        // Kept while no newer change came, but not shown.
        assert!(store.change(old).unwrap().is_none());
        assert!(store.changes(10).unwrap().is_empty());
        let mut moved = a_change(now, "a");
        moved.what = What::Move;
        moved.messages[0].moved_to = "Trash".into();
        let id = store.add_change(&moved, now).unwrap();
        let changes = store.changes(10).unwrap();
        assert_eq!(changes.len(), 1, "the 40-day-old one went");
        assert!(store.change(old).unwrap().is_none());
        assert_eq!(
            changes[0],
            Change {
                id,
                ..moved.clone()
            }
        );
        store.set_undone(id).unwrap();
        assert!(store.change(id).unwrap().unwrap().undone);
        // Where the server put it, once it says.
        store
            .set_moved("a", "INBOX", 7, &[1], "Trash", 9, 120)
            .unwrap();
        let m = &store.change(id).unwrap().unwrap().messages[0];
        assert_eq!((m.moved_uidvalidity, m.moved_floor), (9, 120));
        for i in 0..MAX_CHANGES + 5 {
            store
                .add_change(&a_change(now - 1000 + i, "b"), now)
                .unwrap();
        }
        assert_eq!(store.changes(5000).unwrap().len(), MAX_CHANGES as usize);
        store.forget_account("b").unwrap();
        assert!(store.changes(5000).unwrap().is_empty());
    }

    #[test]
    fn a_folder_kept_here_never_gives_a_uid_twice() {
        let mut store = Store::in_memory();
        let raw = b"From: a@b.c\r\nMessage-ID: <x@y>\r\n\r\nhi\r\n";
        let one = store
            .add_local("a", "Trash", raw, Flags::default(), None)
            .unwrap();
        let two = store
            .add_local("a", "Trash", raw, Flags::default(), None)
            .unwrap();
        // The newest leaves: the next is still past it.
        store.move_local("a", "Trash", &[two], "INBOX").unwrap();
        let three = store
            .add_local("a", "Trash", raw, Flags::default(), None)
            .unwrap();
        assert_eq!((one, two, three), (1, 2, 3));
        store.remove("a", "Trash", &[one, three]).unwrap();
        assert_eq!(
            store
                .add_local("a", "Trash", raw, Flags::default(), None)
                .unwrap(),
            4
        );
        store.forget_account("a").unwrap();
        assert_eq!(
            store
                .add_local("a", "Trash", raw, Flags::default(), None)
                .unwrap(),
            1
        );
    }

    #[test]
    fn folders_are_kept_in_the_sidebars_order_and_gone_ones_removed() {
        let mut store = Store::in_memory();
        store
            .set_folders(
                "a",
                &[
                    folder("Work", None),
                    folder("Trash", Some(Role::Trash)),
                    folder("INBOX", Some(Role::Inbox)),
                    folder("Sent", Some(Role::Sent)),
                ],
            )
            .unwrap();
        store
            .add_headers("a", "Work", &[header(1, "x", 1)])
            .unwrap();
        let names: Vec<String> = store
            .folders("a")
            .unwrap()
            .into_iter()
            .map(|f| f.name)
            .collect();
        assert_eq!(names, ["INBOX", "Sent", "Trash", "Work"]);
        store
            .set_folders("a", &[folder("INBOX", Some(Role::Inbox))])
            .unwrap();
        assert_eq!(store.folders("a").unwrap().len(), 1);
        assert!(
            store.messages("a", "Work", 10).unwrap().is_empty(),
            "its mail went too"
        );
    }

    #[test]
    fn messages_come_newest_first_and_flags_update_in_place() {
        let mut store = Store::in_memory();
        store
            .add_headers(
                "a",
                "INBOX",
                &[header(1, "old", 100), header(2, "new", 200)],
            )
            .unwrap();
        let list = store.messages("a", "INBOX", 10).unwrap();
        assert_eq!(list[0].summary.subject, "new");
        store
            .set_flags(
                "a",
                "INBOX",
                &[(
                    1,
                    Flags {
                        seen: true,
                        flagged: true,
                        ..Flags::default()
                    },
                )],
            )
            .unwrap();
        let old = store.message("a", "INBOX", 1).unwrap().unwrap();
        assert!(old.flags.seen && old.flags.flagged);
        assert_eq!(store.count("a", "INBOX").unwrap(), (1, 2));
        store.remove("a", "INBOX", &[1]).unwrap();
        assert_eq!(store.uids("a", "INBOX", 0, 10).unwrap(), [2]);
    }

    #[test]
    fn bodies_give_a_preview_and_search_finds_words_anywhere() {
        let mut store = Store::in_memory();
        store
            .add_headers("a", "INBOX", &[header(5, "Quarterly report", 1)])
            .unwrap();
        let raw = b"From: alice@example.com\r\nSubject: Quarterly report\r\n\r\n\
Hi,\r\n\r\nthe numbers are in.\r\n> old quote\r\n-- \r\nAlice\r\n";
        store.save_body("a", "INBOX", 5, raw).unwrap();
        store
            .set_preview("a", "INBOX", 5, &mail::preview_of(raw))
            .unwrap();
        let m = store.message("a", "INBOX", 5).unwrap().unwrap();
        assert_eq!(m.preview, "Hi, the numbers are in.");
        assert_eq!(store.body("a", "INBOX", 5).unwrap().unwrap(), raw);
        let found = store.search("a", None, "quarterly numbers", 10).unwrap();
        assert_eq!(found.len(), 1);
        assert!(
            store
                .search("a", None, "quarterly missing", 10)
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .search("a", Some("Sent"), "quarterly", 10)
                .unwrap()
                .is_empty()
        );
        assert!(
            store.search("a", None, "%", 10).unwrap().is_empty(),
            "% is a letter"
        );
    }

    #[test]
    fn structured_search_matches_only_the_named_header_and_escapes_patterns() {
        let mut store = Store::in_memory();
        let mut exact = header(1, r#"Don't "quote" C:\path_50% from:"#, 1);
        exact.summary.cc = "copied@example.net".into();
        let mut broad = header(2, r#"Don't "quote" C:\pathX50X alice@example.com"#, 2);
        broad.summary.from = Addr {
            name: "Bob".into(),
            addr: "bob@example.com".into(),
        };
        store.add_headers("a", "INBOX", &[exact, broad]).unwrap();
        let found = |q| {
            store
                .search("a", Some("INBOX"), q, 10)
                .unwrap()
                .into_iter()
                .map(|m| m.uid)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            found(r#"FrOm:Alice to:me@example.org SUBJECT:"Don't \"quote\" C:\\path_50%""#),
            [1]
        );
        assert_eq!(found(r#"subject:"C:\\path_50%""#), [1]);
        assert_eq!(found(r#""Don't \"quote\"""#), [2, 1]);
        assert_eq!(found("copied@example.net"), [1]);
        assert_eq!(found("from:alice@example.com"), [1]);
        assert!(found("to:copied@example.net").is_empty());
        assert!(found("subject:me@example.org").is_empty());
        assert_eq!(found("subject:alice@example.com"), [2]);
        assert!(found(r#"subject:"' OR 1=1 --""#).is_empty());
        assert_eq!(found("from:"), [1]);
    }

    #[test]
    fn structured_search_date_bounds_are_utc_inclusive_and_exclusive() {
        let mut store = Store::in_memory();
        let midnight = |month, day| {
            chrono::NaiveDate::from_ymd_opt(2024, month, day)
                .unwrap()
                .and_time(chrono::NaiveTime::MIN)
                .and_utc()
                .timestamp()
        };
        let start = midnight(2, 29);
        let end = midnight(3, 1);
        store
            .add_headers(
                "a",
                "INBOX",
                &[
                    header(1, "Unknown", 0),
                    header(2, "Previous day", start - 1),
                    header(3, "Midnight", start),
                    header(4, "Last second", end - 1),
                    header(5, "Following midnight", end),
                ],
            )
            .unwrap();
        let found = |q| {
            store
                .search("a", None, q, 10)
                .unwrap()
                .into_iter()
                .map(|m| m.uid)
                .collect::<Vec<_>>()
        };
        assert_eq!(found("since:2024-02-29 before:2024-03-01"), [4, 3]);
        assert_eq!(found("before:2024-02-29"), [2]);
        assert!(found("since:2023-02-29").is_empty());
    }

    #[test]
    fn local_folders_number_their_mail_and_remember_pop_ids() {
        let mut store = Store::in_memory();
        let raw = b"From: bob@example.org\r\nSubject: hi\r\n\r\nyo\r\n";
        let one = store
            .add_local("p", "INBOX", raw, Flags::default(), Some("uidl-1"))
            .unwrap();
        let two = store
            .add_local("p", "INBOX", raw, Flags::default(), Some("uidl-2"))
            .unwrap();
        assert_eq!((one, two), (1, 2));
        assert_eq!(store.pop_seen("p").unwrap().len(), 2);
        let moved = store.move_local("p", "INBOX", &[1], "Trash").unwrap();
        assert_eq!(moved, [(1, 1)]);
        store.mark_pop_removal("p", "Trash", &[1]).unwrap();
        assert_eq!(store.pop_removals("p").unwrap(), ["uidl-1"]);
        store
            .pop_forget("p", &HashSet::from(["uidl-2".to_string()]))
            .unwrap();
        assert_eq!(
            store.pop_seen("p").unwrap(),
            HashSet::from(["uidl-2".into()])
        );
        // Checked once, the account stays checked when the server empties.
        store.set_pop_checked("p").unwrap();
        store.pop_forget("p", &HashSet::new()).unwrap();
        assert!(store.pop_seen("p").unwrap().is_empty());
        assert!(store.pop_checked("p").unwrap());
        assert!(!store.pop_checked("q").unwrap());
    }

    #[test]
    fn addresses_complete_by_address_or_name() {
        let store = Store::in_memory();
        let alice = Addr {
            name: "Alice Rivera".into(),
            addr: "Alice@Example.com".into(),
        };
        let bob = Addr {
            name: "Bob".into(),
            addr: "bob@example.org".into(),
        };
        store
            .remember(&[alice.clone(), bob.clone()], false, 1)
            .unwrap();
        store.remember(&[alice], true, 2).unwrap();
        // A name seen in mail doesn't replace the one known.
        let spoofed = Addr {
            name: "evil@x.org, Bob".into(),
            addr: "bob@example.org".into(),
        };
        store.remember(&[spoofed], false, 3).unwrap();
        assert_eq!(store.complete_for("", "bob", 5).unwrap()[0].name, "Bob");
        // Nor a name sent on: Alice, written to, keeps hers when a reply-all
        // carries another sender's name for her.
        let renamed = Addr {
            name: "A. R. (old)".into(),
            addr: "alice@example.com".into(),
        };
        store.remember(&[renamed], true, 4).unwrap();
        assert_eq!(
            store.complete_for("", "riv", 5).unwrap()[0].name,
            "Alice Rivera"
        );
        let found = store.complete_for("", "riv", 5).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].addr, "alice@example.com");
        assert_eq!(
            store.complete_for("", "b", 5).unwrap()[0].addr,
            "bob@example.org"
        );
        assert!(store.complete_for("", "", 5).unwrap().is_empty());
    }
}
