//! IMAP (RFC 3501 and the usual extensions), through async-imap: logging
//! in, listing folders, and the handful of commands tuimail sends. Every
//! command has a time limit; a connection that misses one is dropped.

use std::fmt::Write as _;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use async_imap::imap_proto::{
    AttributeValue, MailboxDatum, MessageSection, Response, SectionPath, Status,
};
use async_imap::types::{Fetch, Flag, NameAttribute};
use chrono::Datelike as _;
use futures::TryStreamExt;

use crate::account::{Account, Auth, Security};
use crate::mail;
use crate::net::{self, Conn, Endpoint};
use crate::search::{self, Field, Term};
use crate::store::{Flags, Folder, Gmail, Header, Role};
use crate::{tags, text, utf7};

pub type Session = async_imap::Session<Conn>;

/// How long a command may take; fetching a message's text, longer.
pub const TIMEOUT: Duration = Duration::from_secs(60);
const BODY_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// The biggest message downloaded to read.
pub const MAX_MESSAGE: u32 = 60 << 20;
/// The most flags one check reads back.
const MAX_FLAGS: usize = 100_000;
/// The most keywords read for one message, or one folder's PERMANENTFLAGS.
const MAX_KEYWORDS: usize = 100;
/// UIDs per command, so no command line gets too long.
const UIDS_PER_COMMAND: usize = 400;
/// A complete native-thread result is refused, never truncated, above these limits.
const MAX_CONVERSATION_MESSAGES: usize = 10_000;
const CONVERSATION_BYTES: usize = 64 << 20;

/// The headers fetched for the list.
const HEADER_FIELDS: &str = "BODY.PEEK[HEADER.FIELDS (FROM TO CC SUBJECT DATE MESSAGE-ID \
                             IN-REPLY-TO REFERENCES CONTENT-TYPE)]";

/// A login the server refused: the password (or token) is wrong.
#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the server refused the login: {}", self.0)
    }
}

impl std::error::Error for Refused {}

/// The server said no to a command (NO, BAD), or tuimail wouldn't send
/// it: the connection is still fine.
#[derive(Debug)]
pub struct Said(pub String);

impl std::fmt::Display for Said {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Said {}

async fn timed<T>(
    limit: Duration,
    what: &str,
    f: impl Future<Output = async_imap::error::Result<T>>,
) -> Result<T> {
    use async_imap::error::Error;
    match tokio::time::timeout(limit, f).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e @ (Error::No(_) | Error::Bad(_) | Error::Validate(_) | Error::Append))) => {
            bail!(Said(format!(
                "{what}: {}",
                text::one_line(&e.to_string(), 300)
            )))
        }
        Ok(Err(e)) => bail!("{what}: {}", text::one_line(&e.to_string(), 300)),
        Err(_) => bail!("{what}: the server stopped answering"),
    }
}

/// What the server can do, from CAPABILITY.
#[derive(Clone, Copy, Debug, Default)]
pub struct Caps {
    pub idle: bool,
    pub move_: bool,
    pub uidplus: bool,
    pub gmail: bool,
}

/// Connects, starts TLS (STARTTLS if asked), and logs in.
pub async fn connect(
    endpoint: &Endpoint,
    user: &str,
    secret: &str,
    auth: Auth,
) -> Result<(Session, Caps)> {
    net::check_login(user, secret)?;
    let conn = net::connect(endpoint).await?;
    let mut client = async_imap::Client::new(conn);
    let greeting = tokio::time::timeout(TIMEOUT, client.read_response())
        .await
        .map_err(|_| anyhow!("{} didn't greet", endpoint.shown()))??
        .ok_or_else(|| anyhow!("{} closed the connection", endpoint.shown()))?;
    if let async_imap::imap_proto::Response::Data {
        status: async_imap::imap_proto::Status::Bye,
        ..
    } = greeting.parsed()
    {
        bail!("{} isn't taking connections", endpoint.shown());
    }
    if endpoint.security == Security::Starttls {
        timed(
            TIMEOUT,
            "STARTTLS",
            client.run_command_and_check_ok("STARTTLS", None),
        )
        .await?;
        // Whatever the server sent before TLS is dropped with the client.
        let tcp = client.into_inner().into_plain()?;
        client = async_imap::Client::new(net::start_tls(tcp, endpoint).await?);
    }
    let login = async {
        match auth {
            Auth::Password => client.login(user, secret).await,
            Auth::Oauth2 => {
                client
                    .authenticate(
                        "XOAUTH2",
                        XOAuth2 {
                            user: user.to_string(),
                            token: secret.to_string(),
                            sent: false,
                        },
                    )
                    .await
            }
        }
    };
    let mut session = match tokio::time::timeout(TIMEOUT, login).await {
        Err(_) => bail!("{} didn't answer the login", endpoint.shown()),
        Ok(Ok(session)) => session,
        Ok(Err((async_imap::error::Error::No(words), _))) if wrong_password(&words) => {
            bail!(Refused(text::one_line(&words, 200)))
        }
        Ok(Err((e, _))) => bail!("cannot log in: {}", text::one_line(&e.to_string(), 200)),
    };
    let caps = timed(TIMEOUT, "CAPABILITY", session.capabilities()).await?;
    let caps = Caps {
        idle: caps.has_str("IDLE"),
        move_: caps.has_str("MOVE"),
        uidplus: caps.has_str("UIDPLUS"),
        gmail: caps.has_str("X-GM-EXT-1"),
    };
    Ok((session, caps))
}

/// Whether a NO to a login says the password is wrong, not that the
/// server can't let anyone in now (RFC 5530's codes, which async-imap
/// leaves in the text): only then is it forgotten.
fn wrong_password(words: &str) -> bool {
    let words = words.to_ascii_uppercase();
    ![
        "[UNAVAILABLE]",
        "[INUSE]",
        "[SERVERBUG]",
        "[LIMIT]",
        "SIMULTANEOUS CONNECTIONS",
    ]
    .iter()
    .any(|busy| words.contains(busy))
}

/// XOAUTH2's one message; an error comes back as a challenge, answered
/// with nothing so the server ends the exchange.
struct XOAuth2 {
    user: String,
    token: String,
    sent: bool,
}

impl async_imap::Authenticator for XOAuth2 {
    type Response = String;

    fn process(&mut self, _challenge: &[u8]) -> String {
        if std::mem::replace(&mut self.sent, true) {
            return String::new();
        }
        format!("user={}\x01auth=Bearer {}\x01\x01", self.user, self.token)
    }
}

/// Ends the session politely.
pub async fn logout(mut session: Session) {
    let _ = tokio::time::timeout(Duration::from_secs(5), session.logout()).await;
}

/// The account's folders, with what each is for.
pub async fn folders(session: &mut Session, account: &Account) -> Result<Vec<Folder>> {
    let names: Vec<async_imap::types::Name> = timed(TIMEOUT, "LIST", async {
        session.list(Some(""), Some("*")).await?.try_collect().await
    })
    .await?;
    let mut said = Vec::new();
    let mut folders: Vec<Folder> = names
        .iter()
        .take(2000)
        .map(|name| {
            let attributes = name.attributes();
            let raw = name.name().to_string();
            let shown = utf7::decode(&raw).unwrap_or_else(|| raw.clone());
            let selectable = !attributes
                .iter()
                .any(|a| matches!(a, NameAttribute::NoSelect))
                && !attributes.iter().any(|a| {
                    matches!(a, NameAttribute::Extension(e) if e.eq_ignore_ascii_case("\\NonExistent"))
                });
            let role = role_of(&raw, &shown, name.delimiter(), attributes);
            said.push(role.map(|(_, by)| by));
            Folder {
                role: role.map(|(role, _)| role),
                shown: text::one_line(&shown, 200),
                name: raw,
                delimiter: name.delimiter().map(|d| text::one_line(d, 2)),
                selectable,
                unread: 0,
                total: 0,
            }
        })
        .collect();
    apply_overrides(&mut folders, &mut said, account);
    dedupe_roles(&mut folders, &said);
    Ok(folders)
}

/// Where a folder's role came from, the surest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RoleFrom {
    /// accounts.toml names it.
    Setting,
    /// The server marks it (SPECIAL-USE).
    Attribute,
    /// Its name is one a role usually has.
    Name,
}

/// Folders of other users, shared and public ones, by the names servers
/// give their namespaces (`shared/bob@x.y/Sent`, `Other Users/bob/Sent`):
/// never one of the account's roles, or its sent mail (Bcc and all),
/// drafts and deleted mail would go to a mailbox someone else owns.
fn other_namespace(parts: &[&str]) -> bool {
    parts.len() > 1
        && matches!(
            parts[0].to_lowercase().as_str(),
            "shared"
                | "shared folders"
                | "other users"
                | "public"
                | "public folders"
                | "#shared"
                | "#public"
                | "#users"
                | "user"
                | "users"
        )
}

/// A folder in another user's, a shared or a public namespace, by its name
/// as shown ([`other_namespace`]): never the account's own, so never one
/// an agent acts on, nor a role.
pub fn foreign(shown: &str, delimiter: Option<&str>) -> bool {
    let parts: Vec<&str> = match delimiter.filter(|d| !d.is_empty()) {
        Some(d) => shown.split(d).collect(),
        None => shown.split(['/', '.']).collect(),
    };
    other_namespace(&parts)
}

/// The role of a folder: SPECIAL-USE attributes, else its name, which
/// counts only at the top or right under INBOX or [Gmail] (deeper is a
/// folder of the user's own, or someone else's).
fn role_of(
    raw: &str,
    shown: &str,
    delimiter: Option<&str>,
    attributes: &[NameAttribute],
) -> Option<(Role, RoleFrom)> {
    if raw.eq_ignore_ascii_case("INBOX") {
        return Some((Role::Inbox, RoleFrom::Attribute));
    }
    if foreign(shown, delimiter) {
        return None;
    }
    let parts: Vec<&str> = match delimiter.filter(|d| !d.is_empty()) {
        Some(d) => shown.split(d).collect(),
        None => shown.split(['/', '.']).collect(),
    };
    for a in attributes {
        let role = match a {
            NameAttribute::Sent => Role::Sent,
            NameAttribute::Drafts => Role::Drafts,
            NameAttribute::Trash => Role::Trash,
            NameAttribute::Junk => Role::Junk,
            NameAttribute::Archive => Role::Archive,
            NameAttribute::All => Role::All,
            NameAttribute::Flagged => Role::Flagged,
            _ => continue,
        };
        return Some((role, RoleFrom::Attribute));
    }
    // The last part of the name, for "INBOX.Sent" and "[Gmail]/Spam".
    let personal = match parts.as_slice() {
        [_] => true,
        [parent, _] => matches!(
            parent.to_lowercase().as_str(),
            "inbox" | "[gmail]" | "[google mail]"
        ),
        _ => false,
    };
    if !personal {
        return None;
    }
    let leaf = parts.last().unwrap_or(&shown).to_lowercase();
    let role = match leaf.as_str() {
        "sent" | "sent items" | "sent messages" | "sent mail" | "gesendet"
        | "gesendete elemente" | "envoyés" | "enviados" => Role::Sent,
        "drafts" | "draft" | "entwürfe" | "brouillons" | "borradores" => Role::Drafts,
        "trash" | "deleted items" | "deleted messages" | "bin" | "papierkorb" | "corbeille"
        | "papelera" => Role::Trash,
        "junk" | "spam" | "junk e-mail" | "junk email" | "bulk mail" => Role::Junk,
        "archive" | "archives" | "archiv" => Role::Archive,
        _ => return None,
    };
    Some((role, RoleFrom::Name))
}

/// Folders named in accounts.toml take their role from there.
fn apply_overrides(folders: &mut [Folder], said: &mut [Option<RoleFrom>], account: &Account) {
    let overrides = [
        (&account.sent_folder, Role::Sent),
        (&account.drafts_folder, Role::Drafts),
        (&account.trash_folder, Role::Trash),
        (&account.archive_folder, Role::Archive),
        (&account.junk_folder, Role::Junk),
    ];
    for (name, role) in overrides {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        if folders.iter().any(|f| f.shown == name || f.name == name) {
            for (f, said) in folders.iter_mut().zip(said.iter_mut()) {
                if f.role == Some(role) {
                    f.role = None;
                }
                if f.shown == name || f.name == name {
                    f.role = Some(role);
                    *said = Some(RoleFrom::Setting);
                }
            }
        }
    }
}

/// One folder per role: the surest (setting, then the server's attribute,
/// then the name), the first listed of equals.
fn dedupe_roles(folders: &mut [Folder], said: &[Option<RoleFrom>]) {
    let mut best: std::collections::HashMap<Role, (RoleFrom, usize)> = Default::default();
    for (i, f) in folders.iter().enumerate() {
        if let (Some(role), Some(by)) = (f.role, said.get(i).copied().flatten()) {
            let entry = best.entry(role).or_insert((by, i));
            if by < entry.0 {
                *entry = (by, i);
            }
        }
    }
    for (i, f) in folders.iter_mut().enumerate() {
        if let Some(role) = f.role
            && best.get(&role).is_none_or(|&(_, j)| j != i)
        {
            f.role = None;
        }
    }
}

/// A folder's unread and total counts, from STATUS.
pub async fn status(session: &mut Session, folder: &str) -> Result<(u32, u32)> {
    let mailbox = timed(
        TIMEOUT,
        "STATUS",
        session.status(folder, "(MESSAGES UNSEEN)"),
    )
    .await?;
    Ok((mailbox.unseen.unwrap_or(0), mailbox.exists))
}

/// A folder's UIDVALIDITY and UIDNEXT, from STATUS: before a move, so the
/// messages it puts there can be told from mail that was there, or comes
/// later.
pub async fn uid_next(session: &mut Session, folder: &str) -> Result<(u32, u32)> {
    let mailbox = timed(
        TIMEOUT,
        "STATUS",
        session.status(folder, "(UIDVALIDITY UIDNEXT)"),
    )
    .await?;
    Ok((
        mailbox.uid_validity.unwrap_or(0),
        mailbox.uid_next.unwrap_or(0),
    ))
}

/// What SELECT says about a folder.
#[derive(Clone, Debug)]
pub struct Selected {
    pub uidvalidity: u32,
    pub exists: u32,
    /// New keywords can be kept on its messages (PERMANENTFLAGS has `\*`,
    /// or wasn't said: then every flag can be).
    pub new_keywords: bool,
    /// The keywords it keeps, as PERMANENTFLAGS lists them.
    pub keywords: Vec<String>,
}

impl Selected {
    /// Whether the folder keeps `keyword` on its messages, rather than
    /// only until the connection ends.
    pub fn keeps(&self, keyword: &str) -> bool {
        self.new_keywords
            || self
                .keywords
                .iter()
                .any(|k| k.eq_ignore_ascii_case(keyword))
    }
}

pub async fn select(session: &mut Session, folder: &str) -> Result<Selected> {
    drain(session);
    let mailbox = timed(TIMEOUT, "SELECT", session.select(folder)).await?;
    let permanent = &mailbox.permanent_flags;
    Ok(Selected {
        uidvalidity: mailbox.uid_validity.unwrap_or(0),
        exists: mailbox.exists,
        new_keywords: permanent.is_empty() || permanent.contains(&Flag::MayCreate),
        keywords: permanent
            .iter()
            .filter_map(|f| match f {
                Flag::Custom(k) => Some(k.to_string()),
                _ => None,
            })
            .take(MAX_KEYWORDS)
            .collect(),
    })
}

/// Drops what the server said that no command asked for: kept, it would
/// stay in memory as long as the session (up to 100 of any size).
fn drain(session: &mut Session) {
    while session.unsolicited_responses.try_recv().is_ok() {}
}

/// A FETCH's answers, at most `max` of them and `max_bytes` of message
/// data: a server can't make tuimail hold more than it asked for. Past
/// either, the connection is dropped (an error that isn't [`Said`]), since
/// what's still coming would be read as the next command's answer.
async fn collect(
    what: &str,
    timeout: Duration,
    stream: impl futures::Future<
        Output = async_imap::error::Result<
            impl futures::Stream<Item = async_imap::error::Result<Fetch>>,
        >,
    >,
    max: usize,
    max_bytes: usize,
) -> Result<Vec<Fetch>> {
    timed(timeout, what, async {
        let stream = stream.await?;
        futures::pin_mut!(stream);
        let mut out = Vec::new();
        let mut bytes = 0usize;
        while let Some(fetch) = stream.try_next().await? {
            bytes += fetch.body().map_or(0, <[u8]>::len) + fetch.header().map_or(0, <[u8]>::len);
            out.push(fetch);
            if out.len() > max || bytes > max_bytes {
                return Ok(Err(anyhow!("the server sent more than was asked for")));
            }
        }
        Ok(Ok(out))
    })
    .await?
}

/// The UIDs `criteria` finds, in order.
pub async fn search(session: &mut Session, criteria: &str) -> Result<Vec<u32>> {
    let found = timed(TIMEOUT, "SEARCH", session.uid_search(criteria)).await?;
    let mut uids: Vec<u32> = found.into_iter().collect();
    uids.sort_unstable();
    Ok(uids)
}

/// The messages a move put in the selected folder, found again: for each
/// of `moved` (its Message-ID, without angle brackets, and its size, 0 if
/// not known), the lowest UID from `floor` on (the folder's UIDNEXT just
/// before the move) with that whole Message-ID and size, each UID taken
/// once. Mail that was there before has lower UIDs, so a sender's copy of a
/// Message-ID can't be taken for it; SEARCH HEADER matches part of a
/// header, so what it finds is checked against the whole Message-ID.
pub async fn find_moved(
    session: &mut Session,
    moved: &[(String, u32)],
    floor: u32,
) -> Result<Vec<u32>> {
    let floor = floor.max(1);
    // Valid ids have no quotes, backslashes, spaces or brackets: they go
    // in a quoted string as they are.
    let mut ids: Vec<&str> = (moved.iter())
        .map(|(id, _)| id.as_str())
        .filter(|id| mail::valid_id(id))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    let mut found = Vec::new();
    for chunk in ids.chunks(20) {
        let criteria = chunk
            .iter()
            .rev()
            .map(|id| format!("HEADER Message-ID \"<{id}>\""))
            .reduce(|rest, one| format!("OR {one} {rest}"));
        if let Some(criteria) = criteria {
            found.extend(search(session, &format!("UID {floor}:* {criteria}")).await?);
        }
    }
    // "n:*" also matches the highest UID when that's below n.
    found.retain(|&uid| uid >= floor);
    found.sort_unstable();
    found.dedup();
    let mut headers = headers(session, &found).await?;
    headers.sort_by_key(|h| h.uid);
    let mut uids = Vec::new();
    for (id, size) in moved.iter().filter(|(id, _)| mail::valid_id(id)) {
        let found = headers.iter().position(|h| {
            h.summary.message_id == *id && (*size == 0 || h.size == *size) && !uids.contains(&h.uid)
        });
        if let Some(i) = found {
            uids.push(headers.remove(i).uid);
        }
    }
    uids.sort_unstable();
    Ok(uids)
}

/// UIDs written as IMAP sets, `1:5,7,9:12`, a command's worth each.
pub fn uid_sets(uids: &[u32]) -> Vec<String> {
    let mut sorted = uids.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    sorted
        .chunks(UIDS_PER_COMMAND)
        .map(|chunk| {
            let mut out = String::new();
            let mut i = 0;
            while i < chunk.len() {
                let start = chunk[i];
                let mut end = start;
                while i + 1 < chunk.len() && chunk[i + 1] == end + 1 {
                    i += 1;
                    end = chunk[i];
                }
                if !out.is_empty() {
                    out.push(',');
                }
                if start == end {
                    out.push_str(&start.to_string());
                } else {
                    out.push_str(&format!("{start}:{end}"));
                }
                i += 1;
            }
            out
        })
        .collect()
}

/// Whether a message is marked deleted: it's as good as gone, and isn't
/// listed.
fn deleted(fetch: &Fetch) -> bool {
    fetch.flags().any(|f| matches!(f, Flag::Deleted))
}

fn flags_of(fetch: &Fetch) -> Flags {
    flags_from(fetch.flags())
}

fn flags_from<'a>(raw: impl Iterator<Item = Flag<'a>>) -> Flags {
    let mut flags = Flags::default();
    let mut keywords = Vec::new();
    for flag in raw {
        match flag {
            Flag::Seen => flags.seen = true,
            Flag::Flagged => flags.flagged = true,
            Flag::Answered => flags.answered = true,
            Flag::Draft => flags.draft = true,
            Flag::Custom(k) if keywords.len() < MAX_KEYWORDS => keywords.push(k),
            _ => {}
        }
    }
    flags.tags = tags::from_keywords(keywords.iter().map(|k| k.as_ref()));
    flags
}

/// The list's headers for these messages.
pub async fn headers(session: &mut Session, uids: &[u32]) -> Result<Vec<Header>> {
    let mut out = Vec::new();
    for set in uid_sets(uids) {
        let query = format!("(UID FLAGS RFC822.SIZE INTERNALDATE {HEADER_FIELDS})");
        let asked = set_uids(&set);
        let fetched = collect(
            "FETCH",
            TIMEOUT,
            session.uid_fetch(&set, &query),
            asked.len() + 16,
            MAX_MESSAGE as usize,
        )
        .await?;
        for fetch in &fetched {
            // Only what was asked for: a FETCH the server adds unasked
            // isn't a header to keep.
            let Some(uid) = fetch
                .uid
                .filter(|uid| !deleted(fetch) && asked.contains(uid))
            else {
                continue;
            };
            let mut summary = mail::summarize(fetch.header().unwrap_or(b""));
            if summary.date == 0 {
                summary.date = fetch.internal_date().map(|d| d.timestamp()).unwrap_or(0);
            }
            out.push(Header {
                uid,
                summary,
                flags: flags_of(fetch),
                size: fetch.size.unwrap_or(0),
                gmail: None,
            });
        }
    }
    Ok(out)
}

/// Gmail's FETCH has no public thread-id accessor in async-imap. Use its
/// public command/response API and re-exported parser without retaining
/// unsolicited responses. Interrupted exchanges drop the connection.
async fn gmail_command(
    session: &mut Session,
    command: &str,
    max_responses: usize,
    remaining_bytes: &mut usize,
    mut accept: impl FnMut(&Response<'_>) -> Result<()>,
) -> Result<()> {
    drain(session);
    timed(TIMEOUT, "Gmail conversations", async {
        let id = session.run_command(command).await?;
        let mut count = 0usize;
        while let Some(response) = session.read_response().await? {
            count += 1;
            let bytes = response.borrow_owner().len();
            if count > max_responses || bytes > *remaining_bytes {
                return Ok(Err(anyhow!("the server sent too much conversation data")));
            }
            *remaining_bytes -= bytes;
            match response.parsed() {
                Response::Done {
                    tag,
                    status,
                    outcome,
                } => {
                    if tag != &id {
                        return Ok(Err(anyhow!("the server answered a different command")));
                    }
                    let words =
                        || format!("code: {:?}, info: {:?}", outcome.code, outcome.information);
                    return match status {
                        Status::Ok => Ok(Ok(())),
                        Status::No => Err(async_imap::error::Error::No(words())),
                        Status::Bad => Err(async_imap::error::Error::Bad(words())),
                        _ => Err(async_imap::error::Error::ConnectionLost),
                    };
                }
                Response::Data {
                    status: Status::Bye,
                    ..
                } => {
                    return Err(async_imap::error::Error::ConnectionLost);
                }
                parsed => {
                    if let Err(error) = accept(parsed) {
                        return Ok(Err(error));
                    }
                }
            }
        }
        Err(async_imap::error::Error::ConnectionLost)
    })
    .await?
}

fn gmail_uid(attrs: &[AttributeValue<'_>]) -> Option<u32> {
    if attrs.iter().any(|attr| {
        matches!(attr, AttributeValue::Flags(flags)
        if flags.iter().any(|flag| flag.eq_ignore_ascii_case("\\Deleted")))
    }) {
        return None;
    }
    attrs.iter().find_map(|attr| match attr {
        AttributeValue::Uid(uid) if *uid != 0 => Some(*uid),
        _ => None,
    })
}

/// Native IDs are server-global unsigned numbers, never Message-ID headers.
fn gmail_of(attrs: &[AttributeValue<'_>]) -> Option<Gmail> {
    let mut message_id = None;
    let mut thread_id = None;
    let mut sent = None;
    for attr in attrs {
        match attr {
            AttributeValue::GmailMsgId(value) => message_id = Some(*value),
            AttributeValue::GmailThrId(value) => thread_id = Some(*value),
            AttributeValue::GmailLabels(labels) => {
                sent = Some(
                    labels
                        .iter()
                        // imap-proto leaves quoted-string escapes intact.
                        .any(|label| {
                            label.eq_ignore_ascii_case(r"\Sent")
                                || label.eq_ignore_ascii_case(r"\\Sent")
                        }),
                );
            }
            _ => {}
        }
    }
    Some(Gmail {
        message_id: message_id.filter(|&id| id != 0)?,
        thread_id: thread_id.filter(|&id| id != 0)?,
        sent: sent?,
    })
}

/// Metadata only, for exactly these source UIDs in the selected mailbox.
pub async fn gmail_metadata(session: &mut Session, uids: &[u32]) -> Result<Vec<(u32, Gmail)>> {
    if uids.len() > MAX_CONVERSATION_MESSAGES || uids.contains(&0) {
        bail!(Said(
            "too many or invalid conversation UIDs requested".into()
        ));
    }
    let mut out = std::collections::BTreeMap::new();
    let mut bytes = CONVERSATION_BYTES;
    for set in uid_sets(uids) {
        let asked = set_uids(&set);
        let command = format!("UID FETCH {set} (UID FLAGS X-GM-MSGID X-GM-THRID X-GM-LABELS)");
        gmail_command(
            session,
            &command,
            asked.len() + 32,
            &mut bytes,
            |response| {
                let Response::Fetch(_, attrs) = response else {
                    return Ok(());
                };
                let Some(uid) =
                    gmail_uid(attrs).filter(|uid| asked.contains(uid) && !out.contains_key(uid))
                else {
                    return Ok(());
                };
                if let Some(gmail) = gmail_of(attrs) {
                    out.insert(uid, gmail);
                } else if attrs.iter().any(|attr| {
                    matches!(
                        attr,
                        AttributeValue::GmailMsgId(_)
                            | AttributeValue::GmailThrId(_)
                            | AttributeValue::GmailLabels(_)
                    )
                }) {
                    bail!("the server omitted native conversation metadata");
                }
                Ok(())
            },
        )
        .await?;
    }
    Ok(out.into_iter().collect())
}

/// Matching UIDs in the selected mailbox, without an unbounded folder scan.
pub async fn gmail_thread_uids(session: &mut Session, thread_ids: &[u64]) -> Result<Vec<u32>> {
    let threads: std::collections::BTreeSet<u64> = thread_ids.iter().copied().collect();
    if threads.len() > crate::worker::CONVERSATION_BATCH || threads.contains(&0) {
        bail!(Said(
            "too many or invalid native conversations requested".into()
        ));
    }
    let mut uids = std::collections::BTreeSet::new();
    let mut bytes = CONVERSATION_BYTES;
    // Prefix OR takes two search keys; n-1 ORs form one n-way key.
    if !threads.is_empty() {
        let mut criteria = "OR ".repeat(threads.len() - 1);
        for (index, id) in threads.iter().enumerate() {
            if index != 0 {
                criteria.push(' ');
            }
            criteria.push_str(&format!("X-GM-THRID {id}"));
        }
        gmail_command(
            session,
            &format!("UID SEARCH {criteria}"),
            32,
            &mut bytes,
            |response| {
                if let Response::MailboxData(MailboxDatum::Search(found)) = response {
                    if found.len() > MAX_CONVERSATION_MESSAGES {
                        bail!("the conversation has too many messages");
                    }
                    uids.extend(found.iter().copied().filter(|&uid| uid != 0));
                    if uids.len() > MAX_CONVERSATION_MESSAGES {
                        bail!("the conversation has too many messages");
                    }
                }
                Ok(())
            },
        )
        .await?;
    }
    Ok(uids.into_iter().collect())
}

/// List headers and native metadata for SEARCH's UIDs, checked against its
/// requested native threads as well as its UIDs.
pub async fn gmail_headers(
    session: &mut Session,
    uids: &[u32],
    thread_ids: &[u64],
) -> Result<Vec<Header>> {
    if uids.len() > MAX_CONVERSATION_MESSAGES || uids.contains(&0) {
        bail!(Said(
            "too many or invalid conversation UIDs requested".into()
        ));
    }
    let threads: std::collections::BTreeSet<u64> = thread_ids.iter().copied().collect();
    let mut bytes = CONVERSATION_BYTES;
    let mut out = std::collections::BTreeMap::new();
    for set in uid_sets(uids) {
        let asked = set_uids(&set);
        let command = format!(
            "UID FETCH {set} (UID FLAGS RFC822.SIZE INTERNALDATE {HEADER_FIELDS} X-GM-MSGID X-GM-THRID X-GM-LABELS)"
        );
        gmail_command(
            session,
            &command,
            asked.len() + 32,
            &mut bytes,
            |response| {
                let Response::Fetch(_, attrs) = response else {
                    return Ok(());
                };
                let Some(uid) =
                    gmail_uid(attrs).filter(|uid| asked.contains(uid) && !out.contains_key(uid))
                else {
                    return Ok(());
                };
                let gmail = gmail_of(attrs);
                if gmail.is_some_and(|gmail| !threads.contains(&gmail.thread_id)) {
                    return Ok(());
                }
                let header = attrs.iter().find_map(|attr| match attr {
                    AttributeValue::BodySection {
                        section: Some(SectionPath::Full(MessageSection::Header)),
                        data: Some(header),
                        ..
                    }
                    | AttributeValue::Rfc822Header(Some(header)) => Some(header.as_ref()),
                    _ => None,
                });
                // Ignore genuine unsolicited FLAGS updates, not an incomplete
                // answer to the header/metadata request.
                let Some(header) = header else {
                    if attrs.iter().any(|attr| {
                        matches!(
                            attr,
                            AttributeValue::GmailMsgId(_)
                                | AttributeValue::GmailThrId(_)
                                | AttributeValue::GmailLabels(_)
                                | AttributeValue::BodySection {
                                    section: Some(SectionPath::Full(MessageSection::Header)),
                                    ..
                                }
                                | AttributeValue::Rfc822Header(_)
                        )
                    }) {
                        bail!("the server omitted conversation headers");
                    }
                    return Ok(());
                };
                let Some(gmail) = gmail else {
                    bail!("the server omitted native conversation metadata");
                };
                let mut summary = mail::summarize(header);
                let mut size = 0;
                for attr in attrs {
                    match attr {
                        AttributeValue::InternalDate(date) if summary.date == 0 => {
                            summary.date =
                                chrono::DateTime::parse_from_str(date, "%d-%b-%Y %H:%M:%S %z")
                                    .map(|date| date.timestamp())
                                    .unwrap_or(0);
                        }
                        AttributeValue::Rfc822Size(value) => size = *value,
                        _ => {}
                    }
                }
                let flags = flags_from(
                    attrs
                        .iter()
                        .filter_map(|attr| match attr {
                            AttributeValue::Flags(flags) => {
                                Some(flags.iter().map(|flag| Flag::from(flag.as_ref())))
                            }
                            _ => None,
                        })
                        .flatten(),
                );
                out.insert(
                    uid,
                    Header {
                        uid,
                        summary,
                        flags,
                        size,
                        gmail: Some(gmail),
                    },
                );
                Ok(())
            },
        )
        .await?;
    }
    Ok(out.into_values().collect())
}

/// The UIDs of the messages at places `start..=end` in the folder. Only
/// those: a FETCH the server adds unasked could name any UID.
pub async fn uids_at(session: &mut Session, start: u32, end: u32) -> Result<Vec<u32>> {
    if start == 0 || end < start {
        return Ok(Vec::new());
    }
    let range = (end - start) as usize + 1;
    let fetched = collect(
        "FETCH",
        TIMEOUT,
        session.fetch(format!("{start}:{end}"), "(UID)"),
        range.min(MAX_FLAGS) + 16,
        1 << 20,
    )
    .await?;
    let mut uids: Vec<u32> = fetched
        .iter()
        .filter(|f| (start..=end).contains(&f.message))
        .filter_map(|f| f.uid)
        .collect();
    uids.sort_unstable();
    uids.dedup();
    Ok(uids)
}

/// The flags of every message with a UID in `low..=high`.
pub async fn flags(session: &mut Session, low: u32, high: u32) -> Result<Vec<(u32, Flags)>> {
    if low == 0 || high < low {
        return Ok(Vec::new());
    }
    let range = (high - low) as usize + 1;
    let fetched = collect(
        "FETCH",
        TIMEOUT,
        session.uid_fetch(format!("{low}:{high}"), "(UID FLAGS)"),
        range.min(MAX_FLAGS) + 16,
        MAX_MESSAGE as usize,
    )
    .await?;
    Ok(fetched
        .iter()
        .filter(|f| !deleted(f))
        .filter_map(|f| Some((f.uid?, flags_of(f))))
        .filter(|(uid, _)| (low..=high).contains(uid))
        .collect())
}

/// A whole message, without marking it read; `None` if it's gone.
pub async fn body(session: &mut Session, uid: u32) -> Result<Option<Vec<u8>>> {
    let size = collect(
        "FETCH",
        TIMEOUT,
        session.uid_fetch(uid.to_string(), "(UID RFC822.SIZE)"),
        16,
        1 << 20,
    )
    .await?;
    let Some(size) = size.iter().find(|f| f.uid == Some(uid)).map(|f| f.size) else {
        return Ok(None);
    };
    if size.unwrap_or(0) > MAX_MESSAGE {
        bail!(Said(format!(
            "the message is {}, too big to download",
            mail::size(size.unwrap_or(0) as usize)
        )));
    }
    // The size the server gave is only its word: the bytes that come are
    // held to the cap too.
    let fetched = collect(
        "FETCH",
        BODY_TIMEOUT,
        session.uid_fetch(uid.to_string(), "(UID BODY.PEEK[])"),
        16,
        MAX_MESSAGE as usize + (1 << 20),
    )
    .await?;
    let body = fetched
        .iter()
        .find(|f| f.uid == Some(uid))
        .and_then(|f| f.body());
    if body.is_some_and(|b| b.len() > MAX_MESSAGE as usize) {
        bail!(Said("the message is too big to download".into()));
    }
    Ok(body.map(<[u8]>::to_vec))
}

/// Which flag a key changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagKind {
    Seen,
    Flagged,
    Answered,
}

impl FlagKind {
    fn imap(self) -> &'static str {
        match self {
            FlagKind::Seen => "\\Seen",
            FlagKind::Flagged => "\\Flagged",
            FlagKind::Answered => "\\Answered",
        }
    }
}

pub async fn set_flag(session: &mut Session, uids: &[u32], flag: FlagKind, on: bool) -> Result<()> {
    store_flags(session, uids, flag.imap(), on).await
}

/// Puts keywords on messages, or takes them off: the spellings of a tag
/// ([`tags::keywords`]).
pub async fn set_keywords(
    session: &mut Session,
    uids: &[u32],
    keywords: &[String],
    on: bool,
) -> Result<()> {
    if keywords.is_empty()
        || !keywords
            .iter()
            .all(|k| tags::is_atom(k) && !k.starts_with('\\'))
    {
        bail!(Said("that isn't a tag the server can keep".into()));
    }
    store_flags(session, uids, &keywords.join(" "), on).await
}

/// `+FLAGS` or `-FLAGS` with `list` (flags already checked).
async fn store_flags(session: &mut Session, uids: &[u32], list: &str, on: bool) -> Result<()> {
    let sign = if on { '+' } else { '-' };
    for set in uid_sets(uids) {
        let query = format!("{sign}FLAGS.SILENT ({list})");
        timed(TIMEOUT, "STORE", async {
            session
                .uid_store(&set, &query)
                .await?
                .try_collect::<Vec<_>>()
                .await
        })
        .await?;
    }
    Ok(())
}

/// Moves messages to `to`: MOVE where the server has it, else a copy and
/// a delete.
pub async fn move_to(session: &mut Session, caps: Caps, uids: &[u32], to: &str) -> Result<()> {
    for set in uid_sets(uids) {
        if caps.move_ {
            timed(TIMEOUT, "MOVE", session.uid_mv(&set, to)).await?;
        } else {
            timed(TIMEOUT, "COPY", session.uid_copy(&set, to)).await?;
            expunge(session, caps, &set, &set_uids(&set)).await?;
        }
    }
    Ok(())
}

/// Deletes messages for good.
/// Deletes for good; `false` if some stay marked deleted on the server
/// (without UIDPLUS, while another program's deletes are pending there).
pub async fn delete(session: &mut Session, caps: Caps, uids: &[u32]) -> Result<bool> {
    let ours: std::collections::HashSet<u32> = uids.iter().copied().collect();
    let mut all = true;
    for set in uid_sets(uids) {
        all &= expunge(session, caps, &set, &ours).await?;
    }
    Ok(all)
}

async fn expunge(
    session: &mut Session,
    caps: Caps,
    set: &str,
    ours: &std::collections::HashSet<u32>,
) -> Result<bool> {
    timed(TIMEOUT, "STORE", async {
        session
            .uid_store(set, "+FLAGS.SILENT (\\Deleted)")
            .await?
            .try_collect::<Vec<_>>()
            .await
    })
    .await?;
    if caps.uidplus {
        timed(TIMEOUT, "EXPUNGE", async {
            session
                .uid_expunge(set)
                .await?
                .try_collect::<Vec<_>>()
                .await
        })
        .await?;
    } else {
        // A plain EXPUNGE removes every message marked deleted, also ones
        // another program only marked: it's sent only if all are ours
        // (every delete tuimail still has pending in the folder).
        let marked = search(session, "DELETED").await?;
        if !marked.iter().all(|uid| ours.contains(uid)) {
            return Ok(false);
        }
        timed(TIMEOUT, "EXPUNGE", async {
            session.expunge().await?.try_collect::<Vec<_>>().await
        })
        .await?;
    }
    Ok(true)
}

/// The UIDs in a set written by [`uid_sets`].
fn set_uids(set: &str) -> std::collections::HashSet<u32> {
    let mut out = std::collections::HashSet::new();
    for part in set.split(',') {
        match part.split_once(':') {
            Some((a, b)) => {
                if let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.parse::<u32>()) {
                    out.extend(a.min(b)..=a.max(b));
                }
            }
            None => out.extend(part.parse::<u32>()),
        }
    }
    out
}

/// Adds a message to `folder` (Sent, Drafts).
pub async fn append(session: &mut Session, folder: &str, raw: &[u8], flags: Flags) -> Result<()> {
    let mut list = Vec::new();
    if flags.seen {
        list.push("\\Seen");
    }
    if flags.draft {
        list.push("\\Draft");
    }
    let flags = format!("({})", list.join(" "));
    timed(
        BODY_TIMEOUT,
        "APPEND",
        session.append(folder, Some(&flags), None, raw),
    )
    .await
}

/// Makes a folder (Sent or Drafts, where the server has none).
pub async fn create(session: &mut Session, folder: &str) -> Result<()> {
    timed(TIMEOUT, "CREATE", session.create(folder)).await
}

/// ANDed SEARCH keys. Only text values are quoted; names and operators
/// come from the parsed terms, never directly from the query.
pub fn search_criteria(query: &str) -> Option<String> {
    let mut criteria = String::new();
    for term in search::terms(query) {
        if !criteria.is_empty() {
            criteria.push(' ');
        }
        match term {
            Term::Text(field, word) => push_search_text(&mut criteria, field, &word),
            Term::Tag { name, raw } => {
                let keywords = tags::keywords(&name);
                if let Some((first, rest)) = keywords.split_first() {
                    // Any spelling of the tag (`OR` takes two at a time).
                    for _ in rest {
                        criteria.push_str("OR ");
                    }
                    write!(criteria, "KEYWORD {first}").unwrap();
                    for keyword in rest {
                        write!(criteria, " KEYWORD {keyword}").unwrap();
                    }
                } else {
                    push_search_text(&mut criteria, Field::Any, raw);
                }
            }
            Term::Since(date) | Term::Before(date) => {
                let key = if matches!(term, Term::Since(_)) {
                    "SENTSINCE"
                } else {
                    "SENTBEFORE"
                };
                let month = [
                    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
                    "Dec",
                ][date.month0() as usize];
                write!(criteria, "{key} {}-{month}-{:04}", date.day(), date.year()).unwrap();
            }
        }
    }
    if criteria.is_empty() {
        return None;
    }
    if !criteria.is_ascii() {
        criteria.insert_str(0, "CHARSET UTF-8 ");
    }
    Some(criteria)
}

fn push_search_text(criteria: &mut String, field: Field, word: &str) {
    let mut chars = word.chars().filter(|c| !c.is_control()).peekable();
    if chars.peek().is_none() {
        // Neither omit a term nor send an empty string that matches all mail.
        criteria.push_str("NOT ALL");
        return;
    }
    criteria.push_str(match field {
        Field::Any => "TEXT \"",
        Field::From => "FROM \"",
        Field::To => "TO \"",
        Field::Subject => "SUBJECT \"",
    });
    for c in chars {
        if matches!(c, '\\' | '"') {
            criteria.push('\\');
        }
        criteria.push(c);
    }
    criteria.push('"');
}

/// Waits on a connection of its own for the inbox to change (IDLE), and
/// returns when it does or after `limit`: `Ok(true)` if it changed.
pub async fn idle(session: Session, limit: Duration) -> Result<(Session, bool)> {
    let mut handle = session.idle();
    tokio::time::timeout(TIMEOUT, handle.init())
        .await
        .map_err(|_| anyhow!("IDLE: the server stopped answering"))?
        .context("IDLE")?;
    let changed = {
        let (wait, _stop) = handle.wait_with_timeout(limit);
        matches!(
            wait.await.context("IDLE")?,
            async_imap::extensions::idle::IdleResponse::NewData(_)
        )
    };
    let session = tokio::time::timeout(TIMEOUT, handle.done())
        .await
        .map_err(|_| anyhow!("IDLE: the server stopped answering"))?
        .context("IDLE")?;
    Ok((session, changed))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn a_server_busy_for_now_isnt_a_wrong_password() {
        // As async-imap words a NO: codes it doesn't know stay in the text.
        let no = |info: &str| format!("code: None, info: Some({info:?})");
        assert!(wrong_password(&no(
            "[AUTHENTICATIONFAILED] Invalid credentials"
        )));
        assert!(wrong_password(&no("LOGIN failed.")));
        assert!(!wrong_password(&no("[UNAVAILABLE] Temporary problem")));
        assert!(!wrong_password(&no(
            "[ALERT] Too many simultaneous connections."
        )));
    }

    /// A one-connection IMAP server on 127.0.0.1 that answers each
    /// command after LOGIN with `answer(tag, command)`.
    async fn scripted(answer: impl Fn(&str, &str) -> Vec<u8> + Send + 'static) -> (Session, Caps) {
        scripted_capabilities("IMAP4rev1", answer).await
    }

    pub(crate) async fn scripted_capabilities(
        capabilities: &'static str,
        mut answer: impl FnMut(&str, &str) -> Vec<u8> + Send + 'static,
    ) -> (Session, Caps) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            write.write_all(b"* OK ready\r\n").await.unwrap();
            while let Ok(Some(line)) = lines.next_line().await {
                let (tag, command) = line.split_once(' ').unwrap_or((&line, ""));
                let reply = if command.starts_with("LOGIN") {
                    format!("{tag} OK done\r\n").into_bytes()
                } else if command.starts_with("CAPABILITY") {
                    format!("* CAPABILITY {capabilities}\r\n{tag} OK done\r\n").into_bytes()
                } else {
                    answer(tag, command)
                };
                if write.write_all(&reply).await.is_err() {
                    break;
                }
            }
        });
        let endpoint = Endpoint {
            host: "127.0.0.1".into(),
            port,
            security: Security::None,
            tls: net::tls_config(None).unwrap(),
        };
        connect(&endpoint, "me", "pw", Auth::Password)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_message_bigger_than_the_cap_is_refused_whatever_size_the_server_gives() {
        let (mut session, _) = scripted(|tag, command| {
            if command.contains("BODY.PEEK") {
                let big = MAX_MESSAGE as usize + (2 << 20);
                let mut out = format!("* 1 FETCH (UID 1 BODY[] {{{big}}}\r\n").into_bytes();
                out.resize(out.len() + big, b'a');
                out.extend(format!(")\r\n{tag} OK done\r\n").as_bytes());
                out
            } else {
                // No RFC822.SIZE: the size can't be checked beforehand.
                format!("* 1 FETCH (UID 1)\r\n{tag} OK done\r\n").into_bytes()
            }
        })
        .await;
        assert!(body(&mut session, 1).await.is_err());
    }

    #[tokio::test]
    async fn headers_keep_only_what_was_asked_for() {
        let (mut session, _) = scripted(|tag, _| {
            let mut out = String::new();
            for uid in [1, 2, 99] {
                out.push_str(&format!("* {uid} FETCH (UID {uid} FLAGS ())\r\n"));
            }
            out.push_str(&format!("{tag} OK done\r\n"));
            out.into_bytes()
        })
        .await;
        let got: Vec<u32> = headers(&mut session, &[1, 2])
            .await
            .unwrap()
            .iter()
            .map(|h| h.uid)
            .collect();
        assert_eq!(got, [1, 2]);
        // Many more answers than asked for: the connection is given up.
        let (mut session, _) = scripted(|tag, _| {
            let mut out = String::new();
            for uid in 1..=100 {
                out.push_str(&format!("* {uid} FETCH (UID {uid} FLAGS ())\r\n"));
            }
            out.push_str(&format!("{tag} OK done\r\n"));
            out.into_bytes()
        })
        .await;
        assert!(headers(&mut session, &[1]).await.is_err());
    }

    #[test]
    fn uids_are_written_as_ranges() {
        assert_eq!(uid_sets(&[5, 1, 2, 3, 7, 9, 10, 2]), ["1:3,5,7,9:10"]);
        let back: std::collections::BTreeSet<u32> = set_uids("1:3,5,7,9:10").into_iter().collect();
        assert_eq!(back.into_iter().collect::<Vec<_>>(), [1, 2, 3, 5, 7, 9, 10]);
        assert_eq!(uid_sets(&[]), Vec::<String>::new());
        let many: Vec<u32> = (1..=1000).step_by(2).collect();
        assert_eq!(uid_sets(&many).len(), 2);
    }

    #[test]
    fn folder_roles_come_from_attributes_then_names() {
        let role = |raw: &str, shown: &str, attributes: &[NameAttribute]| {
            role_of(raw, shown, Some("/"), attributes).map(|(role, _)| role)
        };
        assert_eq!(role("INBOX", "INBOX", &[]), Some(Role::Inbox));
        assert_eq!(role("Inbox", "Inbox", &[]), Some(Role::Inbox));
        assert_eq!(
            role(
                "[Gmail]/Sent Mail",
                "[Gmail]/Sent Mail",
                &[NameAttribute::Sent]
            ),
            Some(Role::Sent)
        );
        assert_eq!(
            role_of("INBOX.Trash", "INBOX.Trash", Some("."), &[]).map(|r| r.0),
            Some(Role::Trash)
        );
        assert_eq!(role("Entw&APw-rfe", "Entwürfe", &[]), Some(Role::Drafts));
        assert_eq!(role("Projects", "Projects", &[]), None);
        let account = Account {
            trash_folder: "Bin2".into(),
            ..Account::default()
        };
        let folder = |name: &str, role| Folder {
            name: name.into(),
            shown: name.into(),
            delimiter: None,
            role,
            selectable: true,
            unread: 0,
            total: 0,
        };
        let mut folders = vec![folder("Trash", Some(Role::Trash)), folder("Bin2", None)];
        let mut said = vec![Some(RoleFrom::Name), None];
        apply_overrides(&mut folders, &mut said, &account);
        assert_eq!(folders[0].role, None);
        assert_eq!(folders[1].role, Some(Role::Trash));
        let mut twice = vec![
            folder("Junk", Some(Role::Junk)),
            folder("Spam", Some(Role::Junk)),
        ];
        dedupe_roles(&mut twice, &[Some(RoleFrom::Name), Some(RoleFrom::Name)]);
        assert_eq!((twice[0].role, twice[1].role), (Some(Role::Junk), None));
    }

    #[test]
    fn other_peoples_folders_take_no_role() {
        let role = |name: &str| role_of(name, name, Some("/"), &[]).map(|r| r.0);
        for name in [
            "shared/bob@example.org/Archive",
            "shared/bob@example.org/Sent",
            "Other Users/bob/Trash",
            "Public/Drafts",
            "Projects/Sent",
        ] {
            assert_eq!(role(name), None, "{name}");
        }
        // Even marked, a shared folder isn't the account's.
        let marked = role_of(
            "Shared Folders/team/Sent",
            "Shared Folders/team/Sent",
            Some("/"),
            &[NameAttribute::Sent],
        );
        assert_eq!(marked, None);
        // The server's mark wins over a name guessed earlier in the list.
        let folder = |name: &str, role| Folder {
            name: name.into(),
            shown: name.into(),
            delimiter: Some("/".into()),
            role,
            selectable: true,
            unread: 0,
            total: 0,
        };
        let mut folders = vec![
            folder("Sent", Some(Role::Sent)),
            folder("Sent Items", Some(Role::Sent)),
        ];
        dedupe_roles(
            &mut folders,
            &[Some(RoleFrom::Name), Some(RoleFrom::Attribute)],
        );
        assert_eq!((folders[0].role, folders[1].role), (None, Some(Role::Sent)));
    }

    #[test]
    fn search_words_are_quoted_and_cannot_add_commands() {
        assert_eq!(
            search_criteria("invoice march").unwrap(),
            "TEXT \"invoice\" TEXT \"march\""
        );
        assert_eq!(search_criteria("a\"b\\c").unwrap(), "TEXT \"a\\\"b\\\\c\"");
        assert_eq!(
            search_criteria("Jürgen").unwrap(),
            "CHARSET UTF-8 TEXT \"Jürgen\""
        );
        assert!(
            !search_criteria("x\r\nA1 DELETE INBOX")
                .unwrap()
                .contains('\n')
        );
        assert_eq!(search_criteria("   "), None);
    }

    #[test]
    fn structured_search_uses_only_fixed_keys_and_valid_sent_dates() {
        assert_eq!(
            search_criteria(
                r#"FROM:"Zoë \"Z\"" to:me subject:"C:\\temp" "past due" since:2024-02-29 before:2024-03-01"#,
            )
            .unwrap(),
            r#"CHARSET UTF-8 FROM "Zoë \"Z\"" TO "me" SUBJECT "C:\\temp" TEXT "past due" SENTSINCE 29-Feb-2024 SENTBEFORE 1-Mar-2024"#
        );
        assert_eq!(
            search_criteria(r#"since:2023-02-29 HEADER:"x y" from: subject:"unclosed"#).unwrap(),
            r#"TEXT "since:2023-02-29" TEXT "HEADER:\"x y\"" TEXT "from:" TEXT "subject:\"unclosed""#
        );
        assert_eq!(
            search_criteria("subject:\"x\r\nINBOX\" \0").unwrap(),
            r#"SUBJECT "xINBOX" NOT ALL"#
        );
    }

    #[test]
    fn a_tag_word_searches_for_the_tags_keywords() {
        assert_eq!(
            search_criteria("tag:Receipts march").unwrap(),
            "KEYWORD receipts TEXT \"march\""
        );
        assert_eq!(
            search_criteria("tag:work").unwrap(),
            "OR KEYWORD $label2 KEYWORD work"
        );
        // Not a tag: searched for as text.
        assert_eq!(search_criteria("tag:a(b").unwrap(), "TEXT \"tag:a(b\"");
    }

    #[tokio::test]
    async fn gmail_search_refuses_overlarge_results_instead_of_truncating() {
        let (mut session, _) = scripted(|tag, command| {
            assert_eq!(command, "UID SEARCH X-GM-THRID 7");
            let mut answer = "* SEARCH".to_string();
            for uid in 1..=MAX_CONVERSATION_MESSAGES + 1 {
                answer.push_str(&format!(" {uid}"));
            }
            format!("{answer}\r\n{tag} OK done\r\n").into_bytes()
        })
        .await;
        let error = gmail_thread_uids(&mut session, &[7]).await.unwrap_err();
        assert!(
            error.downcast_ref::<Said>().is_none(),
            "an unfinished oversized response drops the session"
        );
    }

    #[tokio::test]
    async fn gmail_command_limits_count_and_all_response_bytes() {
        for bytes in [1, CONVERSATION_BYTES] {
            let (mut session, _) = scripted(|tag, _| {
                format!("* 1 EXISTS\r\n* 2 EXISTS\r\n* 3 EXISTS\r\n{tag} OK done\r\n").into_bytes()
            })
            .await;
            let mut remaining = bytes;
            let error = gmail_command(
                &mut session,
                "UID SEARCH X-GM-THRID 7",
                2,
                &mut remaining,
                |_| Ok(()),
            )
            .await
            .unwrap_err();
            assert!(error.downcast_ref::<Said>().is_none());
        }
    }

    #[tokio::test]
    async fn gmail_tagged_refusal_consumes_the_completion_and_keeps_the_session_usable() {
        for status in ["NO", "BAD"] {
            let (mut session, _) = scripted(move |tag, command| {
                if command.starts_with("UID FETCH") {
                    format!("* 17 EXISTS\r\n{tag} {status} refused\r\n").into_bytes()
                } else {
                    assert_eq!(command, "UID SEARCH ALL");
                    format!("* SEARCH 7\r\n{tag} OK done\r\n").into_bytes()
                }
            })
            .await;
            let error = gmail_metadata(&mut session, &[7]).await.unwrap_err();
            assert!(error.downcast_ref::<Said>().is_some(), "{error:#}");
            assert_eq!(search(&mut session, "ALL").await.unwrap(), [7]);
        }
    }

    #[tokio::test]
    async fn gmail_wrong_tag_or_bye_drops_the_session() {
        for answer in ["wrong OK done\r\n", "* BYE closing\r\n"] {
            let (mut session, _) = scripted(move |_, _| answer.as_bytes().to_vec()).await;
            let error = gmail_thread_uids(&mut session, &[7]).await.unwrap_err();
            assert!(error.downcast_ref::<Said>().is_none(), "{error:#}");
        }
    }

    #[tokio::test]
    async fn gmail_incomplete_native_metadata_never_becomes_a_complete_result() {
        for with_header in [false, true] {
            let (mut session, _) = scripted(move |tag, _| {
                let header = if with_header { " BODY[HEADER] {14}\r\nSubject: x\r\n\r\n" } else { "" };
                format!("* 1 FETCH (UID 1 FLAGS () X-GM-MSGID 2 X-GM-LABELS (){header})\r\n{tag} OK done\r\n").into_bytes()
            }).await;
            let error = if with_header {
                gmail_headers(&mut session, &[1], &[7]).await.unwrap_err()
            } else {
                gmail_metadata(&mut session, &[1]).await.unwrap_err()
            };
            assert!(error.downcast_ref::<Said>().is_none(), "{error:#}");
            assert!(
                format!("{error:#}").contains("omitted native conversation metadata"),
                "{error:#}"
            );
        }
    }

    #[tokio::test]
    async fn gmail_missing_headers_never_become_a_complete_result() {
        for header in ["", " BODY[HEADER] NIL", " RFC822.HEADER NIL"] {
            let (mut session, _) = scripted(move |tag, _| {
                format!(
                    "* 1 FETCH (UID 1 FLAGS () X-GM-MSGID 2 X-GM-THRID 7 X-GM-LABELS (){header})\r\n{tag} OK done\r\n"
                )
                .into_bytes()
            })
            .await;
            let error = gmail_headers(&mut session, &[1], &[7]).await.unwrap_err();
            assert!(
                format!("{error:#}").contains("omitted conversation headers"),
                "{error:#}"
            );
        }

        let (mut session, _) = scripted(|tag, _| {
            let header = "Subject: Kept\r\n\r\n";
            format!(
                "* 1 FETCH (UID 1 FLAGS (\\Seen))\r\n\
                 * 1 FETCH (UID 1 FLAGS () X-GM-MSGID 2 X-GM-THRID 7 X-GM-LABELS () BODY[HEADER] {{{}}}\r\n{header})\r\n\
                 {tag} OK done\r\n",
                header.len()
            )
            .into_bytes()
        })
        .await;
        let headers = gmail_headers(&mut session, &[1], &[7]).await.unwrap();
        assert_eq!(headers[0].summary.subject, "Kept");
        assert!(!headers[0].flags.seen, "the unsolicited update is ignored");
    }
}
