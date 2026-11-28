//! IMAP (RFC 3501 and the usual extensions), through async-imap: logging
//! in, listing folders, and the handful of commands tuimail sends. Every
//! command has a time limit; a connection that misses one is dropped.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::io;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll, ready};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use async_imap::imap_proto::{
    AttributeValue, MailboxDatum, MessageSection, Outcome, Response, ResponseCode, SectionPath,
    Status, StatusAttribute,
};
use async_imap::types::{Fetch, Flag, NameAttribute, UnsolicitedResponse};
use chrono::Datelike as _;
use futures::{FutureExt, TryStreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::account::{Account, Auth, Security};
use crate::mail;
use crate::net::{self, Conn, Endpoint};
use crate::search::{self, Field, Term};
use crate::store::{Flags, Folder, Gmail, Header, Role};
use crate::{imap_timing, tags, text, utf7};

pub type Session = async_imap::Session<Transport>;

// Bound recursive FETCH data before it reaches async-imap's codec, which
// can start parsing before the response is complete.
const STRUCTURE_PARENS: usize = 128;
const STRUCTURE_DEPTH: u8 = 32;

#[derive(Debug)]
pub struct Transport {
    conn: Conn,
    selected: Option<(String, u32)>,
    // What could already be buffered after the preceding command's tagged
    // line. Any such bytes follow at least one LF in the last read.
    tail: ReadAhead,
    // Exact read-ahead, once a raw exchange has seen its tagged completion.
    tagged: bool,
    buffered: Vec<u8>,
    guard: Option<ReadGuard>,
    buffered_only: bool,
}

#[derive(Debug, Default)]
struct ReadAhead {
    bytes: usize,
    parens: usize,
    trailing_nuls: usize,
}

impl ReadAhead {
    fn after_line(data: &[u8]) -> Self {
        let tail = data
            .iter()
            .position(|&b| b == b'\n')
            .map_or(&[][..], |i| &data[i + 1..]);
        Self {
            bytes: tail.len(),
            parens: opening_parens(tail, STRUCTURE_PARENS),
            trailing_nuls: tail.iter().rev().take_while(|&&b| b == 0).count(),
        }
    }
}

fn opening_parens(data: &[u8], limit: usize) -> usize {
    data.iter().filter(|&&b| b == b'(').take(limit + 1).count()
}

#[derive(Clone, Copy)]
enum Framing {
    Ordinary,
    Structure,
    BodyStructure,
    Sections,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FramingError(&'static str);

impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for FramingError {}

// The pinned parser enters its recursive body grammar only immediately
// after this attribute name. Check every possible entry, even inside
// apparent text: the codec also accepts unrecognized FETCH attributes
// whose fallback syntax does not have the usual quoting rules.
#[derive(Debug, Default)]
struct StructureDepth {
    matched: usize,
    bodies: Vec<BodyDepth>,
}

impl StructureDepth {
    fn read(&mut self, data: &[u8]) -> Result<(), FramingError> {
        const START: &[u8] = b"BODYSTRUCTURE (";
        for &byte in data {
            self.bodies.retain_mut(|body| body.read(byte));
            if self.bodies.iter().any(|body| body.depth > STRUCTURE_DEPTH) {
                return Err(FramingError("IMAP body structure is too deep"));
            }
            self.matched = if byte.eq_ignore_ascii_case(&START[self.matched]) {
                self.matched + 1
            } else {
                // B occurs only at the start of the prefix.
                usize::from(byte.eq_ignore_ascii_case(&b'B'))
            };
            if self.matched == START.len() {
                if self.bodies.len() == STRUCTURE_DEPTH as usize {
                    return Err(FramingError("too many possible IMAP body structures"));
                }
                self.bodies.push(BodyDepth {
                    depth: 1,
                    token: BodyToken::Syntax,
                });
                self.matched = 0;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct BodyDepth {
    depth: u8,
    token: BodyToken,
}

#[derive(Debug, Clone, Copy)]
enum BodyToken {
    Syntax,
    Quoted,
    Escape,
    Length(Option<u32>),
    Cr(u32),
    Lf(u32),
    Literal(u32),
}

impl BodyDepth {
    // None of the recursive grammar crosses a line break except through
    // a literal. Stop tracking a closed or lexically impossible candidate.
    fn read(&mut self, byte: u8) -> bool {
        use BodyToken::*;
        self.token = match (self.token, byte) {
            (Syntax, b'(') => {
                self.depth += 1;
                Syntax
            }
            (Syntax, b')') => {
                self.depth -= 1;
                Syntax
            }
            (Syntax, b'"') => Quoted,
            (Syntax, b'{') => Length(None),
            (Quoted, b'\\') => Escape,
            (Quoted, b'"') => Syntax,
            (Escape, b'"' | b'\\') => Quoted,
            (Syntax | Quoted, b'\r' | b'\n' | 0) => return false,
            (Syntax | Quoted, _) => self.token,
            (Length(n), b'0'..=b'9') => {
                let Some(n) = n
                    .unwrap_or(0)
                    .checked_mul(10)
                    .and_then(|n| n.checked_add(u32::from(byte - b'0')))
                else {
                    return false;
                };
                Length(Some(n))
            }
            (Length(Some(n)), b'}') => Cr(n),
            (Cr(n), b'\r') => Lf(n),
            (Lf(0), b'\n') | (Literal(1), _) => Syntax,
            (Lf(n), b'\n') => Literal(n),
            (Literal(n), _) => Literal(n - 1),
            _ => return false,
        };
        self.depth != 0
    }
}

#[derive(Debug)]
struct ReadGuard {
    bytes: usize,
    framing: GuardFraming,
}

#[derive(Debug)]
enum GuardFraming {
    Ordinary,
    Structure(usize),
    BodyStructure(SectionFraming, StructureDepth),
    Sections(SectionFraming, usize),
}

impl ReadGuard {
    fn read(&mut self, data: &[u8]) -> Result<(), FramingError> {
        self.bytes = self
            .bytes
            .checked_sub(data.len())
            .ok_or(FramingError("too much data returned by IMAP"))?;
        match &mut self.framing {
            GuardFraming::Ordinary => Ok(()),
            GuardFraming::Structure(opens) => count_opens(data, opens),
            GuardFraming::BodyStructure(framing, depth) => {
                depth.read(data)?;
                framing.read(data, self.bytes, None)
            }
            GuardFraming::Sections(framing, opens) => framing.read(data, self.bytes, Some(opens)),
        }
    }
}

fn count_opens(data: &[u8], opens: &mut usize) -> Result<(), FramingError> {
    *opens = opens
        .checked_sub(opening_parens(data, *opens))
        .ok_or(FramingError("too much IMAP body structure"))?;
    Ok(())
}

// Bound literal lengths before the codec can reserve their buffers. Only
// proven BODY section data bypasses the Sections recursion budget.
#[derive(Debug, Default)]
struct SectionFraming {
    line: Vec<u8>,
    probe: Vec<u8>,
    literal: usize,
    continuation: bool,
    quoted: Option<Quote>,
}

#[derive(Debug, Clone, Copy)]
enum Quote {
    Text,
    Escape,
}

impl SectionFraming {
    fn read(
        &mut self,
        mut data: &[u8],
        budget: usize,
        mut opens: Option<&mut usize>,
    ) -> Result<(), FramingError> {
        while !data.is_empty() {
            if self.literal != 0 {
                let skip = data.len().min(self.literal);
                self.literal -= skip;
                data = &data[skip..];
                continue;
            }
            if self.quoted.is_some() {
                data = self.after_quote(data)?;
                continue;
            }
            let sections = opens.is_some();
            let delimiter = data
                .iter()
                .position(|&byte| byte == b'\n' || (sections && byte == b'"'));
            let (chunk, rest) = data.split_at(delimiter.unwrap_or(data.len()));
            if let Some(opens) = opens.as_deref_mut() {
                count_opens(chunk, opens)?;
            }
            if self.line.len() + chunk.len() + 2 > 64 * 1024 {
                return Err(FramingError("too much IMAP FETCH framing"));
            }
            self.line.extend_from_slice(chunk);
            let Some((&end, rest)) = rest.split_first() else {
                break;
            };
            data = rest;
            if end == b'"' {
                if (self.line.ends_with(b"] ") || self.line.ends_with(b"> "))
                    && section_value(&mut self.probe, &self.line, self.continuation)
                {
                    // Keep the prefix usable for the next value probe
                    // without counting or copying the quoted payload.
                    self.line.extend_from_slice(b"\"\"");
                    self.quoted = Some(Quote::Text);
                } else {
                    self.line.push(end);
                }
            } else {
                self.line.push(end);
                let line = self.line.strip_suffix(b"\r\n").ok_or_else(bad_framing)?;
                let literal = line.strip_suffix(b"}").and_then(|prefix| {
                    let open = prefix.iter().rposition(|&byte| byte == b'{')?;
                    let number = &prefix[open + 1..];
                    (!number.is_empty() && number.iter().all(u8::is_ascii_digit))
                        .then(|| (&prefix[..open], number))
                });
                self.continuation = if let Some((prefix, number)) = literal
                    && (self.continuation
                        || is_fetch(line)
                        || !matches!(Response::parse(&self.line), Ok(([], _))))
                {
                    // Non-FETCH status text can end in "{123}" without
                    // declaring a literal. Only parse that line above if
                    // its prefix cannot enter the recursive FETCH grammar.
                    let size = ascii_number(number).ok_or_else(bad_framing)? as usize;
                    if size > budget.saturating_add(rest.len()) {
                        return Err(FramingError("too much data returned by IMAP FETCH"));
                    }
                    if sections && !section_value(&mut self.probe, prefix, self.continuation) {
                        return Err(bad_framing());
                    }
                    self.literal = size;
                    true
                } else {
                    false
                };
                self.line.clear();
            }
        }
        Ok(())
    }

    fn after_quote<'a>(&mut self, data: &'a [u8]) -> Result<&'a [u8], FramingError> {
        for (i, &byte) in data.iter().enumerate() {
            self.quoted = Some(match (self.quoted, byte) {
                (Some(Quote::Text), b'"') => {
                    self.quoted = None;
                    return Ok(&data[i + 1..]);
                }
                (Some(Quote::Text), b'\\') => Quote::Escape,
                (Some(Quote::Escape), b'\\' | b'"') => Quote::Text,
                (Some(Quote::Text), 0 | b'\r' | b'\n') => return Err(bad_framing()),
                (Some(Quote::Text), _) => Quote::Text,
                _ => return Err(bad_framing()),
            });
        }
        Ok(&[])
    }
}

fn bad_framing() -> FramingError {
    FramingError("unexpected IMAP section data framing")
}

fn is_fetch(line: &[u8]) -> bool {
    let mut words = line.splitn(4, |&byte| byte == b' ');
    words.next() == Some(b"*")
        && words.next().is_some_and(|n| ascii_number(n).is_some())
        && words
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case(b"FETCH"))
}

fn ascii_number(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

// Probe the prefix with an empty BODY section literal, which takes the
// same nstring position as a quoted section. The skipped data never
// reaches the probe; structural bytes were already bounded.
fn section_value(probe: &mut Vec<u8>, line: &[u8], continuation: bool) -> bool {
    probe.clear();
    if continuation {
        let Some(rest) = line.strip_prefix(b" ") else {
            return false;
        };
        probe.extend_from_slice(b"* 1 FETCH (");
        probe.extend_from_slice(rest);
    } else {
        probe.extend_from_slice(line);
    }
    let body = probe.len() + b"{0}\r\n".len();
    probe.extend_from_slice(b"{0}\r\n)\r\n");
    matches!(
        Response::parse(probe),
        Ok(([], Response::Fetch(_, attrs)))
            if matches!(attrs.last(), Some(AttributeValue::BodySection { data: Some(data), .. })
                if data.as_ptr() == probe[body..].as_ptr())
    )
}

impl Transport {
    fn new(conn: Conn) -> Self {
        Self {
            conn,
            selected: None,
            tail: ReadAhead::default(),
            tagged: false,
            buffered: Vec::new(),
            guard: None,
            buffered_only: false,
        }
    }

    fn guard(&mut self, bytes: usize, framing: Framing) -> Result<()> {
        let needs_boundary = matches!(framing, Framing::BodyStructure | Framing::Sections);
        if needs_boundary && !self.tagged {
            bail!("unknown IMAP response boundary before downloading the message");
        }
        let mut guard = ReadGuard {
            bytes,
            framing: match framing {
                Framing::Ordinary => GuardFraming::Ordinary,
                Framing::Structure => GuardFraming::Structure(STRUCTURE_PARENS),
                Framing::BodyStructure => GuardFraming::BodyStructure(
                    SectionFraming::default(),
                    StructureDepth::default(),
                ),
                Framing::Sections => {
                    GuardFraming::Sections(SectionFraming::default(), STRUCTURE_PARENS)
                }
            },
        };
        if self.tagged {
            guard.read(&self.buffered)?;
        } else {
            guard.bytes = guard
                .bytes
                .checked_sub(self.tail.bytes)
                .context("too much buffered data before IMAP command")?;
            if let GuardFraming::Structure(opens) = &mut guard.framing {
                *opens = opens
                    .checked_sub(self.tail.parens)
                    .context("too much IMAP structure was buffered before FETCH")?;
            }
        }
        self.tagged = false;
        self.guard = Some(guard);
        Ok(())
    }

    fn saw_tag(&mut self, raw: &[u8], outcome: &Outcome<'_>) -> Result<(), FramingError> {
        self.buffered.clear();
        if self.tail.bytes != 0 {
            // The codec's owner includes zero-filled unused capacity.
            // The tag ended in the last read that supplied bytes. At
            // most bytes after that read's first LF can still be buffered,
            // and any real trailing NULs came from that same read.
            let rest = if matches!(outcome.code, Some(ResponseCode::BadCharset(Some(_)))) {
                // BADCHARSET's list can contain literals in a tagged reply.
                let Ok((rest, Response::Done { .. })) = Response::parse(raw) else {
                    return Err(bad_framing());
                };
                rest
            } else {
                let lf = raw
                    .iter()
                    .position(|&b| b == b'\n')
                    .ok_or_else(bad_framing)?;
                &raw[lf + 1..]
            };
            let rest = &rest[..rest.len().min(self.tail.bytes)];
            let end =
                rest.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1) + self.tail.trailing_nuls;
            self.buffered
                .extend_from_slice(rest.get(..end).ok_or_else(bad_framing)?);
        }
        self.tagged = true;
        Ok(())
    }
}

impl AsyncRead for Transport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.buffered_only {
            return Poll::Pending;
        }
        let start = buf.filled().len();
        ready!(Pin::new(&mut this.conn).poll_read(cx, buf))?;
        let data = &buf.filled()[start..];
        if let Some(guard) = &mut this.guard {
            guard.read(data).map_err(io::Error::other)?;
        } else {
            this.tagged = false;
        }
        this.tail = ReadAhead::after_line(data);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Transport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.guard.is_none() {
            this.tagged = false;
        }
        Pin::new(&mut this.conn).poll_write(cx, data)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}

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
    what: &'static str,
    f: impl Future<Output = async_imap::error::Result<T>>,
) -> Result<T> {
    use async_imap::error::Error;
    let start = imap_timing::start();
    let result = tokio::time::timeout(limit, f).await;
    imap_timing::finish(start, what, None);
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e @ (Error::No(_) | Error::Bad(_) | Error::Validate(_) | Error::Append))) => {
            bail!(Said(format!(
                "{what}: {}",
                text::one_line(&e.to_string(), 300)
            )))
        }
        Ok(Err(Error::Io(e))) => {
            if let Some(error) = e
                .get_ref()
                .and_then(|err| err.downcast_ref::<FramingError>())
            {
                return Err(anyhow!(*error).context(what));
            }
            bail!("{what}: io: {}", text::one_line(&e.to_string(), 300));
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
    let mut client = async_imap::Client::new(Transport::new(conn));
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
        let tcp = client.into_inner().conn.into_plain()?;
        client = async_imap::Client::new(Transport::new(net::start_tls(tcp, endpoint).await?));
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
    let mut said = Vec::new();
    let mut folders = Vec::new();
    exchange(
        session,
        "LIST \"\" *",
        Exchange {
            responses: 10_000,
            bytes: 8 << 20,
            framing: Framing::Ordinary,
            ..Exchange::small("LIST")
        },
        |parsed, _| {
            if let Response::MailboxData(MailboxDatum::List(data)) = parsed
                && folders.len() < 2000
            {
                let attributes = &data.name_attributes;
                let raw = data.name.as_ref();
                let shown = utf7::decode(raw).unwrap_or_else(|| raw.to_string());
                let delimiter = data.delimiter.as_deref();
                let selectable = !attributes.iter().any(|a| {
                    matches!(a, NameAttribute::NoSelect)
                        || matches!(a, NameAttribute::Extension(e) if e.eq_ignore_ascii_case("\\NonExistent"))
                });
                let role = role_of(raw, &shown, delimiter, attributes);
                said.push(role.map(|(_, by)| by));
                folders.push(Folder {
                    role: role.map(|(role, _)| role),
                    shown: text::one_line(&shown, 200),
                    name: raw.to_string(),
                    delimiter: delimiter.map(|d| text::one_line(d, 2)),
                    selectable,
                    unread: 0,
                    total: 0,
                });
            }
            Ok(())
        },
    )
    .await?;
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
    let mut unread = 0;
    let mut total = 0;
    mailbox_status(
        session,
        folder,
        "MESSAGES UNSEEN",
        |attribute| match attribute {
            StatusAttribute::Messages(value) => total = *value,
            StatusAttribute::Unseen(value) => unread = *value,
            _ => {}
        },
    )
    .await?;
    Ok((unread, total))
}

/// A folder's UIDVALIDITY and UIDNEXT, from STATUS: before a move, so the
/// messages it puts there can be told from mail that was there, or comes
/// later.
pub async fn uid_next(session: &mut Session, folder: &str) -> Result<(u32, u32)> {
    let mut validity = 0;
    let mut next = 0;
    mailbox_status(
        session,
        folder,
        "UIDVALIDITY UIDNEXT",
        |attribute| match attribute {
            StatusAttribute::UidValidity(value) => validity = *value,
            StatusAttribute::UidNext(value) => next = *value,
            _ => {}
        },
    )
    .await?;
    Ok((validity, next))
}

async fn mailbox_status(
    session: &mut Session,
    folder: &str,
    items: &str,
    mut accept: impl FnMut(&StatusAttribute),
) -> Result<()> {
    let command = format!("STATUS {} ({items})", quote_folder(folder)?);
    exchange(session, &command, Exchange::small("STATUS"), |parsed, _| {
        if let Response::MailboxData(MailboxDatum::Status { mailbox, status }) = parsed
            && same_folder(mailbox, folder)
        {
            for attribute in status {
                accept(attribute);
            }
        }
        Ok(())
    })
    .await?;
    Ok(())
}

fn quote_folder(folder: &str) -> Result<String> {
    if folder.contains(['\r', '\n', '\0']) {
        bail!(Said("the mailbox name can't go in an IMAP command".into()));
    }
    Ok(format!(
        "\"{}\"",
        folder.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn same_folder(a: &str, b: &str) -> bool {
    a == b || a.eq_ignore_ascii_case("INBOX") && b.eq_ignore_ascii_case("INBOX")
}

fn changed_validity(attributes: &[StatusAttribute], validity: u32) -> bool {
    attributes
        .iter()
        .any(|attr| matches!(attr, StatusAttribute::UidValidity(uid) if *uid != validity))
}

fn closed(outcome: &Outcome<'_>) -> bool {
    // imap-proto doesn't model the RFC 7162 CLOSED code.
    outcome
        .information
        .as_deref()
        .and_then(|info| info.as_bytes().get(..8))
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"[CLOSED]"))
}

fn invalidates(parsed: &Response<'_>, folder: &str, validity: u32) -> bool {
    match parsed {
        Response::Data { status, outcome }
        | Response::Done {
            status, outcome, ..
        } => {
            matches!(status, Status::Bye | Status::PreAuth)
                || closed(outcome)
                || matches!(outcome.code, Some(ResponseCode::UidValidity(uid)) if uid != validity)
        }
        Response::MailboxData(MailboxDatum::Status { mailbox, status }) => {
            same_folder(mailbox, folder) && changed_validity(status, validity)
        }
        _ => false,
    }
}

pub fn forget_selection(session: &mut Session) {
    session.get_mut().selected = None;
}

/// UID reads and Seen changes can reuse a confirmed selection. A fresh
/// SELECT for other commands still obtains their complete mailbox metadata.
pub async fn select_read(session: &mut Session, folder: &str, validity: u32) -> Result<u32> {
    drain(session);
    if validity != 0
        && session.get_ref().tagged
        && session.get_ref().buffered.is_empty()
        && session
            .get_ref()
            .selected
            .as_ref()
            .is_some_and(|(name, uid)| same_folder(name, folder) && *uid == validity)
    {
        return Ok(validity);
    }
    forget_selection(session);
    let command = format!("SELECT {}", quote_folder(folder)?);
    let mut selected = None;
    let mut reported_change = false;
    exchange(session, &command, Exchange::small("SELECT"), |parsed, _| {
        if let Response::Data {
            status: Status::Ok,
            outcome,
        }
        | Response::Done {
            status: Status::Ok,
            outcome,
            ..
        } = parsed
        {
            if closed(outcome) {
                // QRESYNC may close the old mailbox before announcing the new one.
                reported_change |= selected.is_some() || matches!(parsed, Response::Done { .. });
            } else if let Some(ResponseCode::UidValidity(uid)) = outcome.code {
                reported_change |= uid == 0 || selected.is_some_and(|previous| previous != uid);
                selected = Some(uid);
            }
        } else if let Response::MailboxData(MailboxDatum::Status { mailbox, status }) = parsed
            && same_folder(mailbox, folder)
            && validity != 0
            && changed_validity(status, validity)
        {
            reported_change = true;
        }
        Ok(())
    })
    .await?;
    if reported_change {
        bail!(Said("the selected mailbox changed during SELECT".into()));
    }
    if let Some(uid) = selected {
        session.get_mut().selected = Some((folder.to_string(), uid));
    }
    Ok(selected.unwrap_or(0))
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
    forget_selection(session);
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
    while let Ok(response) = session.unsolicited_responses.try_recv() {
        let invalidate = session
            .get_ref()
            .selected
            .as_ref()
            .is_some_and(|(folder, uid)| match response {
                UnsolicitedResponse::Status {
                    mailbox,
                    attributes,
                } => same_folder(&mailbox, folder) && changed_validity(&attributes, *uid),
                UnsolicitedResponse::Other(data) => invalidates(data.parsed(), folder, *uid),
                _ => false,
            });
        if invalidate {
            forget_selection(session);
        }
    }
}

/// A FETCH's answers, at most `max` of them and `max_bytes` of message
/// data: a server can't make tuimail hold more than it asked for. Past
/// either, the connection is dropped (an error that isn't [`Said`]), since
/// what's still coming would be read as the next command's answer.
async fn collect(
    what: &'static str,
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
/// public command/response API and re-exported parser.
async fn gmail_command(
    session: &mut Session,
    command: &str,
    max_responses: usize,
    remaining_bytes: &mut usize,
    mut accept: impl FnMut(&Response<'_>) -> Result<()>,
) -> Result<()> {
    let limits = Exchange {
        responses: max_responses,
        bytes: *remaining_bytes,
        framing: Framing::Ordinary,
        ..Exchange::small("Gmail conversations")
    };
    let read = exchange(session, command, limits, |parsed, _| accept(parsed)).await?;
    *remaining_bytes -= read;
    Ok(())
}

struct Exchange {
    label: &'static str,
    timeout: Duration,
    responses: usize,
    bytes: usize,
    framing: Framing,
    require_selection: bool,
}

impl Exchange {
    fn small(label: &'static str) -> Self {
        Self {
            label,
            timeout: TIMEOUT,
            responses: 256,
            bytes: 1 << 20,
            framing: Framing::Structure,
            require_selection: false,
        }
    }
}

// Consume complete unsolicited responses that the codec already has
// before sending a command that depends on the selected UIDVALIDITY.
// Incomplete replies are left for the exchange; never wait on the socket
// here. The guard has already checked the exact buffered bytes.
fn check_selected(session: &mut Session, max_responses: usize) -> Result<usize> {
    let changed = || Said("the selected mailbox changed before the IMAP command".into());
    if session.get_ref().selected.is_none() {
        bail!(changed());
    }
    if session.get_ref().buffered.is_empty() {
        return Ok(0);
    }
    session.get_mut().buffered_only = true;
    let result = (|| {
        let mut count = 0;
        while let Some(response) = session.read_response().now_or_never() {
            count += 1;
            if count > max_responses {
                bail!("the server sent too many IMAP responses");
            }
            let response = response?.context("the IMAP connection ended")?;
            let parsed = response.parsed();
            if matches!(
                parsed,
                Response::Data {
                    status: Status::Bye | Status::PreAuth,
                    ..
                } | Response::Done { .. }
                    | Response::Continue(_)
            ) {
                bail!("the server sent an unexpected response between IMAP commands");
            }
            if session
                .get_ref()
                .selected
                .as_ref()
                .is_some_and(|(folder, uid)| invalidates(parsed, folder, *uid))
            {
                forget_selection(session);
                bail!(changed());
            }
        }
        Ok(count)
    })();
    session.get_mut().buffered_only = false;
    result
}

/// A serialized, bounded exchange. Only a matching tagged completion can
/// make a refusal safe to report without giving up the connection.
async fn exchange(
    session: &mut Session,
    command: &str,
    limits: Exchange,
    mut accept: impl FnMut(&Response<'_>, &[u8]) -> Result<()>,
) -> Result<usize> {
    drain(session);
    session.get_mut().guard(limits.bytes, limits.framing)?;
    let result = timed(limits.timeout, limits.label, async {
        let mut count = if limits.require_selection {
            match check_selected(session, limits.responses) {
                Ok(count) => count,
                Err(error) => return Ok(Err(error)),
            }
        } else {
            0
        };
        let id = session.run_command(command).await?;
        let mut invalidated = false;
        while let Some(response) = session.read_response().await? {
            count += 1;
            if count > limits.responses {
                return Ok(Err(anyhow!("the server sent too many IMAP responses")));
            }
            let parsed = response.parsed();
            if session
                .get_ref()
                .selected
                .as_ref()
                .is_some_and(|(folder, uid)| invalidates(parsed, folder, *uid))
            {
                forget_selection(session);
                invalidated = true;
            }
            match parsed {
                Response::Done {
                    tag,
                    status,
                    outcome,
                } => {
                    if tag != &id {
                        return Ok(Err(anyhow!("the server answered a different command")));
                    }
                    if let Err(error) = session.get_mut().saw_tag(response.borrow_owner(), outcome)
                    {
                        return Ok(Err(error.into()));
                    }
                    let words =
                        || format!("code: {:?}, info: {:?}", outcome.code, outcome.information);
                    return match status {
                        Status::Ok if invalidated && limits.require_selection => Ok(Err(anyhow!(
                            Said("the selected mailbox changed during the IMAP command".into())
                        ))),
                        Status::Ok => Ok(accept(parsed, response.borrow_owner())),
                        Status::No => Err(async_imap::error::Error::No(words())),
                        Status::Bad => Err(async_imap::error::Error::Bad(words())),
                        _ => Err(async_imap::error::Error::ConnectionLost),
                    };
                }
                Response::Data {
                    status: Status::Bye | Status::PreAuth,
                    ..
                }
                | Response::Continue(_) => return Err(async_imap::error::Error::ConnectionLost),
                _ => {
                    if let Err(error) = accept(parsed, response.borrow_owner()) {
                        return Ok(Err(anyhow!("{error:#}")));
                    }
                }
            }
        }
        Err(async_imap::error::Error::ConnectionLost)
    })
    .await;
    let remaining = session
        .get_mut()
        .guard
        .take()
        .map_or(0, |guard| guard.bytes);
    result??;
    Ok(limits.bytes - remaining)
}

pub async fn fetch_parts(
    session: &mut Session,
    command: &str,
    max_bytes: usize,
    structure: bool,
    mut accept: impl FnMut(&Response<'_>, &[u8]) -> Result<()>,
) -> Result<()> {
    let mut mislabeled = false;
    exchange(
        session,
        command,
        Exchange {
            label: if structure {
                "BODYSTRUCTURE"
            } else {
                "FETCH parts"
            },
            timeout: if structure { TIMEOUT } else { BODY_TIMEOUT },
            responses: 160,
            bytes: max_bytes,
            framing: if structure {
                Framing::BodyStructure
            } else {
                Framing::Sections
            },
            require_selection: true,
        },
        |parsed, raw| {
            if let Response::Fetch(_, attrs) = parsed
                && attrs.iter().any(|attr| {
                    matches!(
                        attr,
                        AttributeValue::BodySection {
                            section: Some(SectionPath::Full(MessageSection::Header)),
                            index: None,
                            data: Some(data),
                        } if !exact_header(raw, data)
                    )
                })
            {
                mislabeled = true;
                return Ok(());
            }
            accept(parsed, raw)
        },
    )
    .await?;
    if mislabeled {
        bail!(Said(
            "the server did not send the whole message header".into()
        ));
    }
    Ok(())
}

fn value_prefix<'a>(raw: &'a [u8], data: &[u8]) -> Option<&'a [u8]> {
    (data.as_ptr() as usize)
        .checked_sub(raw.as_ptr() as usize)
        .and_then(|offset| raw.get(..offset))
}

// imap-proto borrows the contents of both literals and quoted strings without
// unescaping the latter. Literal data, including backslashes, stays untouched.
pub(crate) fn section_bytes<'a>(raw: &[u8], data: &'a [u8]) -> Cow<'a, [u8]> {
    if !value_prefix(raw, data).is_some_and(|prefix| prefix.ends_with(b"\"")) {
        return Cow::Borrowed(data);
    }
    let Some(first) = data.iter().position(|&b| b == b'\\') else {
        return Cow::Borrowed(data);
    };
    let mut decoded = Vec::with_capacity(data.len() - 1);
    decoded.extend_from_slice(&data[..first]);
    let mut tail = &data[first..];
    while let Some((&escaped, rest)) = tail.get(1..).and_then(|tail| tail.split_first()) {
        // A quoted string was already accepted by the codec: each escape
        // is followed by exactly one quote or backslash.
        decoded.push(escaped);
        let Some(next) = rest.iter().position(|&b| b == b'\\') else {
            decoded.extend_from_slice(rest);
            break;
        };
        decoded.extend_from_slice(&rest[..next]);
        tail = &rest[next..];
    }
    Cow::Owned(decoded)
}

// imap-proto aliases HEADER.FIELDS(.NOT) to HEADER. Locate the spelling
// immediately before the parser's borrowed payload, not inside the mail.
fn exact_header(raw: &[u8], data: &[u8]) -> bool {
    let Some(prefix) = value_prefix(raw, data) else {
        return false;
    };
    let before_value = if let Some(before_length) = prefix.strip_suffix(b"}\r\n") {
        before_length
            .iter()
            .rposition(|&b| b == b'{')
            .map(|i| &before_length[..i])
    } else {
        prefix.strip_suffix(b"\"")
    };
    const HEADER: &[u8] = b"BODY[HEADER] ";
    before_value.is_some_and(|prefix| {
        prefix.len() >= HEADER.len()
            && prefix[prefix.len() - HEADER.len()..].eq_ignore_ascii_case(HEADER)
    })
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
pub async fn body(session: &mut Session, uid: u32, size: u32) -> Result<Option<Vec<u8>>> {
    let size = if size == 0 {
        let mut found = None;
        exchange(
            session,
            &format!("UID FETCH {uid} (UID RFC822.SIZE)"),
            Exchange {
                framing: Framing::Sections,
                require_selection: true,
                ..Exchange::small("FETCH size")
            },
            |parsed, _| {
                if let Response::Fetch(_, attrs) = parsed
                    && requested_uid(attrs, uid)
                {
                    let size = attrs.iter().find_map(|attr| match attr {
                        AttributeValue::Rfc822Size(n) => Some(*n),
                        _ => None,
                    });
                    found = size.or(found).or(Some(0));
                }
                Ok(())
            },
        )
        .await?;
        let Some(size) = found else {
            return Ok(None);
        };
        size
    } else {
        size
    };
    if size > MAX_MESSAGE {
        bail!(Said(format!(
            "the message is {}, too big to download",
            mail::size(size as usize)
        )));
    }
    let mut body = None;
    let mut too_big = false;
    let start = imap_timing::start();
    let result = exchange(
        session,
        &format!("UID FETCH {uid} (UID BODY.PEEK[]<0.{}>)", MAX_MESSAGE + 1),
        Exchange {
            label: "FETCH body",
            timeout: BODY_TIMEOUT,
            responses: 17,
            bytes: MAX_MESSAGE as usize + (1 << 20),
            framing: Framing::Sections,
            require_selection: true,
        },
        |parsed, raw| {
            if let Response::Fetch(_, attrs) = parsed
                && requested_uid(attrs, uid)
            {
                for attr in attrs {
                    if let AttributeValue::BodySection {
                        section: None,
                        index: Some(0),
                        data: Some(bytes),
                    } = attr
                    {
                        let bytes = section_bytes(raw, bytes);
                        if bytes.len() > MAX_MESSAGE as usize {
                            too_big = true;
                        } else if body.is_none() {
                            body = Some(bytes.into_owned());
                        }
                    }
                }
            }
            Ok(())
        },
    )
    .await;
    imap_timing::finish(start, "body bytes", body.as_ref().map(Vec::len));
    result?;
    if too_big {
        bail!(Said("the message is too big to download".into()));
    }
    Ok(body)
}

fn requested_uid(attrs: &[AttributeValue<'_>], uid: u32) -> bool {
    let mut uids = attrs.iter().filter_map(|attr| match attr {
        AttributeValue::Uid(n) => Some(*n),
        _ => None,
    });
    uid != 0 && uids.next() == Some(uid) && uids.next().is_none()
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
    if flag == FlagKind::Seen {
        let sign = if on { '+' } else { '-' };
        for set in uid_sets(uids) {
            exchange(
                session,
                &format!("UID STORE {set} {sign}FLAGS.SILENT (\\Seen)"),
                Exchange {
                    framing: Framing::Sections,
                    require_selection: true,
                    ..Exchange::small("STORE")
                },
                |_, _| Ok(()),
            )
            .await?;
        }
        return Ok(());
    }
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
        answer: impl FnMut(&str, &str) -> Vec<u8> + Send + 'static,
    ) -> (Session, Caps) {
        let endpoint = scripted_endpoint(capabilities, answer).await;
        connect(&endpoint, "me", "pw", Auth::Password)
            .await
            .unwrap()
    }

    pub(crate) async fn scripted_endpoint(
        capabilities: &'static str,
        mut answer: impl FnMut(&str, &str) -> Vec<u8> + Send + 'static,
    ) -> Endpoint {
        scripted_connections(capabilities, 1, move |_, tag, command| answer(tag, command)).await
    }

    pub(crate) async fn scripted_connections(
        capabilities: &'static str,
        count: usize,
        mut answer: impl FnMut(usize, &str, &str) -> Vec<u8> + Send + 'static,
    ) -> Endpoint {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            for i in 0..count {
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
                        answer(i, tag, command)
                    };
                    if reply.is_empty() || write.write_all(&reply).await.is_err() {
                        break;
                    }
                }
            }
        });
        Endpoint {
            host: "127.0.0.1".into(),
            port,
            security: Security::None,
            tls: net::tls_config(None).unwrap(),
        }
    }

    #[tokio::test]
    async fn a_message_bigger_than_the_cap_is_refused_whatever_size_the_server_gives() {
        let (mut session, _) = scripted(|tag, command| {
            let reply = match command {
                "SELECT \"INBOX\"" => format!("* OK [UIDVALIDITY 7] stable\r\n{tag} OK done\r\n"),
                "UID FETCH 1 (UID RFC822.SIZE)" => {
                    // No RFC822.SIZE: the size can't be checked beforehand.
                    format!("* 1 FETCH (UID 1)\r\n{tag} OK done\r\n")
                }
                command if command.contains("BODY.PEEK") => {
                    let big = MAX_MESSAGE as usize + (2 << 20);
                    format!("* 1 FETCH (UID 1 BODY[]<0> {{{big}}}\r\n")
                }
                _ => panic!("unexpected command: {command}"),
            };
            reply.into_bytes()
        })
        .await;
        select_read(&mut session, "INBOX", 7).await.unwrap();
        assert!(body(&mut session, 1, 0).await.is_err());
    }

    #[tokio::test]
    async fn known_sizes_use_one_bounded_fetch_and_selection_is_reused_or_renewed() {
        let mut step = 0;
        let (mut session, _) = scripted_capabilities("IMAP4rev1", move |tag, command| {
            let reply = match step {
                0 => {
                    assert_eq!(command, "SELECT \"INBOX\"");
                    "* OK [UIDVALIDITY 7] stable\r\n".into()
                }
                1 => {
                    assert_eq!(
                        command,
                        format!("UID FETCH 1 (UID BODY.PEEK[]<0.{}>)", MAX_MESSAGE + 1)
                    );
                    // Parentheses and CRLF in a literal aren't BODYSTRUCTURE.
                    let raw = format!("{}\r\nhello", "(".repeat(1024));
                    format!("* 1 FETCH (BODY[]<0> {{{}}}\r\n{raw} UID 1)\r\n", raw.len())
                }
                2 => {
                    assert_eq!(command, "UID STORE 1 +FLAGS.SILENT (\\Seen)");
                    String::new()
                }
                3 => {
                    assert_eq!(
                        command,
                        format!("UID FETCH 2 (UID BODY.PEEK[]<0.{}>)", MAX_MESSAGE + 1)
                    );
                    // The only answers have a different UID or partial origin.
                    "* 1 FETCH (UID 1 BODY[]<0> {3}\r\nold)\r\n\
                     * 2 FETCH (UID 2 BODY[]<3> {3}\r\nold)\r\n"
                        .into()
                }
                4 => {
                    assert_eq!(command, "SELECT \"Archive\"");
                    "* OK [UIDVALIDITY 9] stable\r\n".into()
                }
                5 => {
                    assert_eq!(command, "STATUS \"Archive\" (MESSAGES UNSEEN)");
                    "* STATUS Archive (MESSAGES 2 UNSEEN 1 UIDVALIDITY 10)\r\n".into()
                }
                6 => {
                    assert_eq!(command, "SELECT \"Archive\"");
                    "* OK [UIDVALIDITY 10] changed\r\n".into()
                }
                _ => panic!("unexpected command: {command}"),
            };
            step += 1;
            format!("{reply}{tag} OK done\r\n").into_bytes()
        })
        .await;
        assert_eq!(select_read(&mut session, "INBOX", 7).await.unwrap(), 7);
        let raw = body(&mut session, 1, 1234).await.unwrap().unwrap();
        assert!(raw.ends_with(b"\r\nhello"));
        assert_eq!(select_read(&mut session, "inbox", 7).await.unwrap(), 7);
        set_flag(&mut session, &[1], FlagKind::Seen, true)
            .await
            .unwrap();
        assert_eq!(select_read(&mut session, "INBOX", 7).await.unwrap(), 7);
        assert!(body(&mut session, 2, 3).await.unwrap().is_none());
        assert_eq!(select_read(&mut session, "Archive", 9).await.unwrap(), 9);
        assert_eq!(status(&mut session, "Archive").await.unwrap(), (1, 2));
        assert_eq!(select_read(&mut session, "Archive", 9).await.unwrap(), 10);
    }

    #[tokio::test]
    async fn conflicting_select_generations_cannot_be_used_for_uid_reads() {
        let mut step = 0;
        let (mut session, _) = scripted_capabilities("IMAP4rev1", move |tag, command| {
            assert_eq!(command, "SELECT \"INBOX\"");
            let reply = match step {
                0 => format!("* OK [UIDVALIDITY 8] first\r\n{tag} OK [UIDVALIDITY 7] done\r\n"),
                1 => format!(
                    "* OK [CLOSED] old mailbox\r\n* NO [UIDVALIDITY 8] ignored\r\n\
                             * OK [UIDVALIDITY 7] first\r\n{tag} OK [UIDVALIDITY 7] done\r\n"
                ),
                _ => panic!("unexpected command: {command}"),
            };
            step += 1;
            reply.into_bytes()
        })
        .await;
        assert!(
            select_read(&mut session, "INBOX", 7)
                .await
                .unwrap_err()
                .is::<Said>()
        );
        assert_eq!(select_read(&mut session, "INBOX", 7).await.unwrap(), 7);
    }

    #[tokio::test]
    async fn fetch_handles_unsolicited_read_ahead_and_status_text_ending_in_braces() {
        let (mut session, _) = scripted(|tag, command| {
            match command {
                "SELECT \"INBOX\"" => {
                    format!("* OK [UIDVALIDITY 7] stable\r\n{tag} OK selected\r\n* 2 EXI")
                }
                c if c == format!("UID FETCH 1 (UID BODY.PEEK[]<0.{}>)", MAX_MESSAGE + 1) => {
                    format!(
                        "STS\r\n* OK progress {{1}}\r\n* 1 FETCH (UID 1 BODY[]<0> {{3}}\r\none)\r\n\
                         {tag} OK fetched {{1}}\r\n"
                    )
                }
                c if c == format!("UID FETCH 2 (UID BODY.PEEK[]<0.{}>)", MAX_MESSAGE + 1) => {
                    format!("{tag} NO unavailable {{1}}\r\n")
                }
                _ => panic!("unexpected command: {command}"),
            }
            .into_bytes()
        })
        .await;
        assert_eq!(select_read(&mut session, "INBOX", 7).await.unwrap(), 7);
        assert_eq!(
            body(&mut session, 1, 3).await.unwrap().as_deref(),
            Some(&b"one"[..])
        );
        assert!(body(&mut session, 2, 3).await.unwrap_err().is::<Said>());
    }

    #[tokio::test]
    async fn a_buffered_mailbox_change_prevents_the_next_uid_command() {
        for probe_size in [false, true] {
            let (sent, mut commands) = tokio::sync::mpsc::unbounded_channel();
            let (mut session, _) = scripted(move |tag, command| {
                sent.send(command.to_owned()).unwrap();
                let change = "* OK [UIDVALIDITY 8] rebuilt\r\n";
                match command {
                    "SELECT \"INBOX\"" => {
                        let tail = if probe_size { "" } else { change };
                        format!("* OK [UIDVALIDITY 7] stable\r\n{tag} OK selected\r\n{tail}")
                    }
                    "UID FETCH 1 (UID RFC822.SIZE)" if probe_size => {
                        format!("* 1 FETCH (UID 1 RFC822.SIZE 3)\r\n{tag} OK done\r\n{change}")
                    }
                    "SELECT \"Archive\"" => {
                        format!("* OK [UIDVALIDITY 9] stable\r\n{tag} OK selected\r\n")
                    }
                    _ => format!("{tag} OK done\r\n"),
                }
                .into_bytes()
            })
            .await;
            select_read(&mut session, "INBOX", 7).await.unwrap();
            let error = if probe_size {
                body(&mut session, 1, 0).await.unwrap_err()
            } else {
                set_flag(&mut session, &[1], FlagKind::Seen, true)
                    .await
                    .unwrap_err()
            };
            assert!(error.is::<Said>(), "{error:#}");
            assert_eq!(select_read(&mut session, "Archive", 9).await.unwrap(), 9);
            assert_eq!(commands.try_recv().unwrap(), "SELECT \"INBOX\"");
            if probe_size {
                assert_eq!(
                    commands.try_recv().unwrap(),
                    "UID FETCH 1 (UID RFC822.SIZE)"
                );
            }
            assert_eq!(commands.try_recv().unwrap(), "SELECT \"Archive\"");
        }
    }

    #[tokio::test]
    async fn quoted_body_sections_can_be_long_and_contain_parentheses() {
        const COMMAND: &str = "UID FETCH 1 (UID BODY.PEEK[1]<0.80000> BODY.PEEK[2]<0.4>)";
        let text = format!("{} \"quote\" \\", "(".repeat(70_000));
        let raw = text.replace('\\', "\\\\").replace('"', "\\\"");
        let (mut session, _) = scripted(move |tag, command| match command {
            "SELECT \"INBOX\"" => {
                format!("* OK [UIDVALIDITY 7] stable\r\n{tag} OK selected\r\n").into_bytes()
            }
            COMMAND => format!(
                "* 1 FETCH (UID 1 BODY[1]<0> \"{raw}\" BODY[2]<0> {{3}}\r\na\\b)\r\n{tag} OK done\r\n"
            )
            .into_bytes(),
            _ => panic!("unexpected command: {command}"),
        })
        .await;
        select_read(&mut session, "INBOX", 7).await.unwrap();
        let mut bodies = Vec::new();
        fetch_parts(&mut session, COMMAND, 96 << 10, false, |response, raw| {
            if let Response::Fetch(_, attrs) = response {
                for attr in attrs {
                    if let AttributeValue::BodySection {
                        data: Some(data), ..
                    } = attr
                    {
                        bodies.push(section_bytes(raw, data).into_owned());
                    }
                }
            }
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            bodies[0] == text.as_bytes(),
            "quoted body did not round-trip"
        );
        assert_eq!(bodies[1], b"a\\b");
    }

    #[tokio::test]
    async fn a_wide_body_structure_with_attachment_names_still_downloads() {
        const COMMAND: &str = "UID FETCH 1 (UID BODYSTRUCTURE)";
        let (mut session, _) = scripted(|tag, command| {
            match command {
                "SELECT \"INBOX\"" => {
                    format!("* OK [UIDVALIDITY 7] stable\r\n{tag} OK selected\r\n")
                }
                COMMAND => {
                    let name = format!("{}{}.bin", ")".repeat(64), "(".repeat(64));
                    let part = format!(
                        "(\"APPLICATION\" \"OCTET-STREAM\" (\"NAME\" {{{}}}\r\n{name}) \
                         NIL NIL \"BASE64\" 65536 NIL (\"ATTACHMENT\" (\"FILENAME\" \"file.bin\")))",
                        name.len(),
                    );
                    format!(
                        "* 1 FETCH (UID 1 BODYSTRUCTURE ({} \"MIXED\" (\"BOUNDARY\" \"many\")))\r\n\
                         {tag} OK fetched\r\n",
                        part.repeat(32),
                    )
                }
                _ => panic!("unexpected command: {command}"),
            }
            .into_bytes()
        })
        .await;
        select_read(&mut session, "INBOX", 7).await.unwrap();
        let mut structure = false;
        fetch_parts(&mut session, COMMAND, 32 << 10, true, |response, _| {
            if let Response::Fetch(_, attrs) = response {
                structure |= attrs
                    .iter()
                    .any(|a| matches!(a, AttributeValue::BodyStructure(_)));
            }
            Ok(())
        })
        .await
        .unwrap();
        assert!(structure);
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
