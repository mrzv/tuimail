//! Writing mail: the fields of a message being written, turned into a
//! MIME message to send (mail-builder), and the starting text of a reply
//! or a forward.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use mail_builder::MessageBuilder;
use mail_builder::headers::Header;
use mail_builder::headers::address::Address as BuilderAddress;
use mail_builder::headers::content_type::ContentType;
use mail_builder::mime::{BodyPart, MimePart};
use pulldown_cmark::{CodeBlockKind, Event, LinkType, Options, Parser, Tag, TagEnd, html};

use crate::account::{self, Account};
use crate::mail::{self, Addr, Parsed};
use crate::text;

/// The biggest attachment, and all of a message's together.
pub const MAX_ATTACHMENT: u64 = 40 << 20;
pub const MAX_TOTAL: u64 = 60 << 20;

// The parser builds a tree before yielding events; reference links can
// expand well beyond the source even with a small tree.
const MAX_MARKDOWN: usize = 256 << 10;
const MAX_MARKDOWN_HTML: usize = 2 << 20;
const MAX_MARKDOWN_DEPTH: usize = 128;

/// A file to send with the message.
#[derive(Clone, Debug, PartialEq)]
pub enum Attachment {
    /// A file on this computer, read when the message is built.
    File(PathBuf),
    /// Bytes already in hand: a forwarded message's attachments, or a
    /// draft's.
    Data {
        name: String,
        mime: String,
        bytes: Arc<Vec<u8>>,
    },
}

impl Attachment {
    /// A file on this computer, read now, once: what's sent, kept in Sent
    /// and shown is these bytes, whatever the path names later (another
    /// account that can change its folder can't swap the file before the
    /// send). Opened without waiting on a pipe, and only a plain file.
    pub fn snapshot(path: &std::path::Path) -> Result<Attachment> {
        use std::io::Read;
        let shown = crate::config::shown(path);
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = options
            .open(path)
            .with_context(|| format!("cannot read {shown}"))?;
        let meta = file
            .metadata()
            .with_context(|| format!("cannot read {shown}"))?;
        if !meta.is_file() {
            bail!("{shown} isn't a file");
        }
        if meta.len() > MAX_ATTACHMENT {
            bail!(
                "{shown} is too big to send ({})",
                mail::size(meta.len() as usize)
            );
        }
        let mut bytes = Vec::new();
        file.take(MAX_ATTACHMENT + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("cannot read {shown}"))?;
        if bytes.len() as u64 > MAX_ATTACHMENT {
            bail!("{shown} is too big to send");
        }
        let name = Attachment::File(path.to_path_buf()).name();
        Ok(Attachment::Data {
            mime: mime_of(&name).to_string(),
            name,
            bytes: Arc::new(bytes),
        })
    }

    pub fn name(&self) -> String {
        match self {
            Attachment::File(path) => mail::safe_file_name(
                &path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            ),
            Attachment::Data { name, .. } => name.clone(),
        }
    }

    pub fn size(&self) -> u64 {
        match self {
            Attachment::File(path) => std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
            Attachment::Data { bytes, .. } => bytes.len() as u64,
        }
    }

    /// The MIME part and the number of bytes before transfer encoding.
    fn part(&self) -> Result<(MimePart<'_>, usize)> {
        let (mime, name, bytes) = match self {
            Attachment::File(path) => {
                let shown = crate::config::shown(path);
                let meta =
                    std::fs::metadata(path).with_context(|| format!("cannot read {shown}"))?;
                if !meta.is_file() {
                    bail!("{shown} isn't a file");
                }
                if meta.len() > MAX_ATTACHMENT {
                    bail!(
                        "{shown} is too big to send ({})",
                        mail::size(meta.len() as usize)
                    );
                }
                let bytes = std::fs::read(path).with_context(|| format!("cannot read {shown}"))?;
                let name = self.name();
                (
                    Cow::Borrowed(mime_of(&name)),
                    Cow::Owned(name),
                    Cow::Owned(bytes),
                )
            }
            Attachment::Data { name, mime, bytes } => (
                Cow::Borrowed(mime.as_str()),
                Cow::Borrowed(name.as_str()),
                Cow::Borrowed(bytes.as_slice()),
            ),
        };
        let len = bytes.len();
        Ok((
            MimePart::new(ContentType::new(mime), BodyPart::Binary(bytes)).attachment(name),
            len,
        ))
    }
}

/// A file's type, by its extension.
pub fn mime_of(name: &str) -> &'static str {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "txt" | "md" | "log" | "csv" => "text/plain",
        "html" | "htm" => "text/html",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "svg" => "image/svg+xml",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        "json" => "application/json",
        "xml" => "application/xml",
        "ics" => "text/calendar",
        "eml" => "message/rfc822",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "odt" => "application/vnd.oasis.opendocument.text",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        _ => "application/octet-stream",
    }
}

/// A message being written: plain data, edited by the composer.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Draft {
    pub to: String,
    pub cc: String,
    pub bcc: String,
    pub subject: String,
    pub body: String,
    pub markdown: bool,
    pub in_reply_to: String,
    /// Ids separated by spaces.
    pub references: String,
    pub attachments: Vec<Attachment>,
}

impl Draft {
    /// A digest of everything the message says, to tell whether it changed
    /// between being shown and being sent.
    pub fn print(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for field in [
            &self.to,
            &self.cc,
            &self.bcc,
            &self.subject,
            &self.body,
            &self.in_reply_to,
            &self.references,
        ] {
            field.hash(&mut h);
        }
        self.markdown.hash(&mut h);
        for a in &self.attachments {
            match a {
                Attachment::File(path) => path.hash(&mut h),
                Attachment::Data { name, mime, bytes } => {
                    name.hash(&mut h);
                    mime.hash(&mut h);
                    bytes.hash(&mut h);
                }
            }
        }
        h.finish()
    }
}

/// A message ready to go.
pub struct Built {
    pub raw: Vec<u8>,
    /// The envelope: who it's from and every recipient (To, Cc and Bcc).
    pub from: String,
    pub rcpts: Vec<String>,
    /// Everyone it's to, for address completion later.
    pub to: Vec<Addr>,
}

/// Addresses as typed: "Name <addr>, addr; …". Each must be an address;
/// the first that isn't is the error.
pub fn parse_addresses(input: &str) -> Result<Vec<Addr>, String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut angle = false;
    let mut items = Vec::new();
    let mut escaped = false;
    for c in input.chars() {
        if escaped {
            escaped = false;
            current.push(c);
            continue;
        }
        match c {
            '\\' if quoted => {
                escaped = true;
                current.push(c);
            }
            // Only a name is quoted: a `"` in an address, between the
            // brackets, is part of it (and makes it invalid).
            '"' if !angle => {
                quoted = !quoted;
                current.push(c);
            }
            '<' if !quoted => {
                angle = true;
                current.push(c);
            }
            '>' if !quoted => {
                angle = false;
                current.push(c);
            }
            ',' | ';' | '\n' if !quoted && !angle => items.push(std::mem::take(&mut current)),
            c => current.push(c),
        }
    }
    items.push(current);
    for item in items {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (name, addr) = match (item.rfind('<'), item.rfind('>')) {
            (Some(open), Some(close)) if open < close => (
                unquote_name(item[..open].trim()),
                item[open + 1..close].trim(),
            ),
            _ => (String::new(), item),
        };
        if !account::valid_address(addr) {
            return Err(text::one_line(item, 80));
        }
        out.push(Addr {
            name: text::one_line(&name, mail::MAX_NAME),
            addr: addr.to_string(),
        });
    }
    Ok(out)
}

/// A name as written before an address: its quotes and `\` escapes taken
/// out.
fn unquote_name(name: &str) -> String {
    let Some(inner) = name.strip_prefix('"').and_then(|n| n.strip_suffix('"')) else {
        return name.to_string();
    };
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.extend(chars.next()),
            c => out.push(c),
        }
    }
    out.trim().to_string()
}

fn builder_list(addrs: &[Addr]) -> BuilderAddress<'_> {
    let list = addrs
        .iter()
        .map(|a| {
            if a.name.is_empty() {
                BuilderAddress::from(a.addr.as_str())
            } else {
                BuilderAddress::from((a.name.as_str(), a.addr.as_str()))
            }
        })
        .collect();
    BuilderAddress::new_list(list)
}

/// A new Message-ID at the sender's domain: random, so it says nothing
/// about this computer.
pub fn new_message_id(from: &str) -> Result<String> {
    let random = random_hex()?;
    let domain = from
        .rsplit_once('@')
        .map(|(_, d)| d)
        .filter(|d| account::valid_host(d))
        .unwrap_or("tuimail.invalid");
    Ok(format!("{random}@{domain}"))
}

/// 128 random bits as hex, from the system's generator. If it fails,
/// nothing is sent: an id or boundary that isn't random says something.
fn random_hex() -> Result<String> {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("the system's random numbers failed"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

struct Recipients {
    to: Vec<Addr>,
    cc: Vec<Addr>,
    bcc: Vec<Addr>,
}

impl Recipients {
    fn parse(draft: &Draft) -> Result<Self> {
        let field = |input: &str, what: &str| {
            parse_addresses(input)
                .map_err(|bad| anyhow::anyhow!("{what}: “{bad}” isn't an email address"))
        };
        Ok(Self {
            to: field(&draft.to, "To")?,
            cc: field(&draft.cc, "Cc")?,
            bcc: field(&draft.bcc, "Bcc")?,
        })
    }

    fn envelope(&self) -> Vec<String> {
        let mut rcpts: Vec<_> = self
            .to
            .iter()
            .chain(&self.cc)
            .chain(&self.bcc)
            .map(|a| (a.addr.to_lowercase(), &a.addr))
            .collect();
        rcpts.sort_by(|(a, _), (b, _)| a.cmp(b));
        rcpts.dedup_by(|(a, _), (b, _)| a == b);
        rcpts
            .into_iter()
            .map(|(_, address)| address.clone())
            .collect()
    }

    fn built(self, account: &Account, raw: Vec<u8>) -> Built {
        Built {
            raw,
            from: account.email.trim().to_owned(),
            rcpts: self.envelope(),
            to: self.to.into_iter().chain(self.cc).chain(self.bcc).collect(),
        }
    }
}

/// Validates the addresses and returns the deduplicated envelope recipients.
pub fn recipients(draft: &Draft) -> Result<Vec<String>> {
    Ok(Recipients::parse(draft)?.envelope())
}

/// Builds the message `draft` describes, from `account`, dated `date`. With
/// `keep_bcc` the Bcc header stays (the copy in Sent or Drafts); the one
/// sent never has it.
pub fn build(
    draft: &Draft,
    account: &Account,
    message_id: &str,
    date: i64,
    keep_bcc: bool,
) -> Result<Built> {
    let recipients = Recipients::parse(draft)?;
    let raw = build_message(draft, account, message_id, date, &recipients, keep_bcc)?;
    Ok(recipients.built(account, raw))
}

/// Builds the wire message and its Sent copy, serializing the body once.
pub fn build_for_send(
    draft: &Draft,
    account: &Account,
    message_id: &str,
    date: i64,
) -> Result<(Built, Vec<u8>)> {
    let recipients = Recipients::parse(draft)?;
    let raw = build_message(draft, account, message_id, date, &recipients, false)?;
    let mut saved = Vec::new();
    if !recipients.bcc.is_empty() {
        const PREFIX: &[u8] = b"Bcc: ";
        saved.extend_from_slice(PREFIX);
        builder_list(&recipients.bcc).write_header(&mut saved, PREFIX.len());
    }
    saved.reserve_exact(raw.len());
    saved.extend_from_slice(&raw);
    Ok((recipients.built(account, raw), saved))
}

fn build_message(
    draft: &Draft,
    account: &Account,
    message_id: &str,
    date: i64,
    recipients: &Recipients,
    keep_bcc: bool,
) -> Result<Vec<u8>> {
    let Recipients { to, cc, bcc } = recipients;
    let from_addr = account.email.trim();
    let from_name = text::one_line(&account.display_name, mail::MAX_NAME);
    let subject = text::one_line(&draft.subject, mail::MAX_SUBJECT);
    let mut builder = MessageBuilder::new()
        .message_id(message_id)
        .date(date)
        .subject(subject)
        .header(
            "User-Agent",
            mail_builder::headers::raw::Raw::new("tuimail"),
        );
    builder = if from_name.is_empty() {
        builder.from(BuilderAddress::from(from_addr))
    } else {
        builder.from(BuilderAddress::new_address(Some(from_name), from_addr))
    };
    if !to.is_empty() {
        builder = builder.to(builder_list(to));
    }
    if !cc.is_empty() {
        builder = builder.cc(builder_list(cc));
    }
    if keep_bcc && !bcc.is_empty() {
        builder = builder.bcc(builder_list(bcc));
    }
    if !draft.in_reply_to.is_empty() {
        builder = builder.in_reply_to(draft.in_reply_to.as_str());
    }
    let references: Vec<&str> = draft.references.split_whitespace().collect();
    if !references.is_empty() {
        builder = builder.references(references);
    }
    builder
        .body(message_body(draft)?)
        .write_to_vec()
        .context("cannot build the message")
}

fn message_body(draft: &Draft) -> Result<MimePart<'_>> {
    if draft.markdown && draft.body.len() > MAX_MARKDOWN {
        bail!("Markdown source is too large (over 256 KiB)");
    }
    let mut body = text::clean(&draft.body);
    // Keep the Markdown source as written; multipart adds its own line
    // break before the next boundary. Plain mail still ends with a break.
    if !draft.markdown && !body.ends_with('\n') {
        body.push('\n');
    }
    let body = if draft.markdown {
        let rendered = markdown_html(&body)?;
        let plain = ContentType::new("text/plain")
            .attribute("charset", "utf-8")
            .attribute("x-tuimail-format", "markdown");
        multipart(
            "multipart/alternative",
            vec![
                MimePart::new(plain, body.replace('\n', "\r\n")),
                MimePart::new("text/html", rendered),
            ],
        )?
    } else {
        MimePart::new("text/plain", body.replace('\n', "\r\n"))
    };
    if draft.attachments.is_empty() {
        return Ok(body);
    }
    let mut parts = Vec::with_capacity(draft.attachments.len() + 1);
    parts.push(body);
    let mut total = 0;
    for attachment in &draft.attachments {
        let (part, len) = attachment.part()?;
        total += len as u64;
        if total > MAX_TOTAL {
            bail!(
                "the attachments are too big together (over {})",
                mail::size(MAX_TOTAL as usize)
            );
        }
        parts.push(part);
    }
    multipart("multipart/mixed", parts)
}

fn multipart<'a>(kind: &'static str, parts: Vec<MimePart<'a>>) -> Result<MimePart<'a>> {
    // Mail-builder's own boundaries can tie together messages sent by
    // the same process, so use our own random boundary for each multipart.
    let mime = ContentType::new(kind).attribute("boundary", random_hex()?);
    Ok(MimePart::new(mime, parts))
}

fn markdown_html(source: &str) -> Result<String> {
    let mut depth = 0;
    let mut image_depth = 0;
    let mut blocked_link = false;
    let events = Parser::new_ext(source, Options::ENABLE_STRIKETHROUGH)
        .take_while(|event| {
            match event {
                Event::Start(_) => depth += 1,
                Event::End(_) => depth -= 1,
                _ => {}
            }
            depth <= MAX_MARKDOWN_DEPTH
        })
        .filter_map(|event| match event {
            Event::Start(Tag::Image { .. }) => {
                image_depth += 1;
                None
            }
            Event::End(TagEnd::Image) => {
                image_depth -= 1;
                None
            }
            event if image_depth != 0 => match event {
                Event::Html(text)
                | Event::InlineHtml(text)
                | Event::Code(text)
                | Event::Text(text) => Some(Event::Text(text)),
                Event::SoftBreak | Event::HardBreak => Some(Event::Text(" ".into())),
                _ => None,
            },
            Event::Start(Tag::HtmlBlock) => {
                Some(Event::Start(Tag::CodeBlock(CodeBlockKind::Indented)))
            }
            Event::End(TagEnd::HtmlBlock) => Some(Event::End(TagEnd::CodeBlock)),
            Event::Html(text) | Event::InlineHtml(text) => Some(Event::Text(text)),
            Event::Start(Tag::Link {
                link_type,
                mut dest_url,
                title,
                id,
            }) => {
                let email = link_type == LinkType::Email;
                blocked_link = if email {
                    !account::valid_address(&dest_url)
                } else {
                    !mail::usable_link(&dest_url)
                };
                if blocked_link {
                    return None;
                }
                if email {
                    // The renderer adds `mailto:`; the destination is a
                    // literal mailbox, not an already-encoded URI.
                    let escape = |b: u8| !b.is_ascii_alphanumeric() && !b"-._~@".contains(&b);
                    let escapes = dest_url.bytes().filter(|&b| escape(b)).count();
                    if escapes != 0 {
                        let mut encoded = String::with_capacity(dest_url.len() + 2 * escapes);
                        for b in dest_url.bytes() {
                            if escape(b) {
                                write!(encoded, "%{b:02X}").unwrap();
                            } else {
                                encoded.push(char::from(b));
                            }
                        }
                        dest_url = encoded.into();
                    }
                }
                Some(Event::Start(Tag::Link {
                    link_type,
                    dest_url,
                    title,
                    id,
                }))
            }
            Event::End(TagEnd::Link) if std::mem::take(&mut blocked_link) => None,
            _ => Some(event),
        });
    let mut html = HtmlOutput(String::new());
    html::write_html_fmt(&mut html, events)
        .map_err(|_| anyhow::anyhow!("formatted Markdown is too large (over 2 MiB)"))?;
    if depth > MAX_MARKDOWN_DEPTH {
        bail!("Markdown is nested too deeply");
    }
    Ok(html.0)
}

struct HtmlOutput(String);

impl std::fmt::Write for HtmlOutput {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        // CommonMark entities can decode to controls after source cleaning.
        for part in value.split_inclusive(|c| c == '\n' || text::is_hidden(c)) {
            let (text, newline) = match part.chars().next_back() {
                Some('\n') => (&part[..part.len() - 1], "\r\n"),
                Some(c) if text::is_hidden(c) => (&part[..part.len() - c.len_utf8()], ""),
                _ => (part, ""),
            };
            if self.0.len() + text.len() + newline.len() > MAX_MARKDOWN_HTML {
                return Err(std::fmt::Error);
            }
            self.0.push_str(text);
            self.0.push_str(newline);
        }
        Ok(())
    }
}

/// "Re: subject", without piling up Re:s.
pub fn reply_subject(subject: &str) -> String {
    let lower = subject.trim_start().to_lowercase();
    if lower.starts_with("re:") || lower.starts_with("aw:") || lower.starts_with("sv:") {
        subject.trim().to_string()
    } else {
        format!("Re: {}", subject.trim())
    }
}

pub fn forward_subject(subject: &str) -> String {
    let lower = subject.trim_start().to_lowercase();
    if lower.starts_with("fwd:") || lower.starts_with("fw:") {
        subject.trim().to_string()
    } else {
        format!("Fwd: {}", subject.trim())
    }
}

fn joined(addrs: &[Addr]) -> String {
    addrs
        .iter()
        .map(Addr::display)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The signature, after "-- ", if the account has one.
pub fn signature(account: &Account) -> String {
    let sig = account.signature.trim_end();
    if sig.is_empty() {
        String::new()
    } else {
        format!("\n\n-- \n{sig}\n")
    }
}

/// The text a reply or forward starts with: a line to write on, the
/// signature, then `rest`.
fn start_with(account: &Account, rest: &str) -> String {
    let sig = signature(account);
    let sig = sig.trim_start_matches('\n').trim_end();
    if sig.is_empty() {
        format!("\n\n{rest}")
    } else {
        format!("\n\n{sig}\n\n{rest}")
    }
}

/// A reply to `parsed`: to its Reply-To or sender; with `all`, also to its
/// other recipients, never to yourself.
pub fn reply(parsed: &Parsed, account: &Account, all: bool) -> Draft {
    let me = account.email.trim().to_lowercase();
    let not_me = |a: &&Addr| a.addr.to_lowercase() != me;
    // Only addresses mail can go to: a sender's `x"@y` is no recipient.
    let usable = |list: &[Addr]| -> Vec<Addr> {
        list.iter()
            .filter(|a| account::valid_address(&a.addr))
            .cloned()
            .collect()
    };
    let mut to = usable(if parsed.reply_to.is_empty() {
        &parsed.from
    } else {
        &parsed.reply_to
    });
    // Replying to your own message goes to whom it was to; to a sender
    // with no address mail can go to, to nobody.
    let mine = !to.is_empty() && to.iter().all(|a| a.addr.to_lowercase() == me);
    if mine && !parsed.to.is_empty() {
        to = usable(&parsed.to);
    }
    let mut cc = Vec::new();
    if all {
        for a in usable(&parsed.to)
            .iter()
            .chain(&usable(&parsed.cc))
            .filter(not_me)
        {
            let known = |list: &[Addr]| list.iter().any(|b| b.addr.eq_ignore_ascii_case(&a.addr));
            if !known(&to) && !known(&cc) {
                cc.push(a.clone());
            }
        }
    }
    let s = &parsed.summary;
    let mut references: Vec<&str> = s.references.split_whitespace().collect();
    if !s.message_id.is_empty() && !references.contains(&s.message_id.as_str()) {
        references.push(&s.message_id);
    }
    let when = mail::long_date(s.date);
    let who = s.from.display();
    let intro = if when.is_empty() {
        format!("{who} wrote:")
    } else {
        format!("On {when}, {who} wrote:")
    };
    let quoted = mail::quote(&mail::plain_text(parsed));
    Draft {
        to: joined(&to),
        cc: joined(&cc),
        subject: reply_subject(&s.subject),
        body: start_with(account, &format!("{intro}\n{quoted}")),
        in_reply_to: s.message_id.clone(),
        references: references.join(" "),
        ..Draft::default()
    }
}

/// A forward of `parsed`, with its text below and its attachments attached
/// again: `files`, as [`mail::parse_with_contents`] took them out (`None` for
/// one that couldn't be read, which the app says).
pub fn forward(parsed: &Parsed, files: Vec<Option<mail::File>>, account: &Account) -> Draft {
    let s = &parsed.summary;
    let mut header = String::from("---------- Forwarded message ----------\n");
    header.push_str(&format!("From: {}\n", s.from.display()));
    let when = mail::long_date(s.date);
    if !when.is_empty() {
        header.push_str(&format!("Date: {when}\n"));
    }
    header.push_str(&format!("Subject: {}\n", s.subject));
    if !s.to.is_empty() {
        header.push_str(&format!("To: {}\n", s.to));
    }
    if !s.cc.is_empty() {
        header.push_str(&format!("Cc: {}\n", s.cc));
    }
    let attachments = loaded_files(files);
    Draft {
        subject: forward_subject(&s.subject),
        body: start_with(
            account,
            &format!("{header}\n{}", mail::plain_text(parsed).trim_end()),
        ),
        attachments,
        ..Draft::default()
    }
}

fn loaded_files(files: Vec<Option<mail::File>>) -> Vec<Attachment> {
    files
        .into_iter()
        .flatten()
        .map(|file| Attachment::Data {
            name: file.name,
            mime: file.mime,
            bytes: Arc::new(file.bytes),
        })
        .collect()
}

/// A draft saved earlier, to write on: its fields, text and attachments.
pub fn from_saved(parsed: &Parsed, contents: mail::Contents) -> Draft {
    Draft {
        to: joined(&parsed.to),
        cc: joined(&parsed.cc),
        bcc: joined(&contents.bcc),
        subject: parsed.summary.subject.clone(),
        // A draft written as HTML only would otherwise lose its text.
        body: match &parsed.text {
            Some(t) => text::clean(t),
            None => mail::plain_text(parsed),
        },
        markdown: contents.markdown,
        in_reply_to: parsed.summary.in_reply_to.clone(),
        references: parsed.summary.references.clone(),
        attachments: loaded_files(contents.files),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> Account {
        Account {
            email: "me@example.org".into(),
            display_name: "Sam Taylor".into(),
            signature: "Sam".into(),
            ..Account::default()
        }
    }

    #[test]
    fn an_attached_file_is_the_one_read_when_attached() {
        let dir = std::env::temp_dir().join(format!("tuimail-attach-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let report = dir.join("report.pdf");
        std::fs::write(&report, b"REPORT").unwrap();
        let attached = Attachment::snapshot(&report).unwrap();
        // The file changes, or becomes something else, before the send.
        std::fs::write(&report, b"DUMMY-SECRET").unwrap();
        let draft = Draft {
            to: "x@y.z".into(),
            attachments: vec![attached],
            ..Draft::default()
        };
        let id = new_message_id("me@example.org").unwrap();
        let built = build(&draft, &me(), &id, 0, false).unwrap();
        mail::attachments(&built.raw, [(0, "report.pdf")], |name, bytes| {
            assert_eq!((name, bytes), ("report.pdf", &b"REPORT"[..]));
            Ok(())
        })
        .unwrap();
        // Not a plain file: refused, without waiting.
        assert!(Attachment::snapshot(&dir).is_err());
        #[cfg(unix)]
        {
            let fifo = dir.join("pipe");
            let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
            // SAFETY: a valid C string path and mode.
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            assert!(Attachment::snapshot(&fifo).is_err());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sent_mail_has_nothing_that_links_two_accounts() {
        let draft = |email: &str| {
            let account = Account {
                email: email.into(),
                ..Account::default()
            };
            let draft = Draft {
                to: "x@example.com".into(),
                attachments: vec![Attachment::Data {
                    name: "a.txt".into(),
                    mime: "text/plain".into(),
                    bytes: Arc::new(b"x".to_vec()),
                }],
                ..Draft::default()
            };
            let id = new_message_id(email).unwrap();
            let raw = build(&draft, &account, &id, 1_791_715_320, false)
                .unwrap()
                .raw;
            let raw = String::from_utf8(raw).unwrap();
            let at = raw.find("boundary=\"").unwrap() + 10;
            raw[at..at + raw[at..].find('"').unwrap()].to_string()
        };
        let (a, b) = (draft("a@work.example"), draft("b@persona.example"));
        assert_eq!(a.len(), 32, "{a}");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()), "{a}");
        assert_ne!(a, b);
        assert!(!a.contains('_') && !b.contains('_'), "{a} {b}");
    }

    #[test]
    fn a_quote_in_an_address_never_turns_a_name_into_a_recipient() {
        let raw = [
            "From: Mallory <m@evil.example>",
            "To: me@example.org",
            r#"Cc: <x"@a.example>, "a <evil@evil.example>, b" <ap@corp.example>"#,
            "Subject: s",
            "Message-ID: <1@evil.example>",
            "",
            "hi",
            "",
        ]
        .join("\r\n");
        let parsed = mail::parse(raw.as_bytes()).unwrap();
        let d = reply(&parsed, &me(), true);
        let b = build(&d, &me(), "id@example.org", 0, false).unwrap();
        assert!(
            !b.rcpts.iter().any(|r| r == "evil@evil.example"),
            "{:?}",
            b.rcpts
        );
        assert!(
            b.rcpts.iter().any(|r| r == "ap@corp.example"),
            "{:?}",
            b.rcpts
        );

        let raw = [
            "From: Mallory <m@evil.example>",
            "To: me@example.org",
            r#"Cc: <o"brien@partner.example>, Bob <bob@corp.example>, Carol <carol@corp.example>"#,
            "Subject: s",
            "",
            "hi",
            "",
        ]
        .join("\r\n");
        let parsed = mail::parse(raw.as_bytes()).unwrap();
        let d = reply(&parsed, &me(), true);
        let b = build(&d, &me(), "id@example.org", 0, false).unwrap();
        assert!(
            b.rcpts.iter().any(|r| r == "bob@corp.example"),
            "{:?}",
            b.rcpts
        );
        assert!(
            b.rcpts.iter().any(|r| r == "carol@corp.example"),
            "{:?}",
            b.rcpts
        );

        // A sender with no usable address: the reply goes to nobody, not
        // to everyone it was to.
        let raw = [
            r#"From: "Boss" <boss"@corp.example>"#,
            "To: everyone@corp.example, me@example.org",
            "Subject: s",
            "",
            "hi",
            "",
        ]
        .join("\r\n");
        let parsed = mail::parse(raw.as_bytes()).unwrap();
        assert_eq!(reply(&parsed, &me(), false).to, "");

        // Typed or completed: a quote between brackets quotes nothing, and
        // the address is refused rather than another one taken.
        let typed = format!(
            "{}, {}",
            Addr {
                name: "".into(),
                addr: "x\"@a.example".into()
            }
            .display(),
            Addr {
                name: "a <evil@evil.example>, b".into(),
                addr: "ap@corp.example".into()
            }
            .display()
        );
        assert!(parse_addresses(&typed).is_err(), "{typed}");
    }

    #[test]
    fn addresses_are_read_as_people_type_them() {
        let list =
            parse_addresses("Alice <alice@example.com>, bob@example.org; \"Doe, Jane\" <jane@x.y>")
                .unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].name, "Alice");
        assert_eq!(list[1].addr, "bob@example.org");
        assert_eq!(list[2].name, "Doe, Jane");
        assert_eq!(parse_addresses("  ").unwrap(), []);
        // Names come back as they were, however odd, and never as more
        // addresses.
        for name in [
            "Doe, John",
            "evil@x.org, Boss",
            "a \"quoted\" \\ name",
            "<x@y.z>",
        ] {
            let a = Addr {
                name: name.into(),
                addr: "bob@corp.example".into(),
            };
            let back = parse_addresses(&format!("{}, c@d.e", a.display())).unwrap();
            assert_eq!(back.len(), 2, "{name}");
            assert_eq!(back[0], a, "{name}");
        }
        assert_eq!(parse_addresses("alice, bob@x.y").unwrap_err(), "alice");
        assert!(parse_addresses("a@b.c>\r\nBcc: evil@x.y").is_err());
    }

    #[test]
    fn a_built_message_reads_back_and_keeps_bcc_out_of_what_is_sent() {
        let draft = Draft {
            to: "Alice <alice@example.com>".into(),
            cc: "carol@example.net".into(),
            bcc: "boss@example.org".into(),
            subject: "Lunch? 🍜".into(),
            body: "Hi Alice,\n\nnoon?\n".into(),
            markdown: false,
            in_reply_to: "abc@example.com".into(),
            references: "first@x.y abc@example.com".into(),
            attachments: vec![Attachment::Data {
                name: "menu.txt".into(),
                mime: "text/plain".into(),
                bytes: Arc::new(b"soup".to_vec()),
            }],
        };
        let id = new_message_id("me@example.org").unwrap();
        assert!(id.ends_with("@example.org") && id.len() > 40);
        let built = build(&draft, &me(), &id, 1_791_715_320, false).unwrap();
        assert_eq!(built.from, "me@example.org");
        assert_eq!(
            built.rcpts,
            ["alice@example.com", "boss@example.org", "carol@example.net"]
        );
        let text = String::from_utf8_lossy(&built.raw);
        assert!(!text.contains("boss@example.org"), "no Bcc in what's sent");
        assert!(
            text.contains("Date: Sun, 11 Oct 2026 10:42:00 +0000"),
            "UTC: {text}"
        );
        assert!(!text.to_lowercase().contains("x-mailer"));
        let parsed = mail::parse(&built.raw).unwrap();
        assert_eq!(parsed.summary.subject, "Lunch? 🍜");
        assert_eq!(parsed.summary.message_id, id);
        assert_eq!(parsed.summary.in_reply_to, "abc@example.com");
        assert_eq!(parsed.summary.references, "first@x.y abc@example.com");
        assert_eq!(parsed.from[0].name, "Sam Taylor");
        assert!(parsed.text.unwrap().contains("noon?"));
        assert_eq!(parsed.attachments[0].name, "menu.txt");
        let kept = build(&draft, &me(), &id, 1_791_715_320, true).unwrap();
        assert!(String::from_utf8_lossy(&kept.raw).contains("boss@example.org"));
        let bad = Draft {
            to: "not an address".into(),
            ..Draft::default()
        };
        assert!(build(&bad, &me(), &id, 0, false).is_err());
    }

    #[test]
    fn markdown_is_opt_in_and_only_safe_markup_is_rendered() {
        let mut draft = Draft {
            body: [
                "# Plans",
                "",
                "**Bold**, _emphasis_, ~~gone~~, and <b>literal</b>.",
                "",
                "> A quote with `code`",
                "",
                "- A list",
                "",
                r#"<script>alert("not HTML")</script>"#,
                "",
                "[Web](https://example.org/?a=1&b=2) and <alice@example.org>.",
                "<sales%2Bops?#&+@example.org>.",
                "",
                "[script](jav&#x61;script:bad), [local](file:///tmp/secret),",
                "[relative](/tmp/secret), and [data](data:text/html,evil).",
                "",
                "![*local picture*](file:///tmp/secret) and ![remote `picture`](https://example.org/tracking).",
                "",
                "Escaped controls: a&#13;b&#27;c&#x202e;d.",
            ]
            .join("\n"),
            ..Draft::default()
        };
        let build = |draft: &Draft| build(draft, &me(), "id@example.org", 0, false).unwrap();
        let plain = build(&draft);
        let (parsed, contents) = mail::parse_with_contents(&plain.raw).unwrap();
        assert!(parsed.html.is_none());
        assert!(!contents.markdown);
        draft.markdown = true;
        let formatted = build(&draft);
        let (parsed, contents) = mail::parse_with_contents(&formatted.raw).unwrap();
        assert!(contents.markdown);
        let html = parsed.html.as_ref().unwrap();
        for rendered in [
            "<h1>Plans</h1>",
            "<strong>Bold</strong>",
            "<em>emphasis</em>",
            "<del>gone</del>",
            "<blockquote>",
            "<code>code</code>",
            "<li>A list</li>",
            "&lt;b",
            "&lt;script",
            "href=\"https://example.org/?a=1&amp;b=2\"",
            "href=\"mailto:alice@example.org\"",
            "href=\"mailto:sales%252Bops%3F%23%26%2B@example.org\">sales%2Bops?#&amp;+@example.org</a>",
            "local picture and remote picture",
            "Escaped controls: abcd.",
        ] {
            assert!(html.contains(rendered), "{rendered} missing from {html}");
        }
        for excluded in [
            "<b>",
            "<script",
            "javascript:",
            "file:",
            "data:",
            "/tmp/",
            "<img",
            "/tracking",
        ] {
            assert!(!html.contains(excluded), "{excluded} found in {html}");
        }
        assert_eq!(from_saved(&parsed, contents).body, draft.body);
    }

    #[test]
    fn markdown_attachments_and_bcc_round_trip_through_the_right_copies() {
        let draft = Draft {
            to: "Alice <alice@example.com>".into(),
            cc: "ALICE@example.com".into(),
            bcc: "\"Doe, Jane\" <jane@example.org>".into(),
            body: "**Table for two?** 🍜  \n\n> Soon.".into(),
            markdown: true,
            attachments: vec![Attachment::Data {
                name: "menu.txt".into(),
                mime: "text/plain".into(),
                bytes: Arc::new(b"soup".to_vec()),
            }],
            ..Draft::default()
        };
        let (sent, copy) = build_for_send(&draft, &me(), "id@example.org", 0).unwrap();
        assert!(
            copy.ends_with(&sent.raw),
            "the wire message and Sent copy share their MIME"
        );
        assert_eq!(recipients(&draft).unwrap(), sent.rcpts);
        assert_eq!(sent.rcpts, ["alice@example.com", "jane@example.org"]);
        let (parsed, contents) = mail::parse_with_contents(&sent.raw).unwrap();
        assert!(contents.bcc.is_empty());
        assert!(
            parsed
                .html
                .unwrap()
                .contains("<strong>Table for two?</strong>")
        );
        for raw in [
            copy,
            build(&draft, &me(), "id@example.org", 0, true).unwrap().raw,
        ] {
            let encoded = String::from_utf8(raw).unwrap();
            assert!(encoded.contains("multipart/mixed"));
            assert!(encoded.contains("multipart/alternative"));
            assert_eq!(encoded.matches("boundary=\"").count(), 2);
            let (parsed, contents) = mail::parse_with_contents(encoded.as_bytes()).unwrap();
            assert_eq!(from_saved(&parsed, contents), draft);
        }
    }

    #[test]
    fn oversized_and_deeply_nested_markdown_is_not_silently_truncated() {
        let draft = Draft {
            body: "x".repeat(MAX_MARKDOWN + 1),
            markdown: true,
            ..Draft::default()
        };
        let Err(error) = build(&draft, &me(), "id@example.org", 0, true) else {
            panic!("oversized Markdown accepted");
        };
        assert!(error.to_string().contains("source is too large"));
        let quotes = format!("{}quote", "> ".repeat(MAX_MARKDOWN_DEPTH + 1));
        assert!(
            markdown_html(&quotes)
                .unwrap_err()
                .to_string()
                .contains("nested")
        );
        // Each empty block quote renders more than eight times its source length.
        let repeats = ">\n\n".repeat(MAX_MARKDOWN / 3);
        assert!(
            markdown_html(&repeats)
                .unwrap_err()
                .to_string()
                .contains("formatted Markdown is too large")
        );
    }

    #[test]
    fn replies_go_to_the_right_people_and_quote_the_message() {
        let raw = b"From: Alice <alice@example.com>\r\nTo: me@example.org, bob@example.com\r\n\
Cc: Carol <carol@example.net>, ME@example.org\r\nSubject: Re: Plans\r\n\
Message-ID: <m2@example.com>\r\nReferences: <m1@example.com>\r\n\
Date: Sat, 11 Oct 2026 10:42:00 +0000\r\n\r\nSee you there.\r\n";
        let parsed = mail::parse(raw).unwrap();
        let one = reply(&parsed, &me(), false);
        assert_eq!(one.to, "Alice <alice@example.com>");
        assert_eq!(one.cc, "");
        assert_eq!(one.subject, "Re: Plans", "no Re: Re:");
        assert_eq!(one.in_reply_to, "m2@example.com");
        assert_eq!(one.references, "m1@example.com m2@example.com");
        assert!(
            one.body.contains("wrote:\n> See you there."),
            "{}",
            one.body
        );
        assert!(
            one.body.starts_with("\n\n-- \nSam\n\nOn "),
            "the signature first: {:?}",
            one.body
        );
        let all = reply(&parsed, &me(), true);
        assert_eq!(
            all.cc, "bob@example.com, Carol <carol@example.net>",
            "never me"
        );

        let (parsed, contents) = mail::parse_with_contents(raw).unwrap();
        let fwd = forward(&parsed, contents.files, &me());
        assert_eq!(fwd.subject, "Fwd: Re: Plans");
        assert!(fwd.body.contains("From: Alice <alice@example.com>"));
        assert!(fwd.body.contains("See you there."));
        assert!(fwd.to.is_empty());
    }

    #[test]
    fn types_come_from_extensions() {
        assert_eq!(mime_of("Report.PDF"), "application/pdf");
        assert_eq!(mime_of("noext"), "application/octet-stream");
    }
}
