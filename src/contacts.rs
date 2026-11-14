//! Read-only Google CardDAV using an account's existing app password.
//! Google documents OAuth authentication; app-password access can be refused
//! independently of an otherwise working mail login.
//! Nothing is written remotely. A complete batch and its token are returned
//! together; the caller commits them atomically, keeping its cache on any error.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use quick_xml::{events::Event, name::ResolveResult, reader::NsReader};
use reqwest::{Client, Method, StatusCode, Url, redirect::Policy};
use serde::{Deserialize, Serialize};

use crate::{account, mail, net, secrets::Secret, text};

const DISCOVERY: &str = "https://www.googleapis.com/.well-known/carddav";
const REDISCOVER_AFTER: i64 = 14 * 24 * 60 * 60;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const SYNC_TIMEOUT: Duration = Duration::from_secs(240);
const MAX_RESPONSE: usize = 32 * 1024 * 1024;
const MAX_RECEIVED: usize = 128 * 1024 * 1024;
const MAX_KEPT_VCARDS: usize = 64 * 1024 * 1024;
const MAX_REQUESTS: usize = 768;
const MAX_REDIRECTS: usize = 5;
const MAX_PAGES: usize = 128;
const MULTIGET_SIZE: usize = 100;
const MAX_URL: usize = 4096;
const MAX_TOKEN: usize = 4096;
const MAX_ETAG: usize = 1024;
const MAX_VALUES: usize = 64;
const MAX_VCARD_HEADER: usize = 8192;
pub const MAX_CONTACTS: usize = 50_000;
pub const MAX_VCARD: usize = 1024 * 1024;

const DISCOVER_PROPS: &str =
    "<d:current-user-principal/><d:principal-URL/><c:addressbook-home-set/><d:resourcetype/>";
const LIST_PROPS: &str = "<d:getetag/><d:resourcetype/>";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contact {
    pub id: String,
    pub name: String,
    pub emails: Vec<String>,
    pub phones: Vec<String>,
    pub organization: String,
    pub etag: String,
    // Kept for fidelity, never returned to an agent or a CLI JSON consumer.
    #[serde(skip_serializing)]
    pub vcard: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncState {
    pub address_book: String,
    pub sync_token: String,
    pub discovered_at: i64,
}

#[derive(Clone, Debug)]
pub struct SyncBatch {
    pub state: SyncState,
    pub full: bool,
    pub contacts: Vec<Contact>,
    pub deleted: Vec<String>,
}

/// Synchronize personal contacts using this Google account's app password.
/// A refusal must not invalidate the account's otherwise working mail login.
pub async fn sync_google(
    email: &str,
    password: &Secret,
    state: Option<SyncState>,
) -> Result<SyncBatch> {
    net::check_login(email, password.expose())?;
    ensure!(
        account::valid_address(email),
        "Invalid Google contacts email address"
    );
    ensure!(
        !password.expose().is_empty(),
        "A Google app password is required for contacts"
    );
    let client = Client::builder()
        .use_preconfigured_tls((*net::tls_config(None)?).clone())
        .https_only(true)
        .redirect(Policy::none())
        .referer(false)
        .connect_timeout(net::CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .user_agent(concat!("tuimail/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("Could not initialize Google contacts HTTPS")?;
    let discovery = Url::parse(DISCOVERY)?;
    let mut dav = Dav {
        client,
        origin: discovery.clone(),
        email,
        password,
        requests: 0,
        received: 0,
    };
    tokio::time::timeout(SYNC_TIMEOUT, dav.sync(discovery, state))
        .await
        .context("Google contacts sync timed out; cached contacts were kept")?
}

struct Dav<'a> {
    client: Client,
    origin: Url,
    email: &'a str,
    password: &'a Secret,
    requests: usize,
    received: usize,
}

struct Reply {
    url: Url,
    status: StatusCode,
    body: String,
}

#[derive(Debug)]
struct BookMoved;

impl std::fmt::Display for BookMoved {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Google contacts address book moved or is unavailable; rediscovery is required")
    }
}

impl std::error::Error for BookMoved {}

impl Reply {
    fn multistatus(self) -> Result<(Url, MultiStatus)> {
        if matches!(self.status.as_u16(), 404 | 410) {
            bail!(BookMoved);
        }
        require_multistatus(self.status)?;
        Ok((self.url, parse_multistatus(&self.body)?))
    }
}

fn require_multistatus(status: StatusCode) -> Result<()> {
    if matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        bail!(
            "Google rejected CardDAV app-password access (HTTP {}). \
             Cached contacts were kept; the mail login was not changed",
            status.as_u16()
        );
    }
    ensure!(
        status == StatusCode::MULTI_STATUS,
        "Google contacts request failed (HTTP {}); cached contacts were kept",
        status.as_u16()
    );
    Ok(())
}

impl Dav<'_> {
    /// Validate every URL before adding authentication, including redirects,
    /// discovered properties, cached state, and individual resource hrefs.
    fn resolve(&self, base: &Url, href: &str) -> Result<Url> {
        let href = href.trim();
        ensure!(
            !href.is_empty()
                && href.len() <= MAX_URL
                && !href.chars().any(|c| c.is_control() || c.is_whitespace())
                && !href.contains('\\'),
            "Google contacts returned an invalid resource URL"
        );
        let url = base
            .join(href)
            .context("Invalid Google contacts resource URL")?;
        ensure!(
            url.origin() == self.origin.origin()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "Google contacts tried to leave its trusted HTTPS origin"
        );
        Ok(url)
    }

    fn resource(&self, book: &Url, base: &Url, href: &str) -> Result<Url> {
        let url = self.resolve(base, href)?;
        let prefix = format!("{}/", book.path().trim_end_matches('/'));
        ensure!(
            url.path().starts_with(&prefix) && url.path().len() > prefix.len(),
            "Google contacts returned a resource outside its address book"
        );
        Ok(url)
    }

    async fn request(&mut self, method: Method, url: &Url, depth: u8, body: &str) -> Result<Reply> {
        let mut url = self.resolve(&self.origin, url.as_str())?;
        for redirect in 0..=MAX_REDIRECTS {
            self.requests += 1;
            ensure!(
                self.requests <= MAX_REQUESTS,
                "Google contacts exceeded the request limit"
            );
            let mut response = self
                .client
                .request(method.clone(), url.clone())
                .basic_auth(self.email, Some(self.password.expose()))
                .header("Depth", depth.to_string())
                .header("Content-Type", "application/xml; charset=utf-8")
                .header("Accept", "application/xml, text/xml")
                .body(body.to_owned())
                .send()
                .await
                .map_err(|error| error.without_url())
                .context("Could not contact Google CardDAV")?;
            let status = response.status();
            if status == StatusCode::UNAUTHORIZED {
                // The authentication diagnosis does not depend on an error
                // page's encoding, contents, or willingness to finish sending.
                return Ok(Reply {
                    url,
                    status,
                    body: String::new(),
                });
            }
            if matches!(status.as_u16(), 301 | 302 | 307 | 308) {
                ensure!(
                    redirect < MAX_REDIRECTS,
                    "Google contacts redirected too many times"
                );
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .context("Google contacts redirect has no location")?
                    .to_str()
                    .context("Google contacts redirect has an invalid location")?;
                url = self.resolve(&url, location)?;
                continue;
            }
            ensure!(
                response
                    .content_length()
                    .is_none_or(|n| n <= MAX_RESPONSE as u64),
                "Google contacts response is too large"
            );
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|error| error.without_url())
                .context("Could not finish reading Google contacts")?
            {
                self.received = self.received.saturating_add(chunk.len());
                ensure!(
                    bytes.len().saturating_add(chunk.len()) <= MAX_RESPONSE
                        && self.received <= MAX_RECEIVED,
                    "Google contacts exceeded the download size limit"
                );
                bytes.extend_from_slice(&chunk);
            }
            let body = if status == StatusCode::FORBIDDEN {
                // A DAV valid-sync-token error is the one 403 that can be
                // recovered by a full sync. An arbitrary error page is not.
                String::from_utf8(bytes).unwrap_or_default()
            } else {
                String::from_utf8(bytes).context("Google contacts returned non-UTF-8 XML")?
            };
            return Ok(Reply { url, status, body });
        }
        unreachable!("redirect limit is checked before continuing")
    }

    async fn propfind(&mut self, url: &Url, depth: u8, props: &str) -> Result<(Url, MultiStatus)> {
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:propfind xmlns:d=\"DAV:\" \
             xmlns:c=\"urn:ietf:params:xml:ns:carddav\"><d:prop>{props}</d:prop></d:propfind>"
        );
        let reply = self
            .request(Method::from_bytes(b"PROPFIND")?, url, depth, &body)
            .await?;
        reply.multistatus()
    }

    fn own_response<'a>(&self, url: &Url, response: &'a MultiStatus) -> Result<&'a DavResponse> {
        let mut found = None;
        for item in &response.responses {
            let href = self.resolve(url, &item.href)?;
            if same_collection(&href, url) {
                ensure!(
                    found.is_none(),
                    "Google contacts repeated a collection response"
                );
                found = Some(item);
            }
        }
        let found = found.context("Google contacts omitted the requested collection")?;
        if matches!(found.status, Some(404 | 410)) {
            bail!(BookMoved);
        }
        found.success()?;
        Ok(found)
    }

    async fn discover(&mut self, discovery: &Url) -> Result<Url> {
        let (mut url, mut response) = self.propfind(discovery, 0, DISCOVER_PROPS).await?;
        // A server may redirect the well-known URL straight to the address book.
        // Otherwise find its home set, following the principal once if needed.
        for step in 0..2 {
            let item = self.own_response(&url, &response)?;
            if item.is_type(Ns::Card, "addressbook")? {
                return Ok(url);
            }
            if let Some(home) = item.href_property(Ns::Card, "addressbook-home-set")? {
                let home = self.resolve(&url, home)?;
                let (base, listed) = self.propfind(&home, 1, "<d:resourcetype/>").await?;
                let mut books = Vec::new();
                for item in &listed.responses {
                    item.success()?;
                    ensure!(
                        item.property(Ns::Dav, "resourcetype")?.is_some(),
                        "Google contacts omitted a discovered resource type"
                    );
                    let href = self.resolve(&base, &item.href)?;
                    if item.is_type(Ns::Card, "addressbook")? {
                        books.push(href);
                    }
                }
                ensure!(
                    books.len() == 1,
                    "Google contacts did not expose exactly one personal address book"
                );
                return Ok(books.remove(0));
            }
            ensure!(
                step == 0,
                "Google contacts did not expose an address-book home set"
            );
            let principal = item
                .href_property(Ns::Dav, "current-user-principal")?
                .or(item.href_property(Ns::Dav, "principal-URL")?)
                .context("Google contacts did not expose a principal")?;
            let principal = self.resolve(&url, principal)?;
            (url, response) = self.propfind(&principal, 0, DISCOVER_PROPS).await?;
        }
        bail!("Google contacts discovery was incomplete")
    }

    async fn sync(&mut self, discovery: Url, previous: Option<SyncState>) -> Result<SyncBatch> {
        let now = chrono::Utc::now().timestamp();
        let mut state = previous;
        if let Some(known) = &state {
            self.resolve(&discovery, &known.address_book)?;
            if !known.sync_token.is_empty() {
                checked_token(&known.sync_token)?;
            }
        }
        let rediscover = state.as_ref().is_none_or(|known| {
            known.discovered_at > now || now.saturating_sub(known.discovered_at) >= REDISCOVER_AFTER
        });
        if rediscover {
            let book = self.discover(&discovery).await?;
            let same = state.as_ref().is_some_and(|known| {
                self.resolve(&discovery, &known.address_book)
                    .is_ok_and(|old| same_collection(&old, &book))
            });
            state = Some(SyncState {
                address_book: book.to_string(),
                sync_token: if same {
                    state.as_ref().unwrap().sync_token.clone()
                } else {
                    String::new()
                },
                discovered_at: now,
            });
        }
        let state = state.context("Google contacts discovery was incomplete")?;
        match self.sync_book(state).await {
            Err(error) if error.is::<BookMoved>() => {
                // Discovery paths must not be permanently cached. If a book
                // moves before the periodic refresh, retry discovery once now.
                let book = self.discover(&discovery).await?;
                self.sync_book(SyncState {
                    address_book: book.to_string(),
                    sync_token: String::new(),
                    discovered_at: now,
                })
                .await
            }
            result => result,
        }
    }

    async fn sync_book(&mut self, mut state: SyncState) -> Result<SyncBatch> {
        let book = self.resolve(&self.origin, &state.address_book)?;
        if !state.sync_token.is_empty()
            && let Some((token, changes)) = self.changes(&book, &state.sync_token).await?
        {
            let (contacts, deleted) = self.fetch(&book, changes).await?;
            state.sync_token = token;
            return Ok(SyncBatch {
                state,
                full: false,
                contacts,
                deleted,
            });
        }

        // Read the token BEFORE the full listing. A write during this fetch
        // will consequently be returned again by the next incremental sync.
        let (base, token_reply) = self.propfind(&book, 0, "<d:sync-token/>").await?;
        ensure!(same_collection(&base, &book), BookMoved);
        let token = self
            .own_response(&base, &token_reply)?
            .text_property(Ns::Dav, "sync-token")?
            .context("Google contacts did not provide a sync token")?;
        state.sync_token = checked_token(token)?.to_owned();
        let (base, listed) = self.propfind(&book, 1, LIST_PROPS).await?;
        ensure!(same_collection(&base, &book), BookMoved);
        let collection = self.own_response(&base, &listed)?;
        ensure!(
            collection.is_type(Ns::Dav, "collection")?,
            "Google contacts returned an incomplete address book"
        );
        let mut changes = BTreeMap::new();
        for item in listed.responses {
            let href = self.resolve(&base, &item.href)?;
            if same_collection(&href, &book) {
                continue;
            }
            let href = self.resource(&book, &base, &item.href)?.to_string();
            item.success()?;
            let etag = item.etag()?.to_owned();
            ensure!(
                changes.insert(href, Some(etag)).is_none(),
                "Google contacts repeated a contact"
            );
            ensure!(
                changes.len() <= MAX_CONTACTS,
                "Google contacts exceeded the contact limit"
            );
        }
        let (contacts, deleted) = self.fetch(&book, changes).await?;
        Ok(SyncBatch {
            state,
            full: true,
            contacts,
            deleted,
        })
    }

    /// None means the server invalidated the token: discard this in-memory
    /// attempt and do a full fetch. Tokens and pages never reach the store early.
    async fn changes(
        &mut self,
        book: &Url,
        original: &str,
    ) -> Result<Option<(String, BTreeMap<String, Option<String>>)>> {
        let mut token = checked_token(original)?.to_owned();
        let mut changes = BTreeMap::new();
        let mut seen_tokens = BTreeSet::from([token.clone()]);
        for _ in 0..MAX_PAGES {
            let body = format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><d:sync-collection xmlns:d=\"DAV:\">\
                 <d:sync-token>{}</d:sync-token><d:sync-level>1</d:sync-level>\
                 <d:prop><d:getetag/></d:prop></d:sync-collection>",
                quick_xml::escape::escape(&token)
            );
            let reply = self
                .request(Method::from_bytes(b"REPORT")?, book, 0, &body)
                .await?;
            if matches!(reply.status.as_u16(), 403 | 409 | 410) && invalid_sync_token(&reply.body) {
                return Ok(None);
            }
            if matches!(reply.status.as_u16(), 404 | 410) {
                bail!(BookMoved);
            }
            let (base, listed) = reply.multistatus()?;
            ensure!(same_collection(&base, book), BookMoved);
            let next = checked_token(
                listed
                    .token
                    .as_deref()
                    .context("Google contacts omitted the next sync token")?,
            )?
            .to_owned();
            let mut more = false;
            let mut seen = BTreeSet::new();
            for item in listed.responses {
                let href = self.resolve(&base, &item.href)?;
                ensure!(
                    seen.insert(href.to_string()),
                    "Google contacts repeated a change in one page"
                );
                if same_collection(&href, book) {
                    ensure!(
                        item.status == Some(507) && item.limited,
                        "Google contacts returned an unexpected collection status"
                    );
                    more = true;
                    continue;
                }
                let href = self.resource(book, &base, &item.href)?.to_string();
                if matches!(item.status, Some(404 | 410)) {
                    changes.insert(href, None);
                } else {
                    item.success()?;
                    changes.insert(href, Some(item.etag()?.to_owned()));
                }
                ensure!(
                    changes.len() <= MAX_CONTACTS,
                    "Google contacts exceeded the change limit"
                );
            }
            if !more {
                return Ok(Some((next, changes)));
            }
            ensure!(
                seen_tokens.insert(next.clone()),
                "Google contacts pagination made no progress"
            );
            token = next;
        }
        bail!("Google contacts exceeded the sync page limit")
    }

    async fn fetch(
        &mut self,
        book: &Url,
        changes: BTreeMap<String, Option<String>>,
    ) -> Result<(Vec<Contact>, Vec<String>)> {
        let mut contacts = Vec::new();
        let mut kept_bytes = 0usize;
        let (ids, mut deleted): (Vec<_>, Vec<_>) =
            changes.into_iter().partition(|(_, etag)| etag.is_some());
        let mut removed: Vec<String> = deleted.drain(..).map(|(id, _)| id).collect();
        for chunk in ids.chunks(MULTIGET_SIZE) {
            let mut wanted: BTreeSet<String> = chunk.iter().map(|(id, _)| id.clone()).collect();
            let hrefs: String = wanted
                .iter()
                .map(|id| format!("<d:href>{}</d:href>", quick_xml::escape::escape(id)))
                .collect();
            let body = format!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?><c:addressbook-multiget xmlns:d=\"DAV:\" \
                 xmlns:c=\"urn:ietf:params:xml:ns:carddav\"><d:prop><d:getetag/>\
                 <c:address-data content-type=\"text/vcard\" version=\"3.0\"/></d:prop>{hrefs}</c:addressbook-multiget>"
            );
            let (base, reply) = self
                .request(Method::from_bytes(b"REPORT")?, book, 0, &body)
                .await?
                .multistatus()?;
            ensure!(same_collection(&base, book), BookMoved);
            for item in reply.responses {
                let id = self.resource(book, &base, &item.href)?.to_string();
                ensure!(
                    wanted.remove(&id),
                    "Google contacts returned an unrequested or repeated contact"
                );
                if matches!(item.status, Some(404 | 410)) {
                    // Deleted between the listing/report and multiget.
                    removed.push(id);
                    continue;
                }
                item.success()?;
                let etag = item.etag()?;
                let vcard = item
                    .text_property(Ns::Card, "address-data")?
                    .context("Google contacts omitted a requested vCard")?;
                kept_bytes = kept_bytes.saturating_add(vcard.len());
                ensure!(
                    kept_bytes <= MAX_KEPT_VCARDS,
                    "Google contacts exceeded the cached vCard size limit"
                );
                contacts.push(parse_vcard(id, etag, vcard)?);
            }
            ensure!(
                wanted.is_empty(),
                "Google contacts returned an incomplete multiget response"
            );
        }
        Ok((contacts, removed))
    }
}

fn same_collection(left: &Url, right: &Url) -> bool {
    left.origin() == right.origin()
        && left.path().trim_end_matches('/') == right.path().trim_end_matches('/')
}

fn checked_token(token: &str) -> Result<&str> {
    let token = token.trim();
    ensure!(
        !token.is_empty() && token.len() <= MAX_TOKEN && !token.chars().any(char::is_control),
        "Google contacts returned an invalid sync token"
    );
    Ok(token)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ns {
    Dav,
    Card,
    Other,
}

#[derive(Debug)]
struct Node {
    ns: Ns,
    name: String,
    text: String,
    children: Vec<Node>,
}

impl Node {
    fn is(&self, ns: Ns, name: &str) -> bool {
        self.ns == ns && self.name == name
    }

    fn one(&self, ns: Ns, name: &str) -> Result<Option<&Node>> {
        let mut nodes = self.children.iter().filter(|node| node.is(ns, name));
        let first = nodes.next();
        ensure!(
            nodes.next().is_none(),
            "Google contacts repeated an XML property"
        );
        Ok(first)
    }

    fn value(&self) -> Result<&str> {
        ensure!(
            self.children.is_empty(),
            "Google contacts returned nested XML in a text property"
        );
        Ok(&self.text)
    }
}

/// A small, bounded tree keeps structure and expanded namespace names intact.
/// DTDs and custom entities are forbidden; no XML parser fetches external data.
fn parse_xml(xml: &str) -> Result<Node> {
    ensure!(
        xml.len() <= MAX_RESPONSE,
        "Google contacts XML is too large"
    );
    let mut reader = NsReader::from_str(xml);
    reader.config_mut().expand_empty_elements = true;
    reader.config_mut().check_comments = true;
    let mut stack: Vec<Node> = Vec::new();
    let mut root = None;
    let mut count = 0;
    let mut declaration = false;
    loop {
        let (namespace, event) = reader
            .read_resolved_event()
            .context("Malformed Google contacts XML")?;
        match event {
            Event::Start(start) => {
                ensure!(
                    root.is_none() && stack.len() < 24,
                    "Google contacts XML is too deeply nested or has multiple roots"
                );
                count += 1;
                ensure!(
                    count <= 500_000 && start.len() <= 16 * 1024,
                    "Google contacts XML has too many elements or attributes"
                );
                for (index, attr) in start.attributes().enumerate() {
                    ensure!(index < 64, "Google contacts XML has too many attributes");
                    attr.context("Malformed Google contacts XML attribute")?;
                }
                let ns = match namespace {
                    ResolveResult::Bound(ns) if ns.as_ref() == b"DAV:" => Ns::Dav,
                    ResolveResult::Bound(ns)
                        if ns.as_ref() == b"urn:ietf:params:xml:ns:carddav" =>
                    {
                        Ns::Card
                    }
                    ResolveResult::Unknown(_) => {
                        bail!("Google contacts XML has an unbound namespace prefix")
                    }
                    _ => Ns::Other,
                };
                let name = std::str::from_utf8(start.local_name().as_ref())?.to_owned();
                ensure!(
                    name.len() <= 128,
                    "Google contacts XML has an oversized element name"
                );
                stack.push(Node {
                    ns,
                    name,
                    text: String::new(),
                    children: Vec::new(),
                });
            }
            Event::End(_) => {
                let node = stack.pop().context("Unbalanced Google contacts XML")?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    ensure!(root.is_none(), "Google contacts XML has multiple roots");
                    root = Some(node);
                }
            }
            Event::Text(value) => append_xml_text(&mut stack, &value.xml_content()?)?,
            Event::CData(value) => append_xml_text(&mut stack, &value.xml_content()?)?,
            Event::GeneralRef(value) => {
                let escaped = format!("&{};", value.decode()?);
                append_xml_text(&mut stack, &quick_xml::escape::unescape(&escaped)?)?;
            }
            Event::Decl(decl) => {
                ensure!(
                    !declaration && root.is_none() && stack.is_empty(),
                    "Misplaced Google contacts XML declaration"
                );
                declaration = true;
                if let Some(encoding) = decl.encoding() {
                    let encoding = encoding?;
                    ensure!(
                        encoding.eq_ignore_ascii_case(b"utf-8")
                            || encoding.eq_ignore_ascii_case(b"us-ascii"),
                        "Google contacts XML is not UTF-8"
                    );
                }
            }
            Event::Comment(_) => {}
            Event::Eof => break,
            Event::DocType(_) | Event::PI(_) => {
                bail!("Google contacts XML contains an unsupported declaration")
            }
            Event::Empty(_) => unreachable!("empty elements are expanded"),
        }
    }
    ensure!(stack.is_empty(), "Truncated Google contacts XML");
    root.context("Google contacts returned empty XML")
}

fn append_xml_text(stack: &mut [Node], value: &str) -> Result<()> {
    ensure!(
        !value
            .chars()
            .any(|c| (c < ' ' && !matches!(c, '\n' | '\r' | '\t'))
                || matches!(c, '\u{FFFE}' | '\u{FFFF}')),
        "Google contacts XML contains invalid characters"
    );
    if let Some(node) = stack.last_mut() {
        node.text.push_str(value);
    } else {
        ensure!(
            value.trim().is_empty(),
            "Google contacts XML has text outside its root"
        );
    }
    Ok(())
}

struct MultiStatus {
    responses: Vec<DavResponse>,
    token: Option<String>,
}

struct DavResponse {
    href: String,
    status: Option<u16>,
    props: Vec<Node>,
    limited: bool,
}

impl DavResponse {
    fn success(&self) -> Result<()> {
        ensure!(
            self.status.is_none_or(|status| status == 200),
            "Google contacts returned a failed resource response"
        );
        Ok(())
    }

    fn property(&self, ns: Ns, name: &str) -> Result<Option<&Node>> {
        let mut matches = self.props.iter().filter(|prop| prop.is(ns, name));
        let first = matches.next();
        ensure!(
            matches.next().is_none(),
            "Google contacts repeated a successful property"
        );
        Ok(first)
    }

    fn text_property(&self, ns: Ns, name: &str) -> Result<Option<&str>> {
        self.property(ns, name)?.map(Node::value).transpose()
    }

    fn href_property(&self, ns: Ns, name: &str) -> Result<Option<&str>> {
        let Some(prop) = self.property(ns, name)? else {
            return Ok(None);
        };
        Ok(Some(
            prop.one(Ns::Dav, "href")?
                .context("Google contacts omitted a property href")?
                .value()?
                .trim(),
        ))
    }

    fn is_type(&self, ns: Ns, name: &str) -> Result<bool> {
        Ok(self
            .property(Ns::Dav, "resourcetype")?
            .is_some_and(|prop| prop.children.iter().any(|child| child.is(ns, name))))
    }

    fn etag(&self) -> Result<&str> {
        let etag = self
            .text_property(Ns::Dav, "getetag")?
            .context("Google contacts omitted a contact ETag")?
            .trim();
        ensure!(
            !etag.is_empty() && etag.len() <= MAX_ETAG && !etag.chars().any(char::is_control),
            "Google contacts returned an invalid ETag"
        );
        Ok(etag)
    }
}

fn parse_multistatus(xml: &str) -> Result<MultiStatus> {
    let root = parse_xml(xml)?;
    ensure!(
        root.is(Ns::Dav, "multistatus"),
        "Google contacts did not return a DAV multistatus"
    );
    ensure!(
        root.text.trim().is_empty(),
        "Google contacts returned malformed multistatus text"
    );
    let mut result = MultiStatus {
        responses: Vec::new(),
        token: None,
    };
    for node in root.children {
        if node.is(Ns::Dav, "sync-token") {
            ensure!(
                result.token.is_none(),
                "Google contacts repeated its sync token"
            );
            result.token = Some(checked_token(node.value()?)?.to_owned());
        } else if node.is(Ns::Dav, "response") {
            result.responses.push(parse_dav_response(node)?);
            ensure!(
                result.responses.len() <= MAX_CONTACTS + 1,
                "Google contacts returned too many resources"
            );
        } else {
            ensure!(
                node.is(Ns::Dav, "responsedescription"),
                "Google contacts returned an unknown multistatus element"
            );
        }
    }
    Ok(result)
}

fn parse_dav_response(node: Node) -> Result<DavResponse> {
    ensure!(
        node.text.trim().is_empty(),
        "Google contacts returned malformed resource text"
    );
    let href = node
        .one(Ns::Dav, "href")?
        .context("Google contacts omitted a response href")?
        .value()?
        .trim()
        .to_owned();
    ensure!(
        !href.is_empty() && href.len() <= MAX_URL,
        "Google contacts returned an invalid href"
    );
    let status = node
        .one(Ns::Dav, "status")?
        .map(|node| parse_status(node.value()?))
        .transpose()?;
    let error = node.one(Ns::Dav, "error")?;
    let limited = error
        .map(|error| error.one(Ns::Dav, "number-of-matches-within-limits"))
        .transpose()?
        .flatten()
        .is_some();
    ensure!(
        error.is_none() || matches!(status, Some(404 | 410 | 507)),
        "Google contacts returned an error with successful resource properties"
    );
    let mut props = Vec::new();
    let mut has_propstat = false;
    for child in node.children {
        if child.is(Ns::Dav, "propstat") {
            has_propstat = true;
            ensure!(
                child.text.trim().is_empty(),
                "Google contacts returned malformed property status text"
            );
            let status = parse_status(
                child
                    .one(Ns::Dav, "status")?
                    .context("Google contacts omitted a property status")?
                    .value()?,
            )?;
            let prop = child
                .one(Ns::Dav, "prop")?
                .context("Google contacts omitted its properties")?;
            ensure!(
                prop.text.trim().is_empty(),
                "Google contacts returned malformed properties"
            );
            if status == 200 {
                ensure!(
                    child.one(Ns::Dav, "error")?.is_none(),
                    "Google contacts returned an error with successful properties"
                );
                let mut children = child.children;
                let index = children
                    .iter()
                    .position(|node| node.is(Ns::Dav, "prop"))
                    .unwrap();
                props.extend(children.swap_remove(index).children);
            }
        } else {
            ensure!(
                child.ns == Ns::Dav
                    && matches!(
                        child.name.as_str(),
                        "href" | "status" | "error" | "responsedescription" | "location"
                    ),
                "Google contacts returned an unknown response element"
            );
        }
    }
    ensure!(
        status.is_some() != has_propstat,
        "Google contacts omitted or mixed resource statuses"
    );
    Ok(DavResponse {
        href,
        status,
        props,
        limited,
    })
}

fn parse_status(value: &str) -> Result<u16> {
    let mut parts = value.split_whitespace();
    let protocol = parts
        .next()
        .context("Google contacts returned an empty HTTP status")?;
    ensure!(
        matches!(protocol, "HTTP/1.0" | "HTTP/1.1" | "HTTP/2" | "HTTP/2.0"),
        "Google contacts returned an invalid HTTP status"
    );
    let code = parts
        .next()
        .context("Google contacts omitted an HTTP status code")?;
    ensure!(
        code.len() == 3 && code.bytes().all(|b| b.is_ascii_digit()),
        "Google contacts returned an invalid HTTP status code"
    );
    let code: u16 = code.parse()?;
    ensure!(
        (100..=599).contains(&code),
        "Google contacts returned an invalid HTTP status code"
    );
    Ok(code)
}

fn invalid_sync_token(xml: &str) -> bool {
    parse_xml(xml).is_ok_and(|root| {
        root.is(Ns::Dav, "error")
            && root
                .children
                .iter()
                .any(|node| node.is(Ns::Dav, "valid-sync-token"))
    })
}

fn parse_vcard(id: String, etag: &str, raw: &str) -> Result<Contact> {
    ensure!(raw.len() <= MAX_VCARD, "Google contact vCard is too large");
    let unfolded = unfold_vcard(raw)?;
    let mut logical = unfolded.lines().filter(|line| !line.is_empty());
    let first = logical.next().context("Google contact vCard is empty")?;
    ensure!(
        first.eq_ignore_ascii_case("BEGIN:VCARD"),
        "Google contact has an invalid vCard header"
    );
    let mut last = "";
    let mut lines = 1;
    for line in logical {
        lines += 1;
        ensure!(
            lines <= 10_000,
            "Google contact vCard has too many properties"
        );
        check_vcard_header(line)?;
        last = line;
    }
    ensure!(
        last.eq_ignore_ascii_case("END:VCARD"),
        "Google contact has an incomplete vCard"
    );
    let mut parser = ical::VcardParser::new(unfolded.as_bytes());
    let card = parser
        .next()
        .context("Google contact vCard is empty")?
        .context("Could not parse a Google contact vCard")?;
    ensure!(
        parser.next().is_none(),
        "Google contacts returned more than one vCard for a resource"
    );
    let mut contact = Contact {
        id,
        name: String::new(),
        emails: Vec::new(),
        phones: Vec::new(),
        organization: String::new(),
        etag: etag.to_owned(),
        vcard: raw.to_owned(),
    };
    let mut structured_name = String::new();
    let mut version = None;
    for property in card.properties {
        let name = property
            .name
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        let value = property.value.as_deref().unwrap_or("");
        if matches!(name.as_str(), "FN" | "N" | "EMAIL" | "TEL" | "ORG") {
            for (key, values) in property.params.iter().flatten() {
                if key.eq_ignore_ascii_case("ENCODING") {
                    ensure!(
                        values
                            .iter()
                            .all(|value| value.eq_ignore_ascii_case("8BIT")),
                        "Google contact uses an unsupported text encoding"
                    );
                }
                if key.eq_ignore_ascii_case("CHARSET") {
                    ensure!(
                        values
                            .iter()
                            .all(|value| value.eq_ignore_ascii_case("UTF-8")
                                || value.eq_ignore_ascii_case("US-ASCII")),
                        "Google contact uses an unsupported character set"
                    );
                }
            }
        }
        match name.as_str() {
            "VERSION" => {
                ensure!(
                    version.is_none(),
                    "Google contact repeats its vCard version"
                );
                version = Some(value.to_owned());
            }
            "FN" if contact.name.is_empty() => {
                contact.name = text::one_line(&vcard_text(value), mail::MAX_NAME)
            }
            "N" if structured_name.is_empty() => {
                let parts = vcard_parts(value);
                structured_name = [3, 1, 2, 0, 4]
                    .iter()
                    .filter_map(|&i| parts.get(i))
                    .filter(|part| !part.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ");
            }
            "EMAIL" => {
                let email = vcard_text(value);
                let email = email.trim();
                // Never clean/truncate an address into a different recipient.
                if account::valid_address(email)
                    && contact.emails.len() < MAX_VALUES
                    && !contact
                        .emails
                        .iter()
                        .any(|old| old.eq_ignore_ascii_case(email))
                {
                    contact.emails.push(email.to_owned());
                }
            }
            "TEL" => {
                let phone = text::one_line(&vcard_text(value), 120);
                if !phone.is_empty()
                    && contact.phones.len() < MAX_VALUES
                    && !contact.phones.contains(&phone)
                {
                    contact.phones.push(phone);
                }
            }
            "ORG" if contact.organization.is_empty() => {
                contact.organization = text::one_line(&vcard_parts(value).join(" / "), 240)
            }
            _ => {}
        }
    }
    ensure!(
        version.as_deref() == Some("3.0"),
        "Google contact is not a vCard 3.0 resource"
    );
    if contact.name.is_empty() {
        contact.name = text::one_line(&structured_name, mail::MAX_NAME);
    }
    Ok(contact)
}

/// ical trims each physical line before unfolding, which loses meaningful
/// spaces at folds and can even join an invalid email into a valid recipient.
/// Unfold first, preserving every byte except the fold itself.
fn unfold_vcard(raw: &str) -> Result<std::borrow::Cow<'_, str>> {
    if !raw.contains("\n ") && !raw.contains("\n\t") {
        return Ok(std::borrow::Cow::Borrowed(raw));
    }
    let mut unfolded = String::with_capacity(raw.len());
    for line in raw.lines() {
        if line.starts_with([' ', '\t']) {
            ensure!(
                !unfolded.is_empty(),
                "Google contact vCard starts with a folded line"
            );
            unfolded.push_str(&line[1..]);
        } else {
            if !unfolded.is_empty() {
                unfolded.push('\n');
            }
            unfolded.push_str(line);
        }
    }
    Ok(std::borrow::Cow::Owned(unfolded))
}

/// ical's parameter parser searches the remaining line several times per
/// parameter. Bound that work before invoking it, without imposing the small
/// header limit on a property's value (in particular an unfolded PHOTO).
fn check_vcard_header(line: &str) -> Result<()> {
    let mut quoted = false;
    let mut escaped = false;
    let mut separators = 0;
    for (index, ch) in line.char_indices() {
        ensure!(
            index <= MAX_VCARD_HEADER,
            "Google contact vCard parameter header is too large"
        );
        // Count punctuation conservatively, even in quoted/escaped strings:
        // this also bounds work if a malformed header is parsed differently.
        if ch == ';' {
            separators += 1;
            ensure!(
                separators <= 64,
                "Google contact vCard parameter header is too complex"
            );
        }
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        } else if ch == ':' && !quoted {
            return Ok(());
        }
    }
    bail!("Google contact vCard property has no value separator")
}

fn vcard_parts(value: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut escaped = false;
    for (index, ch) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == ';' {
            parts.push(vcard_text(&value[start..index]));
            start = index + 1;
        }
    }
    parts.push(vcard_text(&value[start..]));
    parts
}

fn vcard_text(value: &str) -> String {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n' | 'N') => out.push('\n'),
                Some(ch @ ('\\' | ',' | ';' | ':')) => out.push(ch),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
    };

    const CARD: &str = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Rivera\\, Ada\r\nN:Rivera;Ada;;;\r\nitem1.EMAIL;TYPE=INTERNET,WORK:ada@example.org\r\nEMAIL:ADA@example.org\r\nTEL;TYPE=CELL:+1 555 0100\r\nORG:Example\\; Inc.;Research\r\nNOTE:Private backing information\r\nEND:VCARD\r\n";

    fn multistatus(inner: &str) -> String {
        format!(
            "<d:multistatus xmlns:d=\"DAV:\" xmlns:c=\"urn:ietf:params:xml:ns:carddav\">{inner}</d:multistatus>"
        )
    }

    fn properties(href: &str, props: &str) -> String {
        format!(
            "<d:response><d:href>{href}</d:href><d:propstat><d:prop>{props}</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>"
        )
    }

    fn collection() -> String {
        properties(
            "/book/",
            "<d:resourcetype><d:collection/><c:addressbook/></d:resourcetype>",
        )
    }

    fn card_response(href: &str, vcard: &str) -> String {
        properties(
            href,
            &format!(
                "<d:getetag>\"card-v1\"</d:getetag><c:address-data>{}</c:address-data>",
                quick_xml::escape::escape(vcard)
            ),
        )
    }

    fn gone(href: &str) -> String {
        format!(
            "<d:response><d:href>{href}</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response>"
        )
    }

    struct MockReply {
        status: u16,
        body: String,
        location: Option<String>,
    }

    impl MockReply {
        fn xml(body: String) -> Self {
            Self {
                status: 207,
                body,
                location: None,
            }
        }
    }

    /// Each connection is closed after its response so the fixture also checks
    /// complete Content-Length reads. Only this test constructor permits HTTP.
    async fn server(replies: Vec<MockReply>) -> (Url, JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for reply in replies {
                let (mut socket, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut request = Vec::new();
                let header_end = loop {
                    let mut bytes = [0u8; 4096];
                    let read = socket.read(&mut bytes).await.unwrap();
                    assert!(read > 0);
                    request.extend_from_slice(&bytes[..read]);
                    assert!(request.len() <= 128 * 1024);
                    if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        break end + 4;
                    }
                };
                let headers = std::str::from_utf8(&request[..header_end]).unwrap();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                assert!(length <= 128 * 1024);
                while request.len() < header_end + length {
                    let mut bytes = [0u8; 4096];
                    let read = socket.read(&mut bytes).await.unwrap();
                    assert!(read > 0);
                    request.extend_from_slice(&bytes[..read]);
                }
                requests.push(String::from_utf8(request).unwrap());
                let location = reply
                    .location
                    .map_or(String::new(), |url| format!("Location: {url}\r\n"));
                let response = format!(
                    "HTTP/1.1 {} Fixture\r\nContent-Type: application/xml\r\nContent-Length: {}\r\nConnection: close\r\n{location}\r\n{}",
                    reply.status,
                    reply.body.len(),
                    reply.body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.shutdown().await.unwrap();
            }
            requests
        });
        (origin, task)
    }

    fn dav<'a>(origin: &Url, password: &'a Secret) -> Dav<'a> {
        Dav {
            client: Client::builder()
                .no_proxy()
                .redirect(Policy::none())
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            origin: origin.clone(),
            email: "demo@example.com",
            password,
            requests: 0,
            received: 0,
        }
    }

    fn state(origin: &Url, token: &str) -> SyncState {
        SyncState {
            address_book: origin.join("book/").unwrap().to_string(),
            sync_token: token.to_owned(),
            discovered_at: chrono::Utc::now().timestamp(),
        }
    }

    fn full_replies(card_reply: String) -> Vec<MockReply> {
        vec![
            MockReply::xml(multistatus(&properties(
                "/book/",
                "<d:sync-token>token-before-list</d:sync-token>",
            ))),
            MockReply::xml(multistatus(&format!(
                "{}{}{}",
                collection(),
                properties("/book/a.vcf", "<d:getetag>a</d:getetag>"),
                properties("/book/b.vcf", "<d:getetag>b</d:getetag>")
            ))),
            MockReply::xml(multistatus(&card_reply)),
        ]
    }

    #[tokio::test]
    async fn discovers_then_fetches_a_complete_snapshot_with_a_pre_listing_token() {
        let mut replies = vec![
            MockReply {
                status: 301,
                body: String::new(),
                location: Some("/principal".into()),
            },
            MockReply::xml(multistatus(&properties(
                "/principal",
                "<c:addressbook-home-set><d:href>/home/</d:href></c:addressbook-home-set>",
            ))),
            MockReply::xml(multistatus(&collection())),
        ];
        replies.extend(full_replies(format!(
            "{}{}",
            card_response("/book/a.vcf", CARD),
            card_response(
                "/book/b.vcf",
                "BEGIN:VCARD\nVERSION:3.0\nFN:Phone only\nTEL:555-0199\nEND:VCARD\n"
            )
        )));
        let (origin, task) = server(replies).await;
        let password = Secret::new("app-password");
        let batch = dav(&origin, &password)
            .sync(origin.join(".well-known/carddav").unwrap(), None)
            .await
            .unwrap();
        assert!(batch.full);
        assert_eq!(batch.state.sync_token, "token-before-list");
        assert_eq!(batch.contacts.len(), 2);
        assert_eq!(batch.contacts[0].name, "Rivera, Ada");
        assert_eq!(batch.contacts[0].emails, ["ada@example.org"]);
        assert!(batch.contacts[1].emails.is_empty());
        assert!(batch.deleted.is_empty());
        let requests = task.await.unwrap();
        assert_eq!(requests.len(), 6);
        assert!(requests[0].starts_with("PROPFIND /.well-known/carddav "));
        assert!(requests[3].contains("<d:sync-token/>"));
        assert!(requests[4].to_ascii_lowercase().contains("depth: 1"));
        assert!(requests[5].contains("addressbook-multiget"));
        for request in requests {
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: basic zgvtb0blegftcgxllmnvbtphchatcgfzc3dvcmq=")
            );
        }
    }

    #[tokio::test]
    async fn incremental_sync_finishes_all_pages_and_keeps_tombstones() {
        let page = format!(
            "{}{}<d:response><d:href>/book/</d:href><d:status>HTTP/1.1 507 Insufficient Storage</d:status><d:error><d:number-of-matches-within-limits/></d:error></d:response><d:sync-token>page-1</d:sync-token>",
            properties("/book/a.vcf", "<d:getetag>a</d:getetag>"),
            gone("/book/b.vcf")
        );
        let last = format!(
            "{}<d:sync-token>page-2</d:sync-token>",
            properties("/book/c.vcf", "<d:getetag>c</d:getetag>")
        );
        let (origin, task) = server(vec![
            MockReply::xml(multistatus(&page)),
            MockReply::xml(multistatus(&last)),
            MockReply::xml(multistatus(&format!(
                "{}{}",
                card_response("/book/a.vcf", CARD),
                card_response("/book/c.vcf", CARD)
            ))),
        ])
        .await;
        let password = Secret::new("fixture");
        let batch = dav(&origin, &password)
            .sync(origin.clone(), Some(state(&origin, "old")))
            .await
            .unwrap();
        assert!(!batch.full);
        assert_eq!(batch.state.sync_token, "page-2");
        assert_eq!(batch.contacts.len(), 2);
        assert_eq!(
            batch.deleted,
            [origin.join("book/b.vcf").unwrap().to_string()]
        );
        let requests = task.await.unwrap();
        assert!(requests[1].contains("<d:sync-token>page-1</d:sync-token>"));
        assert!(!requests[2].contains("b.vcf"));
    }

    #[tokio::test]
    async fn moved_book_is_rediscovered_and_replaced_by_a_full_sync() {
        let moved = properties(
            "/moved/",
            "<d:resourcetype><d:collection/><c:addressbook/></d:resourcetype>",
        );
        let redirect = || MockReply {
            status: 301,
            body: String::new(),
            location: Some("/moved/".into()),
        };
        let (origin, task) = server(vec![
            redirect(),
            MockReply::xml(multistatus(
                "<d:sync-token>do-not-commit-this-token</d:sync-token>",
            )),
            redirect(),
            MockReply::xml(multistatus(&moved)),
            MockReply::xml(multistatus(&properties(
                "/moved/",
                "<d:sync-token>new-book-token</d:sync-token>",
            ))),
            MockReply::xml(multistatus(&moved)),
        ])
        .await;
        let password = Secret::new("fixture");
        let batch = dav(&origin, &password)
            .sync(
                origin.join(".well-known/carddav").unwrap(),
                Some(state(&origin, "old-book-token")),
            )
            .await
            .unwrap();
        assert!(batch.full);
        assert_eq!(
            batch.state.address_book,
            origin.join("moved/").unwrap().as_str()
        );
        assert_eq!(batch.state.sync_token, "new-book-token");
        assert!(batch.contacts.is_empty());
        let requests = task.await.unwrap();
        assert_eq!(requests.len(), 6);
        assert!(requests[0].starts_with("REPORT /book/ "));
        assert!(requests[1].starts_with("REPORT /moved/ "));
        assert!(requests[2].starts_with("PROPFIND /.well-known/carddav "));
        assert!(requests[4].contains("<d:sync-token/>"));
        assert!(requests[5].to_ascii_lowercase().contains("depth: 1"));
    }

    #[tokio::test]
    async fn expired_token_restarts_full_sync_and_missing_multiget_never_returns_a_batch() {
        let expired = MockReply {
            status: 403,
            body: "<d:error xmlns:d=\"DAV:\"><d:valid-sync-token/></d:error>".into(),
            location: None,
        };
        let mut replies = vec![expired];
        replies.extend(full_replies(format!(
            "{}{}",
            card_response("/book/a.vcf", CARD),
            gone("/book/b.vcf")
        )));
        let (origin, task) = server(replies).await;
        let password = Secret::new("fixture");
        let batch = dav(&origin, &password)
            .sync(origin.clone(), Some(state(&origin, "expired")))
            .await
            .unwrap();
        assert!(batch.full);
        assert_eq!(batch.contacts.len(), 1);
        assert_eq!(
            batch.deleted,
            [origin.join("book/b.vcf").unwrap().to_string()]
        );
        assert_eq!(task.await.unwrap().len(), 4);

        let (origin, task) = server(full_replies(card_response("/book/a.vcf", CARD))).await;
        let result = dav(&origin, &password)
            .sync(origin.clone(), Some(state(&origin, "")))
            .await;
        assert!(result.is_err());
        assert_eq!(task.await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn rejects_external_redirect_before_sending_another_authenticated_request() {
        let (origin, task) = server(vec![MockReply {
            status: 302,
            body: String::new(),
            location: Some("https://elsewhere.invalid/collect-password".into()),
        }])
        .await;
        let password = Secret::new("fixture-secret");
        let error = dav(&origin, &password)
            .sync(origin.clone(), None)
            .await
            .unwrap_err();
        assert!(!format!("{error:#}").contains("fixture-secret"));
        assert_eq!(task.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn refusal_does_not_retry_or_expose_credentials() {
        let (origin, task) = server(vec![MockReply {
            status: 403,
            body: "<x:error xmlns:x=\"not-DAV:\"><x:valid-sync-token/></x:error>".into(),
            location: None,
        }])
        .await;
        let password = Secret::new("fixture-secret");
        let error = dav(&origin, &password)
            .sync(origin.clone(), Some(state(&origin, "old")))
            .await
            .unwrap_err()
            .to_string();
        assert!(!error.contains("fixture-secret"));
        assert_eq!(task.await.unwrap().len(), 1);
    }

    #[test]
    fn google_urls_never_leave_the_origin_or_smuggle_credentials() {
        let origin = Url::parse(DISCOVERY).unwrap();
        let password = Secret::new("fixture");
        let dav = dav(&origin, &password);
        for href in [
            "http://www.googleapis.com/book",
            "https://evil.invalid/book",
            "//evil.invalid/book",
            "https://www.googleapis.com:444/book",
            "https://user:password@www.googleapis.com/book",
            "/book?token=secret",
            "/book#fragment",
            "/book\r\nX-Injection: value",
            "\\\\evil.invalid/book",
        ] {
            assert!(dav.resolve(&origin, href).is_err(), "accepted {href:?}");
        }
        assert!(dav.resolve(&origin, "/carddav/book").is_ok());
        let book = Url::parse("https://www.googleapis.com/carddav/book/").unwrap();
        assert!(dav.resource(&book, &book, "../another/a.vcf").is_err());
        assert!(
            dav.resource(&book, &book, "/carddav/bookish/a.vcf")
                .is_err()
        );
        assert!(dav.resource(&book, &book, "/carddav/book/a.vcf").is_ok());
    }

    #[test]
    fn xml_checks_namespaces_structure_entities_and_complete_properties() {
        let ordinary = multistatus(&card_response("/book/a.vcf", CARD));
        let renamed = ordinary.replace("d:", "z:").replace("xmlns:d=", "xmlns:z=");
        let response = parse_multistatus(&renamed).unwrap();
        assert_eq!(response.responses[0].etag().unwrap(), "\"card-v1\"");
        assert!(
            response.responses[0]
                .text_property(Ns::Card, "address-data")
                .unwrap()
                .unwrap()
                .contains("Rivera\\, Ada")
        );
        assert!(parse_multistatus("<multistatus xmlns=\"impostor\"/>").is_err());
        assert!(
            parse_multistatus(
                "<d:multistatus xmlns:d=\"DAV:\"><x:response xmlns:x=\"impostor\"/></d:multistatus>"
            )
            .is_err()
        );
        assert!(
            parse_xml("<!DOCTYPE x [<!ENTITY steal SYSTEM 'file:///etc/passwd'>]><x>&steal;</x>")
                .is_err()
        );
        assert!(parse_xml("<x>&unknown;</x>").is_err());
        assert!(parse_xml("<x>&#27;</x>").is_err());
        assert!(parse_xml("<x><y></x>").is_err());
        assert!(parse_xml(&format!("{}{}", "<x>".repeat(25), "</x>".repeat(25))).is_err());
        let split = multistatus(
            "<d:response><d:href>/book/a.vcf</d:href><d:propstat><d:prop><d:getetag>bad</d:getetag></d:prop><d:status>HTTP/1.1 403 Forbidden</d:status></d:propstat><d:propstat><d:prop><c:address-data>ignored</c:address-data></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
        );
        assert!(
            parse_multistatus(&split).unwrap().responses[0]
                .etag()
                .is_err()
        );
    }

    #[test]
    fn vcard_fields_are_unfolded_unescaped_and_sanitized_but_addresses_are_never_rewritten() {
        let raw = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Marí\r\n a\\, Rivera\\n\u{202e}Doctor\r\nEMAIL:valid@example.org\r\nEMAIL:bad\u{202e}@example.org\r\nEMAIL:two@example.org,attacker@example.org\r\nEMAIL:injected\n address@example.org\r\nTEL:555\\n0100\r\nORG:Example\\; Inc.;Research\r\nEND:VCARD\r\n";
        let contact = parse_vcard("id".into(), "etag", raw).unwrap();
        assert_eq!(contact.name, "María, Rivera Doctor");
        assert_eq!(
            contact.emails,
            ["valid@example.org", "injectedaddress@example.org"]
        );
        assert_eq!(contact.phones, ["555 0100"]);
        assert_eq!(contact.organization, "Example; Inc. / Research");
        assert_eq!(contact.vcard, raw);
        let contact = parse_vcard(
            "id".into(),
            "etag",
            "BEGIN:VCARD\nVERSION:3.0\nN:Doe;Jane;Q.;Dr.;Jr.\nEND:VCARD\n",
        )
        .unwrap();
        assert_eq!(contact.name, "Dr. Jane Q. Doe Jr.");
        for invalid in [
            "BEGIN:VCARD\nVERSION:3.0\nFN:Partial\n",
            "BEGIN:VCARD\nVERSION:3.0\nEND:OTHER\n",
            "BEGIN:VCARD\nVERSION:4.0\nEND:VCARD\n",
        ] {
            assert!(parse_vcard("id".into(), "etag", invalid).is_err());
        }
        assert!(parse_vcard("id".into(), "etag", &format!("{CARD}{CARD}")).is_err());
        let serial =
            serde_json::to_string(&parse_vcard("id".into(), "etag", CARD).unwrap()).unwrap();
        assert!(!serial.contains("vcard"));
        assert!(!serial.contains("Private backing information"));
    }

    #[test]
    fn vcard_parameter_headers_are_bounded_while_folded_photo_values_remain_valid() {
        let oversized = format!(
            "BEGIN:VCARD\nVERSION:3.0\nFN;X-LABEL=\"{}\":Name\nEND:VCARD\n",
            "x".repeat(MAX_VCARD_HEADER + 1)
        );
        assert!(parse_vcard("id".into(), "etag", &oversized).is_err());
        let many_parameters = format!(
            "BEGIN:VCARD\nVERSION:3.0\nFN{}:Name\nEND:VCARD\n",
            ";X=A".repeat(65)
        );
        assert!(parse_vcard("id".into(), "etag", &many_parameters).is_err());
        assert!(check_vcard_header(r#"FN;X-LABEL="a\";b:c":Name"#).is_ok());

        let photo = "YWFh".repeat(4096);
        let folded = photo
            .as_bytes()
            .chunks(76)
            .map(|chunk| std::str::from_utf8(chunk).unwrap())
            .collect::<Vec<_>>()
            .join("\r\n ");
        let raw = format!(
            "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Photo Owner\r\n\
             EMAIL;X-LABEL=\"Team: west; branch\":ada@example.org\r\n\
             PHOTO;ENCODING=b;TYPE=JPEG:{folded}\r\nEND:VCARD\r\n"
        );
        let contact = parse_vcard("id".into(), "etag", &raw).unwrap();
        assert_eq!(contact.name, "Photo Owner");
        assert_eq!(contact.emails, ["ada@example.org"]);
        assert_eq!(contact.vcard, raw);
    }

    #[tokio::test]
    async fn periodic_discovery_preserves_the_token_only_for_the_same_book() {
        let (origin, task) = server(vec![
            MockReply::xml(multistatus(&collection())),
            MockReply::xml(multistatus("<d:sync-token>new-token</d:sync-token>")),
        ])
        .await;
        let password = Secret::new("fixture");
        let mut previous = state(&origin, "old-token");
        previous.discovered_at -= REDISCOVER_AFTER;
        let old_discovery = previous.discovered_at;
        let batch = dav(&origin, &password)
            .sync(origin.join("book/").unwrap(), Some(previous))
            .await
            .unwrap();
        assert!(!batch.full);
        assert_eq!(batch.state.sync_token, "new-token");
        assert!(batch.state.discovered_at > old_discovery);
        let requests = task.await.unwrap();
        assert!(requests[1].contains("<d:sync-token>old-token</d:sync-token>"));
    }

    #[tokio::test]
    async fn a_book_moved_during_multiget_is_rediscovered_without_committing_partial_contacts() {
        let moved = properties(
            "/moved/",
            "<d:resourcetype><d:collection/><c:addressbook/></d:resourcetype>",
        );
        let mut replies = full_replies(String::new());
        replies[2].status = 404;
        replies.extend([
            MockReply {
                status: 301,
                body: String::new(),
                location: Some("/moved/".into()),
            },
            MockReply::xml(multistatus(&moved)),
            MockReply::xml(multistatus(&properties(
                "/moved/",
                "<d:sync-token>new-book-token</d:sync-token>",
            ))),
            MockReply::xml(multistatus(&moved)),
        ]);
        let (origin, task) = server(replies).await;
        let password = Secret::new("fixture");
        let batch = dav(&origin, &password)
            .sync(origin.clone(), Some(state(&origin, "")))
            .await
            .unwrap();
        assert!(batch.full);
        assert!(batch.contacts.is_empty());
        assert_eq!(batch.state.sync_token, "new-book-token");
        assert_eq!(
            batch.state.address_book,
            origin.join("moved/").unwrap().as_str()
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn failed_pages_and_nonprogressing_pagination_never_return_a_batch() {
        let limited = "<d:response><d:href>/book/</d:href><d:status>HTTP/1.1 507 Insufficient Storage</d:status><d:error><d:number-of-matches-within-limits/></d:error></d:response>";
        let (origin, task) = server(vec![
            MockReply::xml(multistatus(&format!(
                "{}{limited}<d:sync-token>page-token</d:sync-token>",
                gone("/book/a.vcf")
            ))),
            MockReply {
                status: 500,
                body: String::new(),
                location: None,
            },
        ])
        .await;
        let password = Secret::new("fixture");
        assert!(
            dav(&origin, &password)
                .sync(origin.clone(), Some(state(&origin, "old")))
                .await
                .is_err()
        );
        task.await.unwrap();

        let (origin, task) = server(vec![MockReply::xml(multistatus(&format!(
            "{limited}<d:sync-token>old</d:sync-token>"
        )))])
        .await;
        assert!(
            dav(&origin, &password)
                .sync(origin.clone(), Some(state(&origin, "old")))
                .await
                .is_err()
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn cached_destinations_and_request_and_download_budgets_are_enforced() {
        let origin = Url::parse(DISCOVERY).unwrap();
        let password = Secret::new("fixture-secret");
        let mut previous = state(&origin, "old");
        previous.address_book = "https://user:password@elsewhere.invalid/book/".into();
        let mut client = dav(&origin, &password);
        let error = client
            .sync(origin.clone(), Some(previous))
            .await
            .unwrap_err();
        assert_eq!(client.requests, 0);
        assert!(!format!("{error:#}").contains("fixture-secret"));
        assert!(!format!("{error:#}").contains("user:password"));

        client.requests = MAX_REQUESTS;
        assert!(client.request(Method::GET, &origin, 0, "").await.is_err());

        let (origin, task) = server(vec![MockReply::xml(multistatus(
            "<d:sync-token>new</d:sync-token>",
        ))])
        .await;
        let mut client = dav(&origin, &password);
        client.received = MAX_RECEIVED;
        assert!(
            client
                .sync(origin.clone(), Some(state(&origin, "old")))
                .await
                .is_err()
        );
        task.await.unwrap();
    }

    #[test]
    fn resource_errors_cannot_be_hidden_beside_successful_properties() {
        let mixed = multistatus(
            "<d:response><d:href>/book/a.vcf</d:href><d:error><d:cannot-modify-protected-property/></d:error><d:propstat><d:prop><d:getetag>a</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
        );
        assert!(parse_multistatus(&mixed).is_err());
        let mixed_property = multistatus(
            "<d:response><d:href>/book/a.vcf</d:href><d:propstat><d:prop><d:getetag>a</d:getetag></d:prop><d:status>HTTP/1.1 200 OK</d:status><d:error><d:cannot-modify-protected-property/></d:error></d:propstat></d:response>",
        );
        assert!(parse_multistatus(&mixed_property).is_err());
    }

    #[test]
    fn grouped_properties_keep_all_email_addresses_and_folded_names() {
        let raw = "BEGIN:VCARD\r\nVERSION:3.0\r\nitem1.FN:Rivera\\, \r\n Ada\r\nitem1.EMAIL;TYPE=INTERNET,WORK:ada@example.org\r\nitem2.EMAIL;TYPE=HOME:home@example.net\r\nEMAIL:wrong \r\n person@example.org\r\nitem3.TEL:+1 555 0199\r\nitem4.ORG:Example;Research\r\nEND:VCARD\r\n";
        let contact = parse_vcard("id".into(), "etag", raw).unwrap();
        assert_eq!(contact.name, "Rivera, Ada");
        assert_eq!(contact.emails, ["ada@example.org", "home@example.net"]);
        assert_eq!(contact.phones, ["+1 555 0199"]);
        assert_eq!(contact.organization, "Example / Research");
    }
}
