//! One background task per account: it holds the connection, runs changes
//! in order, and gives explicit opens priority over background reads. The
//! app keeps the cache; a worker never touches it. For IMAP accounts whose server can, a
//! second connection waits on the inbox (IDLE) so new mail shows at once.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use rustls::ClientConfig;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::JoinHandle;

use crate::account::{Account, Protocol};
use crate::imap::{self, Caps, FlagKind, Session};
use crate::net::Endpoint;
use crate::secrets::{Credentials, NeedPassword};
use crate::store::{Flags, Folder, Gmail, Header, Known, Role};
use crate::{imap_mime, imap_timing, mail, pop3, smtp, tags, text};

/// After a failed connection, requests fail at once for this long instead
/// of each waiting to time out.
const OFFLINE_FOR: Duration = Duration::from_secs(20);
/// IDLE is renewed this often (servers drop it after 30 minutes).
const IDLE_FOR: Duration = Duration::from_secs(25 * 60);
/// The most folders whose counts are asked for.
const MAX_STATUS: usize = 200;
/// Only probe the part tree when skipping attachment bytes could matter.
const PARTIAL_MIN: u32 = 512 << 10;
/// The most new POP3 messages downloaded in one check.
const POP_BATCH: usize = 300;
/// The biggest POP3 message downloaded.
const POP_MAX: usize = 60 << 20;
/// The most bytes one check downloads before leaving the rest for the
/// next.
const POP_BYTES: usize = 256 << 20;
/// Visible seed messages per native Gmail conversation request.
pub const CONVERSATION_BATCH: usize = 32;

/// What the app asks an account's worker to do.
#[derive(Clone, Debug)]
pub enum Request {
    /// List the folders, then collect counts after syncing the inbox.
    Folders,
    /// Fetch what's new in a folder, and its flags since `known`.
    Sync {
        folder: String,
        known: Known,
        count: u32,
    },
    /// Fetch up to `count` messages older than UID `below`.
    Older {
        folder: String,
        below: u32,
        count: u32,
    },
    // The requests on UIDs carry `uidvalidity`, what the UIDs meant when
    // they were taken (0: not known, no check): if the server has given
    // the folder a new one since, they mean other messages, and nothing is
    // done to them.
    Body {
        folder: String,
        uid: u32,
        uidvalidity: u32,
        size: u32,
        partial: bool,
        urgent: bool,
        queued: Option<Instant>,
    },
    /// Promote an existing download, without asking for it a second time.
    PrioritizeBody {
        folder: String,
        uid: u32,
        uidvalidity: u32,
    },
    Files {
        id: u64,
        folder: String,
        uid: u32,
        uidvalidity: u32,
        files: Vec<(String, mail::PartRef)>,
    },
    Flag {
        folder: String,
        uids: Vec<u32>,
        flag: FlagKind,
        on: bool,
        uidvalidity: u32,
    },
    Move {
        folder: String,
        uids: Vec<u32>,
        to: String,
        uidvalidity: u32,
    },
    Delete {
        folder: String,
        uids: Vec<u32>,
        uidvalidity: u32,
    },
    /// Adds a message to a folder, made first if it isn't there. `id`
    /// comes back with [`Event::Appended`]. With `retry`, a connection
    /// lost on the way doesn't fail it: it's made once the connection is
    /// back (a copy in Sent); without, it fails (a draft, whose composer
    /// waits).
    Append {
        folder: String,
        raw: Vec<u8>,
        flags: Flags,
        id: u64,
        retry: bool,
    },
    /// The list's headers for these messages (the server has them; the
    /// cache lost them).
    Headers {
        folder: String,
        uids: Vec<u32>,
        uidvalidity: u32,
    },
    /// Complete native Gmail conversations, without syncing All Mail.
    Conversations {
        folder: String,
        uidvalidity: u32,
        uids: Vec<u32>,
        thread_ids: Vec<u64>,
        all: String,
    },
    /// Moves messages back from `folder` to `to` (an undo): each by its
    /// Message-ID and size from UID `floor` on (the folder's UIDNEXT just
    /// before the move put them there, under `uidvalidity`), since their
    /// UIDs there aren't known.
    MoveBack {
        folder: String,
        uidvalidity: u32,
        floor: u32,
        moved: Vec<(String, u32)>,
        to: String,
    },
    /// Puts a tag on messages (`on`) or takes it off.
    Tag {
        folder: String,
        uids: Vec<u32>,
        tag: String,
        on: bool,
        uidvalidity: u32,
    },
    Search {
        folder: String,
        query: String,
        generation: u64,
    },
    /// POP3: download new mail (ids not in `seen`) and delete `remove`
    /// from the server. A `first_check` takes only the newest `count`.
    Pop {
        seen: HashSet<String>,
        remove: Vec<String>,
        count: u32,
        first_check: bool,
    },
}

impl Request {
    /// Whether it changes mail on the server: such a request isn't dropped
    /// while the connection is down, but made once it's back.
    pub fn changes(&self) -> bool {
        matches!(
            self,
            Request::Flag { .. }
                | Request::Tag { .. }
                | Request::Move { .. }
                | Request::MoveBack { .. }
                | Request::Delete { .. }
                | Request::Append { retry: true, .. }
        )
    }

    /// What it was, for an error message.
    fn what(&self) -> &'static str {
        match self {
            Request::Folders => "listing folders",
            Request::Sync { .. } => "checking for mail",
            Request::Older { .. } => "fetching older mail",
            Request::Body { .. } | Request::PrioritizeBody { .. } => "downloading the message",
            Request::Files { .. } => "downloading attachments",
            Request::Flag { .. } => "changing flags",
            Request::Tag { .. } => "tagging",
            Request::Move { .. } | Request::MoveBack { .. } => "moving mail",
            Request::Delete { .. } => "deleting mail",
            Request::Append { .. } => "saving a copy",
            Request::Headers { .. } => "checking for mail",
            Request::Conversations { .. } => "loading Gmail conversations",
            Request::Search { .. } => "searching",
            Request::Pop { .. } => "checking for mail",
        }
    }
}

/// Whether the account can be reached.
#[derive(Clone, Debug, PartialEq)]
pub enum State {
    Connecting,
    Online,
    Offline(String),
    /// No password is known, or the server refused it (`refused`).
    NeedPassword {
        refused: bool,
    },
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Synced {
    pub folder: String,
    pub uidvalidity: u32,
    /// The folder's UIDs changed meaning: what's cached must go.
    pub reset: bool,
    pub new: Vec<Header>,
    /// The flags of every message from `known.low` to `known.high`; cached
    /// ones not in it were deleted elsewhere.
    pub flags: Vec<(u32, Flags)>,
    /// Flags were fetched for this range.
    pub checked: Option<(u32, u32)>,
    /// What's cached now runs from `low` to `high`.
    pub low: u32,
    pub high: u32,
    pub unread: u32,
    pub total: u32,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Popped {
    /// New messages: their POP3 id and text.
    pub new: Vec<(String, Vec<u8>)>,
    /// Ids not downloaded (too big, or older than the first check's
    /// share), so they aren't asked about again.
    pub skipped: Vec<String>,
    /// Every id the server still has.
    pub on_server: HashSet<String>,
    /// Ids deleted from the server.
    pub deleted: Vec<String>,
    /// More new mail is waiting: check again.
    pub more: bool,
}
/// A source mailbox's native metadata and complete All Mail thread headers.
#[derive(Clone, Debug, PartialEq)]
pub struct Conversations {
    pub source_uidvalidity: u32,
    pub all_uidvalidity: u32,
    pub source: Vec<(u32, Gmail)>,
    pub headers: Vec<Header>,
    pub thread_ids: Vec<u64>,
}

#[derive(Clone, Debug)]
pub enum Download {
    Full(Vec<u8>),
    Partial(mail::Partial),
}

/// What a worker tells the app.
#[derive(Clone, Debug)]
pub enum Event {
    State(State),
    Folders(Vec<Folder>),
    FoldersRefused(String),
    Counts {
        folder: String,
        unread: u32,
        total: u32,
    },
    Synced(Synced),
    Older {
        folder: String,
        headers: Vec<Header>,
        low: u32,
    },
    Body {
        folder: String,
        uid: u32,
        uidvalidity: u32,
        partial: bool,
        result: Result<Option<Download>, String>,
    },
    Files {
        id: u64,
        result: Result<Vec<mail::File>, String>,
    },
    Searched {
        folder: String,
        generation: u64,
        uidvalidity: u32,
        headers: Vec<Header>,
    },
    /// The server did what was asked (a move).
    Done {
        folder: String,
    },
    /// A move was made: where to, `to`'s UIDVALIDITY and its UIDNEXT just
    /// before (0 if the server didn't say), for undoing it.
    Moved {
        folder: String,
        uidvalidity: u32,
        uids: Vec<u32>,
        to: String,
        to_uidvalidity: u32,
        floor: u32,
    },
    /// Messages moved back ([`Request::MoveBack`]): those `moved` (their
    /// UIDs in `folder`) of the `asked`.
    MovedBack {
        folder: String,
        to: String,
        moved: Vec<u32>,
        asked: usize,
    },
    /// Deletes for good the server made (`all`: and expunged).
    Deleted {
        folder: String,
        uids: Vec<u32>,
        all: bool,
    },
    /// How many changes haven't reached the server yet.
    Waiting(usize),
    /// A message was added to `folder` (`error` if it wasn't).
    Appended {
        folder: String,
        id: u64,
        error: Option<String>,
    },
    /// Headers asked for with [`Request::Headers`].
    Headers {
        folder: String,
        headers: Vec<Header>,
    },
    Conversations {
        folder: String,
        uidvalidity: u32,
        all: String,
        result: Result<Option<Conversations>, String>,
    },
    Failed {
        what: &'static str,
        error: String,
    },
    /// IDLE saw the inbox change.
    Changed {
        folder: String,
    },
    Popped(Popped),
}

pub type Sink = Arc<dyn Fn(Event) + Send + Sync>;

/// The running worker; dropping it stops it (and its IDLE connection).
pub struct Worker {
    pub tx: UnboundedSender<Request>,
    pub creds: Credentials,
    pub endpoints: Endpoints,
    task: JoinHandle<()>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Where an account's servers are.
#[derive(Clone)]
pub struct Endpoints {
    pub incoming: Endpoint,
    pub smtp: Endpoint,
}

impl Endpoints {
    pub fn of(account: &Account, tls: Arc<ClientConfig>) -> Self {
        Self {
            incoming: Endpoint {
                host: account.host.trim().to_string(),
                port: account.port(),
                security: account.security,
                tls: tls.clone(),
            },
            smtp: Endpoint {
                host: account.smtp_host.trim().to_string(),
                port: account.smtp_port(),
                security: account.smtp_security,
                tls,
            },
        }
    }
}

pub fn spawn(creds: Credentials, endpoints: Endpoints, sink: Sink) -> Worker {
    let (tx, rx) = unbounded_channel();
    let task = match creds.account().protocol {
        Protocol::Imap => tokio::spawn(run_imap(creds.clone(), endpoints.clone(), rx, sink)),
        Protocol::Pop3 => tokio::spawn(run_pop(creds.clone(), endpoints.clone(), rx, sink)),
    };
    Worker {
        tx,
        creds,
        endpoints,
        task,
    }
}

/// A failure while connecting, sorted for the app.
fn login_failed(error: &anyhow::Error) -> State {
    if error.downcast_ref::<NeedPassword>().is_some() {
        State::NeedPassword { refused: false }
    } else if error.downcast_ref::<imap::Refused>().is_some()
        || error.downcast_ref::<pop3::Refused>().is_some()
        || error.downcast_ref::<smtp::Refused>().is_some()
    {
        State::NeedPassword { refused: true }
    } else {
        State::Offline(text::one_line(&format!("{error:#}"), 300))
    }
}

/// Logs in with the account's password; a refused one is forgotten.
async fn imap_login(creds: &Credentials, endpoint: &Endpoint) -> Result<(Session, Caps)> {
    let start = imap_timing::start();
    let connected = async {
        let secret = creds.get().await?;
        let account = creds.account();
        match imap::connect(endpoint, account.username(), secret.expose(), account.auth).await {
            Ok(session) => {
                let _ = creds.remember(&secret).await;
                Ok(session)
            }
            Err(e) => {
                if e.downcast_ref::<imap::Refused>().is_some() {
                    creds.refused(&secret).await;
                }
                Err(e)
            }
        }
    }
    .await;
    imap_timing::finish(start, "connect", None);
    connected
}

/// How many times a held change may break a connection that was up before
/// it's given up: one that fails the same way each time (more than may be
/// read for it, a command that always runs out of time) would otherwise
/// hold every later change, and the account, offline until tuimail quits.
const MAX_TRIES: u32 = 3;

/// Requests waiting together, so POP3 runs only the last check of a batch.
fn pop_batch(first: Request, rx: &mut UnboundedReceiver<Request>) -> VecDeque<Request> {
    let mut out = VecDeque::new();
    enqueue(&mut out, first);
    while let Ok(next) = rx.try_recv() {
        enqueue(&mut out, next);
    }
    out
}

fn enqueue(out: &mut VecDeque<Request>, request: Request) {
    if let Request::PrioritizeBody {
        folder,
        uid,
        uidvalidity,
    } = request
    {
        let mut i = 0;
        for _ in 0..out.len() {
            if matches!(&out[i], Request::Body {
                folder: name, uid: u, uidvalidity: v, urgent: false, ..
            } if *name == folder && *u == uid && *v == uidvalidity)
            {
                let mut body = out.remove(i).unwrap();
                if let Request::Body { urgent, .. } = &mut body {
                    *urgent = true;
                }
                // A promotion belongs at the moment the user opened the
                // mail: it cannot jump a mutation queued before that.
                out.push_back(body);
            } else {
                i += 1;
            }
        }
        return;
    }
    if let Request::Body {
        folder,
        uid,
        uidvalidity,
        partial,
        size,
        urgent,
        ..
    } = &request
        && let Some(i) = out.iter().position(|r| {
            matches!(r, Request::Body {
                folder: name, uid: u, uidvalidity: v, partial: p, ..
            } if name == folder && u == uid && v == uidvalidity && p == partial)
        })
    {
        if let Request::Body {
            size: known,
            urgent: pending,
            ..
        } = &mut out[i]
        {
            if *known == 0 {
                *known = *size;
            }
            if *urgent && !*pending {
                *pending = true;
                let body = out.remove(i).unwrap();
                out.push_back(body);
            }
        }
        return;
    }
    let duplicate = out.iter().position(|r| match (r, &request) {
        (Request::Folders, Request::Folders) => true,
        (Request::Sync { folder: a, .. }, Request::Sync { folder: b, .. }) => a == b,
        (Request::Pop { .. }, Request::Pop { .. }) => true,
        _ => false,
    });
    // The later check goes last: a flag set in between is made before
    // the check reads the flags back.
    if let Some(i) = duplicate {
        out.remove(i);
    }
    out.push_back(request);
}

fn next_imap(requests: &VecDeque<Request>) -> usize {
    let mut change = None;
    for (i, request) in requests.iter().enumerate() {
        if matches!(
            request,
            Request::Files { .. } | Request::Body { urgent: true, .. }
        ) {
            return change.unwrap_or(i);
        }
        if change.is_none() && (request.changes() || matches!(request, Request::Append { .. })) {
            change = Some(i);
        }
    }
    0
}

#[derive(Default)]
struct FolderCounts {
    inbox: Option<String>,
    pending: VecDeque<String>,
}

impl FolderCounts {
    fn after_list(&mut self, folders: &[Folder]) {
        self.inbox = Some(
            folders
                .iter()
                .find(|folder| folder.role == Some(Role::Inbox))
                .map_or_else(|| "INBOX".to_string(), |folder| folder.name.clone()),
        );
        self.pending = folders
            .iter()
            .filter(|folder| folder.selectable)
            .take(MAX_STATUS)
            .map(|folder| folder.name.clone())
            .collect();
    }

    fn syncing(&mut self, folder: &str) {
        if self.inbox.as_deref() == Some(folder) {
            self.inbox = None;
        }
    }

    fn synced(&mut self, folder: &str) {
        self.pending.retain(|name| name != folder);
    }

    fn next(&mut self) -> Option<String> {
        if self.inbox.is_none() {
            self.pending.pop_front()
        } else {
            None
        }
    }
}

/// Whether an error left the connection unusable (as opposed to the server
/// saying no to one command).
fn broken(error: &anyhow::Error) -> bool {
    error.downcast_ref::<imap::Said>().is_none()
}

/// The IDLE task, stopped when the worker ends, however it ends.
#[derive(Default)]
struct Watcher(Option<JoinHandle<()>>);

impl Watcher {
    fn running(&self) -> bool {
        self.0.as_ref().is_some_and(|w| !w.is_finished())
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}

/// While changes are held for a lost connection, it's tried again this
/// often.
const RETRY_EVERY: Duration = Duration::from_secs(30);

/// Tells the app a request failed: an Append by its id, a download by its
/// message (the reader, a reply and agents' reads wait for it), anything
/// else by what it was.
fn report_failure(request: &Request, error: String, sink: &Sink) {
    match request {
        Request::Append { folder, id, .. } => sink(Event::Appended {
            folder: folder.clone(),
            id: *id,
            error: Some(error),
        }),
        Request::Body {
            folder,
            uid,
            uidvalidity,
            partial,
            ..
        } => sink(Event::Body {
            folder: folder.clone(),
            uid: *uid,
            uidvalidity: *uidvalidity,
            partial: *partial,
            result: Err(if error == "offline" {
                "Not downloaded: the account is offline".into()
            } else {
                error
            }),
        }),
        Request::Files { id, .. } => sink(Event::Files {
            id: *id,
            result: Err(error),
        }),
        Request::PrioritizeBody { .. } => {}
        Request::Conversations {
            folder,
            uidvalidity,
            all,
            ..
        } => sink(Event::Conversations {
            folder: folder.clone(),
            uidvalidity: *uidvalidity,
            all: all.clone(),
            result: Err(error),
        }),
        _ => sink(Event::Failed {
            what: request.what(),
            error,
        }),
    }
}

async fn run_imap(
    creds: Credentials,
    endpoints: Endpoints,
    mut rx: UnboundedReceiver<Request>,
    sink: Sink,
) {
    let mut session: Option<(Session, Caps)> = None;
    let mut failed_at: Option<Instant> = None;
    let mut watcher = Watcher::default();
    // Changes asked for while the connection was down, in order, and how
    // many times each broke a connection that was up.
    let mut held: VecDeque<(Request, u32)> = VecDeque::new();
    let mut requests = VecDeque::new();
    let mut counts = FolderCounts::default();
    let mut waiting = 0;
    let mut report = |n: usize, sink: &Sink| {
        if n != waiting {
            waiting = n;
            sink(Event::Waiting(n));
        }
    };
    loop {
        while let Ok(request) = rx.try_recv() {
            enqueue(&mut requests, request);
        }
        let queued = requests.iter().filter(|r| r.changes()).count();
        report(held.len() + queued, &sink);
        let mut retry = false;
        if requests.is_empty() && (session.is_none() || held.is_empty()) {
            if rx.is_closed() {
                break;
            }
            if let Some((s, _)) = session.as_mut()
                && let Some(folder) = counts.next()
            {
                match imap::status(s, &folder).await {
                    Ok((unread, total)) => sink(Event::Counts {
                        folder,
                        unread,
                        total,
                    }),
                    Err(e) if broken(&e) => {
                        session = None;
                        counts = FolderCounts::default();
                        failed_at = Some(Instant::now());
                        sink(Event::State(login_failed(&e)));
                    }
                    Err(_) => {}
                }
                continue;
            }
            let request = if held.is_empty() {
                rx.recv().await
            } else {
                tokio::select! {
                    next = rx.recv() => next,
                    _ = tokio::time::sleep(RETRY_EVERY) => {
                        retry = true;
                        None
                    }
                }
            };
            if let Some(request) = request {
                enqueue(&mut requests, request);
            } else if !retry {
                break;
            }
            if !retry {
                continue;
            }
        }

        let next = next_imap(&requests);
        if session.is_none() {
            let refresh = requests.iter().position(|r| matches!(r, Request::Folders));
            let recently = failed_at.is_some_and(|at| at.elapsed() < OFFLINE_FOR);
            if recently && refresh.is_none() && !retry {
                if let Some(request) = requests.remove(next) {
                    if request.changes() {
                        held.push_back((request, 0));
                    } else {
                        report_failure(&request, "offline".into(), &sink);
                    }
                }
                continue;
            }
            sink(Event::State(State::Connecting));
            match imap_login(&creds, &endpoints.incoming).await {
                Ok(s) => {
                    if s.1.idle && !watcher.running() {
                        watcher.0 = Some(tokio::spawn(watch_inbox(
                            creds.clone(),
                            endpoints.incoming.clone(),
                            sink.clone(),
                        )));
                    }
                    session = Some(s);
                    failed_at = None;
                    sink(Event::State(State::Online));
                }
                Err(e) => {
                    failed_at = Some(Instant::now());
                    sink(Event::State(login_failed(&e)));
                    let request = requests.remove(next);
                    // One connection attempt serves both the priority download
                    // and the refresh that allowed it through the cooldown.
                    if let Some(i) = refresh.filter(|&i| i != next)
                        && let Some(refresh) = requests.remove(i - usize::from(i > next))
                    {
                        report_failure(&refresh, "offline".into(), &sink);
                    }
                    if let Some(request) = request {
                        if request.changes() {
                            held.push_back((request, 0));
                        } else {
                            report_failure(&request, "offline".into(), &sink);
                        }
                    }
                }
            }
            // Drain requests that arrived while connecting; held writes
            // always replay before any newer work, even explicit opens.
            continue;
        }

        let Some((mut request, tries)) = held
            .pop_front()
            .or_else(|| requests.remove(next).map(|request| (request, 0)))
        else {
            continue;
        };
        if let Err(e) = handle_imap(
            &mut request,
            &mut session,
            &creds,
            &endpoints.incoming,
            &sink,
            &mut counts,
        )
        .await
        {
            let lost = broken(&e);
            let error = text::one_line(&format!("{e:#}"), 300);
            if lost && request.changes() && tries + 1 < MAX_TRIES {
                held.push_front((request, tries + 1));
            } else if lost && request.changes() {
                report_failure(
                    &request,
                    format!("{error} (each of {MAX_TRIES} tries: given up)"),
                    &sink,
                );
            } else {
                report_failure(&request, error.clone(), &sink);
            }
            if lost {
                let state = if session.is_none() {
                    login_failed(&e)
                } else {
                    State::Offline(error)
                };
                session = None;
                counts = FolderCounts::default();
                failed_at = Some(Instant::now());
                sink(Event::State(state));
            }
        }
    }
    if let Some((s, _)) = session {
        imap::logout(s).await;
    }
}

/// SELECTs `folder` for something done to UIDs read under `uidvalidity`
/// (0: unknown). A folder the server has made again since has other
/// messages under those UIDs: that's refused, not done.
async fn select_same(s: &mut Session, folder: &str, uidvalidity: u32) -> Result<imap::Selected> {
    let selected = imap::select(s, folder).await?;
    require_validity(folder, uidvalidity, selected.uidvalidity)?;
    Ok(selected)
}

fn require_validity(folder: &str, requested: u32, found: u32) -> Result<()> {
    if requested != 0 && found != requested {
        return Err(imap::Said(format!(
            "{} was made again on the server, so its messages changed: nothing was done",
            shown_folder(folder)
        ))
        .into());
    }
    Ok(())
}

/// A folder's name as an error message shows it.
fn shown_folder(folder: &str) -> String {
    text::one_line(
        &crate::utf7::decode(folder).unwrap_or_else(|| folder.to_string()),
        60,
    )
}

async fn handle_imap(
    request: &mut Request,
    session: &mut Option<(Session, Caps)>,
    creds: &Credentials,
    incoming: &Endpoint,
    sink: &Sink,
    counts: &mut FolderCounts,
) -> Result<()> {
    let (s, caps) = session.as_mut().expect("connected IMAP worker");
    let caps = *caps;
    // Other async-imap calls don't expose every tagged response code.
    // Only carry a selection across exchanges where we inspect them all.
    if !matches!(
        request,
        Request::Body { .. }
            | Request::Files { .. }
            | Request::Flag {
                flag: FlagKind::Seen,
                ..
            }
    ) {
        imap::forget_selection(s);
    }
    use std::mem::take;
    match request {
        Request::Folders => match imap::folders(s, creds.account()).await {
            Ok(folders) => {
                counts.after_list(&folders);
                sink(Event::Folders(folders));
            }
            Err(e) if !broken(&e) => {
                sink(Event::FoldersRefused(text::one_line(
                    &format!("{e:#}"),
                    300,
                )));
            }
            Err(e) => return Err(e),
        },
        Request::Sync {
            folder,
            known,
            count,
        } => {
            counts.syncing(folder);
            let synced = sync(s, folder, *known, *count).await?;
            counts.synced(folder);
            sink(Event::Synced(synced));
        }
        Request::Older {
            folder,
            below,
            count,
        } => {
            imap::select(s, folder).await?;
            let mut uids = if *below > 1 {
                imap::search(s, &format!("UID 1:{}", *below - 1)).await?
            } else {
                Vec::new()
            };
            uids.retain(|&u| u < *below);
            let keep = uids.len().saturating_sub(*count as usize);
            let uids = &uids[keep..];
            let headers = imap::headers(s, uids).await?;
            let low = uids.first().copied().unwrap_or(1);
            sink(Event::Older {
                folder: take(folder),
                headers,
                low,
            });
        }
        Request::Body {
            folder,
            uid,
            uidvalidity,
            size,
            partial,
            queued,
            ..
        } => {
            imap_timing::finish(*queued, "queue", None);
            if *uidvalidity == 0 {
                return Err(imap::Said(
                    "Refresh the folder before downloading this message".into(),
                )
                .into());
            }
            let selected = imap::select_read(s, folder, *uidvalidity).await?;
            require_validity(folder, *uidvalidity, selected)?;
            let attempted_partial = *partial && (*size == 0 || *size >= PARTIAL_MIN);
            let projected = if attempted_partial {
                match imap_mime::read(s, *uid).await {
                    Err(error) if error.is::<imap::FramingError>() => {
                        // A guarded projection may end mid-response. Do
                        // not reuse that connection for the full fetch.
                        *session = None;
                        *session = Some(imap_login(creds, incoming).await?);
                        None
                    }
                    result => result?.map(Download::Partial),
                }
            } else {
                None
            };
            let body = match projected {
                Some(body) => Some(body),
                None => {
                    let s = &mut session.as_mut().expect("connected IMAP worker").0;
                    // A refused projection can invalidate the selection.
                    if attempted_partial {
                        let current = imap::select_read(s, folder, *uidvalidity).await?;
                        require_validity(folder, selected, current)?;
                    }
                    imap::body(s, *uid, *size).await?.map(Download::Full)
                }
            };
            sink(Event::Body {
                folder: take(folder),
                uid: *uid,
                uidvalidity: selected,
                partial: *partial,
                result: Ok(body),
            });
        }
        Request::Files {
            id,
            folder,
            uid,
            uidvalidity,
            files,
        } => {
            if *uidvalidity == 0 {
                return Err(
                    imap::Said("attachments need a known mailbox UIDVALIDITY".into()).into(),
                );
            }
            let selected = imap::select_read(s, folder, *uidvalidity).await?;
            require_validity(folder, *uidvalidity, selected)?;
            let files = imap_mime::attachments(s, *uid, files).await?;
            sink(Event::Files {
                id: *id,
                result: Ok(files),
            });
        }
        Request::Flag {
            folder,
            uids,
            flag,
            on,
            uidvalidity,
        } => {
            if *flag == FlagKind::Seen {
                let selected = imap::select_read(s, folder, *uidvalidity).await?;
                require_validity(folder, *uidvalidity, selected)?;
            } else {
                select_same(s, folder, *uidvalidity).await?;
            }
            imap::set_flag(s, uids, *flag, *on).await?;
        }
        Request::Tag {
            folder,
            uids,
            tag,
            on,
            uidvalidity,
        } => {
            let selected = select_same(s, folder, *uidvalidity).await?;
            if *on {
                let keyword = tags::keyword(tag).unwrap_or_default();
                // A keyword the folder can't keep would be gone at the
                // next connection, with no word said.
                if !selected.keeps(&keyword) {
                    return Err(imap::Said(format!(
                        "{} doesn't keep tags on the server",
                        shown_folder(folder)
                    ))
                    .into());
                }
                imap::set_keywords(s, uids, &[keyword], true).await?;
            } else {
                imap::set_keywords(s, uids, &tags::keywords(tag), false).await?;
            }
        }
        Request::Move {
            folder,
            uids,
            to,
            uidvalidity,
        } => {
            select_same(s, folder, *uidvalidity).await?;
            // Where they'll be, so the move can be undone: from `to`'s
            // UIDNEXT on. Not known if the server doesn't say.
            let (to_uidvalidity, floor) = match imap::uid_next(s, to).await {
                Ok(next) => next,
                Err(e) if e.is::<imap::Said>() => (0, 0),
                Err(e) => return Err(e),
            };
            imap::move_to(s, caps, uids, to).await?;
            sink(Event::Moved {
                folder: take(folder),
                uidvalidity: *uidvalidity,
                uids: take(uids),
                to: to.clone(),
                to_uidvalidity,
                floor,
            });
            sink(Event::Done { folder: take(to) });
        }
        Request::MoveBack {
            folder,
            uidvalidity,
            floor,
            moved,
            to,
        } => {
            // The folder as it was when they were moved there.
            select_same(s, folder, *uidvalidity).await?;
            let uids = imap::find_moved(s, moved, *floor).await?;
            if !uids.is_empty() {
                imap::move_to(s, caps, &uids, to).await?;
            }
            sink(Event::MovedBack {
                folder: take(folder),
                to: take(to),
                moved: uids,
                asked: moved.len(),
            });
        }
        Request::Delete {
            folder,
            uids,
            uidvalidity,
        } => {
            select_same(s, folder, *uidvalidity).await?;
            let all = imap::delete(s, caps, uids).await?;
            sink(Event::Deleted {
                folder: take(folder),
                uids: take(uids),
                all,
            });
        }
        Request::Append {
            folder,
            raw,
            flags,
            id,
            ..
        } => {
            if let Err(e) = imap::append(s, folder, raw, flags.clone()).await {
                // A folder that isn't there yet (Sent, Drafts) is made.
                if broken(&e) {
                    return Err(e);
                }
                imap::create(s, folder).await?;
                imap::append(s, folder, raw, flags.clone()).await?;
            }
            sink(Event::Appended {
                folder: take(folder),
                id: *id,
                error: None,
            });
        }
        Request::Headers {
            folder,
            uids,
            uidvalidity,
        } => {
            select_same(s, folder, *uidvalidity).await?;
            let headers = imap::headers(s, uids).await?;
            sink(Event::Headers {
                folder: take(folder),
                headers,
            });
        }
        Request::Conversations {
            folder,
            uidvalidity,
            uids,
            thread_ids,
            all,
        } => {
            let result = if caps.gmail {
                Some(conversations(s, folder, *uidvalidity, uids, thread_ids, all).await?)
            } else {
                None
            };
            sink(Event::Conversations {
                folder: take(folder),
                uidvalidity: *uidvalidity,
                all: take(all),
                result: Ok(result),
            });
        }
        Request::Search {
            folder,
            query,
            generation,
        } => {
            let Some(criteria) = imap::search_criteria(query) else {
                return Ok(());
            };
            let selected = imap::select(s, folder).await?;
            let uids = imap::search(s, &criteria).await?;
            // The newest matches.
            let keep = uids.len().saturating_sub(200);
            let headers = imap::headers(s, &uids[keep..]).await?;
            sink(Event::Searched {
                folder: take(folder),
                generation: *generation,
                uidvalidity: selected.uidvalidity,
                headers,
            });
        }
        Request::Pop { .. } | Request::PrioritizeBody { .. } => {}
    }
    Ok(())
}

async fn conversations(
    s: &mut Session,
    folder: &str,
    uidvalidity: u32,
    uids: &[u32],
    thread_ids: &[u64],
    all: &str,
) -> Result<Conversations> {
    if uidvalidity == 0
        || uids.len().saturating_add(thread_ids.len()) > CONVERSATION_BATCH
        || uids.contains(&0)
        || thread_ids.contains(&0)
    {
        return Err(imap::Said(
            "Gmail conversations need a known mailbox and bounded native IDs".into(),
        )
        .into());
    }
    let selected = select_same(s, folder, uidvalidity).await?;
    let seeds = imap::gmail_metadata(s, uids).await?;
    let mut threads: Vec<u64> = thread_ids
        .iter()
        .copied()
        .chain(seeds.iter().map(|(_, gmail)| gmail.thread_id))
        .collect();
    threads.sort_unstable();
    threads.dedup();
    let source_uids = imap::gmail_thread_uids(s, &threads).await?;
    let (all_uidvalidity, source, headers) = if folder == all {
        let headers = imap::gmail_headers(s, &source_uids, &threads).await?;
        let source = headers
            .iter()
            .filter_map(|header| header.gmail.map(|gmail| (header.uid, gmail)))
            .collect();
        (selected.uidvalidity, source, headers)
    } else {
        let mut source = imap::gmail_metadata(s, &source_uids).await?;
        source.retain(|(_, gmail)| threads.binary_search(&gmail.thread_id).is_ok());
        let target = imap::select(s, all).await?;
        if target.uidvalidity == 0 {
            return Err(imap::Said("All Mail did not provide UIDVALIDITY".into()).into());
        }
        let all_uids = imap::gmail_thread_uids(s, &threads).await?;
        let headers = imap::gmail_headers(s, &all_uids, &threads).await?;
        (target.uidvalidity, source, headers)
    };
    Ok(Conversations {
        source_uidvalidity: selected.uidvalidity,
        all_uidvalidity,
        source,
        headers,
        thread_ids: threads,
    })
}

/// What's new in `folder` since `known`, and the flags of what's cached.
async fn sync(s: &mut Session, folder: &str, known: Known, count: u32) -> Result<Synced> {
    let selected = imap::select(s, folder).await?;
    let reset = known.uidvalidity != 0 && known.uidvalidity != selected.uidvalidity;
    let known = if reset || known.uidvalidity == 0 {
        Known::default()
    } else {
        known
    };
    let count = count.max(1) as usize;
    let mut new_uids: Vec<u32> = if selected.exists == 0 {
        Vec::new()
    } else if known.high == 0 {
        // The newest `count`, by their place in the folder.
        let start = selected.exists.saturating_sub(count as u32 - 1).max(1);
        imap::uids_at(s, start, selected.exists).await?
    } else {
        // Past the last UID there are none (`high + 1` would wrap to 0, and
        // `0:*` is every message).
        match known.high.checked_add(1) {
            Some(next) => {
                let mut uids = imap::search(s, &format!("UID {next}:*")).await?;
                uids.retain(|&u| u > known.high);
                uids
            }
            None => Vec::new(),
        }
    };
    let gap = new_uids.len() > count;
    if gap {
        new_uids.drain(..new_uids.len() - count);
    }
    let new = imap::headers(s, &new_uids).await?;
    let (flags, checked) = if known.high > 0 && !gap {
        (
            imap::flags(s, known.low, known.high).await?,
            Some((known.low, known.high)),
        )
    } else {
        (Vec::new(), None)
    };
    let low = if known.high == 0 || gap {
        new_uids.first().copied().unwrap_or(0)
    } else {
        known.low
    };
    let high = new_uids.last().copied().unwrap_or(0).max(known.high);
    let unread = match imap::search(s, "UNSEEN").await {
        Ok(uids) => uids.len() as u32,
        Err(e) if !broken(&e) => 0,
        Err(e) => return Err(e),
    };
    Ok(Synced {
        folder: folder.to_string(),
        uidvalidity: selected.uidvalidity,
        reset: reset || gap,
        new,
        flags,
        checked,
        low,
        high,
        unread,
        total: selected.exists,
    })
}

/// Waits on the inbox with IDLE on a connection of its own, reporting each
/// change; reconnects after a failure, waiting longer each time.
async fn watch_inbox(creds: Credentials, endpoint: Endpoint, sink: Sink) {
    let mut wait = Duration::from_secs(15);
    loop {
        let result: Result<()> = async {
            let (mut session, _) = imap_login(&creds, &endpoint).await?;
            tokio::time::timeout(imap::TIMEOUT, session.examine("INBOX"))
                .await
                .map_err(|_| anyhow!("EXAMINE: the server stopped answering"))??;
            wait = Duration::from_secs(15);
            loop {
                let (back, changed) = imap::idle(session, IDLE_FOR).await?;
                session = back;
                if changed {
                    sink(Event::Changed {
                        folder: "INBOX".into(),
                    });
                    // Changes come in bursts (a message, then its flags).
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
        .await;
        if let Err(e) = result
            && matches!(login_failed(&e), State::NeedPassword { .. })
        {
            // The worker asks for the password; this waits for it.
            wait = Duration::from_secs(60);
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(Duration::from_secs(10 * 60));
    }
}

async fn run_pop(
    creds: Credentials,
    endpoints: Endpoints,
    mut rx: UnboundedReceiver<Request>,
    sink: Sink,
) {
    while let Some(first) = rx.recv().await {
        for request in pop_batch(first, &mut rx) {
            let Request::Pop {
                seen,
                remove,
                count,
                first_check,
            } = request
            else {
                continue;
            };
            sink(Event::State(State::Connecting));
            let check = pop_check(
                &creds,
                &endpoints.incoming,
                &seen,
                &remove,
                count,
                first_check,
            );
            match check.await {
                Ok(popped) => {
                    sink(Event::State(State::Online));
                    sink(Event::Popped(popped));
                }
                Err(e) => {
                    let state = login_failed(&e);
                    // The state says it all when the password is wanted.
                    let said = matches!(state, State::NeedPassword { .. });
                    sink(Event::State(state));
                    if !said {
                        sink(Event::Failed {
                            what: "checking for mail",
                            error: text::one_line(&format!("{e:#}"), 300),
                        });
                    }
                }
            }
        }
    }
}

/// One POP3 session: new mail downloaded (newest first, at most
/// [`POP_BATCH`]), `remove` deleted from the server.
async fn pop_check(
    creds: &Credentials,
    endpoint: &Endpoint,
    seen: &HashSet<String>,
    remove: &[String],
    count: u32,
    first_check: bool,
) -> Result<Popped> {
    let secret = creds.get().await?;
    let account = creds.account();
    let mut pop =
        match pop3::connect(endpoint, account.username(), secret.expose(), account.auth).await {
            Ok(pop) => pop,
            Err(e) => {
                if e.downcast_ref::<pop3::Refused>().is_some() {
                    creds.refused(&secret).await;
                }
                return Err(e);
            }
        };
    let _ = creds.remember(&secret).await;
    let ids = pop.uidl().await?;
    let sizes: HashMap<u32, u64> = pop.list().await?.into_iter().collect();
    let mut popped = Popped {
        on_server: ids.iter().map(|(_, id)| id.clone()).collect(),
        ..Popped::default()
    };
    let mut new: Vec<&(u32, String)> = ids.iter().filter(|(_, id)| !seen.contains(id)).collect();
    // Newest (highest number) first.
    new.sort_by_key(|(n, _)| std::cmp::Reverse(*n));
    if first_check && new.len() > count as usize {
        // A first check takes the newest share; the rest stay on the server.
        popped
            .skipped
            .extend(new.drain(count as usize..).map(|(_, id)| id.clone()));
    }
    if new.len() > POP_BATCH {
        new.truncate(POP_BATCH);
        popped.more = true;
    }
    let mut bytes = 0;
    for (n, id) in new {
        if sizes.get(n).copied().unwrap_or(0) > POP_MAX as u64 {
            popped.skipped.push(id.clone());
            continue;
        }
        if bytes > POP_BYTES {
            // The rest at the next check, so memory stays bounded.
            popped.more = true;
            break;
        }
        match pop.retr(*n, POP_MAX).await {
            Ok(raw) => {
                bytes += raw.len();
                popped.new.push((id.clone(), raw));
            }
            Err(e) if e.downcast_ref::<pop3::TooBig>().is_some() => popped.skipped.push(id.clone()),
            Err(e) if e.downcast_ref::<pop3::BadMessage>().is_some() => {
                // The session is out of step: what came so far is kept,
                // this message skipped for good, the rest next time. No
                // QUIT, so nothing is deleted.
                popped.skipped.push(id.clone());
                popped.more = true;
                return Ok(popped);
            }
            Err(e) => return Err(e),
        }
    }
    let mut deleting = Vec::new();
    for id in remove {
        if let Some((n, _)) = ids.iter().find(|(_, i)| i == id) {
            pop.dele(*n).await?;
            deleting.push(id.clone());
        } else {
            // Already gone from the server.
            popped.deleted.push(id.clone());
        }
    }
    // Deletions happen only once QUIT is answered.
    pop.quit().await?;
    popped.deleted.extend(deleting);
    Ok(popped)
}

/// Sends `raw` through the account's SMTP server.
pub async fn send(
    creds: Credentials,
    endpoint: Endpoint,
    from: String,
    to: Vec<String>,
    raw: Vec<u8>,
) -> Result<()> {
    let secret = creds.get().await?;
    let account = creds.account();
    let result = smtp::send(
        &endpoint,
        account.smtp_username(),
        secret.expose(),
        account.auth,
        &from,
        &to,
        &raw,
    )
    .await;
    if let Err(e) = &result
        && e.chain()
            .any(|c| c.downcast_ref::<smtp::Refused>().is_some())
        && account.smtp_username() == account.username()
    {
        creds.refused(&secret).await;
    }
    result
}

/// Whether an error means the password is needed or was refused.
pub fn needs_password(error: &anyhow::Error) -> bool {
    error.chain().any(|c| {
        c.downcast_ref::<NeedPassword>().is_some()
            || c.downcast_ref::<smtp::Refused>().is_some()
            || c.downcast_ref::<imap::Refused>().is_some()
            || c.downcast_ref::<pop3::Refused>().is_some()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_checks_waiting_together_run_once() {
        let (tx, mut rx) = unbounded_channel();
        let sync = |folder: &str, high| Request::Sync {
            folder: folder.into(),
            known: Known {
                uidvalidity: 1,
                low: 1,
                high,
            },
            count: 10,
        };
        tx.send(sync("INBOX", 5)).unwrap();
        tx.send(Request::Folders).unwrap();
        tx.send(sync("Sent", 1)).unwrap();
        tx.send(Request::Folders).unwrap();
        let first = sync("INBOX", 3);
        let all = pop_batch(first, &mut rx);
        assert_eq!(all.len(), 3, "{all:?}");
        assert!(matches!(&all[2], Request::Folders));
        assert!(
            matches!(&all[0], Request::Sync { known, .. } if known.high == 5),
            "the latest"
        );
    }

    #[test]
    fn one_download_answers_every_read_waiting_for_it() {
        let (tx, mut rx) = unbounded_channel();
        let body = |uid| Request::Body {
            folder: "INBOX".into(),
            uid,
            uidvalidity: 7,
            size: 0,
            partial: false,
            urgent: false,
            queued: None,
        };
        for uid in [9, 9, 8, 9] {
            tx.send(body(uid)).unwrap();
        }
        let all = pop_batch(body(9), &mut rx);
        let uids: Vec<u32> = (all.iter())
            .map(|r| match r {
                Request::Body { uid, .. } => *uid,
                _ => 0,
            })
            .collect();
        assert_eq!(uids, [9, 8]);
    }

    #[test]
    fn login_failures_are_told_apart() {
        let need = anyhow!(NeedPassword);
        assert_eq!(login_failed(&need), State::NeedPassword { refused: false });
        let refused = anyhow!(imap::Refused("no".into()));
        assert_eq!(
            login_failed(&refused),
            State::NeedPassword { refused: true }
        );
        assert!(matches!(
            login_failed(&anyhow!("timeout")),
            State::Offline(_)
        ));
        assert!(needs_password(
            &anyhow!(smtp::Refused("x".into())).context("cannot log in")
        ));
    }

    #[test]
    fn a_download_that_fails_is_answered_as_that_download() {
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = events.clone();
        let sink: Sink = Arc::new(move |e| kept.lock().unwrap().push(e));
        let body = Request::Body {
            folder: "INBOX".into(),
            uid: 9,
            uidvalidity: 7,
            size: 0,
            partial: true,
            urgent: false,
            queued: None,
        };
        report_failure(&body, "offline".into(), &sink);
        let events = events.lock().unwrap();
        // The reader, a reply and agents' reads wait for this one.
        assert!(
            matches!(&events[..], [Event::Body {
                uid: 9, uidvalidity: 7, partial: true, result: Err(e), ..
            }] if e.contains("offline")),
            "{events:?}"
        );
    }

    #[tokio::test]
    async fn inbox_sync_and_an_explicit_open_go_before_background_downloads_and_counts() {
        let (log_tx, mut commands) = unbounded_channel();
        let endpoint = imap::tests::scripted_endpoint("IMAP4rev1", move |tag, command| {
            log_tx.send(command.to_string()).unwrap();
            let response = match command {
                "LIST \"\" *" => "* LIST () \"/\" INBOX\r\n* LIST () \"/\" Archive\r\n",
                "SELECT \"INBOX\"" => "* 0 EXISTS\r\n* OK [UIDVALIDITY 7] stable\r\n",
                "UID SEARCH UNSEEN" => "* SEARCH\r\n",
                "STATUS \"Archive\" (MESSAGES UNSEEN)" => {
                    "* STATUS Archive (MESSAGES 2 UNSEEN 1)\r\n"
                }
                "LOGOUT" => "* BYE closing\r\n",
                c if c == format!("UID FETCH 1 (UID BODY.PEEK[]<0.{}>)", imap::MAX_MESSAGE + 1) => {
                    "* 1 FETCH (UID 1 BODY[]<0> {3}\r\none)\r\n"
                }
                c if c == format!("UID FETCH 2 (UID BODY.PEEK[]<0.{}>)", imap::MAX_MESSAGE + 1) => {
                    "* 2 FETCH (UID 2 BODY[]<0> {3}\r\ntwo)\r\n"
                }
                _ => panic!("unexpected command: {command}"),
            };
            format!("{response}{tag} OK done\r\n").into_bytes()
        })
        .await;
        let account = Arc::new(Account {
            email: "me@example.org".into(),
            ..Account::default()
        });
        let creds = Credentials::new(account, false);
        creds.set(crate::secrets::Secret::new("pw")).await;
        let endpoints = Endpoints {
            smtp: endpoint.clone(),
            incoming: endpoint,
        };
        let (tx, rx) = unbounded_channel();
        let from_list = tx.clone();
        let from_sync = tx.clone();
        let (events, mut receive) = unbounded_channel();
        let sink: Sink = Arc::new(move |event| {
            if matches!(&event, Event::Folders(_)) {
                from_list
                    .send(Request::Sync {
                        folder: "INBOX".into(),
                        known: Known::default(),
                        count: 10,
                    })
                    .unwrap();
                for uid in [1, 2] {
                    from_list
                        .send(Request::Body {
                            folder: "INBOX".into(),
                            uid,
                            uidvalidity: 7,
                            size: 3,
                            partial: false,
                            urgent: false,
                            queued: None,
                        })
                        .unwrap();
                }
            }
            if matches!(&event, Event::Synced(_)) {
                // The preview is already queued when the user opens it.
                from_sync
                    .send(Request::PrioritizeBody {
                        folder: "INBOX".into(),
                        uid: 2,
                        uidvalidity: 7,
                    })
                    .unwrap();
            }
            events.send(event).unwrap();
        });
        tx.send(Request::Folders).unwrap();
        let worker = tokio::spawn(run_imap(creds, endpoints, rx, sink));
        let (folders, synced, downloaded) = tokio::time::timeout(Duration::from_secs(5), async {
            let mut folders = false;
            let mut synced = false;
            let mut downloaded = Vec::new();
            while let Some(event) = receive.recv().await {
                match event {
                    Event::Folders(rows) => {
                        assert!(
                            rows.iter()
                                .all(|folder| folder.total == 0 && folder.unread == 0)
                        );
                        folders = true;
                    }
                    Event::Synced(_) => synced = true,
                    Event::Body {
                        uid,
                        result: Ok(Some(Download::Full(_))),
                        ..
                    } => downloaded.push(uid),
                    Event::Counts {
                        folder,
                        unread: 1,
                        total: 2,
                    } if folder == "Archive" => break,
                    Event::State(State::Offline(e)) | Event::Failed { error: e, .. } => {
                        panic!("{e}")
                    }
                    _ => {}
                }
            }
            (folders, synced, downloaded)
        })
        .await
        .unwrap();
        worker.abort();
        assert!(folders && synced);
        assert_eq!(downloaded, [2, 1]);
        let commands: Vec<String> = std::iter::from_fn(|| commands.try_recv().ok()).collect();
        assert_eq!(
            commands,
            [
                "LIST \"\" *".into(),
                "SELECT \"INBOX\"".into(),
                "UID SEARCH UNSEEN".into(),
                "SELECT \"INBOX\"".into(),
                format!("UID FETCH 2 (UID BODY.PEEK[]<0.{}>)", imap::MAX_MESSAGE + 1),
                format!("UID FETCH 1 (UID BODY.PEEK[]<0.{}>)", imap::MAX_MESSAGE + 1),
                "STATUS \"Archive\" (MESSAGES UNSEEN)".into(),
            ]
        );
    }

    #[tokio::test]
    async fn a_queued_refresh_reconnects_before_an_open_even_during_cooldown() {
        let endpoint = imap::tests::scripted_connections("IMAP4rev1", 2, |i, tag, command| {
            if i == 0 {
                assert_eq!(command, "LIST \"\" *");
                return Vec::new(); // The old connection is lost.
            }
            let reply = match command {
                "SELECT \"INBOX\"" => "* OK [UIDVALIDITY 7] stable\r\n",
                c if c == format!("UID FETCH 2 (UID BODY.PEEK[]<0.{}>)", imap::MAX_MESSAGE + 1) => {
                    "* 2 FETCH (UID 2 BODY[]<0> {3}\r\ntwo)\r\n"
                }
                "LIST \"\" *" => "* LIST () \"/\" INBOX\r\n",
                _ => panic!("unexpected command: {command}"),
            };
            format!("{reply}{tag} OK done\r\n").into_bytes()
        })
        .await;
        let creds = Credentials::new(
            Arc::new(Account {
                email: "me@example.org".into(),
                ..Account::default()
            }),
            false,
        );
        creds.set(crate::secrets::Secret::new("pw")).await;
        let endpoints = Endpoints {
            smtp: endpoint.clone(),
            incoming: endpoint,
        };
        let (tx, rx) = unbounded_channel();
        let after_loss = tx.clone();
        let (events, mut receive) = unbounded_channel();
        let retried = std::sync::atomic::AtomicBool::new(false);
        let sink: Sink = Arc::new(move |event| {
            if matches!(&event, Event::State(State::Offline(_))) {
                assert!(!retried.swap(true, std::sync::atomic::Ordering::Relaxed));
                after_loss.send(Request::Folders).unwrap();
                after_loss
                    .send(Request::Body {
                        folder: "INBOX".into(),
                        uid: 2,
                        uidvalidity: 7,
                        size: 3,
                        partial: false,
                        urgent: true,
                        queued: None,
                    })
                    .unwrap();
            }
            events.send(event).unwrap();
        });
        tx.send(Request::Folders).unwrap();
        let worker = tokio::spawn(run_imap(creds, endpoints, rx, sink));
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut opened = false;
            loop {
                match receive.recv().await.unwrap() {
                    Event::Body { uid: 2, result, .. } => {
                        let Some(Download::Full(raw)) = result.unwrap() else {
                            panic!("message didn't download");
                        };
                        assert_eq!(raw, b"two");
                        opened = true;
                    }
                    Event::Folders(_) => {
                        assert!(opened, "refresh overtook the explicit open");
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
        worker.abort();
    }

    #[tokio::test]
    async fn a_projection_over_the_framing_limit_retries_the_full_message_only_under_the_same_uidvalidity()
     {
        for renewed in [7, 8] {
            let endpoint =
                imap::tests::scripted_connections("IMAP4rev1", 2, move |i, tag, command| {
                    let reply = match (i, command) {
                        (0, "SELECT \"INBOX\"") => "* OK [UIDVALIDITY 7] stable\r\n".into(),
                        (0, "UID FETCH 1 (UID BODYSTRUCTURE)") => {
                            let mut structure =
                                "(\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 3 1)".to_owned();
                            for _ in 0..33 {
                                structure = format!("({structure} \"MIXED\")");
                            }
                            format!("* 1 FETCH (UID 1 BODYSTRUCTURE {structure})\r\n")
                        }
                        (1, "SELECT \"INBOX\"") => {
                            format!("* OK [UIDVALIDITY {renewed}] stable\r\n")
                        }
                        (1, c)
                            if renewed == 7
                                && c == format!(
                                    "UID FETCH 1 (UID BODY.PEEK[]<0.{}>)",
                                    imap::MAX_MESSAGE + 1
                                ) =>
                        {
                            "* 1 FETCH (UID 1 BODY[]<0> {3}\r\none)\r\n".into()
                        }
                        _ => panic!("unexpected command on connection {i}: {command}"),
                    };
                    format!("{reply}{tag} OK done\r\n").into_bytes()
                })
                .await;
            let creds = Credentials::new(
                Arc::new(Account {
                    email: "me@example.org".into(),
                    ..Account::default()
                }),
                false,
            );
            creds.set(crate::secrets::Secret::new("pw")).await;
            let mut session = Some(imap_login(&creds, &endpoint).await.unwrap());
            let (events, mut received) = unbounded_channel();
            let sink: Sink = Arc::new(move |event| events.send(event).unwrap());
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                handle_imap(
                    &mut Request::Body {
                        folder: "INBOX".into(),
                        uid: 1,
                        uidvalidity: 7,
                        size: PARTIAL_MIN,
                        partial: true,
                        urgent: true,
                        queued: None,
                    },
                    &mut session,
                    &creds,
                    &endpoint,
                    &sink,
                    &mut FolderCounts::default(),
                ),
            )
            .await
            .unwrap();
            if renewed == 7 {
                result.unwrap();
                assert!(matches!(
                    received.try_recv().unwrap(),
                    Event::Body { result: Ok(Some(Download::Full(bytes))), .. } if bytes == b"one"
                ));
            } else {
                let error = result.unwrap_err();
                assert!(error.is::<imap::Said>() && error.to_string().contains("was made again"));
                assert!(received.try_recv().is_err());
            }
        }
    }

    #[test]
    fn promoting_a_preview_does_not_jump_an_earlier_change_or_draft_append() {
        let mut requests = VecDeque::from([
            Request::Body {
                folder: "INBOX".into(),
                uid: 1,
                uidvalidity: 7,
                size: 2,
                partial: true,
                urgent: false,
                queued: None,
            },
            Request::Flag {
                folder: "INBOX".into(),
                uids: vec![1],
                flag: FlagKind::Seen,
                on: true,
                uidvalidity: 7,
            },
            Request::Append {
                folder: "Drafts".into(),
                raw: Vec::new(),
                flags: Flags::default(),
                id: 3,
                retry: false,
            },
        ]);
        for uid in [1, 2] {
            enqueue(
                &mut requests,
                Request::PrioritizeBody {
                    folder: "INBOX".into(),
                    uid,
                    uidvalidity: 7,
                },
            );
        }
        assert!(matches!(
            requests.remove(next_imap(&requests)),
            Some(Request::Flag { .. })
        ));
        assert!(matches!(
            requests.remove(next_imap(&requests)),
            Some(Request::Append { .. })
        ));
        assert!(matches!(
            requests.pop_front(),
            Some(Request::Body {
                uid: 1,
                urgent: true,
                ..
            })
        ));
        assert!(requests.is_empty());
    }

    fn gmail_header(
        uid: u32,
        message_id: u64,
        thread_id: u64,
        labels: &str,
        flags: &str,
    ) -> String {
        let header = "From: \"Other\" <other@example.org>\r\nTo: me@example.org\r\nSubject: A native thread\r\n\r\n";
        format!(
            "* {uid} FETCH (UID {uid} FLAGS ({flags}) RFC822.SIZE 123 INTERNALDATE \"01-Jan-2026 00:00:00 +0000\" \
             X-GM-MSGID {message_id} X-GM-THRID {thread_id} X-GM-LABELS ({labels}) \
             BODY[HEADER.FIELDS (FROM TO CC SUBJECT DATE MESSAGE-ID IN-REPLY-TO REFERENCES CONTENT-TYPE)] {{{}}}\r\n{header})\r\n",
            header.len()
        )
    }

    #[tokio::test]
    async fn gmail_conversations_fetch_complete_source_mappings_and_all_mail_headers_only() {
        const THREAD: u64 = u64::MAX - 2;
        const FIRST: u64 = u64::MAX - 1;
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        let (mut session, caps) = imap::tests::scripted_capabilities("IMAP4rev1 X-GM-EXT-1", move |tag, command| {
            let step = seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let answer = match step {
                0 => {
                    assert_eq!(command, "SELECT \"INBOX\"");
                    "* 6 EXISTS\r\n* OK [UIDVALIDITY 7] stable\r\n".into()
                }
                1 => {
                    assert_eq!(command, "UID FETCH 1 (UID FLAGS X-GM-MSGID X-GM-THRID X-GM-LABELS)");
                    format!("* 1 FETCH (UID 1 FLAGS () X-GM-MSGID {FIRST} X-GM-THRID {THREAD} X-GM-LABELS (\\Inbox))\r\n\
                             * 8 FETCH (UID 88 X-GM-MSGID 10 X-GM-THRID 10 X-GM-LABELS ())\r\n")
                }
                2 => {
                    assert_eq!(command, format!("UID SEARCH X-GM-THRID {THREAD}"));
                    "* SEARCH 1 4 5 6\r\n".into()
                }
                3 => {
                    assert_eq!(command, "UID FETCH 1,4:6 (UID FLAGS X-GM-MSGID X-GM-THRID X-GM-LABELS)");
                    format!("* 1 FETCH (UID 1 FLAGS () X-GM-MSGID {FIRST} X-GM-THRID {THREAD} X-GM-LABELS (\\Inbox))\r\n\
                             * 2 FETCH (UID 4 FLAGS () X-GM-MSGID 44 X-GM-THRID {THREAD} X-GM-LABELS (\"Sent\"))\r\n\
                             * 3 FETCH (UID 5 FLAGS () X-GM-MSGID 55 X-GM-THRID 55 X-GM-LABELS ())\r\n\
                             * 4 FETCH (UID 6 FLAGS (\\Deleted) X-GM-MSGID 66 X-GM-THRID {THREAD} X-GM-LABELS ())\r\n\
                             * 1 FETCH (UID 1 FLAGS () X-GM-MSGID 1 X-GM-THRID 1 X-GM-LABELS ())\r\n\
                             * 9 FETCH (UID 77 FLAGS () X-GM-MSGID 77 X-GM-THRID {THREAD} X-GM-LABELS ())\r\n")
                }
                4 => {
                    assert_eq!(command, "SELECT \"[Gmail]/All Mail\"");
                    "* 100000 EXISTS\r\n* OK [UIDVALIDITY 9] stable\r\n".into()
                }
                5 => {
                    assert_eq!(command, format!("UID SEARCH X-GM-THRID {THREAD}"));
                    "* SEARCH 8 9 10 11\r\n".into()
                }
                6 => {
                    assert!(command.starts_with("UID FETCH 8:11 (UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[HEADER.FIELDS ("), "{command}");
                    assert!(command.ends_with("X-GM-MSGID X-GM-THRID X-GM-LABELS)"), "{command}");
                    let mut out = "* 8 FETCH (UID 8 FLAGS (\\Seen))\r\n".to_string();
                    out.push_str(&gmail_header(8, FIRST, THREAD, "\\Inbox", "\\Seen"));
                    out.push_str(&gmail_header(9, u64::MAX, THREAD, "\\Sent", ""));
                    out.push_str(&gmail_header(10, 10, 10, "", ""));
                    out.push_str(&gmail_header(11, 11, THREAD, "", "\\Deleted"));
                    out.push_str(&gmail_header(88, 88, THREAD, "", ""));
                    out.push_str(&gmail_header(9, 1, THREAD, "", ""));
                    out
                }
                _ => panic!("unexpected command: {command}"),
            };
            format!("{answer}{tag} OK done\r\n").into_bytes()
        }).await;
        assert!(
            caps.gmail,
            "CAPABILITY, not the account host, gates the extension"
        );
        let got = conversations(&mut session, "INBOX", 7, &[1], &[], "[Gmail]/All Mail")
            .await
            .unwrap();
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 7);
        assert_eq!((got.source_uidvalidity, got.all_uidvalidity), (7, 9));
        assert_eq!(got.thread_ids, [THREAD]);
        assert_eq!(
            got.source.iter().map(|(uid, _)| *uid).collect::<Vec<_>>(),
            [1, 4]
        );
        assert!(
            !got.source[1].1.sent,
            "a user label named Sent isn't the standard label"
        );
        assert_eq!(
            got.headers.iter().map(|h| h.uid).collect::<Vec<_>>(),
            [8, 9]
        );
        assert_eq!(got.headers[0].gmail.unwrap().message_id, FIRST);
        assert_eq!(got.headers[1].gmail.unwrap().message_id, u64::MAX);
        assert!(got.headers[1].gmail.unwrap().sent);
        assert!(got.headers[0].flags.seen);
        assert_eq!(got.headers[0].size, 123);
        assert!(
            got.headers[0].summary.date > 0,
            "INTERNALDATE supplies missing Date"
        );
    }

    #[tokio::test]
    async fn gmail_known_threads_survive_an_empty_source_folder() {
        let mut step = 0;
        let (mut session, _) =
            imap::tests::scripted_capabilities("IMAP4rev1 X-GM-EXT-1", move |tag, command| {
                let answer = match step {
                    0 => {
                        assert_eq!(command, "SELECT \"INBOX\"");
                        "* 0 EXISTS\r\n* OK [UIDVALIDITY 7] stable\r\n".into()
                    }
                    1 => {
                        assert_eq!(
                            command,
                            "UID SEARCH OR OR X-GM-THRID 8 X-GM-THRID 9 X-GM-THRID 10"
                        );
                        "* SEARCH\r\n".into()
                    }
                    2 => {
                        assert_eq!(command, "SELECT \"All\"");
                        "* 100 EXISTS\r\n* OK [UIDVALIDITY 9] stable\r\n".into()
                    }
                    3 => {
                        assert_eq!(
                            command,
                            "UID SEARCH OR OR X-GM-THRID 8 X-GM-THRID 9 X-GM-THRID 10"
                        );
                        "* SEARCH 20\r\n".into()
                    }
                    4 => {
                        assert!(command.starts_with("UID FETCH 20 "));
                        gmail_header(20, 21, 9, "\\Sent", "")
                    }
                    _ => panic!("unexpected command: {command}"),
                };
                step += 1;
                format!("{answer}{tag} OK done\r\n").into_bytes()
            })
            .await;
        let got = conversations(&mut session, "INBOX", 7, &[], &[10, 9, 8, 9], "All")
            .await
            .unwrap();
        assert_eq!(got.thread_ids, [8, 9, 10]);
        assert!(got.source.is_empty());
        assert_eq!(got.headers.len(), 1);
        assert_eq!(got.headers[0].gmail.unwrap().thread_id, 9);
    }

    #[tokio::test]
    async fn gmail_all_mail_source_reuses_the_select_search_and_header_metadata() {
        let mut step = 0;
        let (mut session, _) =
            imap::tests::scripted_capabilities("IMAP4rev1 X-GM-EXT-1", move |tag, command| {
                let answer = match step {
                    0 => {
                        assert_eq!(command, "SELECT \"All\"");
                        "* 2 EXISTS\r\n* OK [UIDVALIDITY 9] stable\r\n".into()
                    }
                    1 => {
                        assert_eq!(command, "UID SEARCH X-GM-THRID 8");
                        "* SEARCH 20\r\n".into()
                    }
                    2 => {
                        assert!(command.starts_with("UID FETCH 20 "));
                        gmail_header(20, 21, 8, "\\Sent", "")
                    }
                    _ => panic!("unexpected command: {command}"),
                };
                step += 1;
                format!("{answer}{tag} OK done\r\n").into_bytes()
            })
            .await;
        let got = conversations(&mut session, "All", 9, &[], &[8], "All")
            .await
            .unwrap();
        assert_eq!((got.source_uidvalidity, got.all_uidvalidity), (9, 9));
        assert_eq!(got.source, [(20, got.headers[0].gmail.unwrap())]);
    }

    #[tokio::test]
    async fn gmail_requests_refuse_unknown_changed_or_missing_uidvalidity() {
        for (expected, advertised, all) in [
            (0, 7, "INBOX"),
            (7, 8, "INBOX"),
            (7, 0, "INBOX"),
            (7, 7, "All"),
        ] {
            let (mut session, _) =
                imap::tests::scripted_capabilities("IMAP4rev1 X-GM-EXT-1", move |tag, command| {
                    let validity = if command == "SELECT \"INBOX\"" {
                        advertised
                    } else {
                        assert_eq!(command, "SELECT \"All\"");
                        0
                    };
                    let code = if validity == 0 {
                        String::new()
                    } else {
                        format!("* OK [UIDVALIDITY {validity}] stable\r\n")
                    };
                    format!("* 0 EXISTS\r\n{code}{tag} OK done\r\n").into_bytes()
                })
                .await;
            let error = conversations(&mut session, "INBOX", expected, &[], &[], all)
                .await
                .unwrap_err();
            assert!(!broken(&error), "{error:#}");
        }
    }

    #[tokio::test]
    async fn gmail_unsupported_is_a_correlated_success_without_sending_commands() {
        let endpoint = imap::tests::scripted_endpoint("IMAP4rev1", |_, command| {
            panic!("unsupported Gmail command: {command}")
        })
        .await;
        let (session, caps) = imap::connect(&endpoint, "me", "pw", crate::account::Auth::Password)
            .await
            .unwrap();
        assert!(!caps.gmail);
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = events.clone();
        let sink: Sink = Arc::new(move |event| kept.lock().unwrap().push(event));
        let creds = Credentials::new(Arc::new(Account::default()), false);
        let mut request = Request::Conversations {
            folder: "INBOX".into(),
            uidvalidity: 7,
            uids: vec![1],
            thread_ids: vec![8],
            all: "All".into(),
        };
        assert!(!request.changes());
        handle_imap(
            &mut request,
            &mut Some((session, caps)),
            &creds,
            &endpoint,
            &sink,
            &mut FolderCounts::default(),
        )
        .await
        .unwrap();
        assert!(
            matches!(&events.lock().unwrap()[..], [Event::Conversations {
            folder, uidvalidity: 7, all, result: Ok(None)
        }] if folder == "INBOX" && all == "All")
        );
    }

    #[test]
    fn gmail_failures_always_echo_the_request_identity() {
        for error in ["offline", "SEARCH: no", "the server stopped answering"] {
            let events = Arc::new(std::sync::Mutex::new(Vec::new()));
            let kept = events.clone();
            let sink: Sink = Arc::new(move |event| kept.lock().unwrap().push(event));
            let request = Request::Conversations {
                folder: "INBOX".into(),
                uidvalidity: 7,
                uids: vec![1],
                thread_ids: vec![8],
                all: "All".into(),
            };
            report_failure(&request, error.into(), &sink);
            assert!(
                matches!(&events.lock().unwrap()[..], [Event::Conversations {
                folder, uidvalidity: 7, all, result: Err(message)
            }] if folder == "INBOX" && all == "All" && message == error)
            );
        }
    }

    #[tokio::test]
    async fn gmail_offline_worker_answers_every_queued_request_without_holding_reads() {
        let account = Arc::new(Account {
            password: crate::account::PasswordFrom::Ask,
            ..Account::default()
        });
        let creds = Credentials::new(account.clone(), false);
        let endpoints = Endpoints::of(&account, crate::net::tls_config(None).unwrap());
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        let kept = events.clone();
        let sink: Sink = Arc::new(move |event| kept.lock().unwrap().push(event));
        let (tx, rx) = unbounded_channel();
        for folder in ["INBOX", "Archive"] {
            tx.send(Request::Conversations {
                folder: folder.into(),
                uidvalidity: 7,
                uids: vec![1],
                thread_ids: vec![8],
                all: "All".into(),
            })
            .unwrap();
        }
        drop(tx);
        // No password, keychain, socket or user configuration is accessed.
        run_imap(creds, endpoints, rx, sink).await;
        let events = events.lock().unwrap();
        let failed: Vec<&str> = events
            .iter()
            .filter_map(|event| match event {
                Event::Conversations {
                    folder,
                    result: Err(error),
                    ..
                } if error == "offline" => Some(folder.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(failed, ["INBOX", "Archive"], "{events:?}");
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Waiting(n) if *n != 0))
        );
    }

    #[tokio::test]
    async fn gmail_request_batch_limit_combines_source_uids_and_known_thread_ids() {
        for (uids, threads) in [
            (vec![0], vec![]),
            (vec![], vec![0]),
            ((1..=CONVERSATION_BATCH as u32).collect(), vec![8]),
            (vec![], (1..=CONVERSATION_BATCH as u64 + 1).collect()),
        ] {
            let (mut session, _) =
                imap::tests::scripted_capabilities("IMAP4rev1 X-GM-EXT-1", |_, command| {
                    panic!("invalid request reached the server: {command}")
                })
                .await;
            let error = conversations(&mut session, "INBOX", 7, &uids, &threads, "All")
                .await
                .unwrap_err();
            assert!(!broken(&error), "{error:#}");
        }
    }
}
