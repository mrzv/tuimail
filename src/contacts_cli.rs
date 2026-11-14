//! Local contact queries for scripts, and an explicit one-way sync.
//! Reading the cache never resolves credentials or contacts a server.

use std::io::IsTerminal;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde_json::json;

use crate::account::{self, Account, Contacts, PasswordFrom};
use crate::agent::{CONTACT_RESULTS, MAX_CONTACT_RESULTS};
use crate::{config, contacts, secrets, store::Store, text};

const HELP: &str = "\
Usage: tuimail contacts sync --account EMAIL [--json]
       tuimail contacts list [--account EMAIL] [--limit N] [--offset N] [--json]
       tuimail contacts search QUERY [--account EMAIL] [--limit N] [--offset N] [--json]
       tuimail contacts get ID --account EMAIL [--json]

Output is JSON by default; --json explicitly selects the same format.
List and search return {contacts, more, limit, offset}; each cached contact has
an account, synced_at (Unix seconds), and contact fields (including id).
Get takes that opaque contact.id and returns one cached contact.
--limit defaults to 50 (1-100); --offset defaults to 0. Quote a query that
contains spaces, or put -- before a query or id that starts with '-'.
An account can be its email address or an unambiguous configured name.

List, search and get read only the local cache, even while offline.
Sync reads Google Contacts into that cache; it never changes Google.
Enable it for an existing Google mail account in accounts.toml with:
  contacts = \"google_carddav\"
It reuses that account's app password from the keychain or password_command.
OAuth mail tokens are not CardDAV passwords. For password = \"ask\", sync
inside tuimail after entering the password. No command accepts a password.
";

#[derive(Debug, PartialEq)]
enum Command {
    Help,
    Sync {
        account: String,
    },
    List {
        account: Option<String>,
        limit: usize,
        offset: usize,
    },
    Search {
        account: Option<String>,
        query: String,
        limit: usize,
        offset: usize,
    },
    Get {
        account: String,
        id: String,
    },
}

/// Parses before opening any file, asking for any secret or making a connection.
fn parse(args: &[String]) -> Result<Command> {
    let Some(verb) = args.first().map(String::as_str) else {
        return Ok(Command::Help);
    };
    if matches!(verb, "-h" | "--help") {
        if args.len() != 1 {
            bail!("unexpected arguments after --help");
        }
        return Ok(Command::Help);
    }
    if !matches!(verb, "sync" | "list" | "search" | "get") {
        bail!(
            "unknown contacts command {:?}; see tuimail contacts --help",
            text::clean(verb)
        );
    }
    if args.len() == 2 && matches!(args[1].as_str(), "-h" | "--help") {
        return Ok(Command::Help);
    }

    let mut account = None;
    let mut limit = None;
    let mut offset = None;
    let mut json = false;
    let mut positional = None;
    let mut options = true;
    let mut rest = args[1..].iter();
    while let Some(arg) = rest.next() {
        if options && arg == "--" {
            options = false;
            continue;
        }
        match arg.as_str() {
            "--account" if options => {
                if account.is_some() {
                    bail!("--account was given twice");
                }
                let value = rest
                    .next()
                    .context("--account needs an account name or address")?;
                if value.trim().is_empty() || value.starts_with('-') {
                    bail!("--account needs an account name or address");
                }
                account = Some(value.clone());
            }
            "--limit" | "--offset" if options => {
                let slot = if arg == "--limit" {
                    &mut limit
                } else {
                    &mut offset
                };
                if slot.is_some() {
                    bail!("{arg} was given twice");
                }
                let value = rest
                    .next()
                    .with_context(|| format!("{arg} needs a number"))?;
                let number = value
                    .parse::<usize>()
                    .with_context(|| format!("{arg} needs a non-negative whole number"))?;
                if (arg == "--limit" && !(1..=MAX_CONTACT_RESULTS).contains(&number))
                    || (arg == "--offset" && number > i64::MAX as usize)
                {
                    bail!("{arg} is out of range; see tuimail contacts --help");
                }
                *slot = Some(number);
            }
            "--json" if options => {
                if json {
                    bail!("--json was given twice");
                }
                json = true;
            }
            other if options && other.starts_with('-') => {
                // Do not repeat values of unknown options: one could be a
                // password typed by mistake (there is no password option).
                bail!("unknown option; see tuimail contacts --help");
            }
            _ => {
                if positional.is_some() {
                    bail!("too many arguments; quote a search query that contains spaces");
                }
                positional = Some(arg.clone());
            }
        }
    }

    let paged = matches!(verb, "list" | "search");
    if !paged && (limit.is_some() || offset.is_some()) {
        bail!("--limit and --offset are only for list and search");
    }
    if matches!(verb, "list" | "sync") && positional.is_some() {
        bail!("{verb} takes no positional argument; use --account for an account");
    }
    let required = |value: Option<String>, description: &str| -> Result<String> {
        value
            .filter(|s| !s.trim().is_empty())
            .with_context(|| format!("{verb} needs {description}"))
    };
    let limit = limit.unwrap_or(CONTACT_RESULTS);
    let offset = offset.unwrap_or(0);
    Ok(match verb {
        "sync" => Command::Sync {
            account: required(account, "--account EMAIL")?,
        },
        "list" => Command::List {
            account,
            limit,
            offset,
        },
        "search" => Command::Search {
            account,
            query: required(positional, "a search query")?,
            limit,
            offset,
        },
        "get" => Command::Get {
            account: required(account, "--account EMAIL")?,
            id: required(positional, "a contact id")?,
        },
        _ => unreachable!(),
    })
}

/// Email addresses take precedence over display names; duplicate names
/// must not choose an account silently.
fn find_account<'a>(accounts: &'a [Account], name: &str) -> Result<&'a Account> {
    let name = name.trim();
    if let Some(account) = accounts.iter().find(|a| a.id().eq_ignore_ascii_case(name)) {
        return Ok(account);
    }
    let mut matches = accounts
        .iter()
        .filter(|a| a.shown_name().eq_ignore_ascii_case(name));
    let account = matches
        .next()
        .context("no such account; see tuimail --check")?;
    if matches.next().is_some() {
        bail!("that account name is ambiguous; use its email address");
    }
    Ok(account)
}

/// A result fetched under old settings must not revive a removed source.
fn same_source(before: &Account, after: &Account) -> bool {
    before.id() == after.id()
        && after.contacts == Contacts::GoogleCarddav
        && after.contacts_problem().is_none()
        && before.auth == after.auth
        && before.password == after.password
        && before.password_command == after.password_command
}

fn output(value: &impl serde::Serialize) -> Result<()> {
    let mut out = serde_json::to_string_pretty(value)?;
    out.push('\n');
    crate::print(&out)
}

fn cached_page(
    store: &Store,
    account: Option<&str>,
    query: Option<&str>,
    limit: usize,
    offset: usize,
) -> Result<serde_json::Value> {
    let mut contacts: Vec<crate::store::CachedContact> =
        store.cached_contacts(account, query, limit + 1, offset)?;
    let more = contacts.len() > limit;
    contacts.truncate(limit);
    Ok(json!({ "contacts": contacts, "more": more, "limit": limit, "offset": offset }))
}

pub async fn run(args: Vec<String>) -> Result<()> {
    let command = parse(&args)?;
    if command == Command::Help {
        return crate::print(HELP);
    }
    let config = config::Config::load()?;
    let path = account::path(&config.data_dir);
    let (accounts, warnings) = account::load(&path)?;
    for warning in warnings {
        eprintln!("{}", text::clean(&warning));
    }
    let mut store = Store::open(&config.data_dir.join("tuimail.db"))?;
    match command {
        Command::List {
            account,
            limit,
            offset,
        } => {
            let account = account
                .as_deref()
                .map(|a| find_account(&accounts, a).map(Account::id))
                .transpose()?;
            output(&cached_page(
                &store,
                account.as_deref(),
                None,
                limit,
                offset,
            )?)
        }
        Command::Search {
            account,
            query,
            limit,
            offset,
        } => {
            let account = account
                .as_deref()
                .map(|a| find_account(&accounts, a).map(Account::id))
                .transpose()?;
            output(&cached_page(
                &store,
                account.as_deref(),
                Some(&query),
                limit,
                offset,
            )?)
        }
        Command::Get { account, id } => {
            let account = find_account(&accounts, &account)?;
            let contact = store
                .get_cached_contact(&account.id(), &id)?
                .context("that contact isn't cached for this account")?;
            output(&contact)
        }
        Command::Sync { account } => {
            let account = find_account(&accounts, &account)?;
            if account.contacts != Contacts::GoogleCarddav {
                bail!(
                    "contacts aren't enabled for this account; set contacts = \"google_carddav\" in accounts.toml"
                );
            }
            if let Some(problem) = account.contacts_problem() {
                bail!("{problem}");
            }
            let id = account.id();
            let (revision, state) = store.contact_sync_state(&id)?;
            // This is the only branch that resolves credentials or uses
            // a network connection; queries above never touch either.
            if account.password == PasswordFrom::Ask {
                bail!(
                    "this account asks for its password inside tuimail; open tuimail and sync contacts there"
                );
            }
            let keychain = account.password == PasswordFrom::Keychain && secrets::init_keychain();
            let credentials = secrets::Credentials::new(Arc::new(account.clone()), keychain);
            if account.password == PasswordFrom::Command {
                let password =
                    secrets::run_command(&account.password_command, std::io::stdin().is_terminal())
                        .await?;
                credentials.set(password).await;
            }
            let password = credentials
                .get()
                .await
                .context("an app password is needed; open tuimail and sync contacts there")?;
            // CardDAV success or failure must never remember or refuse mail
            // credentials: this service may reject a working mail password.
            let batch = contacts::sync_google(account.email.trim(), &password, state).await?;
            let (latest, _) = account::load(&path)?;
            if !latest.iter().any(|a| same_source(account, a)) {
                bail!(
                    "the contact source changed or was removed while syncing; the result was not saved"
                );
            }
            let synced_at = crate::app::now();
            if !store.apply_contact_sync(&id, revision, &batch, synced_at)? {
                bail!("another contact sync completed first; the newer cache was kept; retry sync");
            }
            output(&json!({ "account": id, "synced_at": synced_at, "synced": true }))
        }
        Command::Help => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(args: &[&str]) -> Result<Command> {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn queries_have_stable_defaults_and_explicit_pagination() {
        assert_eq!(command(&[]).unwrap(), Command::Help);
        assert_eq!(
            command(&["list", "--json"]).unwrap(),
            Command::List {
                account: None,
                limit: 50,
                offset: 0
            }
        );
        assert_eq!(
            command(&[
                "search",
                "Alice Example",
                "--offset",
                "20",
                "--account",
                "work@example.org",
                "--limit",
                "10",
                "--json"
            ])
            .unwrap(),
            Command::Search {
                account: Some("work@example.org".into()),
                query: "Alice Example".into(),
                limit: 10,
                offset: 20,
            }
        );
        assert_eq!(
            command(&["get", "--account", "work", "--", "-opaque-id"]).unwrap(),
            Command::Get {
                account: "work".into(),
                id: "-opaque-id".into()
            }
        );
        assert_eq!(
            command(&["sync", "--account", "work"]).unwrap(),
            Command::Sync {
                account: "work".into()
            }
        );
    }

    #[test]
    fn invalid_or_ambiguous_arguments_never_reach_credentials() {
        for args in [
            vec!["sync"],
            vec!["get", "id"],
            vec!["search"],
            vec!["search", ""],
            vec!["list", "extra"],
            vec!["search", "two", "words"],
            vec!["list", "--account"],
            vec!["list", "--account", "--json"],
            vec!["list", "--limit", "0"],
            vec!["list", "--limit", "101"],
            vec!["list", "--limit", "-1"],
            vec!["list", "--offset", "-1"],
            vec!["list", "--offset", "18446744073709551615"],
            vec!["list", "--json", "--json"],
            vec!["list", "--limit", "3", "--limit", "4"],
            vec!["sync", "--account", "work", "--limit", "10"],
            vec!["get", "id", "--account", "work", "--offset", "2"],
            vec![
                "sync",
                "--account",
                "work",
                "--password",
                "never-print-this",
            ],
        ] {
            let error = command(&args).unwrap_err().to_string();
            assert!(!error.contains("never-print-this"));
        }
    }

    #[test]
    fn duplicate_names_need_an_address_and_removed_sources_cannot_finish() {
        let a = Account {
            email: "one@gmail.com".into(),
            name: "work".into(),
            host: "imap.gmail.com".into(),
            smtp_host: "smtp.gmail.com".into(),
            contacts: Contacts::GoogleCarddav,
            ..Account::default()
        };
        let mut b = a.clone();
        b.email = "two@gmail.com".into();
        let accounts = [a.clone(), b];
        assert!(find_account(&accounts, "work").is_err());
        assert_eq!(
            find_account(&accounts, "ONE@gmail.com").unwrap().id(),
            a.id()
        );
        assert!(same_source(&a, &a));
        let mut changed = a.clone();
        changed.contacts = Contacts::None;
        assert!(!same_source(&a, &changed));
        changed = a.clone();
        changed.password = PasswordFrom::Command;
        changed.password_command = vec!["/bin/false".into()];
        assert!(!same_source(&a, &changed));
        changed = a.clone();
        changed.auth = account::Auth::Oauth2;
        assert!(!same_source(&a, &changed));
    }

    #[test]
    fn cached_pages_report_more_only_when_another_match_exists() {
        let mut store = Store::in_memory();
        let contacts = (0..3)
            .map(|i| contacts::Contact {
                id: format!("opaque-{i}/%2F?#"),
                name: format!("Contact {i}\u{1b}"),
                emails: vec![format!("person{i}@example.org")],
                phones: vec!["+1 555\u{1b}0100".into()],
                organization: "Example\u{202e}".into(),
                etag: format!("etag-{i}"),
                vcard: "PRIVATE RAW VCARD".into(),
            })
            .collect();
        let batch = contacts::SyncBatch {
            state: contacts::SyncState {
                address_book: "https://www.googleapis.com/carddav/v1/principals/me/lists/default/"
                    .into(),
                sync_token: "checkpoint".into(),
                discovered_at: 1,
            },
            full: true,
            contacts,
            deleted: vec![],
        };
        store
            .apply_contact_sync("me@example.org", 0, &batch, 42)
            .unwrap();
        let page = cached_page(&store, None, None, 2, 0).unwrap();
        assert_eq!(page["more"], true);
        assert_eq!(page["contacts"].as_array().unwrap().len(), 2);
        assert_eq!(page["contacts"][0]["contact"]["id"], "opaque-0/%2F?#");
        assert_eq!(page["contacts"][0]["synced_at"], 42);
        assert!(!page.to_string().contains("PRIVATE RAW VCARD"));
        assert!(page["contacts"][0]["contact"].get("vcard").is_none());
        for field in ["name", "organization"] {
            let value = page["contacts"][0]["contact"][field].as_str().unwrap();
            assert!(!value.contains(['\u{1b}', '\u{202e}']));
        }
        let id = page["contacts"][0]["contact"]["id"].as_str().unwrap();
        let contact = store
            .get_cached_contact("me@example.org", id)
            .unwrap()
            .unwrap();
        let value = serde_json::to_value(contact).unwrap();
        assert_eq!(value["contact"]["id"], id);
        assert!(value["contact"].get("vcard").is_none());
        assert!(!value.to_string().contains("PRIVATE RAW VCARD"));
        assert!(
            store
                .get_cached_contact("other@example.org", id)
                .unwrap()
                .is_none()
        );
        let last = cached_page(&store, None, None, 2, 2).unwrap();
        assert_eq!(last["more"], false);
        assert_eq!(last["contacts"][0]["contact"]["id"], "opaque-2/%2F?#");
        let exact = cached_page(&store, Some("me@example.org"), Some("person1@"), 1, 0).unwrap();
        assert_eq!(exact["contacts"].as_array().unwrap().len(), 1);
        assert_eq!(exact["more"], false);
        assert!(
            cached_page(&store, None, None, 2, 3).unwrap()["contacts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
}
