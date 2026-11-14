//! Transactional contacts cache shared by the TUI, CLI and MCP readers.

use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde::Serialize;

use super::Store;
use crate::contacts::{Contact, SyncBatch, SyncState};
use crate::mail::{self, Addr};
use crate::{account, text};

const MAX_CONTACTS: usize = 50_000;
const MAX_CARD: usize = 1 << 20;
const MAX_SNAPSHOT: usize = 64 << 20;
const MAX_RESOURCE: usize = 16 << 10;

#[derive(Clone, Debug, Serialize)]
pub struct CachedContact {
    pub account: String,
    pub synced_at: i64,
    pub contact: Contact,
}

fn escaped_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn keep_email(value: &str, seen: &mut HashSet<String>) -> bool {
    account::valid_address(value) && seen.insert(value.to_lowercase())
}

fn clean_phones(values: &[String]) -> Vec<String> {
    values
        .iter()
        .take(100)
        .map(|phone| text::one_line(phone, 256))
        .filter(|phone| !phone.is_empty())
        .collect()
}

fn valid_opaque(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && !value.chars().any(|c| c.is_control() || text::is_hidden(c))
}

fn valid_checkpoint(state: &SyncState) -> bool {
    valid_opaque(&state.address_book, MAX_RESOURCE)
        && state.sync_token.len() <= MAX_RESOURCE
        && !state.sync_token.chars().any(char::is_control)
}

impl Store {
    /// SQLite's lower() only folds ASCII. Keep a separate Unicode key for
    /// completion without renaming old address rows or replacing their names.
    pub(super) fn migrate_contact_addresses(db: &Connection) -> rusqlite::Result<()> {
        let tx = Transaction::new_unchecked(db, TransactionBehavior::Immediate)?;
        for column in ["normalized_addr", "name_fold"] {
            let present: bool = tx.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('addresses') WHERE name=?1",
                [column],
                |row| row.get(0),
            )?;
            if !present {
                tx.execute_batch(&format!(
                    "ALTER TABLE addresses ADD COLUMN {column} TEXT NOT NULL DEFAULT '';"
                ))?;
            }
        }
        let old: Vec<(String, String)> = {
            let mut statement = tx.prepare(
                "SELECT addr,name FROM addresses
                 WHERE normalized_addr='' OR (name_fold='' AND name<>'')",
            )?;
            statement
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        for (address, name) in old {
            tx.execute(
                "UPDATE addresses SET normalized_addr=?2,name_fold=?3 WHERE addr=?1",
                params![
                    address,
                    address.to_lowercase(),
                    text::one_line(&name, mail::MAX_NAME).to_lowercase()
                ],
            )?;
        }
        tx.execute_batch(
            "CREATE INDEX IF NOT EXISTS addresses_by_normalized ON addresses(normalized_addr);",
        )?;
        tx.commit()
    }

    /// The last committed checkpoint, never a token from a partial fetch.
    pub fn contact_sync_state(&self, account: &str) -> Result<(i64, Option<SyncState>)> {
        let found = self
            .db
            .query_row(
                "SELECT revision, address_book, sync_token, discovered_at
                 FROM contact_sources WHERE account = ?1",
                [account],
                |row| {
                    Ok((
                        row.get(0)?,
                        SyncState {
                            address_book: row.get(1)?,
                            sync_token: row.get(2)?,
                            discovered_at: row.get(3)?,
                        },
                    ))
                },
            )
            .optional()?;
        Ok(match found {
            Some((revision, state)) => {
                if revision < 0 || (!state.address_book.is_empty() && !valid_checkpoint(&state)) {
                    bail!("the cached contacts synchronization checkpoint is invalid");
                }
                let state = (!state.address_book.is_empty()).then_some(state);
                (revision, state)
            }
            None => (0, None),
        })
    }

    /// Apply a complete successful fetch atomically. Two syncs starting
    /// from the same revision cannot both commit, even in different processes.
    pub fn apply_contact_sync(
        &mut self,
        account: &str,
        expected_revision: i64,
        batch: &SyncBatch,
        synced_at: i64,
    ) -> Result<bool> {
        if !valid_opaque(account, MAX_RESOURCE) || expected_revision < 0 {
            bail!("the contacts account or revision is invalid");
        }
        if batch.contacts.len() > MAX_CONTACTS || batch.deleted.len() > MAX_CONTACTS {
            bail!("the contacts update is too large");
        }
        if !valid_checkpoint(&batch.state) {
            bail!("the contacts synchronization checkpoint is invalid");
        }
        let mut ids = HashSet::with_capacity(batch.contacts.len() + batch.deleted.len());
        let mut bytes = 0usize;
        for contact in &batch.contacts {
            if !valid_opaque(&contact.id, MAX_RESOURCE)
                || !ids.insert(contact.id.as_str())
                || contact.vcard.len() > MAX_CARD
                || contact.etag.len() > 4096
                || contact.etag.chars().any(char::is_control)
            {
                bail!("the contacts update contains an invalid or repeated contact");
            }
            bytes = bytes.saturating_add(contact.vcard.len());
        }
        if bytes > MAX_SNAPSHOT {
            bail!("the contacts update is too large");
        }
        for id in &batch.deleted {
            if !valid_opaque(id, MAX_RESOURCE) || !ids.insert(id.as_str()) {
                bail!("the contacts update contains an invalid or repeated deletion");
            }
        }

        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<(i64, String)> = tx
            .query_row(
                "SELECT revision, address_book FROM contact_sources WHERE account = ?1",
                [account],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if previous.as_ref().map_or(0, |p| p.0) != expected_revision {
            return Ok(false);
        }
        if !batch.full
            && previous
                .as_ref()
                .is_none_or(|p| p.1 != batch.state.address_book)
        {
            bail!("a full contact sync is needed before this incremental update");
        }
        let revision = expected_revision
            .checked_add(1)
            .context("contacts revision overflow")?;
        if batch.full {
            tx.execute("DELETE FROM contact_emails WHERE account = ?1", [account])?;
            tx.execute("DELETE FROM contacts WHERE account = ?1", [account])?;
        }
        {
            let mut delete_emails =
                tx.prepare("DELETE FROM contact_emails WHERE account = ?1 AND contact_id = ?2")?;
            let mut delete_contact =
                tx.prepare("DELETE FROM contacts WHERE account = ?1 AND id = ?2")?;
            for id in &batch.deleted {
                delete_emails.execute(params![account, id])?;
                delete_contact.execute(params![account, id])?;
            }
            let mut upsert = tx.prepare(
                "INSERT INTO contacts
                     (account,id,name,name_fold,phones,organization,search_text,etag,vcard)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
                 ON CONFLICT(account,id) DO UPDATE SET
                     name=excluded.name, name_fold=excluded.name_fold,
                     phones=excluded.phones, organization=excluded.organization,
                     search_text=excluded.search_text, etag=excluded.etag, vcard=excluded.vcard",
            )?;
            let mut insert_email = tx.prepare(
                "INSERT INTO contact_emails
                     (account,contact_id,email,normalized_email,ordinal)
                 VALUES (?1,?2,?3,?4,?5)",
            )?;
            for contact in &batch.contacts {
                let name = text::one_line(&contact.name, mail::MAX_NAME);
                let organization = text::one_line(&contact.organization, mail::MAX_NAME);
                let phones = clean_phones(&contact.phones);
                let mut seen = HashSet::new();
                let emails: Vec<&String> = contact
                    .emails
                    .iter()
                    .take(100)
                    .filter(|email| keep_email(email, &mut seen))
                    .collect();
                let mut search_text = name.to_lowercase();
                for value in std::iter::once(organization.as_str())
                    .chain(emails.iter().map(|email| email.as_str()))
                    .chain(phones.iter().map(String::as_str))
                {
                    search_text.push('\n');
                    search_text.extend(value.chars().flat_map(char::to_lowercase));
                }
                upsert.execute(params![
                    account,
                    contact.id,
                    name,
                    name.to_lowercase(),
                    serde_json::to_string(&phones)?,
                    organization,
                    search_text,
                    contact.etag,
                    contact.vcard
                ])?;
                delete_emails.execute(params![account, contact.id])?;
                for (ordinal, email) in emails.iter().enumerate() {
                    insert_email.execute(params![
                        account,
                        contact.id,
                        email,
                        email.to_lowercase(),
                        ordinal as i64
                    ])?;
                }
            }
        }
        let (count, bytes): (i64, i64) = tx.query_row(
            "SELECT COUNT(*),
                 COALESCE(SUM(
                     length(CAST(id AS BLOB)) + length(CAST(name AS BLOB)) +
                     length(CAST(name_fold AS BLOB)) + length(CAST(phones AS BLOB)) +
                     length(CAST(organization AS BLOB)) + length(CAST(search_text AS BLOB)) +
                     length(CAST(etag AS BLOB)) + length(CAST(vcard AS BLOB))),0) +
                 COALESCE((SELECT SUM(
                     length(CAST(contact_id AS BLOB)) + length(CAST(email AS BLOB)) +
                     length(CAST(normalized_email AS BLOB)))
                     FROM contact_emails WHERE account=?1),0)
             FROM contacts WHERE account=?1",
            [account],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if count > MAX_CONTACTS as i64 || bytes > MAX_SNAPSHOT as i64 {
            bail!("the synchronized address book is too large");
        }
        tx.execute(
            "INSERT INTO contact_sources
                 (account,revision,address_book,sync_token,discovered_at,last_sync)
             VALUES (?1,?2,?3,?4,?5,?6)
             ON CONFLICT(account) DO UPDATE SET
                 revision=excluded.revision,address_book=excluded.address_book,
                 sync_token=excluded.sync_token,discovered_at=excluded.discovered_at,
                 last_sync=excluded.last_sync",
            params![
                account,
                revision,
                batch.state.address_book,
                batch.state.sync_token,
                batch.state.discovered_at,
                synced_at
            ],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Cached personal contacts, with deterministic pagination. Matching
    /// treats %, _ and backslash literally and folds Unicode before indexing.
    pub fn cached_contacts(
        &self,
        account: Option<&str>,
        query: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<CachedContact>> {
        let pattern = query
            .map(|q| text::one_line(q, 512).trim().to_lowercase())
            .filter(|q| !q.is_empty())
            .map(|q| format!("%{}%", escaped_like(&q)));
        let mut statement = self.db.prepare(
            "SELECT c.account,s.last_sync,c.id,c.name,c.phones,c.organization,c.etag,c.vcard
             FROM contacts c JOIN contact_sources s ON s.account=c.account
             WHERE s.address_book<>'' AND (?1 IS NULL OR c.account=?1)
                 AND (?2 IS NULL OR c.search_text LIKE ?2 ESCAPE '\\')
             ORDER BY c.name_fold,c.account,c.id LIMIT ?3 OFFSET ?4",
        )?;
        let contacts = statement.query_map(
            params![
                account,
                pattern,
                limit.min(1001) as i64,
                offset.min(i64::MAX as usize) as i64
            ],
            |row| self.cached_contact_row(row),
        )?;
        Ok(contacts.collect::<rusqlite::Result<_>>()?)
    }

    pub fn get_cached_contact(&self, account: &str, id: &str) -> Result<Option<CachedContact>> {
        Ok(self
            .db
            .query_row(
                "SELECT c.account,s.last_sync,c.id,c.name,c.phones,c.organization,c.etag,c.vcard
                 FROM contacts c JOIN contact_sources s ON s.account=c.account
                 WHERE s.address_book<>'' AND c.account=?1 AND c.id=?2",
                params![account, id],
                |row| self.cached_contact_row(row),
            )
            .optional()?)
    }

    fn cached_contact_row(&self, row: &rusqlite::Row<'_>) -> rusqlite::Result<CachedContact> {
        let account: String = row.get(0)?;
        let id: String = row.get(2)?;
        let mut statement = self.db.prepare(
            "SELECT email FROM contact_emails WHERE account=?1 AND contact_id=?2
             ORDER BY ordinal,normalized_email LIMIT 100",
        )?;
        let mut emails = Vec::new();
        let mut seen = HashSet::new();
        for email in statement.query_map(params![account, id], |r| r.get::<_, String>(0))? {
            let email = email?;
            if keep_email(&email, &mut seen) {
                emails.push(email);
            }
        }
        if !valid_opaque(&account, MAX_RESOURCE) || !valid_opaque(&id, MAX_RESOURCE) {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let phones: Vec<String> =
            serde_json::from_str(&row.get::<_, String>(4)?).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    4,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
        let vcard: String = row.get(7)?;
        if vcard.len() > MAX_CARD {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(CachedContact {
            account,
            synced_at: row.get(1)?,
            contact: Contact {
                id,
                name: text::one_line(&row.get::<_, String>(3)?, mail::MAX_NAME),
                emails,
                phones: clean_phones(&phones),
                organization: text::one_line(&row.get::<_, String>(5)?, mail::MAX_NAME),
                etag: text::one_line(&row.get::<_, String>(6)?, 4096),
                vcard,
            },
        })
    }

    /// Recipient completion merges sources only at query time. A contact
    /// name wins over a sender-supplied name for the same email; the active
    /// account wins over other address books. Usage remains actual usage.
    pub fn complete_for(&self, account: &str, prefix: &str, limit: usize) -> Result<Vec<Addr>> {
        let prefix = text::one_line(prefix, mail::MAX_NAME).trim().to_lowercase();
        if prefix.is_empty() || limit == 0 {
            return Ok(Vec::new());
        }
        let prefix = escaped_like(&prefix);
        let mut statement = self.db.prepare(
            "WITH learned AS (
                 SELECT name,addr,name_fold,normalized_addr AS normalized,
                     ROW_NUMBER() OVER (
                         PARTITION BY normalized_addr
                         ORDER BY used DESC,(name<>'') DESC,last DESC,addr
                     ) AS duplicate,
                     SUM(used) OVER (PARTITION BY normalized_addr) AS used,
                     MAX(last) OVER (PARTITION BY normalized_addr) AS last
                 FROM addresses
             ), candidates AS (
                 SELECT c.name,e.email AS addr,e.normalized_email AS normalized,c.name_fold,
                     CASE WHEN c.account=?3 THEN 0 ELSE 1 END AS priority,
                     COALESCE(a.used,0) AS used,COALESCE(a.last,0) AS last,
                     c.account AS source,c.id AS id
                 FROM contact_emails e JOIN contacts c
                     ON c.account=e.account AND c.id=e.contact_id
                 JOIN contact_sources s ON s.account=c.account AND s.address_book<>''
                 LEFT JOIN learned a ON a.normalized=e.normalized_email AND a.duplicate=1
                 UNION ALL
                 SELECT name,addr,normalized,name_fold,2,used,last,'',addr
                 FROM learned WHERE duplicate=1
             ), ranked AS (
                 SELECT *,ROW_NUMBER() OVER (
                     PARTITION BY normalized ORDER BY priority,source,id
                 ) AS duplicate FROM candidates
             )
             SELECT name,addr FROM ranked WHERE duplicate=1
                 AND (normalized LIKE ?1 ESCAPE '\\'
                     OR name_fold LIKE ?1 ESCAPE '\\' OR name_fold LIKE ?2 ESCAPE '\\')
             ORDER BY priority,used DESC,last DESC,name_fold,normalized LIMIT ?4",
        )?;
        let rows = statement.query_map(
            params![
                format!("{prefix}%"),
                format!("% {prefix}%"),
                account,
                limit.min(1000) as i64
            ],
            |row| {
                Ok(Addr {
                    name: text::one_line(&row.get::<_, String>(0)?, mail::MAX_NAME),
                    addr: row.get::<_, String>(1)?,
                })
            },
        )?;
        let mut found = Vec::new();
        let mut seen = HashSet::new();
        for row in rows {
            let address = row?;
            if keep_email(&address.addr, &mut seen) {
                found.push(address);
            }
        }
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(id: &str, name: &str, emails: &[&str]) -> Contact {
        Contact {
            id: format!("https://www.googleapis.com/book/{id}"),
            name: name.into(),
            emails: emails.iter().map(|s| (*s).to_owned()).collect(),
            phones: vec!["+1 555 1234".into()],
            organization: "Example Lab".into(),
            etag: "\"one\"".into(),
            vcard: "BEGIN:VCARD\r\nVERSION:3.0\r\nEND:VCARD\r\n".into(),
        }
    }

    fn batch(contacts: Vec<Contact>, full: bool, token: &str) -> SyncBatch {
        SyncBatch {
            state: SyncState {
                address_book: "https://www.googleapis.com/book/".into(),
                sync_token: token.into(),
                discovered_at: 10,
            },
            full,
            contacts,
            deleted: Vec::new(),
        }
    }

    #[test]
    fn contact_sync_and_queries_preserve_account_identity_and_multiple_emails() {
        let mut store = Store::in_memory();
        let first = card(
            "one",
            "Élodie Example",
            &["one@example.org", "two@example.org"],
        );
        assert!(
            store
                .apply_contact_sync("home", 0, &batch(vec![first.clone()], true, "t1"), 11)
                .unwrap()
        );
        assert!(
            store
                .apply_contact_sync(
                    "work",
                    0,
                    &batch(vec![card("one", "Other", &[])], true, "w1"),
                    12
                )
                .unwrap()
        );
        let found = store
            .cached_contacts(Some("home"), Some("ÉLODIE"), 10, 0)
            .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].contact.emails, first.emails);
        let completed = store.complete_for("home", "élodie", 10).unwrap();
        assert_eq!(
            completed
                .iter()
                .map(|address| address.addr.as_str())
                .collect::<Vec<_>>(),
            first.emails.iter().map(String::as_str).collect::<Vec<_>>()
        );
        assert_eq!(found[0].synced_at, 11);
        assert_eq!(
            store
                .cached_contacts(Some("home"), Some("555"), 10, 0)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .cached_contacts(Some("home"), Some("Example Lab"), 10, 0)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(store.cached_contacts(None, None, 1, 1).unwrap().len(), 1);
        assert!(store.cached_contacts(None, None, 1, 2).unwrap().is_empty());
        let json = serde_json::to_value(&found[0]).unwrap();
        assert!(json["contact"].get("vcard").is_none());
        assert_eq!(
            store
                .get_cached_contact("home", &first.id)
                .unwrap()
                .unwrap()
                .contact
                .name,
            first.name
        );
        assert_eq!(
            store
                .get_cached_contact("work", &first.id)
                .unwrap()
                .unwrap()
                .contact
                .name,
            "Other"
        );
    }

    #[test]
    fn incremental_changes_and_deletions_update_completion_without_stale_overwrites() {
        let mut store = Store::in_memory();
        let old = card("one", "Alice", &["old@example.org"]);
        let deleted = card("two", "Bob", &["bob@example.org"]);
        store
            .apply_contact_sync(
                "home",
                0,
                &batch(vec![old.clone(), deleted.clone()], true, "t1"),
                1,
            )
            .unwrap();
        let (revision, state) = store.contact_sync_state("home").unwrap();
        assert_eq!(state.unwrap().sync_token, "t1");
        let new = card("one", "Alice Changed", &["new@example.org"]);
        let mut update = batch(vec![new], false, "t2");
        update.deleted.push(deleted.id.clone());
        assert!(
            store
                .apply_contact_sync("home", revision, &update, 2)
                .unwrap()
        );
        assert!(
            !store
                .apply_contact_sync("home", revision, &batch(vec![old], true, "stale"), 3)
                .unwrap()
        );
        assert!(store.complete_for("home", "old@", 6).unwrap().is_empty());
        assert!(store.complete_for("home", "bob@", 6).unwrap().is_empty());
        assert_eq!(
            store.complete_for("home", "Ali", 6).unwrap()[0].addr,
            "new@example.org"
        );
        assert_eq!(
            store
                .contact_sync_state("home")
                .unwrap()
                .1
                .unwrap()
                .sync_token,
            "t2"
        );
        assert!(
            store
                .get_cached_contact("home", &deleted.id)
                .unwrap()
                .is_none()
        );
        let found = store.complete_for("home", "Changed", 6).unwrap();
        assert_eq!(found[0].name, "Alice Changed");
    }

    #[test]
    fn invalid_batch_does_not_replace_cache_or_checkpoint_and_empty_full_sync_can() {
        let mut store = Store::in_memory();
        let contact = card("one", "Alice", &["alice@example.org"]);
        store
            .apply_contact_sync("home", 0, &batch(vec![contact.clone()], true, "t1"), 1)
            .unwrap();
        let invalid = batch(vec![contact.clone(), contact], true, "bad");
        assert!(store.apply_contact_sync("home", 1, &invalid, 2).is_err());
        assert_eq!(
            store
                .cached_contacts(Some("home"), None, 10, 0)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .contact_sync_state("home")
                .unwrap()
                .1
                .unwrap()
                .sync_token,
            "t1"
        );
        assert!(
            store
                .apply_contact_sync("home", 1, &batch(vec![], true, "empty"), 3)
                .unwrap()
        );
        assert!(
            store
                .cached_contacts(Some("home"), None, 10, 0)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn failed_write_rolls_back_full_replacement_emails_and_checkpoint() {
        let mut store = Store::in_memory();
        let original = card("one", "Original", &["one@example.org", "two@example.org"]);
        store
            .apply_contact_sync("home", 0, &batch(vec![original.clone()], true, "t1"), 11)
            .unwrap();
        let checkpoint = store.contact_sync_state("home").unwrap();
        store
            .db
            .execute_batch(
                "CREATE TRIGGER fail_contact_write BEFORE INSERT ON contacts
                 WHEN NEW.id='https://www.googleapis.com/book/fail'
                 BEGIN SELECT RAISE(ABORT,'test write failure'); END;",
            )
            .unwrap();
        let update = batch(
            vec![
                card("new", "New", &["new@example.org"]),
                card("fail", "Fail", &["fail@example.org"]),
            ],
            true,
            "t2",
        );
        assert!(store.apply_contact_sync("home", 1, &update, 22).is_err());
        assert_eq!(store.contact_sync_state("home").unwrap(), checkpoint);
        let found = store.cached_contacts(Some("home"), None, 10, 0).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].synced_at, 11);
        assert_eq!(found[0].contact.id, original.id);
        assert_eq!(found[0].contact.emails, original.emails);
        assert!(store.complete_for("home", "new@", 10).unwrap().is_empty());
    }

    #[test]
    fn pagination_is_stable_across_tied_names_and_ids_round_trip_exactly() {
        let mut store = Store::in_memory();
        let spaced = card("two  spaces", "Same", &[]);
        for account in ["work", "home"] {
            store
                .apply_contact_sync(
                    account,
                    0,
                    &batch(vec![spaced.clone(), card("one", "Same", &[])], true, "t1"),
                    1,
                )
                .unwrap();
        }
        let all = store.cached_contacts(None, None, 10, 0).unwrap();
        let keys: Vec<_> = all
            .iter()
            .map(|contact| (contact.account.as_str(), contact.contact.id.as_str()))
            .collect();
        assert_eq!(
            keys,
            [
                ("home", "https://www.googleapis.com/book/one"),
                ("home", spaced.id.as_str()),
                ("work", "https://www.googleapis.com/book/one"),
                ("work", spaced.id.as_str()),
            ]
        );
        for (offset, (account, id)) in keys.into_iter().enumerate() {
            let page = store.cached_contacts(None, None, 1, offset).unwrap();
            assert_eq!(page.len(), 1);
            assert_eq!(page[0].account, account);
            assert_eq!(page[0].contact.id, id);
            assert_eq!(
                store
                    .get_cached_contact(account, id)
                    .unwrap()
                    .unwrap()
                    .contact
                    .id,
                id
            );
        }
        assert!(store.cached_contacts(None, None, 1, 4).unwrap().is_empty());
        assert!(store.cached_contacts(None, None, 0, 0).unwrap().is_empty());
    }

    #[test]
    fn autocomplete_prefers_active_contacts_and_deduplicates_without_learning_them() {
        let mut store = Store::in_memory();
        store
            .remember(
                &[Addr {
                    name: "Incoming Name".into(),
                    addr: "same@example.org".into(),
                }],
                true,
                1,
            )
            .unwrap();
        store
            .apply_contact_sync(
                "home",
                0,
                &batch(
                    vec![card("one", "Home Name", &["SAME@example.org"])],
                    true,
                    "h",
                ),
                2,
            )
            .unwrap();
        store
            .apply_contact_sync(
                "work",
                0,
                &batch(
                    vec![card("two", "Work Name", &["same@example.org"])],
                    true,
                    "w",
                ),
                3,
            )
            .unwrap();
        let found = store.complete_for("work", "same@", 6).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "Work Name");
        assert_eq!(
            store.complete_for("home", "same@", 6).unwrap()[0].name,
            "Home Name"
        );
        store.forget_account("work").unwrap();
        assert!(
            store
                .cached_contacts(Some("work"), None, 10, 0)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .cached_contacts(Some("home"), None, 10, 0)
                .unwrap()
                .len(),
            1
        );
        store.forget_account("home").unwrap();
        assert_eq!(
            store.complete_for("", "same@", 6).unwrap()[0].name,
            "Incoming Name"
        );
    }

    #[test]
    fn contacts_search_escapes_wildcards_and_drops_invalid_recipient_addresses() {
        let mut store = Store::in_memory();
        let contact = card(
            "one",
            "100%_Name\u{1b}X",
            &[
                "valid@example.org",
                "VALID@example.org",
                "one@example.org,two@example.org",
                "bad\n@example.org",
            ],
        );
        store
            .apply_contact_sync("home", 0, &batch(vec![contact], true, "t"), 1)
            .unwrap();
        let found = store.cached_contacts(None, Some("%_"), 10, 0).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].contact.emails, ["valid@example.org"]);
        assert!(!found[0].contact.name.contains('\u{1b}'));
        assert!(
            store
                .cached_contacts(None, Some("_other"), 10, 0)
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.complete_for("home", "100%", 6).unwrap().len(), 1);
    }

    #[test]
    fn incremental_sync_requires_the_existing_address_book() {
        let mut store = Store::in_memory();
        assert!(
            store
                .apply_contact_sync("home", 0, &batch(vec![], false, "t"), 1)
                .is_err()
        );
        store
            .apply_contact_sync("home", 0, &batch(vec![], true, "t"), 1)
            .unwrap();
        let mut changed = batch(vec![], false, "t2");
        changed.state.address_book = "https://www.googleapis.com/another-book/".into();
        assert!(store.apply_contact_sync("home", 1, &changed, 2).is_err());
        assert_eq!(
            store
                .contact_sync_state("home")
                .unwrap()
                .1
                .unwrap()
                .sync_token,
            "t"
        );
    }

    #[test]
    fn removal_invalidates_initial_and_existing_syncs_without_resetting_the_revision() {
        let mut store = Store::in_memory();
        let update = batch(
            vec![card("one", "Alice", &["alice@example.org"])],
            true,
            "t1",
        );
        let (initial, _) = store.contact_sync_state("home").unwrap();
        store.forget_account("home").unwrap();
        assert!(
            !store
                .apply_contact_sync("home", initial, &update, 1)
                .unwrap()
        );
        let (removed, state) = store.contact_sync_state("home").unwrap();
        assert!(removed > initial);
        assert!(state.is_none());
        assert!(
            store
                .cached_contacts(Some("home"), None, 10, 0)
                .unwrap()
                .is_empty()
        );
        // Re-adding uses the preserved generation and starts with a full sync.
        assert!(
            store
                .apply_contact_sync("home", removed, &update, 2)
                .unwrap()
        );
        let (before_removal, _) = store.contact_sync_state("home").unwrap();
        store.forget_account("home").unwrap();
        assert!(
            !store
                .apply_contact_sync("home", before_removal, &update, 3)
                .unwrap()
        );
        let (after_removal, state) = store.contact_sync_state("home").unwrap();
        assert!(after_removal > before_removal);
        assert!(state.is_none());
        assert!(store.complete_for("home", "alice", 10).unwrap().is_empty());
        assert!(
            store
                .get_cached_contact("home", &update.contacts[0].id)
                .unwrap()
                .is_none()
        );
        let remaining: (String, String, i64, i64) = store.db.query_row(
            "SELECT address_book,sync_token,discovered_at,last_sync FROM contact_sources WHERE account='home'",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        ).unwrap();
        assert_eq!(remaining, (String::new(), String::new(), 0, 0));
    }

    #[test]
    fn failed_removal_rolls_back_the_contact_rows_and_generation_together() {
        let mut store = Store::in_memory();
        let update = batch(
            vec![card("one", "Alice", &["alice@example.org"])],
            true,
            "t1",
        );
        store.apply_contact_sync("home", 0, &update, 1).unwrap();
        let before = store.contact_sync_state("home").unwrap();
        store
            .db
            .execute_batch(
                "CREATE TRIGGER fail_contact_removal BEFORE DELETE ON contacts
             BEGIN SELECT RAISE(ABORT,'test deletion failure'); END;",
            )
            .unwrap();
        assert!(store.forget_account("home").is_err());
        assert_eq!(store.contact_sync_state("home").unwrap(), before);
        assert_eq!(store.complete_for("home", "alice", 10).unwrap().len(), 1);
        assert_eq!(
            store
                .get_cached_contact("home", &update.contacts[0].id)
                .unwrap()
                .unwrap()
                .contact
                .emails,
            ["alice@example.org"]
        );
    }

    #[test]
    fn canonical_contact_names_are_selected_before_matching_a_prefix() {
        let mut store = Store::in_memory();
        store
            .remember(
                &[Addr {
                    name: "Old Sender Alias".into(),
                    addr: "same@example.org".into(),
                }],
                true,
                1,
            )
            .unwrap();
        store
            .apply_contact_sync(
                "home",
                0,
                &batch(
                    vec![card("one", "Home Alias", &["same@example.org"])],
                    true,
                    "h",
                ),
                2,
            )
            .unwrap();
        store
            .apply_contact_sync(
                "work",
                0,
                &batch(
                    vec![card("two", "Work Alias", &["same@example.org"])],
                    true,
                    "w",
                ),
                3,
            )
            .unwrap();
        assert!(store.complete_for("work", "Old", 10).unwrap().is_empty());
        assert!(store.complete_for("work", "Home", 10).unwrap().is_empty());
        assert!(store.complete_for("home", "Work", 10).unwrap().is_empty());
        assert_eq!(
            store.complete_for("work", "Work", 10).unwrap()[0].name,
            "Work Alias"
        );
        let found = store.complete_for("work", "same@", 10).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "Work Alias");
    }

    #[test]
    fn legacy_unicode_addresses_share_one_completion_key_without_renaming_their_rows() {
        let mut store = Store::in_memory();
        store.db.execute_batch(
            "DROP TABLE addresses;
             CREATE TABLE addresses(addr TEXT PRIMARY KEY,name TEXT NOT NULL,used INTEGER NOT NULL DEFAULT 0,last INTEGER NOT NULL DEFAULT 0);"
        ).unwrap();
        for (address, name, used) in [
            ("Üser@example.org", "Person Learned", 3),
            ("üser@example.org", "Person Other", 0),
        ] {
            store
                .db
                .execute(
                    "INSERT INTO addresses(addr,name,used,last) VALUES (lower(?1),?2,?3,1)",
                    params![address, name, used],
                )
                .unwrap();
        }
        Store::migrate_contact_addresses(&store.db).unwrap();
        Store::migrate_contact_addresses(&store.db).unwrap();
        let names: Vec<(String, String)> = store
            .db
            .prepare("SELECT addr,name FROM addresses ORDER BY addr")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(
            names,
            [
                ("Üser@example.org".into(), "Person Learned".into()),
                ("üser@example.org".into(), "Person Other".into())
            ]
        );
        let learned = store.complete_for("home", "üser", 10).unwrap();
        assert_eq!(learned.len(), 1);
        assert_eq!(learned[0].name, "Person Learned");
        store
            .apply_contact_sync(
                "home",
                0,
                &batch(
                    vec![card("one", "Person Contact", &["Üser@example.org"])],
                    true,
                    "t1",
                ),
                2,
            )
            .unwrap();
        let combined = store.complete_for("home", "Person", 10).unwrap();
        assert_eq!(combined.len(), 1);
        assert_eq!(combined[0].name, "Person Contact");
        // A new learning event supplies the same Unicode normalization,
        // while the established sender name remains protected as before.
        store
            .remember(
                &[Addr {
                    name: "Replacement Name".into(),
                    addr: "Üser@example.org".into(),
                }],
                false,
                3,
            )
            .unwrap();
        let normalized: String = store
            .db
            .query_row(
                "SELECT normalized_addr FROM addresses WHERE addr=?1",
                ["Üser@example.org"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(normalized, "üser@example.org");
        store.forget_account("home").unwrap();
        assert_eq!(
            store.complete_for("", "üser", 10).unwrap()[0].name,
            "Person Learned"
        );
    }

    #[test]
    fn unicode_learning_keeps_established_names_and_whole_safe_addresses() {
        let store = Store::in_memory();
        let original = Addr {
            name: "ÉLODIE\u{1b} Example".into(),
            addr: "Üser@example.org".into(),
        };
        store.remember(&[original], false, 1).unwrap();
        store
            .remember(
                &[
                    Addr {
                        name: "Attacker".into(),
                        addr: "üser@example.org".into(),
                    },
                    Addr {
                        name: "Too long".into(),
                        addr: format!("{}@example.org", "é".repeat(130)),
                    },
                    Addr {
                        name: "Hidden".into(),
                        addr: "safe\u{202e}@example.org".into(),
                    },
                ],
                false,
                2,
            )
            .unwrap();
        let found = store.complete_for("", "élodie", 10).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "ÉLODIE Example");
        assert_eq!(found[0].addr, "Üser@example.org");
        assert!(store.complete_for("", "Attacker", 10).unwrap().is_empty());
        assert!(store.complete_for("", "Too", 10).unwrap().is_empty());
        assert!(store.complete_for("", "safe", 10).unwrap().is_empty());
        // Unicode lowercase keys can grow; they must not replace the
        // original valid recipient spelling or make it get truncated.
        let expanding = format!("{}@example.org", "İ".repeat(100));
        assert!(account::valid_address(&expanding));
        store
            .remember(
                &[Addr {
                    name: "Unicode Key".into(),
                    addr: expanding.clone(),
                }],
                false,
                3,
            )
            .unwrap();
        assert_eq!(
            store.complete_for("", "Unicode", 10).unwrap()[0].addr,
            expanding
        );
    }

    #[test]
    fn cached_fields_are_cleaned_again_without_rewriting_recipient_addresses() {
        let mut store = Store::in_memory();
        let contact = card("one", "Name", &["valid@example.org", "other@example.org"]);
        store
            .apply_contact_sync("home", 0, &batch(vec![contact.clone()], true, "t1"), 1)
            .unwrap();
        store
            .db
            .execute(
                "UPDATE contacts SET name=?1,organization=?2,phones=?3 WHERE account='home'",
                params![
                    "Name\u{1b}X",
                    "Company\nName\u{202e}",
                    serde_json::to_string(&["1\u{1b}2", "3\n4"]).unwrap(),
                ],
            )
            .unwrap();
        for (ordinal, email) in [
            (0, "bad\u{202e}@example.org".to_owned()),
            (1, format!("{}@example.org", "é".repeat(130))),
        ] {
            store
                .db
                .execute(
                    "UPDATE contact_emails SET email=?1 WHERE account='home' AND ordinal=?2",
                    params![email, ordinal],
                )
                .unwrap();
        }
        let found = store
            .get_cached_contact("home", &contact.id)
            .unwrap()
            .unwrap();
        assert_eq!(found.contact.id, contact.id);
        assert_eq!(found.contact.name, "NameX");
        assert_eq!(found.contact.organization, "Company Name");
        assert_eq!(found.contact.phones, ["12", "3 4"]);
        assert!(found.contact.emails.is_empty());
        assert!(store.complete_for("home", "valid", 10).unwrap().is_empty());
    }

    #[test]
    fn oversized_card_is_rejected_without_advancing_the_checkpoint() {
        let mut store = Store::in_memory();
        let original = card("one", "Name", &["valid@example.org"]);
        store
            .apply_contact_sync("home", 0, &batch(vec![original.clone()], true, "t1"), 1)
            .unwrap();
        let mut oversized = original.clone();
        oversized.vcard = "x".repeat(MAX_CARD + 1);
        assert!(
            store
                .apply_contact_sync("home", 1, &batch(vec![oversized], true, "t2"), 2)
                .is_err()
        );
        assert_eq!(store.contact_sync_state("home").unwrap().0, 1);
        let found = store
            .get_cached_contact("home", &original.id)
            .unwrap()
            .unwrap();
        assert_eq!(found.synced_at, 1);
        assert_eq!(found.contact.vcard, original.vcard);
    }
}
