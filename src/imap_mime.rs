//! Read the useful MIME sections of a large message without fetching its
//! attachments. BODYSTRUCTURE is a plan, not the message: the original
//! headers and mail-parser still decide what's shown and what's a file.

use std::fmt::Write as _;

use anyhow::Result;
use async_imap::imap_proto::{
    AttributeValue, BodyContentCommon, BodyContentSinglePart, BodyStructure, ContentEncoding,
    MessageSection, Response, SectionPath,
};

use crate::imap::{self, Session};
use crate::imap_timing;
use crate::mail::{
    self, File, MAX_PARTIAL_BODY, MAX_PARTIAL_DEPTH, MAX_PARTIAL_HEADER, MAX_PARTIAL_PARTS,
    PartRef, Partial,
};

const MAX_STRUCTURE: usize = 256 << 10;
const MIN_SAVED: usize = 256 << 10;
const MAX_WIRE_OVERHEAD: usize = 64 << 10;

struct Node {
    section: Vec<u32>,
    media_type: String,
    subtype: String,
    kind: Kind,
}

enum Kind {
    Multipart {
        boundary: String,
        children: Vec<Node>,
    },
    Leaf {
        octets: u32,
        encoding: String,
        eager: bool,
    },
}

#[derive(Default)]
struct Budget {
    nodes: usize,
    eager: usize,
    deferred: usize,
}

impl Node {
    fn plan(
        structure: &BodyStructure<'_>,
        path: &mut Vec<u32>,
        boundaries: &mut Vec<String>,
        budget: &mut Budget,
    ) -> Option<Self> {
        budget.nodes += 1;
        if budget.nodes > MAX_PARTIAL_PARTS || path.len() > MAX_PARTIAL_DEPTH {
            return None;
        }
        let (common, kind) = match structure {
            BodyStructure::Multipart { common, bodies, .. } => {
                if !mail::supported_multipart(&common.ty.subtype) || bodies.is_empty() {
                    return None;
                }
                let boundary = common
                    .ty
                    .params
                    .as_deref()?
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case("boundary"))?
                    .1
                    .as_ref();
                if !mail::valid_boundary(boundary)
                    || boundaries
                        .iter()
                        .any(|outer| outer.starts_with(boundary) || boundary.starts_with(outer))
                {
                    return None;
                }
                boundaries.push(boundary.to_owned());
                let mut children = Vec::new();
                for (i, body) in bodies.iter().enumerate() {
                    path.push(i as u32 + 1);
                    children.push(Self::plan(body, path, boundaries, budget)?);
                    path.pop();
                }
                (
                    common,
                    Kind::Multipart {
                        boundary: boundaries.pop()?,
                        children,
                    },
                )
            }
            BodyStructure::Text { common, other, .. }
            | BodyStructure::Basic { common, other, .. }
                if !path.is_empty()
                    && !common.ty.ty.eq_ignore_ascii_case("multipart")
                    && !common.ty.ty.eq_ignore_ascii_case("message") =>
            {
                (common, plan_leaf(common, other, budget)?)
            }
            _ => return None,
        };
        Some(Self {
            section: path.clone(),
            media_type: common.ty.ty.to_string(),
            subtype: common.ty.subtype.to_string(),
            kind,
        })
    }

    fn requests<'a>(&'a self, requests: &mut Vec<Section<'a>>) {
        requests.push(Section::headers(&self.section));
        match &self.kind {
            Kind::Multipart { children, .. } => {
                for child in children {
                    child.requests(requests);
                }
            }
            Kind::Leaf {
                octets,
                eager: true,
                ..
            } => {
                requests.push(Section::Body(&self.section, *octets));
            }
            Kind::Leaf { eager: false, .. } => {}
        }
    }

    // Same preorder as requests(): headers, then children or the leaf body.
    fn project(
        &self,
        sections: &mut impl Iterator<Item = Vec<u8>>,
        raw: &mut Vec<u8>,
        refs: &mut Vec<(u32, PartRef)>,
    ) -> Option<()> {
        let headers = sections.next()?;
        let valid = mail::part_header(&headers, |part| {
            let same_type = part.content_type().map_or_else(
                || {
                    self.media_type.eq_ignore_ascii_case("text")
                        && self.subtype.eq_ignore_ascii_case("plain")
                },
                |ct| {
                    ct.ctype().eq_ignore_ascii_case(&self.media_type)
                        && ct
                            .subtype()
                            .is_some_and(|st| st.eq_ignore_ascii_case(&self.subtype))
                },
            );
            same_type
                && match &self.kind {
                    Kind::Multipart { boundary, .. } => {
                        part.content_type().and_then(|ct| ct.attribute("boundary"))
                            == Some(boundary.as_str())
                            && matches!(part.encoding(), mail_parser::Encoding::None)
                    }
                    Kind::Leaf { encoding, .. } => part
                        .content_transfer_encoding()
                        .unwrap_or("7bit")
                        .eq_ignore_ascii_case(encoding),
                }
        })?;
        if !valid {
            return None;
        }
        let offset = u32::try_from(raw.len()).ok()?;
        raw.extend_from_slice(&headers);
        match &self.kind {
            Kind::Multipart { boundary, children } => {
                for child in children {
                    raw.extend_from_slice(b"--");
                    raw.extend_from_slice(boundary.as_bytes());
                    raw.extend_from_slice(b"\r\n");
                    child.project(sections, raw, refs)?;
                    raw.extend_from_slice(b"\r\n");
                }
                raw.extend_from_slice(b"--");
                raw.extend_from_slice(boundary.as_bytes());
                raw.extend_from_slice(b"--");
            }
            Kind::Leaf { octets, eager, .. } => {
                if *eager {
                    raw.extend_from_slice(&sections.next()?);
                }
                refs.push((
                    offset,
                    PartRef {
                        section: self.section.clone(),
                        octets: *octets,
                        downloaded: *eager,
                        mime_sha256: mail::mime_digest(&headers),
                    },
                ));
            }
        }
        Some(())
    }
}

fn plan_leaf(
    common: &BodyContentCommon<'_>,
    other: &BodyContentSinglePart<'_>,
    budget: &mut Budget,
) -> Option<Kind> {
    let encoding = match &other.transfer_encoding {
        ContentEncoding::SevenBit => "7bit",
        ContentEncoding::EightBit => "8bit",
        ContentEncoding::Binary => "binary",
        ContentEncoding::Base64 => "base64",
        ContentEncoding::QuotedPrintable => "quoted-printable",
        ContentEncoding::Other(value) => value,
    };
    let text = common.ty.ty.eq_ignore_ascii_case("text");
    let disposition = common.disposition.as_ref();
    let attached = disposition.is_some_and(|d| d.ty.eq_ignore_ascii_case("attachment"));
    let calendar = (text && common.ty.subtype.eq_ignore_ascii_case("calendar"))
        || common
            .ty
            .params
            .iter()
            .chain(disposition.and_then(|d| d.params.as_ref()))
            .flatten()
            .any(|(key, value)| {
                ["name", "filename", "name*", "filename*"]
                    .iter()
                    .any(|candidate| key.eq_ignore_ascii_case(candidate))
                    && value
                        .as_bytes()
                        .last_chunk::<4>()
                        .is_some_and(|s| s.eq_ignore_ascii_case(b".ics"))
            });
    let octets = other.octets;
    let eager = if calendar {
        octets as usize <= 2 * crate::calendar::MAX_PART_BYTES
    } else {
        text && !attached
    } || octets == 0;
    if eager {
        budget.eager = budget.eager.checked_add(octets as usize)?;
        if budget.eager > MAX_PARTIAL_BODY {
            return None;
        }
    } else {
        budget.deferred = budget.deferred.saturating_add(octets as usize);
    }
    Some(Kind::Leaf {
        octets,
        encoding: encoding.to_owned(),
        eager,
    })
}

/// One command for the structure, then one for the real headers and eager
/// bodies. A complete but unsupported or inconsistent response leaves the
/// session usable for the ordinary full-message path.
pub async fn read(s: &mut Session, uid: u32) -> Result<Option<Partial>> {
    if uid == 0 {
        return Ok(None);
    }
    match project(s, uid).await {
        Err(error) if error.is::<imap::Said>() => Ok(None),
        result => result,
    }
}

async fn project(s: &mut Session, uid: u32) -> Result<Option<Partial>> {
    let mut invalid = false;
    let mut plan = None;
    let mut seen = false;
    let start = imap_timing::start();
    let fetched = imap::fetch_parts(
        s,
        &format!("UID FETCH {uid} (UID BODYSTRUCTURE)"),
        MAX_STRUCTURE,
        true,
        |response, _| {
            if let Response::Fetch(_, attrs) = response {
                for attr in attrs {
                    let AttributeValue::BodyStructure(structure) = attr else {
                        continue;
                    };
                    if seen || !has_uid(attrs, uid) {
                        invalid = true;
                        break;
                    }
                    seen = true;
                    let mut budget = Budget::default();
                    plan = Node::plan(structure, &mut Vec::new(), &mut Vec::new(), &mut budget)
                        .filter(|_| budget.deferred >= MIN_SAVED)
                        .map(|root| (root, budget));
                }
            }
            Ok(())
        },
    )
    .await;
    imap_timing::finish(start, "imap.bodystructure", None);
    fetched?;
    let Some((root, budget)) = plan.filter(|_| !invalid) else {
        return Ok(None);
    };
    let mut requests = Vec::with_capacity(budget.nodes);
    root.requests(&mut requests);
    let cap = budget.eager + budget.nodes * MAX_PARTIAL_HEADER + MAX_WIRE_OVERHEAD;
    let Some(sections) = collect_sections(s, uid, &requests, cap, "imap.reader-sections").await?
    else {
        return Ok(None);
    };
    let mut raw =
        Vec::with_capacity(sections.iter().map(Vec::len).sum::<usize>() + budget.nodes * 160);
    let mut parts = Vec::new();
    let start = imap_timing::start();
    let partial = root
        .project(&mut sections.into_iter(), &mut raw, &mut parts)
        .and_then(|()| {
            raw.extend_from_slice(b"\r\n");
            Partial::new(raw, parts)
        });
    imap_timing::finish(
        start,
        "imap.mime-projection",
        partial.as_ref().map(|p| p.raw.len()),
    );
    Ok(partial)
}

#[derive(Clone, Copy)]
enum Section<'a> {
    Header,
    Mime(&'a [u32]),
    Body(&'a [u32], u32),
}

impl<'a> Section<'a> {
    fn headers(numbers: &'a [u32]) -> Self {
        if numbers.is_empty() {
            Self::Header
        } else {
            Self::Mime(numbers)
        }
    }

    fn append(self, command: &mut String) {
        command.push_str(" BODY.PEEK[");
        let numbers = match self {
            Self::Header => &[][..],
            Self::Mime(numbers) | Self::Body(numbers, _) => numbers,
        };
        for (i, number) in numbers.iter().enumerate() {
            if i != 0 {
                command.push('.');
            }
            write!(command, "{number}").expect("writing into a String");
        }
        match self {
            Self::Header => command.push_str("HEADER]"),
            Self::Mime(_) => command.push_str(".MIME]"),
            Self::Body(_, octets) => {
                write!(command, "]<0.{}>", octets + 1).expect("writing into a String");
            }
        }
    }

    fn matches(self, section: &SectionPath, index: Option<u32>) -> bool {
        match (self, section, index) {
            (Self::Header, SectionPath::Full(MessageSection::Header), None) => true,
            (Self::Mime(want), SectionPath::Part(got, Some(MessageSection::Mime)), None)
            | (Self::Body(want, _), SectionPath::Part(got, None), Some(0)) => want == got,
            _ => false,
        }
    }

    fn length_is_valid(self, length: usize) -> bool {
        match self {
            Self::Header | Self::Mime(_) => length <= MAX_PARTIAL_HEADER,
            // The command asks for one extra byte, so this is exact, not a prefix.
            Self::Body(_, octets) => length == octets as usize,
        }
    }
}

fn has_uid(attrs: &[AttributeValue<'_>], uid: u32) -> bool {
    let mut uids = attrs.iter().filter_map(|attr| match attr {
        AttributeValue::Uid(uid) => Some(*uid),
        _ => None,
    });
    uids.next() == Some(uid) && uids.next().is_none()
}

async fn collect_sections(
    s: &mut Session,
    uid: u32,
    requests: &[Section<'_>],
    wire_cap: usize,
    stage: &'static str,
) -> Result<Option<Vec<Vec<u8>>>> {
    let mut command = format!("UID FETCH {uid} (UID");
    for request in requests {
        request.append(&mut command);
    }
    command.push(')');
    let mut collected = vec![None; requests.len()];
    let mut invalid = false;
    let mut bytes = 0;
    let start = imap_timing::start();
    let result = imap::fetch_parts(s, &command, wire_cap, false, |response, raw| {
        if let Response::Fetch(_, attrs) = response {
            let valid_uid = has_uid(attrs, uid);
            for attr in attrs {
                let AttributeValue::BodySection {
                    section,
                    index,
                    data,
                } = attr
                else {
                    if matches!(attr, AttributeValue::BodyStructure(_)) {
                        invalid = true;
                    }
                    continue;
                };
                let found = section
                    .as_ref()
                    .and_then(|sect| requests.iter().position(|r| r.matches(sect, *index)));
                match (found, data.as_deref()) {
                    (Some(i), Some(data)) if !invalid && valid_uid && collected[i].is_none() => {
                        let data = imap::section_bytes(raw, data);
                        if requests[i].length_is_valid(data.len()) {
                            bytes += data.len();
                            collected[i] = Some(data.into_owned());
                        } else {
                            invalid = true;
                        }
                    }
                    _ => invalid = true,
                }
            }
        }
        Ok(())
    })
    .await;
    imap_timing::finish(start, stage, Some(bytes));
    result?;
    Ok(if invalid {
        None
    } else {
        collected.into_iter().collect()
    })
}

/// Fetch only the selected omitted leaves; never fall back to a whole message
/// here. Even sections with the same name must match their own UID and MIME.
pub async fn attachments(
    s: &mut Session,
    uid: u32,
    files: &[(String, PartRef)],
) -> Result<Vec<File>> {
    let changed =
        || imap::Said("The message changed since its files were listed: open it again".into());
    let too_large = || imap::Said("Those attachments are too large to download together".into());
    if files.is_empty() {
        return Ok(Vec::new());
    }
    if uid == 0 || files.len() >= MAX_PARTIAL_PARTS {
        return Err(changed().into());
    }
    let limit = imap::MAX_MESSAGE as usize;
    let mut requests = Vec::with_capacity(2 * files.len());
    let mut encoded = 0usize;
    for (i, (_, reference)) in files.iter().enumerate() {
        if !reference.valid()
            || reference.downloaded
            || files[..i]
                .iter()
                .any(|(_, prev)| prev.section == reference.section)
        {
            return Err(changed().into());
        }
        encoded = encoded
            .checked_add(reference.octets as usize)
            .and_then(|n| n.checked_add(1))
            .filter(|&n| n <= limit)
            .ok_or_else(too_large)?;
        requests.push(Section::Mime(&reference.section));
        requests.push(Section::Body(&reference.section, reference.octets));
    }
    let cap = encoded + files.len() * MAX_PARTIAL_HEADER + MAX_WIRE_OVERHEAD;
    let mut sections = collect_sections(s, uid, &requests, cap, "imap.selected-sections")
        .await?
        .ok_or_else(changed)?
        .into_iter();
    let mut remaining = limit;
    files
        .iter()
        .map(|(name, reference)| {
            let headers = sections.next().ok_or_else(changed)?;
            let raw = sections.next().ok_or_else(changed)?;
            let (mime, encoding) =
                mail::attachment_header(&headers, reference, name).ok_or_else(changed)?;
            let bytes = if matches!(encoding, mail_parser::Encoding::None) {
                raw
            } else {
                mail::contained(|| encoding.decode(&raw).into_owned()).ok_or_else(changed)?
            };
            remaining = remaining.checked_sub(bytes.len()).ok_or_else(too_large)?;
            Ok(File {
                name: name.clone(),
                mime,
                bytes,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID: u32 = 42;
    const BACK: &str = "2";
    const PLAIN: &[u8] = b"plain version";
    const HTML: &[u8] = b"<p>html version</p>";
    const CALENDAR: &[u8] = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\n\
BEGIN:VEVENT\r\nUID:demo@example.org\r\nDTSTAMP:20261001T120000Z\r\n\
SUMMARY:Calendar demo\r\nDTSTART:20261011T120000Z\r\n\
DTEND:20261011T123000Z\r\nEND:VEVENT\r\nEND:VCALENDAR";
    const ROOT: &[u8] = b"From: a@example.org\r\nReply-To: replies@example.org\r\n\
Subject: Many parts\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=outer\r\n\r\n";
    const ALT: &[u8] = b"Content-Type: multipart/alternative; boundary=options\r\n\r\n";
    const RELATED: &[u8] = b"Content-Type: multipart/related; boundary=inner\r\n\r\n";
    const FILE_MIME: &[u8] = b"Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=same.bin\r\n\
Content-Transfer-Encoding: base64\r\n\r\n";
    const CAL_MIME: &[u8] = b"Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=event.ICS\r\n\r\n";
    const SELECTED: &str = "* 1 EXISTS\r\n* OK [UIDVALIDITY 7] ready\r\n";

    fn structure() -> String {
        format!(
            concat!(
                r#"((("TEXT" "PLAIN" NIL NIL NIL "7BIT" {} 1)"#,
                r#"(("TEXT" "HTML" NIL NIL NIL "7BIT" {} 1)"#,
                r#"("APPLICATION" "OCTET-STREAM" NIL "<inline>" NIL "BASE64" {})"#,
                r#" "RELATED" ("BOUNDARY" "inner")) "ALTERNATIVE" ("BOUNDARY" "options"))"#,
                r#"("APPLICATION" "OCTET-STREAM" NIL NIL NIL "BASE64" {})"#,
                r#"("APPLICATION" "OCTET-STREAM" NIL NIL NIL "7BIT" {} NIL "#,
                r#"("ATTACHMENT" ("FILENAME" "event.ICS")))"#,
                r#" "MIXED" ("BOUNDARY" "outer"))"#,
            ),
            PLAIN.len(),
            HTML.len(),
            MIN_SAVED,
            MIN_SAVED,
            CALENDAR.len(),
        )
    }

    fn literals(tag: &str, uid: u32, attrs: &[(&str, &[u8])]) -> Vec<u8> {
        let mut response = format!("* 1 FETCH (UID {uid}").into_bytes();
        for (section, data) in attrs {
            response.extend_from_slice(format!(" BODY[{section}").as_bytes());
            response.extend_from_slice(format!(" {{{}}}\r\n", data.len()).as_bytes());
            response.extend_from_slice(data);
        }
        response.extend_from_slice(format!(")\r\n{tag} OK done\r\n").as_bytes());
        response
    }

    fn selected_file(tag: &str, section: &str, byte: u8) -> Vec<u8> {
        literals(
            tag,
            UID,
            &[
                (&format!("{section}.MIME]"), FILE_MIME),
                (&format!("{section}]<0>"), &vec![byte; MIN_SAVED]),
            ],
        )
    }

    fn reader_reply(tag: &str, command: &str, plain: &[u8]) -> Vec<u8> {
        if command.starts_with("SELECT ") {
            return format!("{SELECTED}{tag} OK selected\r\n").into_bytes();
        }
        if command == "UID FETCH 42 (UID BODYSTRUCTURE)" {
            return format!(
                "* 1 FETCH (BODYSTRUCTURE {} UID 42)\r\n{tag} OK done\r\n",
                structure()
            )
            .into_bytes();
        }
        assert_eq!(
            command,
            format!(
                "UID FETCH 42 (UID BODY.PEEK[HEADER] BODY.PEEK[1.MIME] \
                 BODY.PEEK[1.1.MIME] BODY.PEEK[1.1]<0.{}> BODY.PEEK[1.2.MIME] \
                 BODY.PEEK[1.2.1.MIME] BODY.PEEK[1.2.1]<0.{}> BODY.PEEK[1.2.2.MIME] \
                 BODY.PEEK[2.MIME] BODY.PEEK[3.MIME] BODY.PEEK[3]<0.{}>)",
                PLAIN.len() + 1,
                HTML.len() + 1,
                CALENDAR.len() + 1,
            ),
        );
        // The server can order sections arbitrarily, and two files can have
        // identical headers. No attachment bytes are sent in this exchange.
        literals(
            tag,
            UID,
            &[
                ("3]<0>", CALENDAR),
                ("1.2.2.MIME]", FILE_MIME),
                ("1.1]<0>", plain),
                ("1.2.1]<0>", HTML),
                ("HEADER]", ROOT),
                ("1.MIME]", ALT),
                ("1.1.MIME]", b"Content-Type: text/plain\r\n\r\n"),
                ("1.2.MIME]", RELATED),
                ("1.2.1.MIME]", b"Content-Type: text/html\r\n\r\n"),
                ("2.MIME]", FILE_MIME),
                ("3.MIME]", CAL_MIME),
            ],
        )
    }

    #[tokio::test]
    async fn both_views_and_calendar_arrive_before_files_and_only_selected_bytes_are_requested() {
        let (mut session, _) = imap::tests::scripted_capabilities("IMAP4rev1", |tag, command| {
            if command.starts_with("UID FETCH 42 (UID BODY.PEEK[2.MIME]") {
                assert_eq!(
                    command,
                    format!(
                        "UID FETCH 42 (UID BODY.PEEK[2.MIME] BODY.PEEK[2]<0.{}>)",
                        MIN_SAVED + 1,
                    ),
                );
                return selected_file(tag, BACK, b'Q');
            }
            if command.starts_with("UID FETCH 42 (UID BODY.PEEK[1.2.2.MIME]") {
                assert_eq!(
                    command,
                    format!(
                        "UID FETCH 42 (UID BODY.PEEK[1.2.2.MIME] BODY.PEEK[1.2.2]<0.{}> \
                         BODY.PEEK[2.MIME] BODY.PEEK[2]<0.{}>)",
                        MIN_SAVED + 1,
                        MIN_SAVED + 1,
                    ),
                );
                return literals(
                    tag,
                    UID,
                    &[
                        ("2]<0>", &vec![b'Q'; MIN_SAVED]),
                        ("1.2.2.MIME]", FILE_MIME),
                        ("2.MIME]", FILE_MIME),
                        ("1.2.2]<0>", &vec![b'A'; MIN_SAVED]),
                    ],
                );
            }
            reader_reply(tag, command, PLAIN)
        })
        .await;
        assert_eq!(
            imap::select_read(&mut session, "INBOX", 7).await.unwrap(),
            7
        );
        let projected = read(&mut session, UID).await.unwrap().unwrap();
        let parsed = &projected.parsed;
        assert!(projected.raw.len() < 2048);
        assert_eq!(parsed.text.as_deref(), Some("plain version"));
        assert_eq!(parsed.html.as_deref(), Some("<p>html version</p>"));
        assert_eq!(parsed.reply_to[0].addr, "replies@example.org");
        assert_eq!(parsed.attachments.len(), 3);
        let back = &parsed.attachments[1];
        let inline = &parsed.attachments[0];
        let invite = &parsed.attachments[2];
        assert_eq!(inline.name, back.name);
        assert_eq!(inline.remote.as_ref().unwrap().section, [1, 2, 2]);
        assert_eq!(back.remote.as_ref().unwrap().section, [2]);
        assert_eq!(back.size, MIN_SAVED);
        assert!(invite.remote.as_ref().unwrap().downloaded);
        assert_eq!(
            mail::attachments(
                &projected.raw,
                [(invite.index, invite.name.as_str())],
                |_, bytes| {
                    assert_eq!(bytes, CALENDAR);
                    Ok(())
                }
            ),
            Ok(vec![()])
        );
        let parsed = projected.parsed.clone();
        let (send, result) = tokio::sync::oneshot::channel();
        mail::in_background(
            move || {
                [false, true].into_iter().all(|prefer_plain| {
                    let body = mail::render(
                        &parsed,
                        80,
                        mail::RenderOptions {
                            prefer_plain,
                            ..Default::default()
                        },
                    );
                    body.from_html != prefer_plain
                        && (0..body.lines.len()).any(|i| body.line(i) == "Summary: Calendar demo")
                })
            },
            move |rendered| {
                let _ = send.send(rendered);
            },
        );
        assert_eq!(result.await.unwrap(), Some(true));
        let choice = |item: &mail::Attachment| (item.name.clone(), item.remote.clone().unwrap());
        let one = attachments(&mut session, UID, &[choice(back)])
            .await
            .unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].name, "same.bin");
        assert_eq!(&one[0].bytes[..3], &[65, 4, 16]);
        let both = attachments(&mut session, UID, &[choice(inline), choice(back)])
            .await
            .unwrap();
        assert_eq!(both.len(), 2);
        assert_eq!(&both[0].bytes[..3], &[0, 0, 0]);
        assert_eq!(&both[1].bytes[..3], &[65, 4, 16]);

        let mut wrong_offset = projected.parts.clone();
        wrong_offset[0].0 += 1;
        assert!(Partial::new(projected.raw.clone(), wrong_offset).is_none());
        let mut wrong_section = projected.parts.clone();
        wrong_section[0].1.section = vec![63];
        assert!(Partial::new(projected.raw.clone(), wrong_section).is_none());
        assert!(Partial::new(projected.raw, projected.parts).is_some());
    }

    #[tokio::test]
    async fn a_body_with_a_different_length_requires_the_whole_message() {
        let (mut session, _) = imap::tests::scripted_capabilities("IMAP4rev1", |tag, command| {
            reader_reply(tag, command, b"plain version!")
        })
        .await;
        imap::select_read(&mut session, "INBOX", 7).await.unwrap();
        assert!(read(&mut session, UID).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn selected_sections_reject_wrong_uid_section_origin_digest_name_and_duplicates() {
        let mime = b"Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=safe.bin\r\n\r\n";
        let changed_mime = b"Content-Type: application/octet-stream\r\n\
Content-Disposition: attachment; filename=safe.bin\r\nContent-ID: <changed>\r\n\r\n";
        let reference = PartRef {
            section: vec![2],
            octets: 4,
            downloaded: false,
            mime_sha256: mail::mime_digest(mime),
        };
        for (uid, section, headers, name, duplicate) in [
            (UID + 1, "2]<0>", &mime[..], "safe.bin", false),
            (UID, "3]<0>", &mime[..], "safe.bin", false),
            (UID, "2]<1>", &mime[..], "safe.bin", false),
            (UID, "2]<0>", &changed_mime[..], "safe.bin", false),
            (UID, "2]<0>", &mime[..], "different.bin", false),
            (UID, "2]<0>", &mime[..], "safe.bin", true),
        ] {
            let (mut session, _) =
                imap::tests::scripted_capabilities("IMAP4rev1", move |tag, command| {
                    if command.starts_with("SELECT ") {
                        return format!("{SELECTED}{tag} OK selected\r\n").into_bytes();
                    }
                    assert_eq!(
                        command,
                        "UID FETCH 42 (UID BODY.PEEK[2.MIME] BODY.PEEK[2]<0.5>)"
                    );
                    let mut response = vec![("2.MIME]", headers), (section, &b"data"[..])];
                    if duplicate {
                        response.push((section, b"data"));
                    }
                    literals(tag, uid, &response)
                })
                .await;
            imap::select_read(&mut session, "INBOX", 7).await.unwrap();
            assert!(
                attachments(&mut session, UID, &[(name.into(), reference.clone())])
                    .await
                    .unwrap_err()
                    .is::<imap::Said>()
            );
        }
    }
}
