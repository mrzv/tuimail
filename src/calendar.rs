//! A read-only view of a few fields of VEVENT. Never interpret a calendar's
//! URLs, recurrence, alarms, or time-zone rules.

use std::borrow::Cow;

use chrono::{NaiveDate, NaiveTime};
use ical::property::Property;

use crate::text;

pub(super) const MAX_PART_BYTES: usize = 64 << 10;
pub(super) const MAX_INVITATIONS: usize = 8;
const MAX_FIELD: usize = 240;
const MAX_EVENTS_PER_PART: usize = 32;
const MAX_TZID: usize = 120;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Invitation {
    summary: Option<String>,
    start: String,
    end: Option<String>,
    organizer: Option<String>,
    location: Option<String>,
}

impl Invitation {
    pub(super) fn fields(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("Summary", self.summary.as_deref()),
            ("Start", Some(self.start.as_str())),
            ("End", self.end.as_deref()),
            ("Organizer", self.organizer.as_deref()),
            ("Location", self.location.as_deref()),
        ]
        .into_iter()
        .filter_map(|(label, value)| value.map(|value| (label, value)))
    }
}

/// Reject incomplete structure before displaying anything. `ical` accepts an
/// unrelated END as a terminator, so pass it just the verified envelope and
/// the properties we show, not alarms or other nested content.
pub(super) fn invitations(raw: &[u8], out: &mut Vec<Invitation>) {
    if raw.len() > MAX_PART_BYTES || out.len() >= MAX_INVITATIONS {
        return;
    }
    let Some(unfolded) = unfold(raw) else {
        return;
    };
    let Ok(source) = std::str::from_utf8(&unfolded) else {
        return;
    };
    let Some(selected) = select_events(source.trim_start_matches('\u{feff}')) else {
        return;
    };
    let Some(Ok(calendar)) = ical::IcalParser::new(selected.as_bytes()).next() else {
        return;
    };
    for event in &calendar.events {
        if let Some(event) = invitation(&event.properties)
            && !out.contains(&event)
        {
            out.push(event);
            if out.len() == MAX_INVITATIONS {
                break;
            }
        }
    }
}

/// Unfold before UTF-8 validation, including folds between the bytes of a
/// character. `ical` would trim meaningful spaces at a fold.
fn unfold(raw: &[u8]) -> Option<Cow<'_, [u8]>> {
    let mut lines = raw.split(|&byte| byte == b'\n');
    let first = lines.next().unwrap_or_default();
    if !lines.any(|line| matches!(line.first(), Some(b' ' | b'\t'))) {
        return Some(Cow::Borrowed(raw));
    }
    let mut unfolded = Vec::with_capacity(raw.len());
    unfolded.extend_from_slice(first);
    let mut has_line = !matches!(first, b"" | b"\r");
    for line in raw.split(|&byte| byte == b'\n').skip(1) {
        if matches!(line.first(), Some(b' ' | b'\t')) {
            if !has_line {
                return None;
            }
            if unfolded.last() == Some(&b'\r') {
                unfolded.pop();
            }
            unfolded.extend_from_slice(&line[1..]);
        } else {
            has_line = !matches!(line, b"" | b"\r");
            unfolded.push(b'\n');
            unfolded.extend_from_slice(line);
        }
    }
    Some(Cow::Owned(unfolded))
}

fn select_events(source: &str) -> Option<String> {
    let mut components: Vec<&str> = Vec::new();
    let mut selected = String::new();
    let mut events = 0;
    for line in source.lines().filter(|line| !line.is_empty()) {
        let (name, _) = line.split_once([':', ';'])?;
        if !is_token(name) {
            return None;
        }
        let top_event = components.len() == 2
            && components[1].eq_ignore_ascii_case("VEVENT")
            && events <= MAX_EVENTS_PER_PART;
        if name.eq_ignore_ascii_case("BEGIN") {
            let component = line[name.len()..].strip_prefix(':')?;
            if !is_token(component) || components.len() == 8 {
                return None;
            }
            if components.is_empty() {
                if !selected.is_empty() || !component.eq_ignore_ascii_case("VCALENDAR") {
                    return None;
                }
                selected.push_str("BEGIN:VCALENDAR\n");
            } else if components.len() == 1 && component.eq_ignore_ascii_case("VEVENT") {
                events += 1;
                if events <= MAX_EVENTS_PER_PART {
                    selected.push_str("BEGIN:VEVENT\n");
                }
            }
            components.push(component);
        } else if name.eq_ignore_ascii_case("END") {
            let component = line[name.len()..].strip_prefix(':')?;
            if !components.pop()?.eq_ignore_ascii_case(component) {
                return None;
            }
            if top_event {
                selected.push_str("END:VEVENT\n");
            } else if components.is_empty() {
                selected.push_str("END:VCALENDAR\n");
            }
        } else if components.is_empty() {
            return None;
        } else if top_event
            && ["SUMMARY", "DTSTART", "DTEND", "ORGANIZER", "LOCATION"]
                .iter()
                .any(|field| name.eq_ignore_ascii_case(field))
        {
            // Bound repeated searches in ical's parameter tokenizer. Parse
            // only the header (a quoted parameter can itself contain ':').
            let value_at = value_start(&line[name.len()..])? + name.len();
            let value = &line[value_at..];
            selected.push_str(&line[..value_at]);
            // Keep the first value byte and any final spaces intact through
            // ical's permissive lexer; remove these sentinels when reading.
            selected.push('_');
            selected.push_str(value);
            selected.push('_');
            selected.push('\n');
        }
    }
    (components.is_empty() && !selected.is_empty()).then_some(selected)
}

fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn value_start(header_and_value: &str) -> Option<usize> {
    // Validate the parameter grammar before ical's permissive tokenizer can
    // reinterpret a malformed TZID or VALUE as part of another parameter.
    let mut rest = header_and_value;
    for _ in 0..32 {
        if rest.starts_with(':') {
            return Some(header_and_value.len() - rest.len() + 1);
        }
        rest = rest.strip_prefix(';')?;
        let end = rest.find(['=', ':', ';'])?;
        if !is_token(&rest[..end]) {
            return None;
        }
        rest = rest[end..].strip_prefix('=')?;
        for count in 1..=10 {
            let (value, tail) = if let Some(quoted) = rest.strip_prefix('"') {
                quoted.split_once('"')?
            } else {
                rest.split_at(rest.find([',', ':', ';'])?)
            };
            if value.is_empty() || value.chars().any(char::is_control) {
                return None;
            }
            rest = tail;
            if header_and_value.len() - rest.len() >= 1024 {
                return None;
            }
            match rest.as_bytes().first()? {
                b';' | b':' => break,
                b',' if count < 10 => rest = &rest[1..],
                _ => return None,
            }
        }
    }
    None
}

fn invitation(properties: &[Property]) -> Option<Invitation> {
    let property = |name: &str| {
        let mut found = properties
            .iter()
            .filter(|p| p.name.eq_ignore_ascii_case(name));
        let first = found.next();
        // Do not choose a value when a single-valued field is repeated.
        found.next().is_none().then_some(first)
    };
    let start = moment(property("DTSTART")??, false)?;
    let end = match property("DTEND")? {
        Some(end) => Some(moment(end, true)?),
        None => None,
    };
    let summary = text_field(property("SUMMARY").flatten());
    let location = text_field(property("LOCATION").flatten());
    let organizer = property("ORGANIZER")
        .flatten()
        .and_then(value)
        .and_then(|v| v.split_once(':'))
        .filter(|(scheme, address)| {
            scheme.eq_ignore_ascii_case("mailto")
                && !address.contains(['?', '#', '%'])
                && crate::account::valid_address(address)
        })
        .map(|(_, address)| address.to_owned());
    Some(Invitation {
        summary,
        start,
        end,
        organizer,
        location,
    })
}

fn value(property: &Property) -> Option<&str> {
    property
        .value
        .as_deref()?
        .strip_prefix('_')?
        .strip_suffix('_')
}

fn text_field(property: Option<&Property>) -> Option<String> {
    let value = value(property?)?;
    let mut unescaped = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => match chars.next() {
                Some('N' | 'n') => unescaped.push('\n'),
                Some(ch @ ('\\' | ',' | ';')) => unescaped.push(ch),
                _ => return None,
            },
            '\r' => return None,
            _ => unescaped.push(ch),
        }
    }
    let cleaned = text::one_line(&unescaped, MAX_FIELD);
    (!cleaned.is_empty()).then_some(cleaned)
}

fn parameter<'a>(property: &'a Property, name: &str) -> Option<Option<&'a str>> {
    let mut parameters = property
        .params
        .iter()
        .flatten()
        .filter(|(key, _)| key == name);
    match parameters.next() {
        None => Some(None),
        Some((_, values)) if values.len() == 1 && parameters.next().is_none() => {
            Some(Some(&values[0]))
        }
        _ => None,
    }
}

fn moment(property: &Property, end: bool) -> Option<String> {
    let raw = value(property)?;
    let kind = parameter(property, "VALUE")?.unwrap_or("DATE-TIME");
    let tzid = parameter(property, "TZID")?;
    let date = raw.get(..8)?;
    if !date.bytes().all(|b| b.is_ascii_digit()) || date.starts_with("0000") {
        return None;
    }
    let date = NaiveDate::parse_from_str(date, "%Y%m%d").ok()?;
    if kind.eq_ignore_ascii_case("DATE") {
        return (raw.len() == 8 && tzid.is_none()).then(|| {
            let detail = if end { "all-day, exclusive" } else { "all-day" };
            format!("{date} ({detail})")
        });
    }
    if !kind.eq_ignore_ascii_case("DATE-TIME")
        || !matches!(raw.as_bytes().get(8), Some(b'T' | b't'))
    {
        return None;
    }
    let time = raw.get(9..15)?;
    if !time.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let time = NaiveTime::parse_from_str(time, "%H%M%S").ok()?;
    let stamp = format!("{date} {time}");
    match (raw.get(15..)?, tzid) {
        ("Z" | "z", None) => Some(format!("{stamp} UTC")),
        ("", None) => Some(format!("{stamp} (floating)")),
        ("", Some(zone))
            if !zone.is_empty()
                && zone == text::one_line(zone, MAX_TZID)
                && !zone.contains(['[', ']']) =>
        {
            Some(format!("{stamp} [TZID: {zone}]"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_keeps_date_and_time_kinds_and_unfolds_utf8() {
        let raw = b"begin:vcalendar\r\n\
BEGIN:VEVENT\r\n\
SUMMARY:Coffee \r\n \xc3\r\n\t\xa9\r\n\
DTSTART;VALUE=DATE:20261011\r\nDTEND;VALUE=DATE:20261012\r\n\
BEGIN:VALARM\r\nSUMMARY:Not the event\r\nEND:VALARM\r\n\
END:VEVENT\r\n\
BEGIN:VEVENT\r\n\
DTSTART;TZID=\"Eastern Standard Time\":20261013T170000\r\n\
DTEND;TZID=\"Eastern Standard Time\":20261013T173000\r\n\
END:VEVENT\r\n\
BEGIN:VEVENT\r\nDTSTART:20261014T123000\r\nEND:VEVENT\r\n\
end:vcalendar";
        let mut events = Vec::new();
        invitations(raw, &mut events);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].summary.as_deref(), Some("Coffee é"));
        assert_eq!(events[0].start, "2026-10-11 (all-day)");
        assert_eq!(
            events[0].end.as_deref(),
            Some("2026-10-12 (all-day, exclusive)")
        );
        assert_eq!(
            events[1].start,
            "2026-10-13 17:00:00 [TZID: Eastern Standard Time]"
        );
        assert_eq!(events[2].start, "2026-10-14 12:30:00 (floating)");
        assert_eq!(events[2].end, None);
    }

    #[test]
    fn calendar_leaves_invalid_or_incomplete_dates_and_components_unshown() {
        for (start, closing) in [
            ("DTSTART:20260230T120000Z", "END:VEVENT"),
            ("DTSTART:20261011T120000-0400", "END:VEVENT"),
            ("DTSTART;TZID=Europe/Paris:20261011T120000Z", "END:VEVENT"),
            ("DTSTART;TZID=:20261011T120000", "END:VEVENT"),
            ("DTSTART:20261011T120000Z", "END:VTODO"),
        ] {
            let raw = format!("BEGIN:VCALENDAR\nBEGIN:VEVENT\n{start}\n{closing}\nEND:VCALENDAR");
            let mut events = Vec::new();
            invitations(raw.as_bytes(), &mut events);
            assert!(events.is_empty(), "{raw}");
        }
    }
}
