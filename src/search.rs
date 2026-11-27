//! Search terms are ANDed (at most eight). Double quotes group a phrase at
//! the start of a term or after a qualifier. Inside them only `\"` and `\\`
//! are escapes; single quotes are ordinary characters. Unknown qualifiers,
//! invalid values, and empty or malformed phrases are searched literally,
//! including their punctuation. An unclosed phrase takes the rest of the query.

use std::borrow::Cow;

use chrono::NaiveDate;

use crate::tags;

pub(crate) const MAX_TERMS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Field {
    Any,
    From,
    To,
    Subject,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Term<'a> {
    Text(Field, Cow<'a, str>),
    Tag { name: String, raw: &'a str },
    Since(NaiveDate),
    Before(NaiveDate),
}

pub(crate) fn terms(mut query: &str) -> impl Iterator<Item = Term<'_>> {
    std::iter::from_fn(move || {
        let start = query.trim_start();
        if start.is_empty() {
            return None;
        }
        let (term, rest) = parse_term(start);
        query = rest;
        Some(term)
    })
    .take(MAX_TERMS)
}

fn parse_term(start: &str) -> (Term<'_>, &str) {
    let (prefix, value) = if start.starts_with('"') {
        (None, start)
    } else if let Some(i) = start.find(|c: char| c == ':' || c.is_whitespace())
        && start.as_bytes()[i] == b':'
    {
        (Some(&start[..i]), &start[i + 1..])
    } else {
        (None, start)
    };
    let quoted = value.strip_prefix('"');
    let (value, rest) = if let Some(quoted) = quoted {
        match phrase(quoted) {
            Some((value, rest)) if rest.is_empty() || rest.starts_with(char::is_whitespace) => {
                (value, rest)
            }
            Some((_, rest)) => {
                let rest = &rest[word_end(rest)..];
                return (literal(&start[..start.len() - rest.len()]), rest);
            }
            None => return (literal(start), ""),
        }
    } else {
        let (value, rest) = value.split_at(word_end(value));
        (Cow::Borrowed(value), rest)
    };
    let raw = &start[..start.len() - rest.len()];
    if value.is_empty() {
        return (literal(raw), rest);
    }
    let is = |field| prefix.is_some_and(|p| p.eq_ignore_ascii_case(field));
    let term = if prefix.is_none() {
        Term::Text(Field::Any, value)
    } else if is("from") {
        Term::Text(Field::From, value)
    } else if is("to") {
        Term::Text(Field::To, value)
    } else if is("subject") {
        Term::Text(Field::Subject, value)
    } else if is("tag") {
        let tag = if quoted.is_some() {
            tags::normalize(&value)
        } else {
            tags::searched(raw)
        };
        tag.map_or_else(|| literal(raw), |name| Term::Tag { name, raw })
    } else if is("since") {
        date(&value).map_or_else(|| literal(raw), Term::Since)
    } else if is("before") {
        date(&value).map_or_else(|| literal(raw), Term::Before)
    } else {
        literal(raw)
    };
    (term, rest)
}

fn literal(value: &str) -> Term<'_> {
    Term::Text(Field::Any, Cow::Borrowed(value))
}

fn word_end(s: &str) -> usize {
    s.find(char::is_whitespace).unwrap_or(s.len())
}

fn phrase(s: &str) -> Option<(Cow<'_, str>, &str)> {
    let mut decoded = None::<String>;
    let mut copied = 0;
    let mut bytes = s.bytes().enumerate().peekable();
    while let Some((i, b)) = bytes.next() {
        match b {
            b'"' => {
                let value = match decoded {
                    Some(mut decoded) => {
                        decoded.push_str(&s[copied..i]);
                        Cow::Owned(decoded)
                    }
                    None => Cow::Borrowed(&s[..i]),
                };
                return Some((value, &s[i + 1..]));
            }
            b'\\' if matches!(bytes.peek(), Some((_, b'"' | b'\\'))) => {
                let (_, escaped) = bytes.next().unwrap();
                let decoded = decoded.get_or_insert_with(String::new);
                decoded.push_str(&s[copied..i]);
                decoded.push(char::from(escaped));
                copied = i + 2;
            }
            _ => {}
        }
    }
    None
}

fn date(s: &str) -> Option<NaiveDate> {
    let bytes = s.as_bytes();
    if bytes.len() != 10
        || !bytes.iter().enumerate().all(|(i, b)| match i {
            4 | 7 => *b == b'-',
            _ => b.is_ascii_digit(),
        })
        || s.starts_with("0000")
    {
        return None;
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phrases_and_qualifiers_share_the_eight_term_limit() {
        use Field::*;
        assert_eq!(
            terms(r#"FrOm:"Zoë \"Z\"" to:me SUBJECT:"C:\\temp\new" "été 2024" tag:WORK Since:2024-02-29 before:"2024-03-01" don't ninth"#)
                .collect::<Vec<_>>(),
            [
                Term::Text(From, "Zoë \"Z\"".into()),
                Term::Text(To, "me".into()),
                Term::Text(Subject, r"C:\temp\new".into()),
                Term::Text(Any, "été 2024".into()),
                Term::Tag {
                    name: "work".into(),
                    raw: "tag:WORK",
                },
                Term::Since(NaiveDate::from_ymd_opt(2024, 2, 29).unwrap()),
                Term::Before(NaiveDate::from_ymd_opt(2024, 3, 1).unwrap()),
                Term::Text(Any, "don't".into()),
            ]
        );
    }

    #[test]
    fn malformed_and_unknown_qualifiers_keep_their_literal_spelling() {
        assert_eq!(
            terms(r#"from: before:2024-2-03 since:2023-02-29 custom:"x y" to:"" "x y"z subject:"no close"#)
                .collect::<Vec<_>>(),
            [
                literal("from:"),
                literal("before:2024-2-03"),
                literal("since:2023-02-29"),
                literal(r#"custom:"x y""#),
                literal(r#"to:"""#),
                literal(r#""x y"z"#),
                literal(r#"subject:"no close"#),
            ]
        );
    }
}
