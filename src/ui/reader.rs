//! The message being read: its subject and who it's from and to, its
//! attachments, then its text, scrolled.

use std::ops::Range;

use ratatui::Frame;
use ratatui::buffer::CellWidth;
use ratatui::layout::{Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use unicode_segmentation::UnicodeSegmentation;

use super::{border, bordered, fit, fit_middle, hint_spans, scrollbar};
use crate::app::{App, Focus, Item};
use crate::mail::{self, Addr, Body, Role, Seg};
use crate::text::{cols, wrap};
use crate::theme::Colors;

/// The slice of a particular body layout that the last frame showed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BodyView {
    pub area: Rect,
    pub generation: u64,
    first: usize,
}

/// (Body line, column boundary), with `width` denoting the right margin.
type BodyCell = (usize, usize);

impl BodyView {
    fn cell(self, pos: Position) -> BodyCell {
        let width = usize::from(self.area.width);
        if pos.y < self.area.top() {
            (self.first, 0)
        } else if pos.y >= self.area.bottom() {
            (self.first + usize::from(self.area.height) - 1, width)
        } else {
            (
                self.first + usize::from(pos.y - self.area.y),
                usize::from(pos.x.saturating_sub(self.area.x)).min(width),
            )
        }
    }

    pub(crate) fn web_link_at(self, body: &Body, pos: Position) -> Option<&str> {
        if !self.area.contains(pos) {
            return None;
        }
        let (row, column) = self.cell(pos);
        let (_, _, _, role) = visible_glyphs(&body.lines[row], usize::from(self.area.width))
            .find(|&(_, end, _, _)| column < end)?;
        let url = body.links.get(role.link_index()?)?.as_str();
        // Keep mailto in the composer via the link picker.
        (mail::usable_link(url)
            && !url
                .get(..7)
                .is_some_and(|s| s.eq_ignore_ascii_case("mailto:")))
        .then_some(url)
    }

    pub fn begin(self, pos: Position) -> BodySelection {
        let anchor = self.cell(pos);
        BodySelection {
            anchor,
            end: anchor,
            width: usize::from(self.area.width),
            dragging: true,
            moved: false,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct BodySelection {
    anchor: BodyCell,
    end: BodyCell,
    width: usize,
    pub dragging: bool,
    moved: bool,
}

impl BodySelection {
    pub fn drag(&mut self, view: BodyView, pos: Position) {
        self.moved = true;
        self.release(view, pos);
    }

    /// A drag that returns to its starting cell is still not a click.
    pub fn release(&mut self, view: BodyView, pos: Position) -> bool {
        self.end = view.cell(pos);
        !self.moved && self.anchor == self.end
    }

    pub fn has_text(self, body: &Body) -> bool {
        let ((first, _), (last, _)) = self.bounds();
        self.anchor != self.end
            && (first..=last).any(|row| self.glyphs(row, &body.lines[row]).next().is_some())
    }

    fn bounds(self) -> (BodyCell, BodyCell) {
        (self.anchor.min(self.end), self.anchor.max(self.end))
    }

    fn glyphs(self, row: usize, line: &[Seg]) -> impl Iterator<Item = (usize, &str)> {
        let ((first, left), (last, right)) = self.bounds();
        let columns = if (first..=last).contains(&row) {
            let start = if row == first { left } else { 0 };
            let end = if row == last { right } else { self.width };
            start..end
        } else {
            0..0
        };
        selected_glyphs(line, self.width, columns)
    }

    pub fn text(self, body: &Body) -> String {
        let ((first, _), (last, _)) = self.bounds();
        let mut out = String::new();
        for (i, line) in body.lines[first..=last].iter().enumerate() {
            if i != 0 {
                out.push('\n');
            }
            for (_, glyph) in self.glyphs(first + i, line) {
                out.push_str(glyph);
            }
        }
        out
    }
}

/// Match Paragraph's unwrapped rows. A wide glyph is selected whole if
/// either column is in the selection; padding and clipped text aren't copied.
fn selected_glyphs(
    line: &[Seg],
    width: usize,
    columns: Range<usize>,
) -> impl Iterator<Item = (usize, &str)> {
    visible_glyphs(line, width)
        .take_while(move |&(start, _, _, _)| start < columns.end)
        .filter(move |&(_, end, _, _)| end > columns.start && !columns.is_empty())
        .map(|(start, _, glyph, _)| (start, glyph))
}

fn visible_glyphs(line: &[Seg], width: usize) -> impl Iterator<Item = (usize, usize, &str, Role)> {
    let mut column = 0;
    line.iter()
        .flat_map(|seg| seg.text.graphemes(true).map(|glyph| (glyph, seg.role)))
        .filter_map(move |(glyph, role)| {
            let w = usize::from(glyph.cell_width());
            if w == 0 || w > width || glyph.contains(char::is_control) {
                return None;
            }
            let start = column;
            column += w;
            Some((start, column, glyph, role))
        })
        .take_while(move |&(_, end, _, _)| end <= width)
}

fn body_line<'a>(segs: &'a [Seg], c: &Colors) -> Line<'a> {
    Line::from_iter(segs.iter().map(|seg| {
        let style = match seg.role {
            Role::Text => Style::new().fg(c.text),
            Role::Quote(depth) if depth % 2 == 1 => Style::new().fg(c.quote),
            Role::Quote(_) => Style::new().fg(c.quote_deeper),
            Role::Link(_) | Role::ImageLink(_) => Style::new().fg(c.link),
            Role::Bold => Style::new().fg(c.text).add_modifier(Modifier::BOLD),
            Role::Italic => Style::new().fg(c.text).add_modifier(Modifier::ITALIC),
            Role::Code => Style::new().fg(c.ok),
            Role::Note => Style::new().fg(c.dim),
        };
        Span::styled(seg.text.as_str(), style)
    }))
}

/// A sender as the reader shows it: the address always in full (cut in
/// the middle, so its domain shows, if even it doesn't fit), then the name
/// the sender chose in what room is left, quoted when it could pass for an
/// address. A name can never push the address out of view.
fn sender<'a>(label: Span<'a>, from: &Addr, room: usize, c: &Colors) -> Line<'a> {
    let identity = Style::new()
        .fg(c.correspondent)
        .add_modifier(Modifier::BOLD);
    let named = !from.name.is_empty() && from.name != from.addr;
    if !named {
        return Line::from(vec![
            label,
            Span::styled(fit_middle(&from.addr, room), identity),
        ]);
    }
    let addr = format!("<{}>", fit_middle(&from.addr, room.saturating_sub(2)));
    let shown = from.display();
    let name = shown
        .strip_suffix(&format!(" <{}>", from.addr))
        .unwrap_or(&from.name)
        .to_string();
    let name_room = room.saturating_sub(cols(&addr) + 1);
    let mut spans = vec![label];
    if name_room >= 4 {
        spans.push(Span::styled(fit(&name, name_room), identity));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(addr, Style::new().fg(c.text)));
    Line::from(spans)
}

/// One line per member; the active message's body follows its header.
fn thread_header(
    item: &Item,
    active: bool,
    draft: Option<&'static str>,
    width: usize,
    now: i64,
    c: &Colors,
) -> Line<'static> {
    let m = &item.message;
    let date = mail::short_date(m.summary.date, now);
    let (draft, gap, draft_width) = super::draft_marker(draft, width.saturating_sub(2));
    let room =
        width.saturating_sub(2 + draft_width + if date.is_empty() { 0 } else { cols(&date) + 2 });
    let subject = if m.summary.subject.is_empty() {
        "(no subject)"
    } else {
        &m.summary.subject
    };
    let addr = fit_middle(&m.summary.from.addr, room.div_ceil(2));
    let subject = if addr.is_empty() {
        fit(subject, room)
    } else {
        let subject = fit(subject, room.saturating_sub(cols(&addr) + 2));
        format!("  {subject}")
    };
    let style = if active {
        Style::new().fg(c.accent).add_modifier(Modifier::BOLD)
    } else if !m.flags.seen {
        Style::new().fg(c.text).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(c.subtext)
    };
    Line::from(vec![
        Span::styled(if active { "▾ " } else { "▸ " }, style),
        Span::styled(draft, Style::new().fg(c.tag)),
        Span::raw(gap),
        Span::styled(addr, style.fg(c.correspondent)),
        Span::styled(subject, style),
        Span::styled(
            if date.is_empty() {
                date
            } else {
                format!("  {date}")
            },
            Style::new().fg(c.date),
        ),
    ])
}

pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    let c = app.colors.clone();
    let focused = app.focus == Focus::Reader;
    let reader = app.reader.as_ref();
    let (body, error) = reader
        .map(|r| (r.body.as_ref(), r.error.as_ref()))
        .unwrap_or_default();
    let mut block = bordered().border_style(border(focused, &c));
    // Label the body on screen, not the preference for the next layout.
    if let (Some(body), None) = (body, error)
        && let Some(parsed) = reader.and_then(|r| r.parsed.as_deref())
        && (parsed.text.is_some() || parsed.html.is_some())
    {
        let label = if body.from_html {
            " HTML "
        } else {
            " Plain text "
        };
        if label.len() + 2 <= usize::from(area.width) {
            let title = Span::styled(label, Style::new().fg(c.subtext));
            block = block.title_top(Line::from(title).right_aligned());
        }
    }
    if focused {
        let hint = if reader.is_some_and(crate::app::Reader::has_selection) {
            " `y` copy selection · `Esc` clear "
        } else if app.reader_is_draft() {
            if app.reader_thread().is_some() {
                " `Enter` edit draft · `[ ]` newer/older reply "
            } else {
                " `Enter` edit draft "
            }
        } else if app.reader_thread().is_some() {
            " `[ ]` newer/older reply "
        } else {
            " `o` links · `A` files · `J K` next/previous "
        };
        block = block.title_bottom(Line::from(hint_spans(hint, &c)).right_aligned());
    }
    let inner = block.inner(area);
    frame.render_widget(block, area);
    // One column of margin each side.
    let text_area = Rect {
        x: inner.x + 1,
        width: inner.width.saturating_sub(2),
        ..inner
    };
    app.reader_width
        .set(text_area.width.saturating_sub(1).max(20));
    app.reader_rows.set(inner.height);
    let Some(reader) = reader else {
        let lines = vec![
            Line::default(),
            Line::from(Span::styled(
                "  Enter opens the message under the cursor",
                Style::new().fg(c.dim),
            )),
        ];
        frame.render_widget(Paragraph::new(lines), inner);
        return;
    };
    let width = usize::from(text_area.width);
    let m = &reader.message;
    let mut lines: Vec<Line> = Vec::new();
    // The subject, wrapped.
    let subject = if m.summary.subject.is_empty() {
        "(no subject)".to_string()
    } else {
        m.summary.subject.clone()
    };
    for part in wrap(&subject, width.max(10)) {
        lines.push(Line::from(Span::styled(
            part.to_string(),
            Style::new().fg(c.text).add_modifier(Modifier::BOLD),
        )));
    }
    lines.push(Line::default());
    let label = |name: &str| Span::styled(format!("{name:<6}"), Style::new().fg(c.subtext));
    let parsed = reader.parsed.as_ref();
    let froms: Vec<Addr> = match parsed {
        Some(p) if !p.from.is_empty() => p.from.clone(),
        _ => vec![m.summary.from.clone()],
    };
    for (i, from) in froms.iter().take(4).enumerate() {
        let name = if i == 0 { "From" } else { "" };
        lines.push(sender(label(name), from, width.saturating_sub(6), &c));
    }
    if froms.len() > 4 {
        lines.push(Line::from(vec![
            label(""),
            Span::styled(
                format!("and {} more", froms.len() - 4),
                Style::new().fg(c.dim),
            ),
        ]));
    }
    let address_line = |name: &str, list: &str, lines: &mut Vec<Line>| {
        if list.is_empty() {
            return;
        }
        let wrapped = wrap(list, width.saturating_sub(6).max(10));
        for (i, part) in wrapped.iter().take(4).enumerate() {
            lines.push(Line::from(vec![
                label(if i == 0 { name } else { "" }),
                Span::styled(part.to_string(), Style::new().fg(c.text)),
            ]));
        }
        if wrapped.len() > 4 {
            lines.push(Line::from(vec![
                label(""),
                Span::styled(
                    format!("and more ({} lines)", wrapped.len() - 4),
                    Style::new().fg(c.dim),
                ),
            ]));
        }
    };
    address_line("To", &m.summary.to, &mut lines);
    address_line("Cc", &m.summary.cc, &mut lines);
    // Where a reply goes when that isn't only the sender: every address,
    // those that aren't the sender's first, without the names (which could
    // pass for addresses, or push one out of view).
    if let Some(p) = parsed {
        let theirs = |a: &Addr| froms.iter().any(|f| f.addr.eq_ignore_ascii_case(&a.addr));
        let (same, other): (Vec<&Addr>, Vec<&Addr>) = p.reply_to.iter().partition(|a| theirs(a));
        if !other.is_empty() {
            let mut seen: Vec<String> = Vec::new();
            for a in other.iter().chain(&same) {
                let addr = a.addr.to_lowercase();
                if !seen.contains(&addr) {
                    seen.push(addr);
                }
            }
            address_line("Reply", &seen.join(", "), &mut lines);
        }
    }
    let date = mail::long_date(m.summary.date);
    if !date.is_empty() {
        lines.push(Line::from(vec![
            label("Date"),
            Span::styled(date, Style::new().fg(c.date)),
        ]));
    }
    if !m.flags.tags.is_empty() {
        let text: Vec<String> = m.flags.tags.iter().map(|t| format!("#{t}")).collect();
        for (i, part) in wrap(&text.join(" "), width.saturating_sub(6).max(10))
            .iter()
            .take(2)
            .enumerate()
        {
            lines.push(Line::from(vec![
                label(if i == 0 { "Tags" } else { "" }),
                Span::styled(part.to_string(), Style::new().fg(c.tag)),
            ]));
        }
    }
    if let Some(parsed) = parsed
        && !parsed.attachments.is_empty()
    {
        let names: Vec<String> = parsed
            .attachments
            .iter()
            .map(|a| format!("{} ({})", a.name, mail::size(a.size)))
            .collect();
        let text = format!("{} {}", app.icons.attachment, names.join(", "));
        for (i, part) in wrap(&text, width.saturating_sub(6).max(10))
            .iter()
            .take(3)
            .enumerate()
        {
            lines.push(Line::from(vec![
                label(if i == 0 { "Files" } else { "" }),
                Span::styled(part.to_string(), Style::new().fg(c.subtext)),
            ]));
        }
    }
    lines.push(Line::from(Span::styled(
        "─".repeat(width),
        Style::new().fg(c.border),
    )));
    let mut body_lines = [].as_slice();
    match (body, error) {
        (_, Some(error)) => {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                error.clone(),
                Style::new().fg(c.red),
            )));
        }
        (Some(body), None) => body_lines = &body.lines,
        (None, None) => {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                format!("{} Downloading…", app.icons.loading),
                Style::new().fg(c.dim),
            )));
        }
    }
    let rows = usize::from(inner.height);
    let (max, scroll, body_view) = {
        let thread = app.reader_thread();
        let body_start = lines.len() + thread.as_ref().map_or(0, |(_, active)| active + 1);
        let max = (lines.len()
            + body_lines.len()
            + thread.as_ref().map_or(0, |(members, _)| members.len()))
        .saturating_sub(rows)
        .max(reader.format_scroll_anchor);
        let scroll = reader.scroll.min(max);
        let body = body_lines.iter().map(|line| body_line(line, &c));
        // Lines wider than the pane are cut, not wrapped.
        let shown: Vec<_> = if let Some((members, active)) = thread {
            let now = crate::app::now();
            let headers = members.enumerate().map(|(i, item)| {
                thread_header(
                    item,
                    i == active,
                    app.is_draft(item.account, &item.message)
                        .then_some(app.icons.drafts),
                    width,
                    now,
                    &c,
                )
            });
            headers
                .clone()
                .take(active + 1)
                .chain(lines)
                .chain(body)
                .chain(headers.skip(active + 1))
                .skip(scroll)
                .take(rows)
                .collect()
        } else {
            lines
                .into_iter()
                .chain(body)
                .skip(scroll)
                .take(rows)
                .collect()
        };
        frame.render_widget(Paragraph::new(shown), text_area);

        let first = scroll.max(body_start);
        let end = (scroll + rows).min(body_start + body_lines.len());
        let mut body_view = None;
        if first < end && width != 0 && reader.selectable_body().is_some() {
            let y = text_area.y + (first - scroll) as u16;
            if let Some(selection) = reader.selection.filter(|s| s.width == width) {
                for (i, line) in body_lines[first - body_start..end - body_start]
                    .iter()
                    .enumerate()
                {
                    for (x, _) in selection.glyphs(first - body_start + i, line) {
                        frame.buffer_mut()[(text_area.x + x as u16, y + i as u16)].bg = c.selected;
                    }
                }
            }
            if !app.mouse_blocked() {
                body_view = Some(BodyView {
                    area: Rect::new(text_area.x, y, text_area.width, (end - first) as u16),
                    generation: reader.layout_generation,
                    first: first - body_start,
                });
            }
        }
        (max, scroll, body_view)
    };
    app.reader_view = body_view;
    if let Some(reader) = app.reader.as_mut() {
        reader.record_scroll(scroll, rows);
    }
    scrollbar(frame, area, max, scroll, &c);
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use crate::app::tests::{app, open_first, wait_for_layout, with_mail};
    use crate::app::{App, Focus};
    use crate::store::Flags;
    use crate::ui::tests::{drawn, screen};

    /// The reader on a message with these headers, at 160 columns.
    async fn reading(headers: &str) -> String {
        let mut app = app();
        with_mail(&mut app);
        let id = app.accounts[0].id.clone();
        let raw = format!(
            "{headers}\r\nTo: me@example.org\r\nSubject: Account review\r\n\
             Date: Mon, 1 Jan 2035 00:00:00 +0000\r\nMessage-ID: <x1@evil.example>\r\n\r\nhi\r\n"
        );
        app.store
            .add_local(&id, "INBOX", raw.as_bytes(), Flags::default(), None)
            .unwrap();
        app.reload();
        app.focus = Focus::List;
        screen(&mut app, 160, 40);
        open_first(&mut app).await;
        screen(&mut app, 160, 40)
    }

    #[tokio::test]
    async fn a_long_sender_name_never_hides_the_address() {
        let shown = reading(
            "From: \"service@paypal.com <service@paypal.com> on behalf of PayPal Account \
             Review Department, case 4471-2209-118\" <attacker@evil.example>",
        )
        .await;
        let row = shown.lines().find(|l| l.contains("From")).unwrap();
        assert!(row.contains("<attacker@evil.example>"), "{row}");

        // A name that could pass for an address is quoted, as in To and Cc.
        let shown = reading("From: \"PayPal <service@paypal.com>\" <attacker2@evil.example>").await;
        assert!(
            shown.contains("\"PayPal <service@paypal.com>\" <attacker2@evil.example>"),
            "{shown}"
        );

        // A long address keeps its domain.
        let shown = reading(
            "From: <service@paypal.com.account-verification-secure-login-center-7781-\
             and-some-more-padding.evil.example>",
        )
        .await;
        let row = shown.lines().find(|l| l.contains("From")).unwrap();
        assert!(row.contains("evil.example"), "{row}");
    }

    #[tokio::test]
    async fn halfwidth_sound_marks_never_hide_the_address() {
        // No columns to unicode-width, one each as drawn: measured the
        // first way, the name would push the address out of the row.
        for name in [
            format!(
                "PayPal Security{}",
                format!(" {}", "\u{FF9E}".repeat(10)).repeat(6)
            ),
            format!("PayPal Security {}", "\u{FF76}\u{FF9E}".repeat(40)),
        ] {
            let shown = reading(&format!("From: \"{name}\" <attacker@evil.example>")).await;
            let row = shown.lines().find(|l| l.contains("From")).unwrap();
            assert!(row.contains("<attacker@evil.example>"), "{row}");
        }
    }

    #[tokio::test]
    async fn every_reply_destination_is_shown() {
        let long = format!("Alice Rivera, Finance, {}", "x".repeat(90));
        let shown = reading(&format!(
            "From: \"Alice Rivera\" <alice@example.com>\r\nReply-To: \"Alice Rivera\" \
             <alice@example.com>, <evil@evil.example>, \"{long}\" <alice@example.com>"
        ))
        .await;
        let row = shown.lines().find(|l| l.contains("Reply")).expect(&shown);
        assert!(row.contains("evil@evil.example"), "{row}");
    }

    #[tokio::test]
    async fn a_message_shows_its_headers_then_its_text() {
        let mut app = app();
        with_mail(&mut app);
        app.focus = Focus::List;
        screen(&mut app, 160, 40);
        open_first(&mut app).await;
        let shown = screen(&mut app, 160, 40);
        assert!(
            shown.contains("From  Alice Rivera <alice@example.com>"),
            "{shown}"
        );
        assert!(
            shown.contains("To    Sam Taylor <me@example.org>"),
            "{shown}"
        );
        assert!(shown.contains("Are we still on for noon?"), "{shown}");
        assert!(shown.contains("menu.pdf"), "the attachment: {shown}");
        let date = crate::mail::long_date(app.reader.as_ref().unwrap().message.summary.date);
        // Narrow: the reader takes the window, then Esc goes back.
        let shown = screen(&mut app, 60, 30);
        assert!(shown.contains("Are we still on"), "{shown}");
        let buffer = drawn(&mut app, 60, 30);
        let color_at = |field: &str| {
            let (y, line) = shown
                .lines()
                .enumerate()
                .find(|(_, line)| line.contains(field))
                .unwrap();
            let x = crate::text::cols(&line[..line.find(field).unwrap()]) as u16;
            buffer[(x, y as u16)].fg
        };
        assert_eq!(color_at("Alice Rivera"), app.colors.correspondent);
        assert_eq!(color_at(&date), app.colors.date);
        assert_eq!(color_at("Lunch tomorrow?"), app.colors.text);
    }

    #[tokio::test]
    async fn the_border_tracks_the_body_shown_when_switching_formats() {
        let mut app = app();
        with_mail(&mut app);
        let (account, folder, uid) = app.items[0].key();
        let plain = "More plain.\r\n".repeat(24);
        let html = "<p>More HTML.</p>".repeat(40);
        let raw = format!(
            "From: sender@example.org\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/alternative; boundary=alt\r\n\r\n\
             --alt\r\nContent-Type: text/plain\r\n\r\nPlain version.\r\n{plain}\r\n\
             --alt\r\nContent-Type: text/html\r\n\r\n<p>HTML version.</p>{html}<p>End of HTML.</p>\r\n\
             --alt--\r\n"
        );
        app.store
            .save_body(&app.accounts[account].id, &folder, uid, raw.as_bytes())
            .unwrap();
        open_first(&mut app).await;

        let check = |app: &mut App, label: &str, text: &str| {
            let shown = screen(app, 60, 22);
            let top = shown.lines().next().unwrap();
            assert!(top.ends_with(label), "{top}");
            assert!(shown.contains(text), "{shown}");
        };
        check(&mut app, " HTML ╮", "HTML version.");
        app.on_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
        check(&mut app, " HTML ╮", "End of HTML.");
        app.on_key(KeyEvent::new(KeyCode::Char('H'), KeyModifiers::NONE));
        check(&mut app, " HTML ╮", "HTML version.");
        wait_for_layout(&mut app).await;
        check(&mut app, " Plain text ╮", "Plain version.");
    }

    #[tokio::test]
    async fn attachment_only_messages_have_no_format_label() {
        let shown = reading(
            "From: sender@example.org\r\nMIME-Version: 1.0\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Disposition: attachment; filename=document.bin",
        )
        .await;
        assert!(shown.contains("document.bin"), "{shown}");
        assert!(shown.contains("(no text)"), "{shown}");
        let top = shown.lines().next().unwrap();
        assert!(
            !top.contains(" Plain text ") && !top.contains(" HTML "),
            "{top}"
        );
    }

    #[tokio::test]
    async fn tags_show_under_the_date() {
        let mut app = app();
        with_mail(&mut app);
        let (id, uid) = (app.accounts[0].id.clone(), app.items[0].message.uid);
        let flags = Flags {
            tags: vec!["travel".into(), "work".into()],
            ..Flags::default()
        };
        app.store.set_flags(&id, "INBOX", &[(uid, flags)]).unwrap();
        app.reload();
        open_first(&mut app).await;
        let shown = screen(&mut app, 160, 40);
        let date = shown
            .lines()
            .position(|l| l.contains("Date  "))
            .expect(&shown);
        let tags = shown
            .lines()
            .position(|l| l.contains("Tags  #travel #work"))
            .expect(&shown);
        assert_eq!(tags, date + 1, "{shown}");
    }
}
