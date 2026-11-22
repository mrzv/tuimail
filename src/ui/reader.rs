//! The message being read: its subject and who it's from and to, its
//! attachments, then its text, scrolled.

use std::fmt::Write;
use std::num::NonZeroU16;
use std::ops::Range;

use ratatui::Frame;
use ratatui::buffer::{Buffer, CellDiffOption, CellWidth};
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

    pub fn begin(self, pos: Position) -> BodySelection {
        let anchor = self.cell(pos);
        BodySelection {
            anchor,
            end: anchor,
            width: usize::from(self.area.width),
            dragging: true,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct BodySelection {
    anchor: BodyCell,
    end: BodyCell,
    width: usize,
    pub dragging: bool,
}

impl BodySelection {
    pub fn extend(&mut self, view: BodyView, pos: Position) {
        self.end = view.cell(pos);
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
            Role::Link(_) => Style::new().fg(c.link).add_modifier(Modifier::UNDERLINED),
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
    let named = !from.name.is_empty() && from.name != from.addr;
    if !named {
        return Line::from(vec![
            label,
            Span::styled(
                fit_middle(&from.addr, room),
                Style::new().fg(c.text).add_modifier(Modifier::BOLD),
            ),
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
        spans.push(Span::styled(
            fit(&name, name_room),
            Style::new().fg(c.text).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw(" "));
    }
    spans.push(Span::styled(addr, Style::new().fg(c.text)));
    Line::from(spans)
}

/// One line per member; the active message's body follows its header.
fn thread_header(item: &Item, active: bool, width: usize, now: i64, c: &Colors) -> Line<'static> {
    let m = &item.message;
    let date = mail::short_date(m.summary.date, now);
    let room = width.saturating_sub(2 + if date.is_empty() { 0 } else { cols(&date) + 2 });
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
        Span::styled(addr, style),
        Span::styled(subject, style),
        Span::styled(
            if date.is_empty() {
                date
            } else {
                format!("  {date}")
            },
            Style::new().fg(c.dim),
        ),
    ])
}

pub fn draw(frame: &mut Frame, app: &mut App, area: Rect) {
    let c = app.colors.clone();
    let focused = app.focus == Focus::Reader;
    let mut block = bordered().border_style(border(focused, &c));
    if focused {
        let hint = if app
            .reader
            .as_ref()
            .is_some_and(crate::app::Reader::has_selection)
        {
            " `y` copy selection · `Esc` clear "
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
    let Some(reader) = app.reader.as_ref() else {
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
            Span::styled(date, Style::new().fg(c.text)),
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
    match (&reader.body, &reader.error) {
        (_, Some(error)) => {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                error.clone(),
                Style::new().fg(c.red),
            )));
        }
        (Some(body), None) => {
            if body.from_html {
                lines.push(Line::from(Span::styled(
                    fit("HTML as text, nothing fetched · H plain text", width),
                    Style::new().fg(c.dim),
                )));
                lines.push(Line::default());
            }
            body_lines = &body.lines;
        }
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
        .saturating_sub(rows);
        let scroll = reader.scroll.min(max);
        let body = body_lines.iter().map(|line| body_line(line, &c));
        // Lines wider than the pane are cut, not wrapped.
        let shown: Vec<_> = if let Some((members, active)) = thread {
            let now = crate::app::now();
            let headers = members
                .enumerate()
                .map(|(i, item)| thread_header(item, i == active, width, now, &c));
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
        reader.scroll = scroll;
    }
    scrollbar(frame, area, max, scroll, &c);
}

/// Add terminal-only metadata after drawing, using the same body and viewport
/// as mouse selection. A popup has no body view, so no link lies under it.
pub(crate) fn hyperlinks(frame: &mut Frame, app: &App) {
    if !app.demo
        && let Some(view) = app.reader_view
        && let Some(body) = app
            .reader
            .as_ref()
            .and_then(|reader| reader.selectable_body())
    {
        link_body(frame.buffer_mut(), view, body);
    }
}

fn link_body(buffer: &mut Buffer, view: BodyView, body: &Body) {
    if body.links.is_empty() {
        return;
    }
    let mut symbol = String::new();
    for (row, line) in body.lines[view.first..][..usize::from(view.area.height)]
        .iter()
        .enumerate()
    {
        let y = view.area.y + row as u16;
        let mut glyphs = visible_glyphs(line, usize::from(view.area.width)).peekable();
        while let Some((start, mut end, glyph, Role::Link(index))) =
            glyphs.find(|item| matches!(item.3, Role::Link(_)))
        {
            let Some(url) = body.links.get(index).filter(|url| {
                // Keep mailto in the composer via the link picker.
                // Kitty truncates its 2048-byte ID-plus-URL storage; leave
                // room for the ID and keep longer links in the picker.
                url.len() <= 2000
                    && mail::usable_link(url)
                    && !url
                        .get(..7)
                        .is_some_and(|s| s.eq_ignore_ascii_case("mailto:"))
            }) else {
                while glyphs.next_if(|item| item.3 == Role::Link(index)).is_some() {}
                continue;
            };

            let x = view.area.x + start as u16;
            let style = buffer[(x, y)].style();
            symbol.clear();
            let _ = write!(
                symbol,
                "\x1b]8;id=tuimail-{}-{index};{url}\x1b\\",
                view.generation
            );
            symbol.push_str(glyph);
            while let Some((_, next_end, glyph, _)) = glyphs.next_if(|&(next, _, _, role)| {
                role == Role::Link(index) && buffer[(view.area.x + next as u16, y)].style() == style
            }) {
                end = next_end;
                symbol.push_str(glyph);
            }
            symbol.push_str("\x1b]8;;\x1b\\");

            // Diff the open, text and close together: a partial redraw must
            // never leave an OSC 8 span open or retain a removed destination.
            buffer[(x, y)]
                .set_symbol(&symbol)
                .set_diff_option(CellDiffOption::ForcedWidth(
                    NonZeroU16::new((end - start) as u16).unwrap(),
                ));
            for tail in x + 1..view.area.x + end as u16 {
                buffer[(tail, y)].set_diff_option(CellDiffOption::Skip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::widgets::Widget;

    use crate::app::Focus;
    use crate::app::tests::{app, open_first, with_mail};
    use crate::store::Flags;
    use crate::ui::tests::screen;

    #[test]
    fn terminal_hyperlinks_follow_the_visible_text_and_clear_on_redraw() {
        let body = mail::render_html(
            "<a href='https://one.example/path'><strong>界Web</strong></a> \
             <a href='mailto:a@example.org'>mail</a>",
            40,
        );
        let area = Rect::new(0, 0, 10, 1);
        let view = BodyView {
            area,
            first: 0,
            generation: 7,
        };
        let mut plain = Buffer::empty(area);
        Paragraph::new(body_line(
            &body.lines[0],
            &Colors::named(crate::theme::DEFAULT),
        ))
        .render(area, &mut plain);
        let mut linked = plain.clone();
        link_body(&mut linked, view, &body);
        assert_eq!(
            linked[(0, 0)].symbol(),
            "\x1b]8;id=tuimail-7-0;https://one.example/path\x1b\\界Web\x1b]8;;\x1b\\",
        );
        assert_eq!(linked[(6, 0)].symbol(), "m");
        assert_eq!(linked[(6, 0)].diff_option, CellDiffOption::None);
        assert!(linked.diff(&linked).is_empty());

        let mut next = body;
        next.links[0] = "https://two.example/path".into();
        let mut changed = plain.clone();
        link_body(&mut changed, view, &next);
        let updates = linked.diff(&changed);
        assert_eq!(updates.len(), 1);
        assert!(updates[0].2.symbol().contains("https://two.example/path"));

        next.links[0] = "https://two.example/\x1b]8;;unexpected".into();
        let mut unsafe_target = plain.clone();
        link_body(&mut unsafe_target, view, &next);
        assert_eq!(unsafe_target, plain);
        next.links[0] = format!("https://two.example/{}", "a".repeat(2000));
        let mut long_target = plain.clone();
        link_body(&mut long_target, view, &next);
        assert_eq!(long_target, plain);
        // Identical visible glyphs must still be rewritten to remove their
        // hyperlink metadata. The trailing cell of 界 is not a glyph.
        let cleared: Vec<_> = changed.diff(&plain).iter().map(|item| item.0).collect();
        assert_eq!(cleared, [0, 2, 3, 4]);
    }

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
        // Narrow: the reader takes the window, then Esc goes back.
        let shown = screen(&mut app, 60, 30);
        assert!(shown.contains("Are we still on"), "{shown}");
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
