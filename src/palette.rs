//! Searchable labels for actions already exposed by the keyboard.

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Command {
    Compose,
    Search,
    Refresh,
    Settings,
    Help,
    Undo,
    Changes,
    Open,
    Reply,
    ReplyAll,
    Forward,
    Archive,
    Junk,
    Move,
    Tag,
    Star,
    Read,
    Delete,
    Conversation,
    Format,
    Links,
    Attachments,
    Unsubscribe,
    Attach,
    Editor,
    SaveDraft,
    Markdown,
    Original,
}

impl Command {
    pub fn targets_mail(self) -> bool {
        matches!(
            self,
            Self::Open
                | Self::Reply
                | Self::ReplyAll
                | Self::Forward
                | Self::Archive
                | Self::Junk
                | Self::Move
                | Self::Tag
                | Self::Star
                | Self::Read
                | Self::Delete
                | Self::Conversation
                | Self::Format
                | Self::Links
                | Self::Attachments
                | Self::Unsubscribe
        )
    }
}

const ENTRIES: &[(Command, &str, &str)] = {
    use Command::*;
    &[
        (Compose, "Write a new message", "c"),
        (Search, "Search mail", "/"),
        (Open, "Open the selected message or draft", "Enter"),
        (Reply, "Reply", "r"),
        (ReplyAll, "Reply to all", "a"),
        (Forward, "Forward message", "f"),
        (Archive, "Archive mail", "e"),
        (Junk, "Move to Junk", "!"),
        (Move, "Move to a folder", "m"),
        (Delete, "Delete mail", "d"),
        (Tag, "Add or remove a tag", "t"),
        (Star, "Star or unstar mail", "s"),
        (Read, "Mark read or unread", "u"),
        (Conversation, "Collapse or expand conversation", "v"),
        (Format, "Switch between HTML and plain text", "H"),
        (Links, "Show links", "o"),
        (Attachments, "Show attachments", "A"),
        (Unsubscribe, "Unsubscribe from mailing list", "U"),
        (Refresh, "Check for new mail", "R"),
        (Undo, "Undo last mail change", "z"),
        (Changes, "Show changes to undo", "Z"),
        (Settings, "Open settings and themes", "O"),
        (Help, "Show keyboard shortcuts", "?"),
        (Attach, "Attach a file", "Ctrl-o"),
        (Editor, "Open body in external editor", "Ctrl-e"),
        (SaveDraft, "Save and close draft", "Ctrl-d"),
        (Markdown, "Switch between Markdown and plain text", "F4"),
        (Original, "Switch between reply and original message", "F2"),
    ]
};

pub(crate) struct Palette {
    entries: Vec<(Command, &'static str, &'static str)>,
    pub selected: usize,
    pub list_changed: bool,
    pub selection_visible: bool,
}

impl Palette {
    pub fn new(available: impl Fn(Command) -> bool) -> Self {
        Self {
            entries: ENTRIES
                .iter()
                .copied()
                .filter(|(command, _, _)| available(*command))
                .collect(),
            selected: 0,
            list_changed: false,
            selection_visible: false,
        }
    }

    pub fn matching<'a>(
        &'a self,
        query: &'a str,
    ) -> impl Iterator<Item = (Command, &'static str, &'static str)> + 'a {
        self.entries
            .iter()
            .copied()
            .filter(move |&(_, label, key)| {
                query.split_whitespace().all(|word| {
                    key == word
                        || label
                            .as_bytes()
                            .windows(word.len())
                            .any(|part| part.eq_ignore_ascii_case(word.as_bytes()))
                })
            })
    }
}
