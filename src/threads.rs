//! Conversations: the list's messages put in threads by what answers what
//! (Message-ID, In-Reply-To, References), the conversation with the newest
//! message first, each in the order it was written, replies under what
//! they answer. Done here, from the headers in the cache, so it's the same
//! for every server, and for POP3.
//!
//! Those headers are the sender's: anyone can make a message look like a
//! reply in a conversation whose Message-ID they know. Every row still
//! says who it's from, and the reader shows the address first.

use std::collections::HashMap;

use crate::mail::Summary;

/// Replies deeper than this are drawn at this depth.
pub const MAX_DEPTH: usize = 6;
/// A message this far down a conversation starts another: checking that a
/// reply doesn't answer itself walks up this far at most.
const MAX_CHAIN: usize = 1000;

/// Where a message goes in the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placed {
    /// Its place in what was given.
    pub index: usize,
    /// The lines that show where it is in its conversation: `├─`, `└─`,
    /// `│ ` and spaces, two columns a level; empty for a conversation's
    /// first message.
    pub tree: String,
    /// It answers a message with the same subject (`Re: …`): the subject
    /// needn't show again.
    pub same_subject: bool,
}

fn ids(summary: &Summary) -> impl Iterator<Item = &str> {
    std::iter::once(summary.message_id.as_str())
        .chain(std::iter::once(summary.in_reply_to.as_str()))
        .chain(summary.references.split_whitespace())
        .filter(|id| !id.is_empty())
}

fn named_parents(summary: &Summary) -> impl Iterator<Item = &str> {
    std::iter::once(summary.in_reply_to.as_str())
        .chain(summary.references.split_whitespace().rev())
        .filter(|id| !id.is_empty())
}

/// Messages connected to the seed indices by their conversation headers.
/// Shared references count even when the message they name isn't cached.
pub fn connected(summaries: &[&Summary], seeds: impl IntoIterator<Item = usize>) -> Vec<bool> {
    let mut keep = vec![false; summaries.len()];
    let mut pending: Vec<usize> = seeds.into_iter().collect();
    for &i in &pending {
        keep[i] = true;
    }
    let mut by_id: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, summary) in summaries.iter().enumerate() {
        if keep[i] {
            continue;
        }
        for id in ids(summary) {
            by_id.entry(id).or_default().push(i);
        }
    }
    while let Some(i) = pending.pop() {
        for id in ids(summaries[i]) {
            // Each header id is visited once, even in long conversations.
            if let Some(messages) = by_id.remove(id) {
                for j in messages {
                    if !keep[j] {
                        keep[j] = true;
                        pending.push(j);
                    }
                }
            }
        }
    }
    keep
}

/// Header-only members inherit a native thread only when their connected
/// component names exactly one, within the same account.
fn infer_groups(summaries: &[&Summary], groups: &mut [(usize, Option<u64>)]) {
    if !groups.iter().any(|(_, thread)| thread.is_some())
        || groups.iter().all(|(_, thread)| thread.is_some())
    {
        return;
    }
    let mut by_id: HashMap<(usize, &str), Vec<usize>> = HashMap::new();
    for (i, summary) in summaries.iter().enumerate() {
        if let Some(&(account, _)) = groups.get(i) {
            for id in ids(summary) {
                by_id.entry((account, id)).or_default().push(i);
            }
        }
    }
    let mut visited = vec![false; summaries.len()];
    let mut pending = Vec::new();
    let mut members = Vec::new();
    for i in 0..summaries.len() {
        let Some(&(account, None)) = groups.get(i) else {
            continue;
        };
        if visited[i] {
            continue;
        }
        visited[i] = true;
        pending.push(i);
        let mut native = None;
        let mut ambiguous = false;
        while let Some(j) = pending.pop() {
            members.push(j);
            for id in ids(summaries[j]) {
                if let Some(related) = by_id.remove(&(account, id)) {
                    for k in related {
                        if let Some(thread) = groups[k].1 {
                            ambiguous |= native.is_some_and(|was| was != thread);
                            native = Some(thread);
                        } else if !visited[k] {
                            visited[k] = true;
                            pending.push(k);
                        }
                    }
                }
            }
        }
        for j in members.drain(..) {
            if !ambiguous {
                groups[j].1 = native;
            }
        }
    }
}

/// `summaries` as threads: each conversation in turn, newest first.
#[cfg(test)]
pub fn arrange(summaries: &[&Summary]) -> Vec<Placed> {
    arrange_arrived(summaries, summaries.len(), &[], &mut [])
}

/// As [`arrange`], knowing where each message is and its UID there
/// (`arrived`: a number for its account and folder, and its UID): of
/// messages with one Message-ID in one folder, the one that came first is
/// the one replies go under, not one a sender dated later.
/// Groups are scoped to an account; native thread IDs keep their members
/// together even without reply headers. Sender headers can't cross groups.
/// `groups` holds each account and optional thread ID as scratch space;
/// missing IDs are inferred from unambiguous header connections.
/// The first `listed` messages establish the conversations. Supplemental
/// drafts can reply within those conversations but cannot change their grouping.
pub fn arrange_arrived(
    summaries: &[&Summary],
    listed: usize,
    arrived: &[(usize, u32)],
    groups: &mut [(usize, Option<u64>)],
) -> Vec<Placed> {
    let messages = &summaries[..listed];
    let listed_groups = listed.min(groups.len());
    infer_groups(messages, &mut groups[..listed_groups]);
    let group = |i: usize| groups.get(i).copied();
    // A Message-ID's first message: another copy stands alone.
    let index_ids = |by_id: &mut HashMap<_, usize>, use_native| {
        for (i, s) in messages.iter().enumerate() {
            if s.message_id.is_empty() {
                continue;
            }
            let group =
                group(i).map(|(account, native)| (account, if use_native { native } else { None }));
            let first = by_id.entry((s.message_id.as_str(), group)).or_insert(i);
            if let (Some(&(place, uid)), Some(&(was_place, was_uid))) =
                (arrived.get(i), arrived.get(*first))
                && place == was_place
                && uid < was_uid
            {
                *first = i;
            }
        }
    };
    let mut by_id = HashMap::new();
    index_ids(&mut by_id, true);
    // Each message answers the nearest one it names that's here: the one
    // it replies to, else the latest of its references.
    let mut parent: Vec<Option<usize>> = vec![None; summaries.len()];
    for (i, s) in messages.iter().enumerate() {
        for id in named_parents(s) {
            if let Some(&p) = by_id.get(&(id, group(i)))
                && p != i
                && !answers(&parent, p, i)
            {
                parent[i] = Some(p);
                break;
            }
        }
    }
    // Gmail's native grouping also includes messages without References.
    // Join its otherwise separate roots under the oldest one.
    let mut group_roots = HashMap::new();
    for (i, p) in parent[..listed].iter().enumerate() {
        if p.is_none()
            && let Some((account, Some(thread))) = group(i)
        {
            let root = group_roots.entry((account, thread)).or_insert(i);
            if (summaries[i].date, i) < (summaries[*root].date, *root) {
                *root = i;
            }
        }
    }
    for (i, p) in parent[..listed].iter_mut().enumerate() {
        if p.is_none()
            && let Some((account, Some(thread))) = group(i)
            && let Some(&root) = group_roots.get(&(account, thread))
            && root != i
        {
            *p = Some(root);
        }
    }
    // Attach only to listed messages, without using draft headers as
    // evidence for Gmail group inference or as parents of other mail.
    let draft_parent = |by_id: &HashMap<_, usize>, i: usize, group| {
        named_parents(summaries[i]).find_map(|id| by_id.get(&(id, group)).copied())
    };
    let mut header_only = false;
    for (i, p) in parent.iter_mut().enumerate().skip(listed) {
        if let Some((account, Some(thread))) = group(i) {
            *p = draft_parent(&by_id, i, group(i))
                .or_else(|| group_roots.get(&(account, thread)).copied())
                .or_else(|| draft_parent(&by_id, i, Some((account, None))));
        } else if group_roots.is_empty() {
            *p = draft_parent(&by_id, i, group(i));
        } else {
            header_only = true;
        }
    }
    if header_only {
        // Look up the nearest named parent across this account's groups.
        by_id.clear();
        index_ids(&mut by_id, false);
        for (i, p) in parent.iter_mut().enumerate().skip(listed) {
            if group(i).is_none_or(|(_, native)| native.is_none()) {
                *p = draft_parent(&by_id, i, group(i));
            }
        }
    }
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); listed];
    let mut roots = Vec::new();
    let mut attached = 0;
    for (i, p) in parent.iter().enumerate() {
        if let Some(p) = p {
            children[*p].push(i);
            attached += usize::from(i >= listed);
        } else if i < listed {
            roots.push(i);
        }
    }
    let date = |i: usize| summaries[i].date;
    for list in &mut children {
        list.sort_by_key(|&i| (date(i), i));
    }
    // A conversation is as new as its newest message.
    let mut newest = vec![i64::MIN; listed];
    for &root in &roots {
        let mut stack = vec![root];
        let mut latest = i64::MIN;
        while let Some(i) = stack.pop() {
            latest = latest.max(date(i));
            if let Some(kids) = children.get(i) {
                stack.extend(kids);
            }
        }
        newest[root] = latest;
    }
    roots.sort_by_key(|&i| (std::cmp::Reverse(newest[i]), i));
    let subject = |i: usize| base_subject(&summaries[i].subject);
    let mut out = Vec::with_capacity(listed + attached);
    for root in roots {
        // Depth first; with each message, whether each level above it (and
        // it) has more to come below, for the lines.
        let mut stack: Vec<(usize, Vec<bool>)> = vec![(root, Vec::new())];
        while let Some((i, more)) = stack.pop() {
            let tree = tree(&more);
            let same_subject = parent[i].is_some_and(|p| subject(p) == subject(i));
            out.push(Placed {
                index: i,
                tree,
                same_subject,
            });
            let Some(kids) = children.get(i) else {
                continue;
            };
            for (k, &child) in kids.iter().enumerate().rev() {
                let mut levels = more.clone();
                levels.push(k + 1 < kids.len());
                stack.push((child, levels));
            }
        }
    }
    out
}

/// Whether `from`, or what it answers, all the way up, is `message`: it
/// can't then answer `message` too. Past [`MAX_CHAIN`], taken as yes.
fn answers(parent: &[Option<usize>], from: usize, message: usize) -> bool {
    let mut at = Some(from);
    for _ in 0..MAX_CHAIN {
        match at {
            Some(i) if i == message => return true,
            Some(i) => at = parent[i],
            None => return false,
        }
    }
    true
}

/// The lines before a message: for each level above, `│ ` if more comes
/// there below, and its own `├─` (more answers to the same message come)
/// or `└─`.
fn tree(more: &[bool]) -> String {
    let Some((own, above)) = more.split_last() else {
        return String::new();
    };
    let above = &above[above.len().saturating_sub(MAX_DEPTH - 1)..];
    let mut out = String::new();
    for &more in above {
        out.push_str(if more { "│ " } else { "  " });
    }
    out.push_str(if *own { "├─" } else { "└─" });
    out
}

/// A subject without the `Re:` and `Fwd:` replies put before it.
pub fn base_subject(subject: &str) -> String {
    let mut s = subject.trim();
    loop {
        let lower = s.to_lowercase();
        let Some(cut) = [
            "re:", "fwd:", "fw:", "aw:", "sv:", "wg:", "vs:", "antw:", "tr:",
        ]
        .iter()
        .find(|p| lower.starts_with(*p)) else {
            break;
        };
        s = s[cut.len()..].trim_start();
    }
    s.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(id: &str, reply_to: &str, refs: &str, date: i64, subject: &str) -> Summary {
        Summary {
            message_id: id.into(),
            in_reply_to: reply_to.into(),
            references: refs.into(),
            date,
            subject: subject.into(),
            ..Summary::default()
        }
    }

    /// The order, as (index, tree).
    fn order(list: &[Summary]) -> Vec<(usize, String)> {
        let refs: Vec<&Summary> = list.iter().collect();
        arrange(&refs)
            .into_iter()
            .map(|p| (p.index, p.tree))
            .collect()
    }

    #[test]
    fn replies_go_under_what_they_answer_and_the_newest_conversation_first() {
        let list = [
            summary("a", "", "", 10, "Plan"),
            summary("x", "", "", 30, "Lunch"),
            summary("b", "a", "a", 20, "Re: Plan"),
            summary("c", "a", "a", 40, "Re: Plan"),
            summary("d", "b", "a b", 50, "Re: Re: Plan"),
        ];
        assert_eq!(
            order(&list),
            [
                (0, "".into()),
                (2, "├─".into()),
                (4, "│ └─".into()),
                (3, "└─".into()),
                (1, "".into()),
            ]
        );
    }

    #[test]
    fn a_later_copy_of_a_message_id_doesnt_take_its_replies() {
        // The genuine message came first (UID 1); a sender's copy of its
        // Message-ID, dated later, is listed before it.
        let list = [
            summary("a", "", "", 90, "Forged"),
            summary("r", "a", "a", 20, "Re: Plan"),
            summary("a", "", "", 10, "Plan"),
        ];
        let refs: Vec<&Summary> = list.iter().collect();
        let placed = arrange_arrived(&refs, refs.len(), &[(0, 5), (0, 2), (0, 1)], &mut []);
        let reply = placed.iter().position(|p| p.index == 1).unwrap();
        assert_eq!(placed[reply - 1].index, 2, "under the first: {placed:?}");
    }

    #[test]
    fn a_missing_message_is_skipped_to_the_one_before() {
        // d answers b, which isn't here: under a.
        let list = [
            summary("a", "", "", 10, "Plan"),
            summary("d", "b", "a b", 50, "Re: Plan"),
        ];
        assert_eq!(order(&list), [(0, "".into()), (1, "└─".into())]);
    }

    #[test]
    fn loops_copies_and_messages_without_ids_stand_alone() {
        let list = [
            summary("a", "b", "b", 10, "A"),
            summary("b", "a", "a", 20, "B"),
            summary("a", "", "", 30, "A again"),
            summary("", "a", "a", 5, "No id"),
        ];
        // a answers b, so b can't answer a; the copy of a, newest, stands
        // alone; the message with no id still answers a.
        assert_eq!(
            order(&list),
            [
                (2, "".into()),
                (1, "".into()),
                (0, "└─".into()),
                (3, "  └─".into()),
            ]
        );
    }

    #[test]
    fn deep_conversations_stay_on_the_screen() {
        let list: Vec<Summary> = (0..50)
            .map(|i| {
                let parent = if i == 0 {
                    String::new()
                } else {
                    format!("m{}", i - 1)
                };
                summary(&format!("m{i}"), &parent, &parent, i, "Long")
            })
            .collect();
        let placed = order(&list);
        assert_eq!(placed.len(), 50);
        assert!(
            placed
                .iter()
                .all(|(_, t)| t.chars().count() <= 2 * MAX_DEPTH)
        );
    }

    #[test]
    fn a_full_list_is_threaded_at_once() {
        // Every message answers the one before, with a hundred
        // references: as many as a folder lists.
        let list: Vec<Summary> = (0..20_000)
            .map(|i| {
                let refs: Vec<String> = (i.max(100) - 100..i).map(|j| format!("m{j}")).collect();
                let parent = refs.last().cloned().unwrap_or_default();
                summary(&format!("m{i}"), &parent, &refs.join(" "), i, "Long")
            })
            .collect();
        let started = std::time::Instant::now();
        let placed = order(&list);
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        assert_eq!(placed.len(), 20_000);
        let roots = placed.iter().filter(|(_, tree)| tree.is_empty()).count();
        assert!(
            roots >= 20_000 / (MAX_CHAIN + 1),
            "a new one every thousand: {roots}"
        );
    }

    #[test]
    fn sent_messages_follow_connections_not_subjects_or_empty_ids() {
        let list = [
            summary("received", "sent", "missing sent", 30, "Plan"),
            summary("sent-again", "sent", "missing sent", 40, "Re: Plan"),
            summary("sent", "", "", 20, "Plan"),
            summary("sibling", "missing", "missing", 10, "Re: Plan"),
            summary("unrelated", "", "", 50, "Plan"),
            summary("", "", "", 60, "Plan"),
            summary("loop-a", "loop-b", "", 70, "Plan"),
            summary("loop-b", "loop-a", "", 80, "Plan"),
        ];
        let refs: Vec<&Summary> = list.iter().collect();
        assert_eq!(
            connected(&refs, [0]),
            [true, true, true, true, false, false, false, false]
        );
        assert_eq!(connected(&refs, []), [false; 8]);
    }

    #[test]
    fn native_threads_join_missing_headers_without_crossing_accounts_or_groups() {
        let list = [
            summary("new", "", "", 30, "Plan"),
            summary("old", "", "", 10, "Plan"),
            summary("other", "old", "old", 40, "Re: Plan"),
            summary("old", "", "", 5, "Other account"),
            summary("reply", "old", "old", 20, "Re: Plan"),
        ];
        let refs: Vec<_> = list.iter().collect();
        let mut groups = [
            (0, Some(7)),
            (0, Some(7)),
            (0, Some(8)),
            (1, Some(7)),
            (0, Some(7)),
        ];
        let placed = arrange_arrived(&refs, refs.len(), &[], &mut groups);
        let order: Vec<_> = placed.iter().map(|p| (p.index, p.tree.as_str())).collect();
        assert_eq!(order, [(2, ""), (1, ""), (4, "├─"), (0, "└─"), (3, "")]);
    }

    #[test]
    fn header_only_members_join_native_threads_without_crossing_accounts_or_ambiguities() {
        let list = [
            summary("incoming", "first", "", 20, "Plan"),
            summary("archived", "", "", 5, "Plan"),
            summary("first", "", "", 10, "Plan"),
            summary("last", "first", "", 30, "Re: Plan"),
            summary("other", "", "", 40, "Other"),
            summary("ambiguous", "incoming", "incoming other", 50, "Re: Plan"),
            summary("foreign", "incoming", "", 60, "Re: Plan"),
        ];
        let refs: Vec<_> = list.iter().collect();
        let mut groups = [
            (0, Some(7)),
            (0, Some(7)),
            (0, None),
            (0, None),
            (0, Some(8)),
            (0, None),
            (1, None),
        ];
        let placed = arrange_arrived(&refs, refs.len(), &[], &mut groups);
        let order: Vec<_> = placed.iter().map(|p| p.index).collect();
        assert_eq!(order, [6, 5, 4, 1, 2, 0, 3]);
        assert!(placed[..4].iter().all(|p| p.tree.is_empty()));
        assert!(placed[4..].iter().all(|p| !p.tree.is_empty()));
    }

    #[test]
    fn a_reply_with_the_same_subject_needs_none() {
        let list = [
            summary("a", "", "", 10, "Plan"),
            summary("b", "a", "a", 20, "RE: Fwd:  plan"),
            summary("c", "a", "a", 30, "Re: Change of plan"),
        ];
        let refs: Vec<&Summary> = list.iter().collect();
        let same: Vec<bool> = arrange(&refs).iter().map(|p| p.same_subject).collect();
        assert_eq!(same, [false, true, false]);
    }
}
