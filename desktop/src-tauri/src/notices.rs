//! What deserves a notification, worked out by comparing two snapshots. Pure,
//! like `model`, so the rules are tested rather than watched.
//!
//! A notice says that something happened, never what an agent wrote about it.

use std::collections::HashSet;

use chrono::{DateTime, Duration, Utc};

use crate::model::{Health, Reach, Snapshot};

/// Warn this long before a session ends.
const ENDING_SOON_MINUTES: i64 = 10;

#[derive(Debug, Clone, PartialEq)]
pub enum Notice {
    Waiting(usize),
    EndingSoon { label: String, minutes: i64 },
    Ended { label: String },
    Locked,
    Unreachable,
    Back,
    KeyProblem { slug: String },
    KeyStopped { slug: String },
}

impl Notice {
    pub fn text(&self) -> String {
        match self {
            Notice::Waiting(1) => "An agent is waiting for your decision. Open the menu bar icon to review it.".into(),
            Notice::Waiting(n) => format!("{n} things are waiting for your decision. Open the menu bar icon to review them."),
            Notice::EndingSoon { label, minutes } => {
                format!("Session “{label}” ends in about {minutes} min.")
            }
            Notice::Ended { label } => format!("Session “{label}” has ended."),
            Notice::Locked => "The vault is locked. Agents cannot use any key until you unlock it.".into(),
            // Only what the companion knows: it lost contact. Whether agents
            // are affected depends on why, which it cannot tell from here.
            Notice::Unreachable => "The companion lost contact with agent-vault, so what it shows may be out of date. It keeps trying.".into(),
            Notice::Back => "The companion is in contact with agent-vault again.".into(),
            Notice::KeyProblem { slug } => format!("The key “{slug}” failed its check. It may have expired or been revoked."),
            Notice::KeyStopped { slug } => format!("The key “{slug}” is stopped. No agent can use it."),
        }
    }
}

/// What the companion remembers between refreshes so nothing is said twice.
#[derive(Debug, Default)]
pub struct Memo {
    /// Pending ids already announced. `None` until the first look.
    seen: Option<HashSet<String>>,
    /// Sessions already given their "ending soon" warning.
    warned: HashSet<String>,
    /// Sessions the user just ended from the menu: their end needs no notice.
    quiet: HashSet<String>,
}

impl Memo {
    /// The user ended these themselves and was already told.
    pub fn ended_by_user<I: IntoIterator<Item = String>>(&mut self, ids: I) {
        self.quiet.extend(ids);
    }

    /// The command failed, so these sessions are still running after all.
    pub fn not_ended(&mut self, ids: &[String]) {
        for id in ids {
            self.quiet.remove(id);
        }
    }
}

pub fn notices(
    prev: &Snapshot,
    next: &Snapshot,
    now: DateTime<Utc>,
    memo: &mut Memo,
) -> Vec<Notice> {
    let mut out = Vec::new();
    let was_up = matches!(prev.reach, Reach::Up(_));
    let Reach::Up(status) = &next.reach else {
        if was_up && matches!(next.reach, Reach::Down(_)) {
            out.push(Notice::Unreachable);
        }
        return out;
    };
    if matches!(prev.reach, Reach::Down(_)) {
        out.push(Notice::Back);
    }

    // Requests waiting. On the first look, mention whatever is already there.
    if !next.unread.pending {
        let ids: HashSet<String> = next.pending.iter().map(|p| p.id.clone()).collect();
        let fresh = match &memo.seen {
            Some(before) => ids.difference(before).count(),
            None => ids.len(),
        };
        memo.seen = Some(ids);
        if fresh > 0 {
            out.push(Notice::Waiting(fresh));
        }
    }

    if let Reach::Up(before) = &prev.reach {
        if !before.locked && status.locked {
            out.push(Notice::Locked);
        }
    }

    if !next.unread.sessions {
        // Ended: there before, gone now. Only when both lists were really read.
        if was_up && !prev.unread.sessions {
            for s in &prev.sessions {
                if next.session(&s.id).is_none() && !memo.quiet.remove(&s.id) {
                    out.push(Notice::Ended {
                        label: s.label.clone(),
                    });
                }
            }
        }
        // Ending soon: once per session.
        for s in &next.sessions {
            let Some(end) = s.expires_at.filter(|_| !s.infinite) else {
                continue;
            };
            let left = end - now;
            if left <= Duration::zero() {
                continue; // already over: the next refresh reports it as ended
            }
            if left <= Duration::minutes(ENDING_SOON_MINUTES) && memo.warned.insert(s.id.clone()) {
                out.push(Notice::EndingSoon {
                    label: s.label.clone(),
                    minutes: ((left.num_seconds() + 59) / 60).max(1),
                });
            }
        }
        memo.warned.retain(|id| next.session(id).is_some());
        memo.quiet.retain(|id| next.session(id).is_some());
    }

    // Keys: only changes seen while running. A key that was already failing
    // when the companion started is shown in the menu, not announced.
    if was_up && !prev.unread.keys && !next.unread.keys {
        for k in &next.keys {
            let Some(before) = prev.keys.iter().find(|p| p.slug == k.slug) else {
                continue;
            };
            if !before.stopped && k.stopped {
                out.push(Notice::KeyStopped {
                    slug: k.slug.clone(),
                });
            } else if before.health == Health::Ok && k.health == Health::Problem {
                out.push(Notice::KeyProblem {
                    slug: k.slug.clone(),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::tests::{busy, now, up};
    use crate::model::{parse_pending, Snapshot};
    use serde_json::json;

    #[test]
    fn first_look_mentions_what_is_already_waiting_and_then_only_new_items() {
        let mut memo = Memo::default();
        let first = busy();
        assert_eq!(
            notices(&Snapshot::loading(), &first, now(), &mut memo),
            [Notice::Waiting(2)]
        );
        assert!(
            notices(&first, &first, now(), &mut memo).is_empty(),
            "nothing new, nothing said"
        );
        let mut more = first.clone();
        more.pending = parse_pending(&json!([{"id":"sr_1"},{"id":"ap_2"},{"id":"sr_3"}]));
        assert_eq!(
            notices(&first, &more, now(), &mut memo),
            [Notice::Waiting(1)]
        );
    }

    #[test]
    fn a_session_is_warned_about_once_and_announced_when_it_ends() {
        let mut memo = Memo::default();
        let snap = busy(); // one session ending 15:12
        notices(&Snapshot::loading(), &snap, now(), &mut memo);
        let near = now() + Duration::minutes(183); // 15:03, nine minutes left
        assert_eq!(
            notices(&snap, &snap, near, &mut memo),
            [Notice::EndingSoon {
                label: "keys-models".into(),
                minutes: 9
            }]
        );
        assert!(notices(&snap, &snap, near + Duration::minutes(1), &mut memo).is_empty());
        // Past its end, a session that is still listed is not "ending soon".
        let mut late = Memo::default();
        assert_eq!(
            notices(&snap, &snap, now() + Duration::minutes(200), &mut late),
            [Notice::Waiting(2)]
        );
        let mut after = snap.clone();
        after.sessions.clear();
        assert_eq!(
            notices(&snap, &after, near, &mut memo),
            [Notice::Ended {
                label: "keys-models".into()
            }]
        );
    }

    #[test]
    fn a_session_the_user_ended_is_not_announced_again() {
        let mut memo = Memo::default();
        let snap = busy();
        notices(&Snapshot::loading(), &snap, now(), &mut memo);
        memo.ended_by_user(["s1".to_string()]);
        let mut after = snap.clone();
        after.sessions.clear();
        assert!(notices(&snap, &after, now(), &mut memo).is_empty());
    }

    #[test]
    fn an_unread_list_is_not_mistaken_for_sessions_ending() {
        let mut memo = Memo::default();
        let snap = busy();
        notices(&Snapshot::loading(), &snap, now(), &mut memo);
        let mut failed = snap.clone();
        failed.sessions.clear();
        failed.unread.sessions = true;
        assert!(notices(&snap, &failed, now(), &mut memo).is_empty());
        // And reading it again afterwards does not announce an end either.
        assert!(notices(&failed, &snap, now(), &mut memo).is_empty());
    }

    #[test]
    fn locking_and_losing_the_daemon_are_announced() {
        let mut memo = Memo::default();
        let open = Snapshot::only(up(false));
        let locked = Snapshot::only(up(true));
        notices(&Snapshot::loading(), &open, now(), &mut memo);
        assert_eq!(notices(&open, &locked, now(), &mut memo), [Notice::Locked]);
        assert!(notices(&locked, &locked, now(), &mut memo).is_empty());
        let down = Snapshot::only(Reach::Down("x".into()));
        assert_eq!(
            notices(&locked, &down, now(), &mut memo),
            [Notice::Unreachable]
        );
        assert!(notices(&down, &down, now(), &mut memo).is_empty());
        assert_eq!(notices(&down, &open, now(), &mut memo), [Notice::Back]);
        // A vault that was locked before the companion started is not news.
        let mut fresh = Memo::default();
        assert!(notices(&Snapshot::loading(), &locked, now(), &mut fresh).is_empty());
    }

    #[test]
    fn key_trouble_is_announced_only_when_it_starts() {
        let mut memo = Memo::default();
        let snap = busy(); // anthropic-api already failing, hf already stopped
        assert_eq!(
            notices(&Snapshot::loading(), &snap, now(), &mut memo),
            [Notice::Waiting(2)]
        );
        let mut worse = snap.clone();
        worse.keys[0].health = Health::Problem; // openai-api was ok
        assert_eq!(
            notices(&snap, &worse, now(), &mut memo),
            [Notice::KeyProblem {
                slug: "openai-api".into()
            }]
        );
        let mut stopped = worse.clone();
        stopped.keys[0].stopped = true;
        assert_eq!(
            notices(&worse, &stopped, now(), &mut memo),
            [Notice::KeyStopped {
                slug: "openai-api".into()
            }]
        );
    }

    #[test]
    fn no_notice_carries_text_an_agent_wrote() {
        // Labels are the user's own; pending notices carry counts only.
        let n = Notice::Waiting(1).text();
        assert!(!n.contains("sr_") && !n.contains("claim"));
    }
}
