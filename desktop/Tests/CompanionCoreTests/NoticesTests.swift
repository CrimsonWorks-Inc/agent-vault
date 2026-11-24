import Foundation
import Testing
@testable import CompanionCore

@Suite struct Notices {
    @Test func firstLookMentionsWhatIsAlreadyWaitingAndThenOnlyNewItems() {
        var memo = Memo()
        let first = busy()
        #expect(notices(.loading(), first, now: now, memo: &memo) == [.waiting(2)])
        #expect(notices(first, first, now: now, memo: &memo).isEmpty, "nothing new, nothing said")
        var more = first
        more.pending = parsePending(j(#"[{"id":"sr_1"},{"id":"ap_2"},{"id":"sr_3"}]"#))
        #expect(notices(first, more, now: now, memo: &memo) == [.waiting(1)])
    }

    @Test func aSessionIsWarnedAboutOnceAndAnnouncedWhenItEnds() {
        var memo = Memo()
        let snap = busy() // one session ending 15:12
        _ = notices(.loading(), snap, now: now, memo: &memo)
        let near = now.addingTimeInterval(183 * 60) // 15:03, nine minutes left
        #expect(notices(snap, snap, now: near, memo: &memo) == [.endingSoon(label: "keys-models", minutes: 9)])
        #expect(notices(snap, snap, now: near.addingTimeInterval(60), memo: &memo).isEmpty)
        // Past its end, a session that is still listed is not "ending soon".
        var late = Memo()
        #expect(notices(snap, snap, now: now.addingTimeInterval(200 * 60), memo: &late) == [.waiting(2)])
        var after = snap
        after.sessions = []
        #expect(notices(snap, after, now: near, memo: &memo) == [.ended(label: "keys-models")])
    }

    @Test func aSessionTheUserEndedIsNotAnnouncedAgain() {
        var memo = Memo()
        let snap = busy()
        _ = notices(.loading(), snap, now: now, memo: &memo)
        memo.endedByUser(["s1"])
        var after = snap
        after.sessions = []
        #expect(notices(snap, after, now: now, memo: &memo).isEmpty)
    }

    @Test func aFailedCommandPutsTheSessionBackOnWatch() {
        var memo = Memo()
        let snap = busy()
        _ = notices(.loading(), snap, now: now, memo: &memo)
        memo.endedByUser(["s1"])
        memo.notEnded(["s1"])
        var after = snap
        after.sessions = []
        #expect(notices(snap, after, now: now, memo: &memo) == [.ended(label: "keys-models")])
    }

    @Test func anUnreadListIsNotMistakenForSessionsEnding() {
        var memo = Memo()
        let snap = busy()
        _ = notices(.loading(), snap, now: now, memo: &memo)
        var failed = snap
        failed.sessions = []
        failed.unread.sessions = true
        #expect(notices(snap, failed, now: now, memo: &memo).isEmpty)
        // And reading it again afterwards does not announce an end either.
        #expect(notices(failed, snap, now: now, memo: &memo).isEmpty)
    }

    @Test func lockingAndLosingTheDaemonAreAnnounced() {
        var memo = Memo()
        let open = Snapshot(reach: up(false))
        let locked = Snapshot(reach: up(true))
        _ = notices(.loading(), open, now: now, memo: &memo)
        #expect(notices(open, locked, now: now, memo: &memo) == [.locked])
        #expect(notices(locked, locked, now: now, memo: &memo).isEmpty)
        let down = Snapshot(reach: .down("x"))
        #expect(notices(locked, down, now: now, memo: &memo) == [.unreachable])
        #expect(notices(down, down, now: now, memo: &memo).isEmpty)
        #expect(notices(down, open, now: now, memo: &memo) == [.back])
        // A vault that was locked before the companion started is not news.
        var fresh = Memo()
        #expect(notices(.loading(), locked, now: now, memo: &fresh).isEmpty)
    }

    @Test func keyTroubleIsAnnouncedOnlyWhenItStarts() {
        var memo = Memo()
        let snap = busy() // anthropic-api already failing, hf already stopped
        #expect(notices(.loading(), snap, now: now, memo: &memo) == [.waiting(2)])
        var worse = snap
        worse.keys[0].health = .problem // openai-api was ok
        #expect(notices(snap, worse, now: now, memo: &memo) == [.keyProblem(slug: "openai-api")])
        var stopped = worse
        stopped.keys[0].stopped = true
        #expect(notices(worse, stopped, now: now, memo: &memo) == [.keyStopped(slug: "openai-api")])
    }

    @Test func noNoticeCarriesTextAnAgentWrote() {
        // Labels are the user's own; waiting notices carry counts only.
        for placement in [Placement.island, .menuBar] {
            let n = Notice.waiting(1).text(placement)
            #expect(!n.contains("sr_") && !n.contains("claim"))
        }
        #expect(Notice.waiting(2).text(.island).contains("notch"))
        #expect(Notice.waiting(2).text(.menuBar).contains("menu bar"))
    }
}
