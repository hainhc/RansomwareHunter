package detect

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"time"

	"ransomwarehunter/internal/event"
)

type transKey struct {
	from, to string
	appended bool
}

// incidentState là trạng thái đầy đủ của incident đang mở; Incident là ảnh chụp của nó.
type incidentState struct {
	id            string
	system, share string
	opened        time.Time
	lastEvent     time.Time
	score         int
	evalScore     int
	evalRules     []RuleHit
	canaryRule    *RuleHit

	total       int
	transitions map[transKey]int
	newExts     map[string]int
	dirs        map[string]struct{}
	actors      map[string]*ActorStat
	notes       map[string]int
	canaries    []CanaryHit
	samples     []FileChange
	sources     map[string]struct{}
	pending     []FileChange

	dirty             bool
	notified          bool
	notifiedSev       Severity
	lastNotify        time.Time
	lastNotifiedTotal int
}

func newIncident(system, share string, now time.Time) *incidentState {
	b := make([]byte, 2)
	_, _ = rand.Read(b)
	return &incidentState{
		id:          "INC-" + now.Format("20060102-150405") + "-" + hex.EncodeToString(b),
		system:      system,
		share:       share,
		opened:      now,
		lastEvent:   now,
		transitions: map[transKey]int{},
		newExts:     map[string]int{},
		dirs:        map[string]struct{}{},
		actors:      map[string]*ActorStat{},
		notes:       map[string]int{},
		sources:     map[string]struct{}{},
		dirty:       true,
	}
}

func (inc *incidentState) touch(ts time.Time) {
	if ts.After(inc.lastEvent) {
		inc.lastEvent = ts
	}
	inc.dirty = true
}

func (inc *incidentState) add(c *change, sampleSize int) {
	inc.total++
	inc.touch(c.ts)
	inc.transitions[transKey{c.tr.From, c.tr.To, c.tr.Appended}]++
	inc.newExts[c.tr.To]++
	inc.dirs[c.dir] = struct{}{}
	if k := c.actor.Key(); k != "" {
		a := inc.actors[k]
		if a == nil {
			a = &ActorStat{Actor: *c.actor}
			inc.actors[k] = a
		}
		a.Count++
	}
	if c.source != "" {
		inc.sources[c.source] = struct{}{}
	}
	fc := c.fileChange()
	if len(inc.samples) < sampleSize {
		inc.samples = append(inc.samples, fc)
	}
	inc.pending = append(inc.pending, fc)
}

// setEval ghi nhận một lần chấm điểm. Luật hiển thị là của lần chấm điểm cao nhất
// (cùng một scope), không gộp mô tả từ các scope khác nhau.
func (inc *incidentState) setEval(pts int, hits []RuleHit) {
	if pts >= inc.evalScore {
		inc.evalScore = pts
		inc.evalRules = append(inc.evalRules[:0], hits...)
		inc.dirty = true
	}
	inc.updateScore()
}

// setCanary ghi nhận file mồi bị tác động: điểm tối đa ngay lập tức.
func (inc *incidentState) setCanary(h RuleHit) {
	inc.canaryRule = &h
	inc.dirty = true
	inc.updateScore()
}

func (inc *incidentState) updateScore() {
	inc.score = min(inc.evalScore, ScoreMax)
	if inc.canaryRule != nil {
		inc.score = ScoreMax
	}
}

func (inc *incidentState) snapshot(cfg Config, closed time.Time) Incident {
	out := Incident{
		ID:        inc.id,
		System:    inc.system,
		Share:     inc.share,
		Opened:    inc.opened,
		LastEvent: inc.lastEvent,
		Closed:    closed,
		Active:    closed.IsZero(),
		Score:     inc.score,
		Severity:  SeverityOf(inc.score),
		Total:     inc.total,
		DirCount:  len(inc.dirs),
		Canaries:  append([]CanaryHit(nil), inc.canaries...),
		Samples:   append([]FileChange(nil), inc.samples...),
	}
	if inc.canaryRule != nil {
		out.Rules = append(out.Rules, *inc.canaryRule)
	}
	out.Rules = append(out.Rules, inc.evalRules...)
	sort.Slice(out.Rules, func(i, j int) bool {
		if out.Rules[i].Points != out.Rules[j].Points {
			return out.Rules[i].Points > out.Rules[j].Points
		}
		return out.Rules[i].ID < out.Rules[j].ID
	})

	for k, n := range inc.transitions {
		to := event.Transition{From: k.from, To: k.to, Appended: k.appended}.Display()
		out.Transitions = append(out.Transitions, TransitionStat{From: k.from, To: to, Count: n})
	}
	sort.Slice(out.Transitions, func(i, j int) bool {
		a, b := out.Transitions[i], out.Transitions[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.From+a.To < b.From+b.To
	})
	if top := cfg.SnapshotTop; top > 0 && len(out.Transitions) > top {
		rest := 0
		for _, t := range out.Transitions[top:] {
			rest += t.Count
		}
		out.Transitions = append(out.Transitions[:top], TransitionStat{From: "(khác)", To: "", Count: rest})
	}

	out.NewExts = sortedCounts(inc.newExts, 10)
	for _, a := range inc.actors {
		out.Actors = append(out.Actors, *a)
	}
	sort.Slice(out.Actors, func(i, j int) bool { return out.Actors[i].Count > out.Actors[j].Count })
	if len(out.Actors) > 20 {
		out.Actors = out.Actors[:20]
	}
	for name, d := range inc.notes {
		out.Notes = append(out.Notes, NoteStat{Name: name, Dirs: d})
	}
	sort.Slice(out.Notes, func(i, j int) bool { return out.Notes[i].Dirs > out.Notes[j].Dirs })
	if len(out.Notes) > 10 {
		out.Notes = out.Notes[:10]
	}
	for s := range inc.sources {
		out.Sources = append(out.Sources, s)
	}
	sort.Strings(out.Sources)
	return out
}

func sortedCounts(m map[string]int, limit int) []KeyCount {
	out := make([]KeyCount, 0, len(m))
	for k, v := range m {
		out = append(out, KeyCount{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}
