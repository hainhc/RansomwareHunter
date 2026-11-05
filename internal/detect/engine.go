package detect

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"ransomwarehunter/internal/event"
)

// shareState là trạng thái phát hiện của một share.
type shareState struct {
	system, share string
	inv           map[string]time.Time // kho đuôi: đuôi → lần đầu thấy (zero = có từ baseline)
	scopes        map[string]*window
	recent        []*change // thay đổi trong cửa sổ, chờ đưa vào incident nếu bị kích hoạt
	notes         *noteTracker
	pairer        *pairer
	inc           *incidentState
}

// Stats là bộ đếm hoạt động của engine.
type Stats struct {
	Events     uint64
	Renames    uint64
	ExtChanges uint64
	Incidents  uint64
}

// Engine là detection engine. Không an toàn cho nhiều goroutine: dùng Run, hoặc gọi
// Process/Learn/Tick từ một goroutine duy nhất.
type Engine struct {
	cfg      Config
	out      Output
	log      *slog.Logger
	shares   map[string]*shareState
	known    map[string]bool
	canaries map[string]bool
	noteExts map[string]bool
	noteSkip map[string]bool
	now      time.Time
	stats    counters
}

// New tạo engine.
func New(cfg Config, out Output, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	e := &Engine{
		cfg:      cfg,
		out:      out,
		log:      log,
		shares:   map[string]*shareState{},
		known:    lowerSet(cfg.KnownExts),
		canaries: map[string]bool{},
		noteExts: lowerSet(cfg.NoteExts),
		noteSkip: lowerSet(cfg.NoteIgnore),
	}
	for _, c := range cfg.Canaries {
		e.canaries[canaryKey(c.System, c.Share, c.Path)] = true
	}
	return e
}

// Stats trả về bộ đếm hiện tại; an toàn khi gọi từ goroutine khác.
func (e *Engine) Stats() Stats {
	return Stats{
		Events:     e.stats.events.Load(),
		Renames:    e.stats.renames.Load(),
		ExtChanges: e.stats.extChanges.Load(),
		Incidents:  e.stats.incidents.Load(),
	}
}

type counters struct {
	events, renames, extChanges, incidents atomic.Uint64
}

// Run xử lý sự kiện cho tới khi ctx bị hủy hoặc kênh events đóng.
func (e *Engine) Run(ctx context.Context, events <-chan event.FileEvent, baselines <-chan Baseline) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			e.Tick(time.Now())
			return
		case ev, ok := <-events:
			if !ok {
				e.Tick(time.Now())
				return
			}
			e.Process(ev)
		case b := <-baselines:
			e.Learn(b)
		case now := <-tick.C:
			e.Tick(now)
		}
	}
}

// Learn nạp kho đuôi ban đầu của share: các đuôi này không bị coi là "lạ" (R3).
func (e *Engine) Learn(b Baseline) {
	s := e.shareFor(b.System, b.Share)
	for ext := range b.Exts {
		if _, ok := s.inv[ext]; ok || len(s.inv) < e.cfg.InvCap {
			s.inv[ext] = time.Time{}
		}
	}
	e.log.Info("nạp baseline đuôi file", "system", b.System, "share", b.Share, "exts", len(b.Exts))
}

// Process xử lý một sự kiện.
func (e *Engine) Process(ev event.FileEvent) {
	e.stats.events.Add(1)
	if ev.TS.IsZero() {
		ev.TS = time.Now()
	}
	if ev.TS.After(e.now) {
		e.now = ev.TS
	}
	s := e.shareFor(ev.System, ev.Share)
	if ev.Canary || e.isCanary(ev) {
		e.canaryHit(s, ev)
	}
	if ev.IsDir {
		return
	}
	switch ev.Op {
	case event.OpRename:
		e.rename(s, ev)
	case event.OpCreate:
		e.learn(s, event.Ext(lastElem(ev.Path)), ev.TS)
		if r, ok := s.pairer.create(ev); ok {
			e.rename(s, r)
			return
		}
		e.noteCreate(s, ev)
	case event.OpDelete:
		if r, ok := s.pairer.delete(ev); ok {
			e.rename(s, r)
		}
	}
}

func (e *Engine) rename(s *shareState, ev event.FileEvent) {
	e.stats.renames.Add(1)
	oldName, newName := lastElem(ev.OldPath), lastElem(ev.Path)
	e.learn(s, event.Ext(oldName), ev.TS)
	tr, changed := event.Classify(oldName, newName)
	if !changed || e.cfg.Benign.IsBenign(oldName, newName) {
		e.learn(s, event.Ext(newName), ev.TS)
		return
	}
	e.stats.extChanges.Add(1)
	c := &change{
		ts:      ev.TS,
		dir:     event.Dir(ev.Path),
		oldPath: ev.OldPath,
		newPath: ev.Path,
		tr:      tr,
		actor:   ev.Actor,
		pair:    ev.Pair,
		size:    ev.Size,
		source:  ev.Source,
		unseen:  e.isNewExt(s, tr.NewExt, ev.TS) && !event.IsCommonExt(tr.NewExt),
		known:   e.known[tr.NewExt],
	}
	e.learn(s, tr.NewExt, ev.TS)

	if s.inc != nil {
		s.inc.add(c, e.cfg.SampleSize)
		if len(s.inc.pending) >= e.cfg.FlushEvery {
			e.flush(s)
		}
	} else {
		s.recent = append(s.recent, c)
		if len(s.recent) > e.cfg.RecentCap {
			s.recent = append(s.recent[:0], s.recent[len(s.recent)-e.cfg.RecentCap:]...)
		}
	}

	sec := ev.TS.Unix()
	for _, key := range scopeKeys(c) {
		w := s.scopes[key]
		if w == nil {
			w = newWindow(e.cfg.Window)
			s.scopes[key] = w
		}
		w.add(sec, c)
		// Chấm điểm tối đa một lần mỗi giây cho mỗi scope; Tick xử lý phần còn lại.
		if w.n >= e.cfg.MinRenames && w.evalSec != sec {
			w.evalSec, w.dirty = sec, false
			e.score(s, w)
		}
	}
}

func scopeKeys(c *change) []string {
	keys := []string{"s:", "t:" + topDirs(c.dir, 2)}
	if k := c.actor.Key(); k != "" {
		keys = append(keys, "a:"+k)
	}
	return keys
}

func topDirs(dir string, n int) string {
	idx := 0
	for i := 0; i < n; i++ {
		j := strings.IndexByte(dir[idx:], '/')
		if j < 0 {
			return dir
		}
		idx += j + 1
	}
	return dir[:idx-1]
}

// evaluate chấm điểm một scope theo R1–R4, R6.
func (e *Engine) evaluate(w *window) (int, []RuleHit) {
	cfg := e.cfg
	if w.n < cfg.MinRenames {
		return 0, nil
	}
	n := float64(w.n)
	hits := []RuleHit{{ID: "R1", Points: 30, Desc: fmt.Sprintf("%d file bị đổi đuôi trong %s", w.n, cfg.Window)}}
	topKey, topN := top(w.to)
	switch {
	case float64(topN) >= cfg.ConvergenceRatio*n && w.sourcesOf(topKey) >= cfg.MinSourceExts:
		hits = append(hits, RuleHit{ID: "R2", Points: 30, Desc: fmt.Sprintf(
			"Hội tụ đuôi: %.0f%% thành %s từ %d đuôi gốc khác nhau", 100*float64(topN)/n, topKey, w.sourcesOf(topKey))})
	case float64(len(w.to)) >= cfg.RandomExtRatio*n:
		hits = append(hits, RuleHit{ID: "R2b", Points: 30, Desc: fmt.Sprintf(
			"Đuôi ngẫu nhiên: %d đuôi mới khác nhau cho %d file", len(w.to), w.n)})
	}
	if float64(w.unseen) >= cfg.UnseenRatio*n {
		hits = append(hits, RuleHit{ID: "R3", Points: 15, Desc: fmt.Sprintf(
			"%.0f%% đuôi mới là đuôi lạ (chưa từng có trên share, không phải định dạng phổ biến)", 100*float64(w.unseen)/n)})
	}
	if len(w.dirs) >= cfg.MinDirs {
		hits = append(hits, RuleHit{ID: "R4", Points: 10, Desc: fmt.Sprintf("%d thư mục bị ảnh hưởng", len(w.dirs))})
	}
	if w.known > 0 {
		hits = append(hits, RuleHit{ID: "R6", Points: 40, Desc: fmt.Sprintf(
			"%d file mang đuôi ransomware đã biết", w.known)})
	}
	pts := 0
	for _, h := range hits {
		pts += h.Points
	}
	return pts, hits
}

func (e *Engine) score(s *shareState, w *window) {
	pts, hits := e.evaluate(w)
	if pts == 0 {
		return
	}
	if h, ok := e.noteRule(s); ok {
		pts += h.Points
		hits = append(hits, h)
	}
	e.raise(s, pts, hits)
}

func (e *Engine) noteRule(s *shareState) (RuleHit, bool) {
	st := s.notes.top()
	if st == nil {
		return RuleHit{}, false
	}
	return RuleHit{ID: "R5", Points: 30, Desc: fmt.Sprintf(
		"Nghi ransom note: %q xuất hiện ở %d thư mục", st.name, len(st.dirs))}, true
}

// raise nâng điểm incident của share, mở incident nếu cần.
func (e *Engine) raise(s *shareState, pts int, hits []RuleHit) {
	if pts > ScoreMax {
		pts = ScoreMax
	}
	if pts < ScoreMedium {
		return
	}
	if s.inc == nil {
		e.open(s)
	}
	s.inc.setEval(pts, hits)
	e.notifyIfNeeded(s)
}

func (e *Engine) open(s *shareState) {
	inc := newIncident(s.system, s.share, e.now)
	e.stats.incidents.Add(1)
	for _, c := range s.recent {
		inc.add(c, e.cfg.SampleSize)
	}
	s.recent = s.recent[:0]
	for _, st := range s.notes.crossed {
		inc.notes[st.name] = len(st.dirs)
	}
	s.inc = inc
	e.log.Warn("mở incident", "id", inc.id, "system", s.system, "share", s.share)
}

func (e *Engine) noteCreate(s *shareState, ev event.FileEvent) {
	name := lastElem(ev.Path)
	if !e.noteExts[event.Ext(name)] || e.noteSkip[strings.ToLower(name)] {
		return
	}
	st, crossed := s.notes.add(name, event.Dir(ev.Path), ev.TS)
	if st == nil {
		return
	}
	if s.inc != nil && len(st.dirs) >= e.cfg.NoteMinDirs {
		s.inc.notes[st.name] = len(st.dirs)
		s.inc.touch(ev.TS)
	}
	if crossed {
		h, _ := e.noteRule(s)
		best, bestHits := h.Points, []RuleHit{h}
		// Nếu share đang có scope đổi đuôi vượt ngưỡng, cộng dồn với điểm cao nhất của các scope.
		for _, w := range s.scopes {
			if p, hits := e.evaluate(w); p > 0 && p+h.Points > best {
				best, bestHits = p+h.Points, append(hits, h)
			}
		}
		e.raise(s, best, bestHits)
	}
}

func (e *Engine) canaryHit(s *shareState, ev event.FileEvent) {
	if s.inc == nil {
		e.open(s)
	}
	inc := s.inc
	hit := CanaryHit{TS: ev.TS, Op: ev.Op.String(), Verb: opVerb(ev), Path: ev.Path, Actor: ev.Actor}
	if ev.Op == event.OpRename {
		hit.Path, hit.NewPath = ev.OldPath, ev.Path
	}
	if len(inc.canaries) < 100 {
		inc.canaries = append(inc.canaries, hit)
	}
	inc.touch(ev.TS)
	inc.setCanary(RuleHit{ID: "R7", Points: ScoreMax, Desc: fmt.Sprintf(
		"File mồi %s bị %s", hit.Path, hit.Verb)})
	e.notifyIfNeeded(s)
}

func opVerb(ev event.FileEvent) string {
	switch ev.Op {
	case event.OpRename:
		return "đổi tên"
	case event.OpDelete:
		if ev.Source == "canary" { // stat() không phân biệt được xóa với đổi tên
			return "xóa hoặc đổi tên"
		}
		return "xóa"
	case event.OpModify:
		return "sửa đổi"
	case event.OpCreate:
		return "tạo lại"
	}
	return ev.Op.String()
}

func (e *Engine) notifyIfNeeded(s *shareState) {
	inc := s.inc
	sev := SeverityOf(inc.score)
	if sev < SevHigh {
		return
	}
	var kind AlertKind
	switch {
	case !inc.notified:
		kind = KindOpened
	case sev > inc.notifiedSev:
		kind = KindEscalated
	default:
		return
	}
	e.emit(s, kind)
}

func (e *Engine) emit(s *shareState, kind AlertKind) {
	inc := s.inc
	e.flush(s)
	if kind != KindNone {
		inc.notified = true
		inc.notifiedSev = SeverityOf(inc.score)
		inc.lastNotify = e.now
		inc.lastNotifiedTotal = inc.total
	}
	inc.dirty = false
	e.out.IncidentChanged(inc.snapshot(e.cfg, time.Time{}), kind)
}

func (e *Engine) flush(s *shareState) {
	if inc := s.inc; inc != nil && len(inc.pending) > 0 {
		e.out.FileChanges(inc.id, inc.pending)
		inc.pending = nil
	}
}

// Tick chạy mỗi giây: trượt cửa sổ, chấm điểm phần còn lại, gửi cập nhật, đóng incident.
func (e *Engine) Tick(now time.Time) {
	if now.After(e.now) {
		e.now = now
	}
	sec := now.Unix()
	for _, s := range e.shares {
		for key, w := range s.scopes {
			w.advance(sec)
			if w.n == 0 {
				delete(s.scopes, key)
				continue
			}
			if w.dirty && w.n >= e.cfg.MinRenames {
				w.evalSec, w.dirty = sec, false
				e.score(s, w)
			}
		}
		s.notes.prune(now)
		s.pairer.expire(now)
		e.pruneRecent(s, now)

		inc := s.inc
		if inc == nil {
			continue
		}
		switch {
		case now.Sub(inc.lastEvent) >= e.cfg.IncidentQuiet:
			e.flush(s)
			kind := KindNone
			if inc.notified {
				kind = KindClosed
			}
			e.out.IncidentChanged(inc.snapshot(e.cfg, now), kind)
			e.log.Info("đóng incident", "id", inc.id, "total", inc.total)
			s.inc = nil
		case inc.notified && inc.total > inc.lastNotifiedTotal && now.Sub(inc.lastNotify) >= e.cfg.UpdateInterval:
			e.emit(s, KindUpdate)
		case inc.dirty || len(inc.pending) > 0:
			e.emit(s, KindNone)
		}
	}
}

func (e *Engine) pruneRecent(s *shareState, now time.Time) {
	i := 0
	for i < len(s.recent) && now.Sub(s.recent[i].ts) > e.cfg.Window {
		i++
	}
	if i > 0 {
		s.recent = append(s.recent[:0], s.recent[i:]...)
	}
}

func (e *Engine) shareFor(system, share string) *shareState {
	key := system + "|" + share
	s := e.shares[key]
	if s == nil {
		s = &shareState{
			system: system,
			share:  share,
			inv:    map[string]time.Time{},
			scopes: map[string]*window{},
			notes:  newNoteTracker(e.cfg),
			pairer: newPairer(e.cfg),
		}
		e.shares[key] = s
	}
	return s
}

func (e *Engine) learn(s *shareState, ext string, ts time.Time) {
	if _, ok := s.inv[ext]; !ok && len(s.inv) < e.cfg.InvCap {
		s.inv[ext] = ts
	}
}

func (e *Engine) isNewExt(s *shareState, ext string, ts time.Time) bool {
	first, ok := s.inv[ext]
	if !ok {
		return true
	}
	return !first.IsZero() && ts.Sub(first) < e.cfg.NewExtAge
}

func (e *Engine) isCanary(ev event.FileEvent) bool {
	if len(e.canaries) == 0 {
		return false
	}
	if e.canaries[canaryKey(ev.System, ev.Share, ev.Path)] {
		return true
	}
	return ev.OldPath != "" && e.canaries[canaryKey(ev.System, ev.Share, ev.OldPath)]
}

func canaryKey(system, share, p string) string {
	return system + "|" + share + "|" + strings.ToLower(p)
}

func lowerSet(v []string) map[string]bool {
	m := make(map[string]bool, len(v))
	for _, s := range v {
		m[strings.ToLower(strings.TrimPrefix(s, "."))] = true
	}
	return m
}
