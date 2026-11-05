package detect

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"ransomwarehunter/internal/event"
)

type call struct {
	inc  Incident
	kind AlertKind
}

type fakeOut struct {
	calls []call
	files map[string][]FileChange
}

func (f *fakeOut) IncidentChanged(inc Incident, kind AlertKind) {
	f.calls = append(f.calls, call{inc, kind})
}

func (f *fakeOut) FileChanges(id string, ch []FileChange) {
	if f.files == nil {
		f.files = map[string][]FileChange{}
	}
	f.files[id] = append(f.files[id], ch...)
}

func (f *fakeOut) alerts() []call {
	var out []call
	for _, c := range f.calls {
		if c.kind != KindNone {
			out = append(out, c)
		}
	}
	return out
}

func (f *fakeOut) last() (Incident, bool) {
	if len(f.calls) == 0 {
		return Incident{}, false
	}
	return f.calls[len(f.calls)-1].inc, true
}

var t0 = time.Date(2026, 10, 30, 14, 2, 0, 0, time.UTC)

func newTestEngine(t *testing.T, mut func(*Config)) (*Engine, *fakeOut) {
	t.Helper()
	cfg := DefaultConfig()
	if mut != nil {
		mut(&cfg)
	}
	out := &fakeOut{}
	e := New(cfg, out, slog.New(slog.NewTextHandler(io.Discard, nil)))
	e.Learn(Baseline{System: "nas01", Share: "Finance", Exts: map[string]int{
		"docx": 1, "xlsx": 1, "pdf": 1, "jpg": 1, "jpeg": 1, "txt": 1, "": 1,
	}})
	return e, out
}

func ren(ts time.Time, oldPath, newPath string) event.FileEvent {
	return event.FileEvent{TS: ts, System: "nas01", Share: "Finance", Op: event.OpRename,
		OldPath: oldPath, Path: newPath, Pair: event.PairExact, Source: "test"}
}

// attack đổi đuôi n file trong dirs thư mục, mỗi file cách nhau step.
func attack(e *Engine, n, dirs int, step time.Duration, suffix func(i int) string) time.Time {
	exts := []string{"docx", "xlsx", "pdf"}
	ts := t0
	for i := 0; i < n; i++ {
		dir := fmt.Sprintf("Phong%02d/2026", i%dirs)
		name := fmt.Sprintf("file%04d.%s", i, exts[i%len(exts)])
		e.Process(ren(ts, dir+"/"+name, dir+"/"+name+suffix(i)))
		ts = ts.Add(step)
	}
	return ts
}

func TestAttackAppendedExtension(t *testing.T) {
	e, out := newTestEngine(t, nil)
	end := attack(e, 300, 20, 100*time.Millisecond, func(int) string { return ".lockbit" })
	e.Tick(end)

	alerts := out.alerts()
	if len(alerts) == 0 {
		t.Fatal("không có cảnh báo")
	}
	first := alerts[0]
	if first.kind != KindOpened {
		t.Fatalf("kind = %v", first.kind)
	}
	inc, _ := out.last()
	if inc.Severity != SevCritical || inc.Score != ScoreMax {
		t.Fatalf("severity=%v score=%d rules=%+v", inc.Severity, inc.Score, inc.Rules)
	}
	if inc.Total != 300 || inc.DirCount != 20 {
		t.Fatalf("total=%d dirs=%d", inc.Total, inc.DirCount)
	}
	want := map[string]bool{"R1": true, "R2": true, "R3": true, "R4": true, "R6": true}
	for _, r := range inc.Rules {
		delete(want, r.ID)
	}
	if len(want) > 0 {
		t.Fatalf("thiếu luật %v trong %+v", want, inc.Rules)
	}
	if tr := inc.Transitions[0]; tr.Count != 100 || !strings.HasSuffix(tr.To, ".lockbit") {
		t.Fatalf("transition đầu = %+v", tr)
	}
	if got := len(out.files[inc.ID]); got != 300 {
		t.Fatalf("danh sách file có %d dòng, muốn 300 (gồm cả thay đổi trước khi mở incident)", got)
	}
}

func TestUnknownExtensionStillDetected(t *testing.T) {
	// Đuôi không có trong danh sách đã biết: vẫn phải HIGH/CRITICAL nhờ hội tụ + đuôi lạ.
	e, out := newTestEngine(t, nil)
	e.Tick(attack(e, 200, 15, 100*time.Millisecond, func(int) string { return ".qwmzx" }))
	inc, _ := out.last()
	if inc.Severity != SevCritical || len(out.alerts()) == 0 {
		t.Fatalf("severity=%v score=%d rules=%+v", inc.Severity, inc.Score, inc.Rules)
	}
}

func TestVictimIDTemplateConverges(t *testing.T) {
	e, out := newTestEngine(t, nil)
	e.Tick(attack(e, 120, 12, 100*time.Millisecond, func(i int) string {
		return fmt.Sprintf(".id-%08X.[decrypt@mail.cc].wallet", 0xA0000000+i)
	}))
	inc, _ := out.last()
	if inc.Severity < SevHigh || inc.NewExts[0].Key != ".id-{HEX}.[{EMAIL}].wallet" {
		t.Fatalf("severity=%v newExts=%+v", inc.Severity, inc.NewExts)
	}
}

func TestRandomExtensionPerFile(t *testing.T) {
	e, out := newTestEngine(t, nil)
	e.Tick(attack(e, 100, 10, 100*time.Millisecond, func(i int) string { return fmt.Sprintf(".x%cq%c", 'a'+i%26, 'a'+i/26) }))
	inc, _ := out.last()
	found := false
	for _, r := range inc.Rules {
		found = found || r.ID == "R2b"
	}
	if !found || inc.Severity < SevHigh {
		t.Fatalf("severity=%v rules=%+v", inc.Severity, inc.Rules)
	}
}

func TestBenignMassRenameNoAlert(t *testing.T) {
	// Chuẩn hóa .jpeg → .jpg hàng loạt: 1 đuôi gốc, đuôi đích quen thuộc → tối đa MEDIUM, không gửi cảnh báo.
	e, out := newTestEngine(t, nil)
	ts := t0
	for i := 0; i < 1000; i++ {
		dir := fmt.Sprintf("Anh/Album%02d", i%30)
		e.Process(ren(ts, fmt.Sprintf("%s/IMG_%04d.jpeg", dir, i), fmt.Sprintf("%s/IMG_%04d.jpg", dir, i)))
		ts = ts.Add(20 * time.Millisecond)
	}
	e.Tick(ts)
	if a := out.alerts(); len(a) > 0 {
		t.Fatalf("cảnh báo giả: %+v", a[0].inc.Rules)
	}
	if inc, ok := out.last(); ok && inc.Severity > SevMedium {
		t.Fatalf("severity=%v", inc.Severity)
	}
}

func TestNormalizeToCommonExtNotStrange(t *testing.T) {
	// .jpg → .webp khi share chưa từng có .webp: định dạng phổ biến nên không tính R3 → không cảnh báo.
	e, out := newTestEngine(t, nil)
	ts := t0
	for i := 0; i < 2000; i++ {
		dir := fmt.Sprintf("Anh/Album%02d", i%40)
		e.Process(ren(ts, fmt.Sprintf("%s/IMG_%04d.jpg", dir, i), fmt.Sprintf("%s/IMG_%04d.webp", dir, i)))
	}
	e.Tick(ts.Add(time.Second))
	if a := out.alerts(); len(a) > 0 {
		t.Fatalf("cảnh báo giả: score=%d %+v", a[0].inc.Score, a[0].inc.Rules)
	}
}

func TestBenignThenAttackRulesNotMixed(t *testing.T) {
	// Tái hiện E2E: 2000 file .jpg → .webp hợp lệ, 50 giây sau tấn công thật trong cùng cửa sổ 60s.
	// Cảnh báo không được quy kết "hội tụ thành .webp" cho cuộc tấn công.
	e, out := newTestEngine(t, nil)
	for i := 0; i < 2000; i++ {
		dir := fmt.Sprintf("Anh/Album%02d", i%40)
		e.Process(ren(t0, fmt.Sprintf("%s/IMG_%04d.jpg", dir, i), fmt.Sprintf("%s/IMG_%04d.webp", dir, i)))
	}
	e.Tick(t0.Add(time.Second))
	exts := []string{"docx", "xlsx", "pdf", "pptx", "csv"}
	ts := t0.Add(50 * time.Second)
	for i := 0; i < 300; i++ {
		p := fmt.Sprintf("KeToan/T%02d/hd%03d.%s", i%30, i, exts[i%len(exts)])
		e.Process(ren(ts, p, p+".dmr64"))
		ts = ts.Add(100 * time.Millisecond)
		e.Tick(ts)
	}
	a := out.alerts()
	if len(a) == 0 {
		t.Fatal("không cảnh báo tấn công")
	}
	for _, c := range a {
		for _, r := range c.inc.Rules {
			if strings.Contains(r.Desc, ".webp") {
				t.Fatalf("luật quy kết nhầm: %+v", r)
			}
		}
	}
	if inc, _ := out.last(); inc.Severity != SevCritical {
		t.Fatalf("severity=%v rules=%+v", inc.Severity, inc.Rules)
	}
}

func TestOfficeSavePatternIgnored(t *testing.T) {
	e, out := newTestEngine(t, nil)
	ts := t0
	for i := 0; i < 500; i++ {
		dir := fmt.Sprintf("Phong%02d", i%20)
		doc := fmt.Sprintf("%s/BaoCao%03d.docx", dir, i)
		e.Process(ren(ts, doc, dir+"/~WRL0001.tmp"))
		e.Process(ren(ts, dir+"/~WRD0000.tmp", doc))
		ts = ts.Add(50 * time.Millisecond)
	}
	e.Tick(ts)
	if len(out.calls) > 0 {
		t.Fatalf("không được mở incident: %+v", out.calls[0].inc.Rules)
	}
}

func TestRansomNoteAloneIsMedium(t *testing.T) {
	e, out := newTestEngine(t, nil)
	for i := 0; i < 12; i++ {
		e.Process(event.FileEvent{TS: t0, System: "nas01", Share: "Finance", Op: event.OpCreate,
			Path: fmt.Sprintf("Phong%02d/Restore-My-Files.txt", i)})
	}
	e.Tick(t0.Add(time.Second))
	inc, ok := out.last()
	if !ok || inc.Severity != SevMedium || len(out.alerts()) != 0 {
		t.Fatalf("ok=%v severity=%v alerts=%d", ok, inc.Severity, len(out.alerts()))
	}
	if len(inc.Notes) != 1 || inc.Notes[0].Name != "Restore-My-Files.txt" || inc.Notes[0].Dirs != 12 {
		t.Fatalf("notes=%+v", inc.Notes)
	}
}

func TestCanaryImmediateCritical(t *testing.T) {
	e, out := newTestEngine(t, func(c *Config) {
		c.Canaries = []CanaryRef{{System: "nas01", Share: "Finance", Path: "!000_Do_Not_Delete.docx"}}
	})
	e.Process(ren(t0, "!000_Do_Not_Delete.docx", "!000_Do_Not_Delete.docx.akira"))
	a := out.alerts()
	if len(a) != 1 || a[0].inc.Severity != SevCritical || len(a[0].inc.Canaries) != 1 {
		t.Fatalf("alerts=%+v", a)
	}
}

func TestCopyEncryptDeletePairing(t *testing.T) {
	e, out := newTestEngine(t, nil)
	ts := t0
	exts := []string{"docx", "xlsx", "pdf"}
	for i := 0; i < 120; i++ {
		dir := fmt.Sprintf("Phong%02d", i%12)
		name := fmt.Sprintf("%s/hd%03d.%s", dir, i, exts[i%3])
		e.Process(event.FileEvent{TS: ts, System: "nas01", Share: "Finance", Op: event.OpCreate, Path: name + ".crypted"})
		e.Process(event.FileEvent{TS: ts, System: "nas01", Share: "Finance", Op: event.OpDelete, Path: name})
		ts = ts.Add(100 * time.Millisecond)
	}
	e.Tick(ts)
	inc, _ := out.last()
	if inc.Severity != SevCritical || inc.Total != 120 || inc.Samples[0].Pair != "INFERRED" {
		t.Fatalf("severity=%v total=%d samples=%+v", inc.Severity, inc.Total, inc.Samples[:1])
	}
}

func TestUpdateAndClose(t *testing.T) {
	e, out := newTestEngine(t, nil)
	end := attack(e, 100, 10, 100*time.Millisecond, func(int) string { return ".lockbit" })
	e.Tick(end)
	// Tiếp diễn sau 3 phút → bản cập nhật.
	t1 := end.Add(3 * time.Minute)
	e.Process(ren(t1, "Phong01/x.docx", "Phong01/x.docx.lockbit"))
	e.Tick(t1)
	// Yên lặng 10 phút → đóng.
	e.Tick(t1.Add(11 * time.Minute))
	var kinds []AlertKind
	for _, a := range out.alerts() {
		kinds = append(kinds, a.kind)
	}
	want := []AlertKind{KindOpened, KindUpdate, KindClosed}
	if fmt.Sprint(kinds) != fmt.Sprint(want) {
		t.Fatalf("kinds=%v muốn %v", kinds, want)
	}
	inc, _ := out.last()
	if inc.Active || inc.Total != 101 {
		t.Fatalf("active=%v total=%d", inc.Active, inc.Total)
	}
}

func TestBelowThresholdNoIncident(t *testing.T) {
	e, out := newTestEngine(t, nil)
	e.Tick(attack(e, 40, 10, 100*time.Millisecond, func(int) string { return ".lockbit" }))
	if len(out.calls) > 0 {
		t.Fatalf("không được mở incident với 40 file: %+v", out.calls[0].inc)
	}
}

func TestSlowAttackOutsideWindow(t *testing.T) {
	// 100 file trải đều trong 10 phút (10 file/phút) không vượt R1 ở cửa sổ 60s.
	e, out := newTestEngine(t, nil)
	e.Tick(attack(e, 100, 10, 6*time.Second, func(int) string { return ".lockbit" }))
	if len(out.calls) > 0 {
		t.Fatalf("score=%d", out.calls[0].inc.Score)
	}
}

func BenchmarkProcessAttack(b *testing.B) {
	cfg := DefaultConfig()
	out := &discardOut{}
	e := New(cfg, out, slog.New(slog.NewTextHandler(io.Discard, nil)))
	evs := make([]event.FileEvent, 100_000)
	for i := range evs {
		dir := fmt.Sprintf("Phong%03d/Sub%02d", i%500, i%17)
		name := fmt.Sprintf("file%06d.docx", i)
		evs[i] = event.FileEvent{System: "nas01", Share: "Finance", Op: event.OpRename,
			OldPath: dir + "/" + name, Path: dir + "/" + name + ".lockbit"}
	}
	b.ResetTimer()
	ts := t0
	for i := 0; i < b.N; i++ {
		ev := evs[i%len(evs)]
		ev.TS = ts
		if i%50_000 == 0 {
			ts = ts.Add(time.Second)
			e.Tick(ts)
		}
		e.Process(ev)
	}
}

type discardOut struct{}

func (discardOut) IncidentChanged(Incident, AlertKind) {}
func (discardOut) FileChanges(string, []FileChange)    {}
