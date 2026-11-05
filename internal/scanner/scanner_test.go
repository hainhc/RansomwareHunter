package scanner

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"ransomwarehunter/internal/event"
)

func TestDiffDirPairing(t *testing.T) {
	old := []entry{
		{name: "a.docx", id: 1, size: 1000},
		{name: "b.xlsx", id: 2, size: 2000},
		{name: "c.pdf", id: 3, size: 300000},
		{name: "d.txt", id: 4, size: 10},
		{name: "keep.txt", id: 5, size: 5},
		{name: "sub", id: 6, dir: true},
	}
	cur := []entry{
		{name: "Restore-My-Files.txt", id: 20, size: 900},
		{name: "a.docx.lockbit", id: 1, size: 1000},  // cùng ID
		{name: "b.xlsx.lockbit", id: 21, size: 2600}, // ID mới, tên chứa tên cũ
		{name: "keep.txt", id: 5, size: 6},           // sửa đổi
		{name: "sub2", id: 6, dir: true},             // thư mục đổi tên
		{name: "zz9.bin", id: 22, size: 301000},      // ID mới, tên khác hẳn, kích thước gần c.pdf
	}
	sortEntries(old)
	sortEntries(cur)
	d := diffDir("Finance", old, cur, event.FileEvent{System: "s", Share: "x"})

	got := map[string]string{}
	for _, ev := range d.events {
		got[ev.Op.String()+" "+ev.OldPath+" -> "+ev.Path] = ev.Pair.String()
	}
	want := map[string]string{
		"RENAME Finance/a.docx -> Finance/a.docx.lockbit": "EXACT",
		"RENAME Finance/b.xlsx -> Finance/b.xlsx.lockbit": "INFERRED",
		"RENAME Finance/c.pdf -> Finance/zz9.bin":         "WEAK",
		"RENAME Finance/sub -> Finance/sub2":              "EXACT",
		"MODIFY  -> Finance/keep.txt":                     "",
		"CREATE  -> Finance/Restore-My-Files.txt":         "",
		"DELETE  -> Finance/d.txt":                        "",
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("thiếu/sai %q: có=%v pair=%q", k, ok, g)
		}
	}
	if len(got) != len(want) {
		t.Errorf("thừa sự kiện: %v", got)
	}
	if len(d.movedDirs) != 1 || d.movedDirs[0] != [2]string{"Finance/sub", "Finance/sub2"} {
		t.Errorf("movedDirs=%v", d.movedDirs)
	}
}

func TestDiffNoFalsePrefixPair(t *testing.T) {
	old := []entry{{name: "a", id: 0, size: 1}}
	cur := []entry{{name: "ab.txt", id: 0, size: 900000}}
	d := diffDir("", old, cur, event.FileEvent{})
	for _, ev := range d.events {
		if ev.Op == event.OpRename {
			t.Fatalf("ghép sai: %+v", ev)
		}
	}
}

func TestScannerDetectsRenames(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 3; i++ {
		dir := filepath.Join(root, fmt.Sprintf("Phong%d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 4; j++ {
			write(t, filepath.Join(dir, fmt.Sprintf("f%d.docx", j)), 100+j)
		}
	}
	// Thư mục snapshot phải bị bỏ qua.
	if err := os.MkdirAll(filepath.Join(root, ".snapshot", "hourly"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, ".snapshot", "hourly", "x.docx"), 1)

	out := make(chan event.FileEvent, 1000)
	baseCh := make(chan map[string]int, 1)
	s := New(Config{System: "nas01", Share: "Finance", Root: root, Workers: 4},
		out, func(m map[string]int) { baseCh <- m }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)
	var base map[string]int
	select {
	case base = <-baseCh:
	case <-time.After(5 * time.Second):
		t.Fatal("hết thời gian chờ quét lần đầu")
	}
	if base["docx"] != 12 {
		t.Fatalf("baseline=%v", base)
	}

	// Mô phỏng ransomware trên thư mục Phong1 + tạo thư mục mới + đổi tên thư mục.
	for j := 0; j < 4; j++ {
		p := filepath.Join(root, "Phong1", fmt.Sprintf("f%d.docx", j))
		must(t, os.Rename(p, p+".lockbit"))
	}
	write(t, filepath.Join(root, "Phong1", "README_DECRYPT.txt"), 50)
	must(t, os.MkdirAll(filepath.Join(root, "Moi"), 0o755))
	write(t, filepath.Join(root, "Moi", "n.pdf"), 7)
	must(t, os.Rename(filepath.Join(root, "Phong2"), filepath.Join(root, "Phong2-old")))

	// Cycle trực tiếp, thay vì chờ ticker; thêm một lượt để chắc chắn mtime đã cập nhật.
	s.Cycle(ctx, false)
	s.Cycle(ctx, false)

	var got []string
	drain(out, func(ev event.FileEvent) {
		got = append(got, fmt.Sprintf("%s %s>%s %s", ev.Op, ev.OldPath, ev.Path, ev.Pair))
	})
	sort.Strings(got)
	want := []string{
		"CREATE >Moi/n.pdf ",
		"CREATE >Phong1/README_DECRYPT.txt ",
		"RENAME Phong1/f0.docx>Phong1/f0.docx.lockbit EXACT",
		"RENAME Phong1/f1.docx>Phong1/f1.docx.lockbit EXACT",
		"RENAME Phong1/f2.docx>Phong1/f2.docx.lockbit EXACT",
		"RENAME Phong1/f3.docx>Phong1/f3.docx.lockbit EXACT",
		"RENAME Phong2>Phong2-old EXACT",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("sự kiện:\n%v\nmuốn:\n%v", got, want)
	}
	st := s.Stats()
	if st.Dirs != 5 || st.Files != 14 {
		t.Fatalf("stats=%+v", st)
	}
}

func write(t *testing.T, p string, size int) {
	t.Helper()
	must(t, os.WriteFile(p, make([]byte, size), 0o644))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func drain(ch <-chan event.FileEvent, fn func(event.FileEvent)) {
	for {
		select {
		case ev := <-ch:
			fn(ev)
		default:
			return
		}
	}
}
