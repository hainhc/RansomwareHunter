//go:build windows

package usn

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestLiveJournal chạy trên volume chứa thư mục tạm; cần quyền Administrator và journal đã bật.
func TestLiveJournal(t *testing.T) {
	dir := t.TempDir()
	vol := filepath.VolumeName(dir)
	j, err := Open(vol)
	if err != nil {
		if errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			t.Skip("cần quyền Administrator để đọc USN Journal")
		}
		t.Fatal(err)
	}
	defer j.Close()
	jd, err := j.Query()
	if err != nil {
		t.Skip("journal chưa bật:", err)
	}
	root, err := RootFRN(vol)
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTracker("test", vol, nil, root)
	if err := j.Enum(context.Background(), jd.NextUSN, func(r Record) {
		if r.IsDir() {
			tr.AddDir(r.FRN, r.ParentFRN, r.Name)
		}
	}); err != nil {
		t.Fatal(err)
	}

	p := filepath.Join(dir, "BaoCao.xlsx")
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(p, p+".lockbit"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	_, recs, _, err := j.Read(jd.NextUSN, jd.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		for _, ev := range tr.Handle(r) {
			if ev.Op.String() == "RENAME" && strings.HasSuffix(ev.Path, "BaoCao.xlsx.lockbit") &&
				strings.HasSuffix(ev.OldPath, "BaoCao.xlsx") {
				return
			}
		}
	}
	t.Fatalf("không thấy sự kiện RENAME trong %d bản ghi", len(recs))
}
