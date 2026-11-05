package canary

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"ransomwarehunter/internal/event"
)

func TestDeployAndDetect(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "Phong1"), 0o755); err != nil {
		t.Fatal(err)
	}
	paths, err := Deploy(root, []string{"", "Phong1"}, nil)
	if err != nil || len(paths) != 6 {
		t.Fatalf("paths=%v err=%v", paths, err)
	}
	out := make(chan event.FileEvent, 10)
	m := New(Config{System: "s", Share: "x", Root: root, Paths: paths}, out, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, p := range paths {
		m.state[p] = m.stat(p)
	}
	ctx := context.Background()
	m.Check(ctx)
	if len(out) != 0 {
		t.Fatal("không thay đổi mà vẫn phát sự kiện")
	}

	abs := filepath.Join(root, "Phong1", DefaultNames[0])
	if err := os.Rename(abs, abs+".lockbit"); err != nil {
		t.Fatal(err)
	}
	m.Check(ctx)
	if len(out) != 1 {
		t.Fatalf("có %d sự kiện", len(out))
	}
	ev := <-out
	if !ev.Canary || ev.Op != event.OpDelete || ev.Path != "Phong1/"+DefaultNames[0] {
		t.Fatalf("ev=%+v", ev)
	}
	m.Check(ctx)
	if len(out) != 0 {
		t.Fatal("phát lặp lại khi không có thay đổi mới")
	}
}
