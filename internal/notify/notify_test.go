package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ransomwarehunter/internal/detect"
	"ransomwarehunter/internal/event"
)

func sample() Alert {
	t := time.Date(2026, 10, 30, 14, 2, 11, 0, time.Local)
	return Alert{Kind: detect.KindOpened, Incident: detect.Incident{
		ID: "INC-1", System: "nas01", Share: `\\nas01\Finance`, Opened: t, LastEvent: t.Add(89 * time.Second),
		Active: true, Score: 100, Severity: detect.SevCritical, Total: 3214, DirCount: 187,
		Rules:       []detect.RuleHit{{ID: "R2", Points: 30, Desc: "Hội tụ đuôi"}},
		Transitions: []detect.TransitionStat{{From: ".xlsx", To: ".xlsx.lockbit", Count: 1402}},
		NewExts:     []detect.KeyCount{{Key: ".lockbit", Count: 3201}},
		Actors:      []detect.ActorStat{{Actor: event.Actor{User: `CORP\user01`, ClientIP: "10.10.5.23"}, Count: 3214}},
		Notes:       []detect.NoteStat{{Name: "Restore-My-Files.txt", Dirs: 187}},
		Samples:     []detect.FileChange{{OldPath: "2026/Q3/BaoCao.xlsx", NewPath: "2026/Q3/BaoCao.xlsx.lockbit"}},
		FilesURL:    "http://rh.local/api/v1/incidents/INC-1/files.csv",
	}}
}

func TestFormatText(t *testing.T) {
	s := FormatText(sample())
	for _, want := range []string{
		`[CRITICAL] Nghi ngờ ransomware – \\nas01\Finance (INC-1)`,
		"3.214 file bị đổi đuôi trong 1m29s, 187 thư mục",
		".lockbit (99,6%)",
		".xlsx → .xlsx.lockbit",
		`"Restore-My-Files.txt" xuất hiện ở 187 thư mục`,
		`CORP\user01 từ 10.10.5.23`,
		"2026/Q3/BaoCao.xlsx  →  BaoCao.xlsx.lockbit",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("thiếu %q trong:\n%s", want, s)
		}
	}
}

func TestCEFEscaping(t *testing.T) {
	c := CEF(sample())
	if !strings.HasPrefix(c, "CEF:0|RansomwareHunter|RansomwareHunter|0.1|RH-OPENED|") ||
		!strings.Contains(c, `cs2=\\\\nas01\\Finance`) || !strings.Contains(c, `suser=CORP\\user01`) ||
		!strings.Contains(c, "|10|") {
		t.Fatal(c)
	}
}

func TestTelegramAndWebhook(t *testing.T) {
	var gotText, gotKind string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/botTOKEN/sendMessage":
			_ = r.ParseForm()
			gotText = r.Form.Get("text")
		case "/hook":
			var a struct {
				Kind string `json:"kind"`
			}
			_ = json.NewDecoder(r.Body).Decode(&a)
			gotKind = a.Kind
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	if err := (&Telegram{Token: "TOKEN", ChatID: "1", BaseURL: srv.URL}).Send(ctx, sample()); err != nil {
		t.Fatal(err)
	}
	if err := (&Webhook{URL: srv.URL + "/hook"}).Send(ctx, sample()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotText, "Nghi ngờ ransomware") || gotKind != "OPENED" {
		t.Fatalf("text=%q kind=%q", gotText, gotKind)
	}
	err := (&Telegram{Token: "SECRET", ChatID: "1", BaseURL: srv.URL}).Send(ctx, sample())
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("lỗi phải có và không chứa token: %v", err)
	}
}
