package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"ransomwarehunter/internal/detect"
)

// Console in cảnh báo ra stdout.
type Console struct {
	W  io.Writer
	mu sync.Mutex
}

func (c *Console) Name() string { return "console" }

func (c *Console) Send(_ context.Context, a Alert) error {
	w := c.W
	if w == nil {
		w = os.Stdout
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := fmt.Fprintf(w, "\n%s\n%s%s\n", strings.Repeat("=", 78), FormatText(a), strings.Repeat("=", 78))
	return err
}

// Telegram gửi qua Bot API.
type Telegram struct {
	Token   string
	ChatID  string
	BaseURL string // mặc định https://api.telegram.org
	Client  *http.Client
}

func (t *Telegram) Name() string { return "telegram" }

func (t *Telegram) Send(ctx context.Context, a Alert) error {
	base := t.BaseURL
	if base == "" {
		base = "https://api.telegram.org"
	}
	text := FormatText(a)
	if r := []rune(text); len(r) > 4000 {
		text = string(r[:4000]) + "\n…"
	}
	form := url.Values{"chat_id": {t.ChatID}, "text": {text}, "disable_web_page_preview": {"true"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/bot"+t.Token+"/sendMessage",
		strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return doRequest(t.Client, req)
}

// Webhook POST JSON {kind, incident} tới URL (tích hợp SOAR).
type Webhook struct {
	URL        string
	AuthHeader string // giá trị header Authorization, nếu cần
	Client     *http.Client
}

func (w *Webhook) Name() string { return "webhook" }

func (w *Webhook) Send(ctx context.Context, a Alert) error {
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.AuthHeader != "" {
		req.Header.Set("Authorization", w.AuthHeader)
	}
	return doRequest(w.Client, req)
}

func doRequest(c *http.Client, req *http.Request) error {
	if c == nil {
		c = http.DefaultClient
	}
	resp, err := c.Do(req)
	if err != nil {
		if ue, ok := err.(*url.Error); ok {
			return fmt.Errorf("%s: %w", ue.Op, ue.Err) // bỏ URL khỏi lỗi
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		// Không ghi URL vào lỗi: URL Telegram chứa token.
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	return nil
}

// Email gửi qua SMTP. TLS: "starttls" (mặc định, cổng 587), "implicit" (cổng 465), "none".
type Email struct {
	Host     string
	Port     int
	TLS      string
	Username string
	Password string
	From     string
	To       []string
}

func (e *Email) Name() string { return "email" }

func (e *Email) Send(ctx context.Context, a Alert) error {
	msg := e.message(a)
	addr := net.JoinHostPort(e.Host, fmt.Sprint(e.Port))
	d := net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if e.TLS == "implicit" {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, &tls.Config{ServerName: e.Host})
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if e.TLS == "" || e.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("máy chủ SMTP không hỗ trợ STARTTLS")
		}
		if err := c.StartTLS(&tls.Config{ServerName: e.Host}); err != nil {
			return err
		}
	}
	if e.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", e.Username, e.Password, e.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(e.From); err != nil {
		return err
	}
	for _, to := range e.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (e *Email) message(a Alert) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", e.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(e.To, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", Subject(a)))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	qp := quotedprintable.NewWriter(&b)
	_, _ = qp.Write([]byte(strings.ReplaceAll(FormatText(a), "\n", "\r\n")))
	_ = qp.Close()
	return b.Bytes()
}

// Syslog gửi bản ghi CEF tới SIEM qua UDP hoặc TCP.
type Syslog struct {
	Network string // "udp" hoặc "tcp"
	Address string
	mu      sync.Mutex
	conn    net.Conn
}

func (s *Syslog) Name() string { return "syslog" }

func (s *Syslog) Send(ctx context.Context, a Alert) error {
	line := CEF(a)
	host, _ := os.Hostname()
	// RFC 5424, facility local4 (20); mức syslog theo severity.
	pri := 20*8 + 4
	switch a.Incident.Severity {
	case detect.SevCritical:
		pri = 20*8 + 2
	case detect.SevHigh:
		pri = 20*8 + 3
	}
	msg := fmt.Sprintf("<%d>1 %s %s ransomwarehunter - - - %s\n", pri, time.Now().UTC().Format(time.RFC3339), host, line)
	s.mu.Lock()
	defer s.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if s.conn == nil {
			d := net.Dialer{Timeout: 5 * time.Second}
			c, err := d.DialContext(ctx, s.Network, s.Address)
			if err != nil {
				return err
			}
			s.conn = c
		}
		if _, err := s.conn.Write([]byte(msg)); err != nil {
			s.conn.Close()
			s.conn = nil
			continue
		}
		return nil
	}
	return fmt.Errorf("gửi syslog tới %s thất bại", s.Address)
}

// CEF định dạng cảnh báo theo ArcSight Common Event Format.
func CEF(a Alert) string {
	inc := a.Incident
	sev := map[detect.Severity]int{detect.SevMedium: 5, detect.SevHigh: 8, detect.SevCritical: 10}[inc.Severity]
	ext := []string{
		"rt=" + fmt.Sprint(inc.LastEvent.UnixMilli()),
		"act=" + cefExt(a.Kind.String()),
		"cs1Label=incidentId", "cs1=" + cefExt(inc.ID),
		"cs2Label=share", "cs2=" + cefExt(inc.Share),
		"cs3Label=system", "cs3=" + cefExt(inc.System),
		"cnt=" + fmt.Sprint(inc.Total),
		"cn1Label=score", "cn1=" + fmt.Sprint(inc.Score),
		"cn2Label=dirCount", "cn2=" + fmt.Sprint(inc.DirCount),
	}
	if len(inc.NewExts) > 0 {
		ext = append(ext, "cs4Label=newExtension", "cs4="+cefExt(inc.NewExts[0].Key))
	}
	if len(inc.Actors) > 0 {
		if u := inc.Actors[0].Actor.User; u != "" {
			ext = append(ext, "suser="+cefExt(u))
		}
		if ip := inc.Actors[0].Actor.ClientIP; ip != "" {
			ext = append(ext, "src="+cefExt(ip))
		}
	}
	if inc.FilesURL != "" {
		ext = append(ext, "cs5Label=filesUrl", "cs5="+cefExt(inc.FilesURL))
	}
	var rules []string
	for _, r := range inc.Rules {
		rules = append(rules, r.ID)
	}
	ext = append(ext, "cs6Label=rules", "cs6="+cefExt(strings.Join(rules, ",")))
	return fmt.Sprintf("CEF:0|RansomwareHunter|RansomwareHunter|0.1|RH-%s|%s|%d|%s",
		cefHdr(a.Kind.String()), cefHdr(kindTitle[a.Kind]), sev, strings.Join(ext, " "))
}

func cefHdr(s string) string {
	return strings.NewReplacer(`\`, `\\`, "|", `\|`, "\n", " ").Replace(s)
}

func cefExt(s string) string {
	return strings.NewReplacer(`\`, `\\`, "=", `\=`, "\n", `\n`, "\r", `\r`).Replace(s)
}
