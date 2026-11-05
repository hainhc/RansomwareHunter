// Package config đọc cấu hình JSON của rh-server và rh-agent-win.
// Bí mật (mật khẩu, token) không ghi trong file mà đọc từ biến môi trường được chỉ định.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"ransomwarehunter/internal/detect"
	"ransomwarehunter/internal/syslogconn"
	"ransomwarehunter/internal/usn"
)

// Duration nhận chuỗi kiểu "60s", "5m" hoặc số giây.
type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(v)
		return nil
	}
	var n float64
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("thời lượng không hợp lệ: %s", b)
	}
	*d = Duration(time.Duration(n * float64(time.Second)))
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// D trả về time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// Server là cấu hình rh-server.
type Server struct {
	DataDir        string `json:"data_dir"`
	Listen         string `json:"listen"`
	PublicURL      string `json:"public_url"`       // URL gốc dùng trong liên kết cảnh báo
	IngestTokenEnv string `json:"ingest_token_env"` // biến môi trường chứa token cho agent
	UIUser         string `json:"ui_user"`
	UIPasswordEnv  string `json:"ui_password_env"`
	LogLevel       string `json:"log_level"`

	Detect   Detect    `json:"detect"`
	Scanners []Scanner `json:"scanners"`
	USN      []USN     `json:"usn"`
	Canaries []Canary  `json:"canaries"`
	Syslog   *SyslogIn `json:"syslog"`
	Notify   Notify    `json:"notify"`
}

// SyslogIn là bộ nhận log thao tác file từ NAS (Synology, QNAP, Samba…).
type SyslogIn struct {
	ListenUDP     string         `json:"listen_udp"`
	ListenTCP     string         `json:"listen_tcp"`
	CaptureFile   string         `json:"capture_file"` // ghi dòng không đọc được để hiệu chỉnh định dạng
	CaptureMax    int            `json:"capture_max"`
	Devices       []SyslogDevice `json:"devices"`
	CustomFormats []SyslogFormat `json:"custom_formats"`
}

// SyslogDevice là một NAS gửi syslog.
type SyslogDevice struct {
	Address     string `json:"address"` // IP nguồn; "*" = mọi nguồn chưa khai báo
	System      string `json:"system"`
	Format      string `json:"format"`       // "synology", "qnap" hoặc tên trong custom_formats
	SharePrefix string `json:"share_prefix"` // vd "\\\\syno01\\": share = prefix + thư mục đầu của path
	StripPrefix string `json:"strip_prefix"` // regex bỏ khỏi đầu path, vd "^/share/CACHEDEV\\d+_DATA/"
}

// SyslogFormat là định dạng log tự khai báo (regex có nhóm op, path hoặc old/new, user, ip…).
type SyslogFormat struct {
	Name      string            `json:"name"`
	Regex     string            `json:"regex"`
	Ops       map[string]string `json:"ops"` // giá trị op trong log → CREATE | DELETE | RENAME | MODIFY
	RenameSep string            `json:"rename_sep"`
	DirKinds  []string          `json:"dir_kinds"`
}

// Detect ghi đè tham số phát hiện; trường bằng 0 giữ giá trị mặc định.
type Detect struct {
	Window         Duration `json:"window"`
	MinRenames     int      `json:"min_renames"`
	MinDirs        int      `json:"min_dirs"`
	NoteMinDirs    int      `json:"note_min_dirs"`
	IncidentQuiet  Duration `json:"incident_quiet"`
	UpdateInterval Duration `json:"update_interval"`
	ExtraKnownExts []string `json:"extra_known_exts"`
	BenignFromExts []string `json:"benign_from_exts"`
	BenignToExts   []string `json:"benign_to_exts"`
}

// Scanner là một share quét Tầng C.
type Scanner struct {
	System      string   `json:"system"`
	Share       string   `json:"share"`
	Root        string   `json:"root"`
	Interval    Duration `json:"interval"`
	HotInterval Duration `json:"hot_interval"`
	HotWindow   Duration `json:"hot_window"`
	Workers     int      `json:"workers"`
	OpsPerSec   int      `json:"ops_per_sec"`
	Exclude     []string `json:"exclude"`
}

// USN là một volume Windows đọc USN Journal.
type USN struct {
	Volume       string     `json:"volume"`
	System       string     `json:"system"`
	Roots        []usn.Root `json:"roots"`
	StateFile    string     `json:"state_file"`
	PollInterval Duration   `json:"poll_interval"`
}

// Source chuyển sang cấu hình của gói usn.
func (u USN) Source() usn.SourceConfig {
	return usn.SourceConfig{Volume: u.Volume, System: u.System, Roots: u.Roots,
		StateFile: u.StateFile, PollInterval: u.PollInterval.D()}
}

// Canary là danh sách file mồi trên một share.
type Canary struct {
	System   string   `json:"system"`
	Share    string   `json:"share"`
	Root     string   `json:"root"`
	Paths    []string `json:"paths"`
	Interval Duration `json:"interval"`
}

// Notify là cấu hình kênh cảnh báo.
type Notify struct {
	Console  bool      `json:"console"`
	Email    *Email    `json:"email"`
	Telegram *Telegram `json:"telegram"`
	Syslog   *Syslog   `json:"syslog"`
	Webhook  *Webhook  `json:"webhook"`
}

type Email struct {
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	TLS         string   `json:"tls"`
	Username    string   `json:"username"`
	PasswordEnv string   `json:"password_env"`
	From        string   `json:"from"`
	To          []string `json:"to"`
}

type Telegram struct {
	TokenEnv string `json:"token_env"`
	ChatID   string `json:"chat_id"`
}

type Syslog struct {
	Network string `json:"network"`
	Address string `json:"address"`
}

type Webhook struct {
	URL           string `json:"url"`
	AuthHeaderEnv string `json:"auth_header_env"`
}

// Agent là cấu hình rh-agent-win.
type Agent struct {
	ServerURL      string `json:"server_url"`
	IngestTokenEnv string `json:"ingest_token_env"`
	LogLevel       string `json:"log_level"`
	USN            []USN  `json:"usn"`
}

// Load đọc file JSON vào v (không chấp nhận trường lạ để bắt lỗi chính tả).
func Load(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("đọc cấu hình %s: %w", path, err)
	}
	return nil
}

// Validate kiểm tra cấu hình server và điền giá trị mặc định.
func (c *Server) Validate() error {
	if c.DataDir == "" {
		c.DataDir = "data"
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8470"
	}
	if c.PublicURL == "" {
		c.PublicURL = "http://" + c.Listen
	}
	c.PublicURL = strings.TrimSuffix(c.PublicURL, "/")
	if len(c.Scanners)+len(c.USN) == 0 && c.IngestTokenEnv == "" && c.Syslog == nil {
		return fmt.Errorf("cần ít nhất một nguồn: scanners, usn, syslog hoặc ingest_token_env cho agent")
	}
	for i, s := range c.Scanners {
		if s.System == "" || s.Share == "" || s.Root == "" {
			return fmt.Errorf("scanners[%d]: cần system, share, root", i)
		}
	}
	for i, u := range c.USN {
		if u.Volume == "" || u.System == "" {
			return fmt.Errorf("usn[%d]: cần volume, system", i)
		}
	}
	for i, k := range c.Canaries {
		if k.System == "" || k.Share == "" || k.Root == "" || len(k.Paths) == 0 {
			return fmt.Errorf("canaries[%d]: cần system, share, root, paths", i)
		}
	}
	if s := c.Syslog; s != nil {
		if s.ListenUDP == "" && s.ListenTCP == "" {
			return fmt.Errorf("syslog: cần listen_udp hoặc listen_tcp")
		}
		if _, err := s.Receiver(); err != nil {
			return err
		}
	}
	return nil
}

// Receiver dựng cấu hình cho gói syslogconn.
func (s *SyslogIn) Receiver() (syslogconn.Config, error) {
	formats := map[string]*syslogconn.Format{}
	for k, f := range syslogconn.Builtin {
		formats[k] = f
	}
	for _, cf := range s.CustomFormats {
		f, err := syslogconn.NewCustom(cf.Name, cf.Regex, cf.Ops, cf.RenameSep, cf.DirKinds)
		if err != nil {
			return syslogconn.Config{}, err
		}
		formats[cf.Name] = f
	}
	out := syslogconn.Config{ListenUDP: s.ListenUDP, ListenTCP: s.ListenTCP, CaptureFile: s.CaptureFile, CaptureMax: s.CaptureMax}
	if len(s.Devices) == 0 {
		return out, fmt.Errorf("syslog: cần ít nhất một devices")
	}
	for i, d := range s.Devices {
		f := formats[d.Format]
		if d.Address == "" || d.System == "" || f == nil {
			return out, fmt.Errorf("syslog.devices[%d]: cần address, system và format hợp lệ (%q)", i, d.Format)
		}
		dev := syslogconn.Device{Address: d.Address, System: d.System, Format: f, SharePrefix: d.SharePrefix}
		if d.StripPrefix != "" {
			re, err := regexp.Compile(d.StripPrefix)
			if err != nil {
				return out, fmt.Errorf("syslog.devices[%d].strip_prefix: %w", i, err)
			}
			dev.Strip = re
		}
		out.Devices = append(out.Devices, dev)
	}
	return out, nil
}

// DetectConfig áp ghi đè lên cấu hình mặc định của engine.
func (c *Server) DetectConfig() detect.Config {
	d := detect.DefaultConfig()
	o := c.Detect
	if o.Window > 0 {
		d.Window = o.Window.D()
	}
	if o.MinRenames > 0 {
		d.MinRenames = o.MinRenames
	}
	if o.MinDirs > 0 {
		d.MinDirs = o.MinDirs
	}
	if o.NoteMinDirs > 0 {
		d.NoteMinDirs = o.NoteMinDirs
	}
	if o.IncidentQuiet > 0 {
		d.IncidentQuiet = o.IncidentQuiet.D()
	}
	if o.UpdateInterval > 0 {
		d.UpdateInterval = o.UpdateInterval.D()
	}
	d.KnownExts = append(d.KnownExts, o.ExtraKnownExts...)
	for _, e := range o.BenignFromExts {
		d.Benign.FromExts[strings.ToLower(strings.TrimPrefix(e, "."))] = true
	}
	for _, e := range o.BenignToExts {
		d.Benign.ToExts[strings.ToLower(strings.TrimPrefix(e, "."))] = true
	}
	for _, k := range c.Canaries {
		for _, p := range k.Paths {
			d.Canaries = append(d.Canaries, detect.CanaryRef{System: k.System, Share: k.Share, Path: normPath(p)})
		}
	}
	return d
}

func normPath(p string) string { return strings.Trim(strings.ReplaceAll(p, `\`, "/"), "/") }

// NormPaths chuẩn hóa danh sách đường dẫn tương đối về dạng '/'.
func NormPaths(ps []string) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = normPath(p)
	}
	return out
}

// Secret đọc bí mật từ biến môi trường; rỗng nếu không cấu hình.
func Secret(env string) (string, error) {
	if env == "" {
		return "", nil
	}
	v := os.Getenv(env)
	if v == "" {
		return "", fmt.Errorf("biến môi trường %s chưa được đặt", env)
	}
	return v, nil
}
