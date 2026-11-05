// rh-server: detection engine + scanner Tầng C + canary + (trên Windows) USN Journal + API.
//
//	rh-server run -config configs/rh-server.json
//	rh-server canary-deploy -root \\nas01\Finance -dirs ".,Phong KeToan,Phong NhanSu"
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"ransomwarehunter/internal/api"
	"ransomwarehunter/internal/canary"
	"ransomwarehunter/internal/config"
	"ransomwarehunter/internal/detect"
	"ransomwarehunter/internal/event"
	"ransomwarehunter/internal/notify"
	"ransomwarehunter/internal/scanner"
	"ransomwarehunter/internal/store"
	"ransomwarehunter/internal/syslogconn"
	"ransomwarehunter/internal/usn"
)

func main() {
	cmd := "run"
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "run":
		err = run(args)
	case "canary-deploy":
		err = canaryDeploy(args)
	case "syslog-test":
		err = syslogTest(args)
	default:
		err = fmt.Errorf("lệnh không hợp lệ %q (run | canary-deploy | syslog-test)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "lỗi:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/rh-server.json", "file cấu hình JSON")
	_ = fs.Parse(args)

	var cfg config.Server
	if err := config.Load(*cfgPath, &cfg); err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)

	notifiers, err := buildNotifiers(cfg.Notify)
	if err != nil {
		return err
	}
	ingestToken, err := config.Secret(cfg.IngestTokenEnv)
	if err != nil {
		return err
	}
	uiPassword, err := config.Secret(cfg.UIPasswordEnv)
	if err != nil {
		return err
	}
	if cfg.UIUser == "" && !strings.HasPrefix(cfg.Listen, "127.0.0.1:") && !strings.HasPrefix(cfg.Listen, "localhost:") {
		log.Warn("API xem incident không yêu cầu đăng nhập trên địa chỉ không phải localhost; đặt ui_user/ui_password_env")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	disp := notify.NewDispatcher(log, notifiers...)
	go disp.Run(ctx)
	st, err := store.Open(cfg.DataDir, cfg.PublicURL, disp, log)
	if err != nil {
		return err
	}
	defer st.Close()

	events := make(chan event.FileEvent, 100_000)
	baselines := make(chan detect.Baseline, 64)
	engine := detect.New(cfg.DetectConfig(), st, log)
	engineDone := make(chan struct{})
	go func() {
		engine.Run(ctx, events, baselines)
		close(engineDone)
	}()

	var scanners []*scanner.Scanner
	for _, sc := range cfg.Scanners {
		sc := sc
		s := scanner.New(scanner.Config{
			System: sc.System, Share: sc.Share, Root: sc.Root,
			Interval: sc.Interval.D(), HotInterval: sc.HotInterval.D(), HotWindow: sc.HotWindow.D(),
			Workers: sc.Workers, OpsPerSec: sc.OpsPerSec, Exclude: sc.Exclude,
		}, events, func(exts map[string]int) {
			_ = sendCtx(ctx, baselines, detect.Baseline{System: sc.System, Share: sc.Share, Exts: exts})
		}, log)
		scanners = append(scanners, s)
		go retry(ctx, log, "scanner "+sc.Share, s.Run)
	}
	for _, u := range cfg.USN {
		src := u.Source()
		go retry(ctx, log, "usn "+u.Volume, func(ctx context.Context) error {
			return usn.Run(ctx, src, func(evs []event.FileEvent) error {
				for _, ev := range evs {
					if err := sendCtx(ctx, events, ev); err != nil {
						return err
					}
				}
				return nil
			}, func(share string, exts map[string]int) {
				_ = sendCtx(ctx, baselines, detect.Baseline{System: src.System, Share: share, Exts: exts})
			}, log)
		})
	}
	for _, k := range cfg.Canaries {
		m := canary.New(canary.Config{System: k.System, Share: k.Share, Root: k.Root,
			Paths: config.NormPaths(k.Paths), Interval: k.Interval.D()}, events, log)
		go m.Run(ctx)
	}
	var syslogRecv *syslogconn.Receiver
	if cfg.Syslog != nil {
		rc, err := cfg.Syslog.Receiver()
		if err != nil {
			return err
		}
		if syslogRecv, err = syslogconn.New(rc, events, log); err != nil {
			return err
		}
		go retry(ctx, log, "syslog", syslogRecv.Run)
	}

	status := func() any {
		out := map[string]any{"engine": engine.Stats(), "queue": len(events)}
		var ss []map[string]any
		for i, s := range scanners {
			st := s.Stats()
			ss = append(ss, map[string]any{
				"share": cfg.Scanners[i].Share, "dirs": st.Dirs, "files": st.Files, "cycles": st.Cycles,
				"last_cycle": st.LastCycle.String(), "last_hot": st.LastHot.String(),
				"initial_scan": st.InitialScan.String(), "ops": st.Ops, "errors": st.Errors,
			})
		}
		out["scanners"] = ss
		if syslogRecv != nil {
			out["syslog"] = syslogRecv.Stats()
		}
		return out
	}
	srv := &http.Server{
		Addr: cfg.Listen,
		Handler: (&api.Server{Store: st, Events: events, Baselines: baselines, IngestToken: ingestToken,
			UIUser: cfg.UIUser, UIPassword: uiPassword, Status: status}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Info("API đang lắng nghe", "addr", cfg.Listen, "public_url", cfg.PublicURL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("API lỗi", "err", err)
			stop()
		}
	}()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				es := engine.Stats()
				log.Info("trạng thái", "events", es.Events, "renames", es.Renames, "ext_changes", es.ExtChanges,
					"incidents", es.Incidents, "queue", len(events))
			}
		}
	}()

	<-ctx.Done()
	log.Info("đang dừng")
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	<-engineDone
	return nil
}

func sendCtx[T any](ctx context.Context, ch chan<- T, v T) error {
	select {
	case ch <- v:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// retry chạy fn, khởi động lại sau 30 giây nếu lỗi (vd share tạm thời không truy cập được).
func retry(ctx context.Context, log *slog.Logger, name string, fn func(context.Context) error) {
	for {
		err := fn(ctx)
		if ctx.Err() != nil {
			return
		}
		log.Error("nguồn dữ liệu lỗi, thử lại sau 30s", "source", name, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
}

func buildNotifiers(n config.Notify) ([]notify.Notifier, error) {
	var out []notify.Notifier
	if n.Console {
		out = append(out, &notify.Console{})
	}
	if e := n.Email; e != nil {
		pw, err := config.Secret(e.PasswordEnv)
		if err != nil {
			return nil, err
		}
		out = append(out, &notify.Email{Host: e.Host, Port: e.Port, TLS: e.TLS, Username: e.Username,
			Password: pw, From: e.From, To: e.To})
	}
	if t := n.Telegram; t != nil {
		tok, err := config.Secret(t.TokenEnv)
		if err != nil {
			return nil, err
		}
		out = append(out, &notify.Telegram{Token: tok, ChatID: t.ChatID})
	}
	if s := n.Syslog; s != nil {
		out = append(out, &notify.Syslog{Network: s.Network, Address: s.Address})
	}
	if w := n.Webhook; w != nil {
		auth, err := config.Secret(w.AuthHeaderEnv)
		if err != nil {
			return nil, err
		}
		out = append(out, &notify.Webhook{URL: w.URL, AuthHeader: auth})
	}
	if len(out) == 0 {
		return nil, errors.New("chưa cấu hình kênh cảnh báo nào (notify)")
	}
	return out, nil
}

func canaryDeploy(args []string) error {
	fs := flag.NewFlagSet("canary-deploy", flag.ExitOnError)
	root := fs.String("root", "", "gốc share (đường dẫn đã mount)")
	dirs := fs.String("dirs", ".", "các thư mục tương đối, phân tách bằng dấu phẩy; \".\" là gốc share")
	names := fs.String("names", "", "tên file mồi, phân tách bằng dấu phẩy (mặc định: "+strings.Join(canary.DefaultNames, ", ")+")")
	_ = fs.Parse(args)
	if *root == "" {
		return errors.New("cần -root")
	}
	var ds []string
	for _, d := range strings.Split(*dirs, ",") {
		d = strings.Trim(strings.ReplaceAll(strings.TrimSpace(d), `\`, "/"), "/")
		if d == "." {
			d = ""
		}
		ds = append(ds, d)
	}
	var ns []string
	if *names != "" {
		ns = strings.Split(*names, ",")
	}
	paths, err := canary.Deploy(*root, ds, ns)
	for _, p := range paths {
		fmt.Println(p)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Đã có %d file mồi. Thêm danh sách trên vào canaries[].paths trong cấu hình.\n", len(paths))
	return nil
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	_ = l.UnmarshalText([]byte(strings.ToUpper(level)))
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}
