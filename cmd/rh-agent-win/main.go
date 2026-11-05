// rh-agent-win: đọc USN Journal trên Windows File Server / host mount LUN SAN và gửi sự kiện
// về rh-server qua HTTP. Cần chạy với quyền Administrator (hoặc dưới dạng service LocalSystem).
//
//	set RH_INGEST_TOKEN=...
//	rh-agent-win -config configs/rh-agent.json
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"ransomwarehunter/internal/api"
	"ransomwarehunter/internal/config"
	"ransomwarehunter/internal/detect"
	"ransomwarehunter/internal/event"
	"ransomwarehunter/internal/usn"
)

const (
	batchMax  = 5_000
	bufferMax = 1_000_000 // giữ tối đa chừng này sự kiện khi server không truy cập được
)

func main() {
	cfgPath := flag.String("config", "configs/rh-agent.json", "file cấu hình JSON")
	flag.Parse()
	if err := run(*cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "lỗi:", err)
		os.Exit(1)
	}
}

func run(cfgPath string) error {
	var cfg config.Agent
	if err := config.Load(cfgPath, &cfg); err != nil {
		return err
	}
	if cfg.ServerURL == "" || len(cfg.USN) == 0 {
		return errors.New("cần server_url và ít nhất một usn")
	}
	token, err := config.Secret(cfg.IngestTokenEnv)
	if err != nil {
		return err
	}
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(strings.ToUpper(cfg.LogLevel)))
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	c := &client{base: strings.TrimSuffix(cfg.ServerURL, "/"), token: token, log: log,
		http: &http.Client{Timeout: 30 * time.Second}}
	go c.sender(ctx)

	var wg sync.WaitGroup
	for _, u := range cfg.USN {
		src := u.Source()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				err := usn.Run(ctx, src, c.enqueue, func(share string, exts map[string]int) {
					c.postRetry(ctx, "/api/v1/baseline", detect.Baseline{System: src.System, Share: share, Exts: exts})
				}, log)
				if ctx.Err() != nil {
					return
				}
				log.Error("đọc USN lỗi, thử lại sau 30s", "volume", src.Volume, "err", err)
				select {
				case <-ctx.Done():
				case <-time.After(30 * time.Second):
				}
			}
		}()
	}
	wg.Wait()
	c.flush(context.Background())
	return nil
}

type client struct {
	base, token string
	http        *http.Client
	log         *slog.Logger

	mu      sync.Mutex
	buf     []event.FileEvent
	dropped int
}

func (c *client) enqueue(evs []event.FileEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, evs...)
	if over := len(c.buf) - bufferMax; over > 0 {
		c.buf = append(c.buf[:0], c.buf[over:]...)
		c.dropped += over
	}
	return nil
}

// sender gửi theo lô mỗi giây; lỗi thì giữ lại và thử lại ở lượt sau.
func (c *client) sender(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.flush(ctx)
		}
	}
}

func (c *client) flush(ctx context.Context) {
	for {
		c.mu.Lock()
		if c.dropped > 0 {
			c.log.Warn("bộ đệm đầy, đã bỏ sự kiện cũ nhất", "count", c.dropped)
			c.dropped = 0
		}
		n := min(len(c.buf), batchMax)
		batch := append([]event.FileEvent(nil), c.buf[:n]...)
		c.mu.Unlock()
		if n == 0 {
			return
		}
		if err := c.post(ctx, "/api/v1/events", api.EventBatch{Events: batch}); err != nil {
			c.log.Warn("gửi sự kiện lỗi, sẽ thử lại", "pending", n, "err", err)
			return
		}
		c.mu.Lock()
		c.buf = append(c.buf[:0], c.buf[n:]...)
		c.mu.Unlock()
	}
}

func (c *client) post(ctx context.Context, path string, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *client) postRetry(ctx context.Context, path string, v any) {
	for delay := time.Second; ctx.Err() == nil; delay = min(2*delay, time.Minute) {
		err := c.post(ctx, path, v)
		if err == nil {
			return
		}
		c.log.Warn("gửi baseline lỗi, thử lại", "err", err)
		select {
		case <-ctx.Done():
		case <-time.After(delay):
		}
	}
}
