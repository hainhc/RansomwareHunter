// Package notify gửi cảnh báo qua console, email, Telegram, syslog CEF và webhook.
package notify

import (
	"context"
	"log/slog"
	"time"
)

// Notifier là một kênh gửi cảnh báo.
type Notifier interface {
	Name() string
	Send(ctx context.Context, a Alert) error
}

// Dispatcher gửi cảnh báo bất đồng bộ để engine không bị chặn bởi mạng.
type Dispatcher struct {
	ch        chan Alert
	notifiers []Notifier
	log       *slog.Logger
}

// NewDispatcher tạo dispatcher.
func NewDispatcher(log *slog.Logger, notifiers ...Notifier) *Dispatcher {
	return &Dispatcher{ch: make(chan Alert, 256), notifiers: notifiers, log: log}
}

// Send xếp cảnh báo vào hàng đợi; không chặn.
func (d *Dispatcher) Send(a Alert) {
	select {
	case d.ch <- a:
	default:
		d.log.Error("hàng đợi cảnh báo đầy, bỏ cảnh báo", "incident", a.Incident.ID, "kind", a.Kind)
	}
}

// Run gửi cảnh báo cho tới khi ctx bị hủy; thử lại 3 lần mỗi kênh.
func (d *Dispatcher) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case a := <-d.ch:
			for _, n := range d.notifiers {
				d.deliver(ctx, n, a)
			}
		}
	}
}

func (d *Dispatcher) deliver(ctx context.Context, n Notifier, a Alert) {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err = n.Send(sctx, a)
		cancel()
		if err == nil {
			d.log.Info("đã gửi cảnh báo", "channel", n.Name(), "incident", a.Incident.ID, "kind", a.Kind)
			return
		}
	}
	d.log.Error("gửi cảnh báo thất bại", "channel", n.Name(), "incident", a.Incident.ID, "err", err)
}
