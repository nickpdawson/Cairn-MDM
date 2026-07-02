package mdmcore

import (
	"context"
	"log/slog"

	nlog "github.com/micromdm/nanolib/log"
)

// slogAdapter bridges NanoMDM's structured logger interface (Info/Debug/With
// with alternating key/value variadics) onto a standard library slog.Logger, so
// the whole binary logs through one handler.
type slogAdapter struct {
	l *slog.Logger
}

// NewLogAdapter wraps an slog.Logger as a NanoMDM nlog.Logger.
func NewLogAdapter(l *slog.Logger) nlog.Logger { return &slogAdapter{l: l} }

func (a *slogAdapter) Info(args ...interface{})  { a.log(slog.LevelInfo, args) }
func (a *slogAdapter) Debug(args ...interface{}) { a.log(slog.LevelDebug, args) }

func (a *slogAdapter) With(args ...interface{}) nlog.Logger {
	return &slogAdapter{l: a.l.With(args...)}
}

// log maps NanoMDM's key/value args onto slog. NanoMDM conventionally passes a
// leading "msg" key; promote it to slog's message field for readable output and
// treat the remainder as attributes.
func (a *slogAdapter) log(level slog.Level, args []interface{}) {
	msg := ""
	if len(args) >= 2 {
		if k, ok := args[0].(string); ok && k == "msg" {
			if m, ok := args[1].(string); ok {
				msg = m
				args = args[2:]
			}
		}
	}
	a.l.Log(context.Background(), level, msg, args...)
}
