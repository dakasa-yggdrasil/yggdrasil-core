package transportplugin

import (
	"io"
	"log"

	hclog "github.com/hashicorp/go-hclog"
	"go.uber.org/zap"
)

// pluginHCLogger bridges go-plugin's hclog.Logger requirement onto a
// zap.Logger, so plugin subprocess logs land in the core's structured
// output alongside everything else. The "plugin" field tags lines
// with the short name so they can be filtered.
func pluginHCLogger(base *zap.Logger, name string) hclog.Logger {
	if base == nil {
		// Fall back to a discarding logger — go-plugin expects a
		// non-nil hclog instance even when the core has no logger.
		return hclog.New(&hclog.LoggerOptions{
			Name:   "transportplugin." + name,
			Output: io.Discard,
			Level:  hclog.NoLevel,
		})
	}

	tagged := base.With(zap.String("plugin", name))
	return &zapHCLogger{base: tagged, name: "transportplugin." + name}
}

// zapHCLogger implements the subset of hclog.Logger that go-plugin
// actually invokes during plugin lifecycle (Trace/Debug/Info/Warn/
// Error and the leveled With/Named variants). Anything deeper in the
// hclog surface routes to the base zap logger at sensible levels.
type zapHCLogger struct {
	base *zap.Logger
	name string
}

func (l *zapHCLogger) Log(level hclog.Level, msg string, args ...any) {
	switch level {
	case hclog.Trace, hclog.Debug:
		l.base.Debug(msg, zapArgsFromHCLog(args)...)
	case hclog.Info:
		l.base.Info(msg, zapArgsFromHCLog(args)...)
	case hclog.Warn:
		l.base.Warn(msg, zapArgsFromHCLog(args)...)
	case hclog.Error:
		l.base.Error(msg, zapArgsFromHCLog(args)...)
	default:
		l.base.Info(msg, zapArgsFromHCLog(args)...)
	}
}

func (l *zapHCLogger) Trace(msg string, args ...any) { l.Log(hclog.Trace, msg, args...) }
func (l *zapHCLogger) Debug(msg string, args ...any) { l.Log(hclog.Debug, msg, args...) }
func (l *zapHCLogger) Info(msg string, args ...any)  { l.Log(hclog.Info, msg, args...) }
func (l *zapHCLogger) Warn(msg string, args ...any)  { l.Log(hclog.Warn, msg, args...) }
func (l *zapHCLogger) Error(msg string, args ...any) { l.Log(hclog.Error, msg, args...) }

func (l *zapHCLogger) IsTrace() bool { return false }
func (l *zapHCLogger) IsDebug() bool { return true }
func (l *zapHCLogger) IsInfo() bool  { return true }
func (l *zapHCLogger) IsWarn() bool  { return true }
func (l *zapHCLogger) IsError() bool { return true }

func (l *zapHCLogger) ImpliedArgs() []any { return nil }

func (l *zapHCLogger) With(args ...any) hclog.Logger {
	return &zapHCLogger{base: l.base.With(zapArgsFromHCLog(args)...), name: l.name}
}

func (l *zapHCLogger) Name() string { return l.name }

func (l *zapHCLogger) Named(name string) hclog.Logger {
	combined := l.name + "." + name
	return &zapHCLogger{base: l.base.Named(name), name: combined}
}

func (l *zapHCLogger) ResetNamed(name string) hclog.Logger {
	return &zapHCLogger{base: l.base.Named(name), name: name}
}

func (l *zapHCLogger) SetLevel(hclog.Level) {}

func (l *zapHCLogger) GetLevel() hclog.Level { return hclog.Info }

func (l *zapHCLogger) StandardLogger(_ *hclog.StandardLoggerOptions) *log.Logger {
	return log.New(l.StandardWriter(nil), l.name+" ", 0)
}

func (l *zapHCLogger) StandardWriter(_ *hclog.StandardLoggerOptions) io.Writer {
	return zapInfoWriter{logger: l.base}
}

// zapArgsFromHCLog converts hclog-style flat args (k, v, k, v, ...)
// into zap fields. Unpaired trailing keys are dropped silently — the
// same policy hclog itself uses.
func zapArgsFromHCLog(args []any) []zap.Field {
	fields := make([]zap.Field, 0, len(args)/2)
	for i := 0; i+1 < len(args); i += 2 {
		key, ok := args[i].(string)
		if !ok {
			continue
		}
		fields = append(fields, zap.Any(key, args[i+1]))
	}
	return fields
}

// zapInfoWriter adapts a zap logger into an io.Writer. Only used by
// StandardWriter + StandardLogger for third-party packages that
// demand a *log.Logger; hclog invokes it rarely.
type zapInfoWriter struct {
	logger *zap.Logger
}

func (w zapInfoWriter) Write(p []byte) (int, error) {
	w.logger.Info(string(p))
	return len(p), nil
}
