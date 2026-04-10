package monitoring

import (
	"os"
	"strings"
	"sync/atomic"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Logger stores the package-level logger for addons that want a shared structured logger.
var Logger *zap.Logger

var pkgLogger atomic.Pointer[zap.Logger]

// SetLogger stores the logger for concurrent-safe later retrieval.
func SetLogger(logger *zap.Logger) {
	pkgLogger.Store(logger)
}

// GetLogger returns the package-level logger.
func GetLogger() *zap.Logger {
	return pkgLogger.Load()
}

// NewZapLoggerWithRotation creates a JSON zap logger with rotating files.
func NewZapLoggerWithRotation(serviceName string) *zap.Logger {
	file := "/var/log/" + serviceName + ".log"
	if value := os.Getenv("LOG_FILE"); value != "" {
		file = value
	}

	level := zap.InfoLevel
	switch strings.ToLower(os.Getenv("ENV_MODE")) {
	case "development", "test":
		level = zap.DebugLevel
	}

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(&lumberjack.Logger{
			Filename:   file,
			MaxSize:    10,
			MaxBackups: 5,
			MaxAge:     30,
			Compress:   true,
		}),
		level,
	)

	return zap.New(core)
}
