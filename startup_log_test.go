package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestStartupLogDoesNotExposeBrokerCredentials(t *testing.T) {
	for _, tc := range []struct {
		name       string
		brokerURL  string
		configured bool
	}{
		{name: "configured", brokerURL: "amqp://private-user:private-password@broker.example:5672/private-vhost", configured: true},
		{name: "absent", configured: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BROKER_URL", tc.brokerURL)
			t.Setenv("DB_HOST", "lab-db")
			var output bytes.Buffer
			logger := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.AddSync(&output), zap.InfoLevel))
			logStartup(logger, "core", "127.0.0.1:9080")
			var record map[string]any
			if err := json.Unmarshal(output.Bytes(), &record); err != nil {
				t.Fatalf("decode startup log: %v", err)
			}
			if record["broker_configured"] != tc.configured || record["service"] != "core" || record["db_host"] != "lab-db" {
				t.Fatalf("unexpected startup log fields: %#v", record)
			}
			if strings.Contains(output.String(), "private-") || strings.Contains(output.String(), "broker.example") {
				t.Fatal("startup log exposed broker URL material")
			}
		})
	}
}
