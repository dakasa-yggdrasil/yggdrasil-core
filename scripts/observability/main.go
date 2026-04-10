package main

import (
	"encoding/json"
	"os"
)

func main() {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"service":      "yggdrasil-core",
		"envMode":      firstNonEmpty(os.Getenv("ENV_MODE"), "production"),
		"logFile":      firstNonEmpty(os.Getenv("LOG_FILE"), "/var/log/yggdrasil-core.log"),
		"jwtKeySet":    os.Getenv("JWT_KEY") != "",
		"metricsRoute": "/internal-yggdrasil-core/metrics",
	})
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
