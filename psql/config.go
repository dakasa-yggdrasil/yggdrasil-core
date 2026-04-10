package psql

import (
	"fmt"
	"os"
)

// Config stores the PostgreSQL connection parameters.
type Config struct {
	Name     string
	User     string
	Password string
	Host     string
	Port     string
	SSLMode  string
}

// LoadConfig reads the PostgreSQL configuration from the environment.
func LoadConfig() Config {
	return Config{
		Name:     getenv("DB_NAME", "yggdrasil_core"),
		User:     getenv("DB_USER", "postgres"),
		Password: getenv("DB_PASSWORD", "someAwesomePassword"),
		Host:     getenv("DB_HOST", "127.0.0.1"),
		Port:     getenv("DB_PORT", "5432"),
		SSLMode:  getenv("DB_SSLMODE", "disable"),
	}
}

// DSN returns the pq-compatible connection string.
func (c Config) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Host,
		c.Port,
		c.User,
		c.Password,
		c.Name,
		c.SSLMode,
	)
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
