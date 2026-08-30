package provisioner

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

// serviceSpec defines the environment variables a service needs.
type serviceSpec struct {
	name           string
	port           string // HTTP listen port (SERVICE_NAME derived from name)
	dbName         string // empty = stateless, no DB vars
	needsS3        bool
	needsSES       bool
	needsSNS       bool
	needsYggdrasil bool              // needs YGGDRASIL_AUTH_URL (tartaro services)
	needsJWT       bool              // needs JWT_KEY (app/enterprise services)
	needsHMAC      bool              // needs DAKASA_HMAC_SECRET
	needsSystem    bool              // needs SYSTEM_TOKEN
	corsScope      string            // "app", "enterprise", "tartaro", "shared"
	extra          map[string]string // additional env vars
}

// allServices returns the 19 DaKasa microservice specs.
func allServices() []serviceSpec {
	return []serviceSpec{
		// ── App scope ──
		{name: "identities", port: "9080", dbName: "identities",
			needsJWT: true, needsHMAC: true, needsSystem: true, needsSES: true, needsSNS: true, corsScope: "app"},
		{name: "hall", port: "9082", dbName: "hall",
			needsJWT: true, needsHMAC: true, needsSystem: true, corsScope: "app"},
		{name: "room", port: "9081", dbName: "room",
			needsJWT: true, needsHMAC: true, needsSystem: true, corsScope: "app"},
		{name: "notify", port: "9084", dbName: "notify",
			needsJWT: true, needsHMAC: true, needsSystem: true, needsSES: true, needsSNS: true, corsScope: "app"},
		{name: "media-compressor", port: "9083", dbName: "compressor",
			needsJWT: true, needsSystem: true, needsS3: true, corsScope: "app"},
		{name: "rta", port: "3000", corsScope: "app"},

		// ── Enterprise scope ──
		{name: "enterprise-api", port: "9050", dbName: "enterprise-identities",
			needsJWT: true, needsHMAC: true, needsSystem: true, corsScope: "enterprise"},
		{name: "enterprise-ads-api", port: "9102", dbName: "enterprise-ads",
			needsJWT: true, needsHMAC: true, needsSystem: true, corsScope: "enterprise"},
		{name: "enterprise-payments-api", port: "9101", dbName: "enterprise-payments",
			needsJWT: true, needsHMAC: true, needsSystem: true, needsS3: true, corsScope: "enterprise"},
		{name: "enterprise-notify", port: "9104", dbName: "enterprise-notify",
			needsJWT: true, needsHMAC: true, needsSystem: true, needsSES: true, corsScope: "enterprise"},
		{name: "enterprise-media-compressor", port: "9103",
			needsJWT: true, needsSystem: true, needsS3: true, corsScope: "enterprise"},
		{name: "enterprise-rta", port: "3101", corsScope: "enterprise"},

		// ── Shared scope ──
		{name: "orchestrator", port: "9222", dbName: "orchestrator",
			needsJWT: true, needsHMAC: true, needsSystem: true, corsScope: "shared",
			extra: map[string]string{
				"TEMPORAL_HOST_PORT": "temporal-server.infra.svc.cluster.local:7233",
			}},

		// ── Tartaro scope (Yggdrasil auth, no JWT) ──
		{name: "tartaro-api", port: "8090", dbName: "tartaro",
			needsYggdrasil: true, needsHMAC: true, corsScope: "tartaro"},
		{name: "tartaro-operations", port: "8093", dbName: "tartaro",
			needsYggdrasil: true, needsHMAC: true, corsScope: "tartaro"},
		{name: "tartaro-legal", port: "8092", dbName: "tartaro",
			needsYggdrasil: true, needsSystem: true, corsScope: "tartaro"},
		{name: "tartaro-review", port: "8091", dbName: "tartaro",
			needsYggdrasil: true, corsScope: "tartaro"},
		{name: "tartaro-notify", port: "8094",
			needsYggdrasil: true, needsSES: true, corsScope: "tartaro"},
		{name: "tartaro-rta", port: "3200",
			needsYggdrasil: true, needsHMAC: true, corsScope: "tartaro"},
	}
}

// corsOrigins maps scope names to allowed origins.
func corsOrigins(domain string) map[string]string {
	if domain == "" {
		domain = "dakasa.me"
	}
	return map[string]string{
		"app":        "https://app." + domain,
		"enterprise": "https://enterprise." + domain,
		"tartaro":    "https://tartaro." + domain,
		"shared":     "https://app." + domain + ",https://enterprise." + domain,
	}
}

// generateAndStoreSecrets builds the data map for each of the 19 services,
// upserts them as managed secrets, and returns the list of created names and
// any errors.
func generateAndStoreSecrets(
	ctx context.Context,
	db *sql.DB,
	logger *zap.Logger,
	req ProvisionRequest,
	snsTopicARN string,
) (created []string, errors []string) {

	dbHost := defaultString(req.DBHost, "unified-database")
	dbUser := defaultString(req.DBUser, "superuser")
	dbPassword := defaultString(req.DBPassword, "superpass")
	dbPort := "5432"

	brokerURL := envOrDefault("BROKER_URL", "amqp://guest:guest@rabbitmq.infra.svc.cluster.local:5672/")
	redisAddr := envOrDefault("REDIS_ADDR", "redis.infra.svc.cluster.local:6379")

	// Shared auth secrets — generate if not provided in environment.
	jwtKey := envOrDefault("JWT_KEY", "")
	if jwtKey == "" {
		jwtKey = mustRandomHex(32)
		logger.Info("generated JWT_KEY (not found in environment)")
	}

	hmacSecret := envOrDefault("DAKASA_HMAC_SECRET", "")
	if hmacSecret == "" {
		hmacSecret = mustRandomHex(32)
		logger.Info("generated DAKASA_HMAC_SECRET (not found in environment)")
	}

	systemToken := envOrDefault("SYSTEM_TOKEN", "")
	if systemToken == "" {
		systemToken = mustRandomHex(16)
		logger.Info("generated SYSTEM_TOKEN (not found in environment)")
	}

	// AWS credentials come from the environment (same ones the provisioner itself uses).
	awsAccessKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	awsSecretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	awsRegion := envOrDefault("AWS_REGION", "sa-east-1")

	domain := envOrDefault("DAKASA_DOMAIN", "dakasa.me")
	origins := corsOrigins(domain)

	for _, svc := range allServices() {
		data := make(map[string]string)

		// Common vars for all services.
		data["BROKER_URL"] = brokerURL
		data["REDIS_ADDR"] = redisAddr
		data["ENV_MODE"] = "production"

		// Service identity vars (PORT + SERVICE_NAME).
		if svc.port != "" {
			data["PORT"] = svc.port
		}
		data["SERVICE_NAME"] = "dakasa-" + svc.name

		// CORS allowed origins.
		if origin, ok := origins[svc.corsScope]; ok {
			data["CORS_ALLOWED_ORIGINS"] = origin
		}

		// JWT key (app/enterprise services).
		if svc.needsJWT {
			data["JWT_KEY"] = jwtKey
		}

		// HMAC secret (inter-service request signing).
		if svc.needsHMAC {
			data["DAKASA_HMAC_SECRET"] = hmacSecret
		}

		// System token (metrics auth).
		if svc.needsSystem {
			data["SYSTEM_TOKEN"] = systemToken
		}

		// Yggdrasil auth URL (tartaro services).
		if svc.needsYggdrasil {
			data["YGGDRASIL_AUTH_URL"] = "http://yggdrasil.dakasa:9080"
		}

		// Database vars (only for stateful services).
		if svc.dbName != "" {
			data["DB_HOST"] = dbHost
			data["DB_PORT"] = dbPort
			data["DB_USER"] = dbUser
			data["DB_PASSWORD"] = dbPassword
			data["DB_NAME"] = svc.dbName
			data["DATABASE_URL"] = fmt.Sprintf(
				"postgres://%s:%s@%s:%s/%s?sslmode=disable",
				dbUser, dbPassword, dbHost, dbPort, svc.dbName,
			)
		}

		// S3 vars.
		if svc.needsS3 {
			data["AWS_ACCESS_KEY_ID"] = awsAccessKeyID
			data["AWS_SECRET_ACCESS_KEY"] = awsSecretAccessKey
			data["AWS_REGION"] = awsRegion
			data["S3_BUCKET"] = req.S3Bucket
		}

		// SES vars.
		if svc.needsSES {
			data["AWS_ACCESS_KEY_ID"] = awsAccessKeyID
			data["AWS_SECRET_ACCESS_KEY"] = awsSecretAccessKey
			data["AWS_REGION"] = awsRegion
			data["SES_FROM_EMAIL"] = req.SESEmail
		}

		// SNS vars.
		if svc.needsSNS {
			data["AWS_ACCESS_KEY_ID"] = awsAccessKeyID
			data["AWS_SECRET_ACCESS_KEY"] = awsSecretAccessKey
			data["AWS_REGION"] = awsRegion
			if snsTopicARN != "" {
				data["SNS_TOPIC_ARN"] = snsTopicARN
			}
		}

		// Payment/integration keys — injected from Yggdrasil's own environment.
		if svc.name == "enterprise-payments-api" {
			injectIfSet(data, "STRIPE_API_KEY")
			injectIfSet(data, "STRIPE_WEBHOOK_SECRET")
			injectIfSet(data, "STRIPE_ENTERPRISE_ACCT")
			injectIfSet(data, "STRIPE_CONTABILITY_ACCT")
			injectIfSet(data, "STRIPE_REWARDS_ACCT")
			injectIfSet(data, "NFE_IO_API_KEY")
			injectIfSet(data, "NFE_IO_COMPANY_ID")
			injectIfSet(data, "NFE_IO_BASE_URL")
			injectIfSet(data, "NFE_IO_SERVICE_INVOICE_PATH")
			injectIfSet(data, "NFEIO_WEBHOOK_SECRET")
		}
		if svc.name == "identities" {
			injectIfSet(data, "EFI_PIX_KEY")
			injectIfSet(data, "EFI_API_CLIENT_KEY_ID")
			injectIfSet(data, "EFI_API_CLIENT_SECRET")
			// Certificate file paths (mounted from efi-certificates Secret)
			data["EFI_CERTIFICATE"] = "/etc/efi-certificates/producao-wallet.p12"
			data["EFI_CERTIFICATE_WEBHOOK"] = "/etc/efi-certificates/webhook-prod.crt"
		}

		// tartaro-operations cross-DB access.
		if svc.name == "tartaro-operations" {
			data["PAYMENTS_DB_HOST"] = dbHost
			data["PAYMENTS_DB_PORT"] = dbPort
			data["PAYMENTS_DB_USER"] = dbUser
			data["PAYMENTS_DB_PASSWORD"] = dbPassword
			data["PAYMENTS_DB_NAME"] = "enterprise-payments"
			data["IDENTITIES_DB_HOST"] = dbHost
			data["IDENTITIES_DB_PORT"] = dbPort
			data["IDENTITIES_DB_USER"] = dbUser
			data["IDENTITIES_DB_PASSWORD"] = dbPassword
			data["IDENTITIES_DB_NAME"] = "identities"
		}

		// Service-specific extra env vars.
		for k, v := range svc.extra {
			data[k] = v
		}

		secretName := "dakasa-" + svc.name
		_, err := repository.UpsertManagedSecret(ctx, db, model.UpsertManagedSecretRequest{
			Namespace: req.Namespace,
			Name:      secretName,
			Status:    "active",
			Data:      data,
			Metadata: map[string]any{
				"provisioned_by": "aws-provisioner",
				"service":        svc.name,
			},
		})
		if err != nil {
			errMsg := fmt.Sprintf("secret %s/%s: %v", req.Namespace, secretName, err)
			errors = append(errors, errMsg)
			logger.Error("upsert managed secret failed",
				zap.String("namespace", req.Namespace),
				zap.String("name", secretName),
				zap.Error(err),
			)
		} else {
			created = append(created, secretName)
			logger.Info("managed secret upserted",
				zap.String("namespace", req.Namespace),
				zap.String("name", secretName),
			)
		}
	}

	return created, errors
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// injectIfSet copies an environment variable into the data map if it is set and non-empty.
func injectIfSet(data map[string]string, key string) {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		data[key] = v
	}
}

// mustRandomHex returns n random bytes encoded as hex. Panics if crypto/rand fails.
func mustRandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return hex.EncodeToString(b)
}
