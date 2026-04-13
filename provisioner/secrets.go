package provisioner

import (
	"context"
	"database/sql"
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
	port           string            // HTTP listen port (SERVICE_NAME derived from name)
	dbName         string            // empty = stateless, no DB vars
	needsS3        bool
	needsSES       bool
	needsSNS       bool
	needsYggdrasil bool              // needs YGGDRASIL_AUTH_URL (tartaro services)
	extra          map[string]string // additional env vars
}

// allServices returns the 19 DaKasa microservice specs.
func allServices() []serviceSpec {
	return []serviceSpec{
		{name: "identities", port: "9080", dbName: "identities", extra: map[string]string{
			"ENV_MODE": "development",
		}},
		{name: "hall", port: "9082", dbName: "hall"},
		{name: "room", port: "9081", dbName: "room"},
		{name: "notify", port: "9084", dbName: "notify", needsSES: true, needsSNS: true, extra: map[string]string{
			"SKIP_PUSH": "true",
		}},
		{name: "media-compressor", port: "9083", needsS3: true},
		{name: "rta", port: "3000"},
		{name: "enterprise-api", port: "9050", dbName: "enterprise-identities"},
		{name: "enterprise-ads-api", port: "9102", dbName: "enterprise-ads"},
		{name: "enterprise-payments-api", port: "9101", dbName: "enterprise-payments", needsS3: true},
		{name: "enterprise-notify", port: "9104", dbName: "enterprise-notify", needsSES: true},
		{name: "enterprise-media-compressor", port: "9103", needsS3: true},
		{name: "enterprise-rta", port: "3101"},
		{name: "orchestrator", port: "9222", dbName: "orchestrator", extra: map[string]string{
			"TEMPORAL_HOST_PORT": "temporal-server.infra.svc.cluster.local:7233",
		}},
		{name: "tartaro-api", port: "8090", dbName: "tartaro", needsYggdrasil: true},
		{name: "tartaro-operations", port: "8093", dbName: "tartaro", needsYggdrasil: true},
		{name: "tartaro-legal", port: "8092", dbName: "tartaro", needsYggdrasil: true},
		{name: "tartaro-review", port: "8091", dbName: "tartaro", needsYggdrasil: true},
		{name: "tartaro-notify", port: "8094", needsSES: true, needsYggdrasil: true, extra: map[string]string{
			"LOG_FILE": "/dev/stderr",
			"SKIP_SES": "false",
		}},
		{name: "tartaro-rta", port: "3200", needsYggdrasil: true},
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

	// AWS credentials come from the environment (same ones the provisioner itself uses).
	awsAccessKeyID := os.Getenv("AWS_ACCESS_KEY_ID")
	awsSecretAccessKey := os.Getenv("AWS_SECRET_ACCESS_KEY")
	awsRegion := envOrDefault("AWS_REGION", "sa-east-1")

	for _, svc := range allServices() {
		data := make(map[string]string)

		// Common vars for all services.
		data["BROKER_URL"] = brokerURL
		data["REDIS_ADDR"] = redisAddr

		// Service identity vars (PORT + SERVICE_NAME).
		if svc.port != "" {
			data["PORT"] = svc.port
		}
		data["SERVICE_NAME"] = "dakasa-" + svc.name

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
