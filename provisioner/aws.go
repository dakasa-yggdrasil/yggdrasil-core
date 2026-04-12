package provisioner

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"go.uber.org/zap"
)

// ProvisionRequest describes the AWS resources and secrets to provision for a namespace.
type ProvisionRequest struct {
	Namespace  string `json:"namespace"`
	S3Bucket   string `json:"s3_bucket"`
	SESEmail   string `json:"ses_email"`
	SNSTopic   string `json:"sns_topic"`
	DBHost     string `json:"db_host"`
	DBUser     string `json:"db_user"`
	DBPassword string `json:"db_password"`
}

// ProvisionResult summarises what was provisioned.
type ProvisionResult struct {
	S3Bucket       string   `json:"s3_bucket"`
	SESEmail       string   `json:"ses_email"`
	SNSTopicARN    string   `json:"sns_topic_arn"`
	SecretsCreated []string `json:"secrets_created"`
	Errors         []string `json:"errors,omitempty"`
}

// AWSProvisioner creates and manages AWS resources for DaKasa namespaces.
type AWSProvisioner struct {
	db        *sql.DB
	logger    *zap.Logger
	region    string
	s3Client  *s3.Client
	sesClient *ses.Client
	snsClient *sns.Client
}

// NewAWSProvisioner loads the default AWS credential chain and creates SDK clients.
// Returns an error if credentials are not available.
func NewAWSProvisioner(ctx context.Context, db *sql.DB, logger *zap.Logger) (*AWSProvisioner, error) {
	region := strings.TrimSpace(os.Getenv("AWS_REGION"))
	if region == "" {
		region = "sa-east-1"
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("aws provisioner: load config: %w", err)
	}

	// Verify credentials are resolvable.
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws provisioner: retrieve credentials: %w", err)
	}
	if creds.AccessKeyID == "" {
		return nil, fmt.Errorf("aws provisioner: no access key in resolved credentials")
	}

	return &AWSProvisioner{
		db:        db,
		logger:    logger,
		region:    region,
		s3Client:  s3.NewFromConfig(cfg),
		sesClient: ses.NewFromConfig(cfg),
		snsClient: sns.NewFromConfig(cfg),
	}, nil
}

// ProvisionAll orchestrates S3, SES, SNS provisioning and then generates
// all managed secrets for the namespace.
func (p *AWSProvisioner) ProvisionAll(ctx context.Context, req ProvisionRequest) (*ProvisionResult, error) {
	result := &ProvisionResult{
		S3Bucket: req.S3Bucket,
		SESEmail: req.SESEmail,
	}

	// --- S3 ---
	if err := p.EnsureS3Bucket(ctx, req.S3Bucket); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("s3: %v", err))
		p.logger.Error("provision s3 bucket failed", zap.String("bucket", req.S3Bucket), zap.Error(err))
	} else {
		p.logger.Info("s3 bucket ensured", zap.String("bucket", req.S3Bucket))
	}

	// --- SES ---
	if err := p.EnsureSESIdentity(ctx, req.SESEmail); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("ses: %v", err))
		p.logger.Error("provision ses identity failed", zap.String("email", req.SESEmail), zap.Error(err))
	} else {
		p.logger.Info("ses identity ensured", zap.String("email", req.SESEmail))
	}

	// --- SNS ---
	topicARN, err := p.EnsureSNSTopic(ctx, req.SNSTopic)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("sns: %v", err))
		p.logger.Error("provision sns topic failed", zap.String("topic", req.SNSTopic), zap.Error(err))
	} else {
		result.SNSTopicARN = topicARN
		p.logger.Info("sns topic ensured", zap.String("topic", req.SNSTopic), zap.String("arn", topicARN))
	}

	// --- Secrets ---
	created, secretErrors := generateAndStoreSecrets(ctx, p.db, p.logger, req, topicARN)
	result.SecretsCreated = created
	if len(secretErrors) > 0 {
		result.Errors = append(result.Errors, secretErrors...)
	}

	return result, nil
}

// EnsureS3Bucket creates the bucket if it does not already exist and sets CORS
// for media uploads.
func (p *AWSProvisioner) EnsureS3Bucket(ctx context.Context, name string) error {
	_, err := p.s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: &name,
		CreateBucketConfiguration: &s3types.CreateBucketConfiguration{
			LocationConstraint: s3types.BucketLocationConstraint(p.region),
		},
	})
	if err != nil {
		// BucketAlreadyOwnedByYou is fine — idempotent.
		if !isBucketAlreadyOwnedByYou(err) {
			return fmt.Errorf("create bucket %q: %w", name, err)
		}
	}

	// Set CORS for media uploads.
	_, corsErr := p.s3Client.PutBucketCors(ctx, &s3.PutBucketCorsInput{
		Bucket: &name,
		CORSConfiguration: &s3types.CORSConfiguration{
			CORSRules: []s3types.CORSRule{
				{
					AllowedHeaders: []string{"*"},
					AllowedMethods: []string{"GET", "PUT", "POST"},
					AllowedOrigins: []string{"*"},
					MaxAgeSeconds:  ptr(int32(3600)),
				},
			},
		},
	})
	if corsErr != nil {
		return fmt.Errorf("set cors on bucket %q: %w", name, corsErr)
	}

	return nil
}

// EnsureSESIdentity sends a verification email for the given address.
// The SES VerifyEmailIdentity API is idempotent.
func (p *AWSProvisioner) EnsureSESIdentity(ctx context.Context, email string) error {
	_, err := p.sesClient.VerifyEmailIdentity(ctx, &ses.VerifyEmailIdentityInput{
		EmailAddress: &email,
	})
	if err != nil {
		return fmt.Errorf("verify ses identity %q: %w", email, err)
	}
	return nil
}

// EnsureSNSTopic creates a topic (idempotent) and returns its ARN.
func (p *AWSProvisioner) EnsureSNSTopic(ctx context.Context, name string) (string, error) {
	out, err := p.snsClient.CreateTopic(ctx, &sns.CreateTopicInput{
		Name: &name,
	})
	if err != nil {
		return "", fmt.Errorf("create sns topic %q: %w", name, err)
	}
	if out.TopicArn == nil {
		return "", fmt.Errorf("sns topic %q returned nil ARN", name)
	}
	return *out.TopicArn, nil
}

// isBucketAlreadyOwnedByYou checks for the S3 BucketAlreadyOwnedByYou error.
func isBucketAlreadyOwnedByYou(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "BucketAlreadyOwnedByYou")
}

func ptr[T any](v T) *T { return &v }
