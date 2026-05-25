package message

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDescribeIntegrationType_OmitsExpectedVersion verifies the discovery
// semantics fix: DescribeIntegrationType must NOT send
// AdapterDescribeRequest.expected_version. The yggdrasil-sdk-go adapter
// guard rejects describe RPCs whose expected_version does not match the
// adapter's current version, which creates a chicken-and-egg deadlock for
// manifest_sync:
//
//   - Adapter ships 1.7.1 (deployed image).
//   - integration_type manifest still pinned to 1.7.0 (DB record).
//   - /sync calls DescribeIntegrationType to discover the new version.
//   - Old behavior: sends expected_version=1.7.0, adapter rejects with
//     "version_mismatch: expected 1.7.0 but adapter is 1.7.1", sync emits
//     sync_skipped(reason=rpc_failed), operator stuck.
//   - New behavior: omits expected_version, adapter returns its current
//     describe payload (1.7.1), manifestsync.MergeSpec adopts the new
//     adapter.version, ApplyManifestVersion creates v=8 → drift auto-heals.
func TestDescribeIntegrationType_OmitsExpectedVersion(t *testing.T) {
	var capturedRequest model.AdapterDescribeRequest

	// Stub adapter that captures the request and returns a "live" describe
	// payload. Mirrors what an adapter at v1.7.1 would send when asked to
	// describe itself.
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &capturedRequest))

		// Build the inner RPC envelope shape the adapter SDK emits.
		describeResp := model.AdapterDescribeResponse{
			Provider: "github",
			Adapter: model.IntegrationAdapterSpec{
				Transport:      "http_json",
				Version:        "1.7.1", // live version, drifts forward from pinned 1.7.0
				TimeoutSeconds: 20,
				Endpoints:      model.IntegrationAdapterRoute{Describe: "/describe"},
			},
			Capabilities:     []string{"describe"},
			CredentialSchema: model.IntegrationSchemaSpec{Mode: "inline"},
			InstanceSchema:   model.IntegrationSchemaSpec{Mode: "inline"},
			ResourceTypes:    []model.IntegrationResourceType{},
			ActionCatalog: []model.IntegrationActionDefinition{
				{Name: "list_repos"},
			},
		}
		respBytes, err := json.Marshal(describeResp)
		require.NoError(t, err)

		// Wrap in the SDK HTTP envelope (content_type + base64 body).
		envelope := map[string]any{
			"content_type": "application/json",
			"body":         base64.StdEncoding.EncodeToString(respBytes),
		}
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	defer stub.Close()

	typeManifest := model.Manifest{
		ID: uuid.New(),
		Metadata: model.ManifestMetadata{
			Namespace: "global",
			Name:      "github",
		},
	}
	instanceManifest := model.Manifest{
		ID: uuid.New(),
		Metadata: model.ManifestMetadata{
			Namespace: "dakasa",
			Name:      "github-prod",
		},
	}
	typeSpec := model.IntegrationTypeManifestSpec{
		Provider: "github",
		Adapter: model.IntegrationAdapterSpec{
			Transport:      "http_json",
			Version:        "1.7.0", // PINNED — adapter actually serves 1.7.1
			TimeoutSeconds: 20,
			Endpoints:      model.IntegrationAdapterRoute{Describe: "/describe"},
		},
	}
	instanceSpec := model.IntegrationInstanceManifestSpec{
		Config: map[string]any{"base_url": stub.URL},
	}

	liveSpec, err := DescribeIntegrationType(
		context.Background(),
		nil, // amqp conn unused for http_json transport
		instanceManifest,
		typeManifest,
		instanceSpec,
		typeSpec,
	)
	require.NoError(t, err)

	// The key invariant: ExpectedVersion was NOT sent. Provider passes
	// through unchanged because it identifies which adapter is being asked.
	assert.Empty(t, capturedRequest.ExpectedVersion,
		"DescribeIntegrationType must omit expected_version so manifest_sync can discover forward/backward adapter drift without chicken-and-egg deadlock")
	assert.Equal(t, "github", strings.TrimSpace(capturedRequest.Provider))

	// And the live spec reflects the new adapter version that the syncer
	// can now merge into the integration_type manifest.
	assert.Equal(t, "1.7.1", liveSpec.Adapter.Version)
}
