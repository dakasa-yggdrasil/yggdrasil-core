package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacityfixturetest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func capacityMutationTestPrincipal(t *testing.T, token, instance string) []capacityMutationPrincipal {
	t.Helper()
	config := []capacityMutationPrincipalConfig{{PrincipalID: "fixture-adapter", Status: "active", ExpiresAt: time.Now().Add(time.Hour), RotationID: "fixture-rotation", TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(token))), IntegrationInstanceID: instance, Capabilities: []string{"ensure_server", "destroy_server"}}}
	raw, _ := json.Marshal(config)
	t.Setenv(capacityMutationPrincipalsEnv, string(raw))
	principals, err := loadCapacityMutationPrincipals(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return principals
}

func TestCapacityMutationCredentialScope(t *testing.T) {
	token := "fixture-private-adapter-token"
	instance := uuid.NewString()
	server := &Server{capacityMutationPrincipals: capacityMutationTestPrincipal(t, token, instance)}
	var fallthroughCalls int
	handler := server.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fallthroughCalls++; w.WriteHeader(204) }))
	for _, test := range []struct {
		method, path, credential string
		status                   int
	}{
		{"POST", capacityMutationBasePath + "/redeem", "", 401},
		{"POST", capacityMutationBasePath + "/redeem", "human-session-token", 401},
		{"GET", "/healthz", token, 403},
		{"POST", "/api/v1/workflow-runs", token, 403},
		{"POST", "/api/v1/events", token, 403},
		{"POST", capacityMutationBasePath + "/redeem?url=https://caller.example", token, 403},
		{"GET", capacityMutationBasePath + "/../events", token, 403},
	} {
		request := httptest.NewRequest(test.method, test.path, strings.NewReader("{}"))
		if test.credential != "" {
			request.Header.Set("Authorization", "Bearer "+test.credential)
		}
		request.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: "human-cookie"})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status || strings.Contains(response.Body.String(), token) {
			t.Fatalf("%s %s: %d %s", test.method, test.path, response.Code, response.Body.String())
		}
	}
	if fallthroughCalls != 0 {
		t.Fatal("adapter credential reached another credential surface")
	}
	server.capacityMutationPrincipals[0].base.status = "revoked"
	request := httptest.NewRequest("GET", "/healthz", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 401 {
		t.Fatal(response.Code)
	}
	server.capacityMutationPrincipals[0].base.status = "active"
	request = httptest.NewRequest("GET", "/healthz", nil)
	request.Header.Add("Authorization", "Bearer "+token)
	request.Header.Add("Authorization", "Bearer another")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 401 {
		t.Fatal("ambiguous credential fell through", response.Code)
	}
}

func TestCapacityMutationInventoryFailsClosed(t *testing.T) {
	token := "fixture-private-adapter-token"
	instance := uuid.NewString()
	capacityMutationTestPrincipal(t, token, instance)
	for _, raw := range []string{"", "null", "[]", "{}", `[{"principal_id":"unknown","unknown":true}]`} {
		t.Setenv(capacityMutationPrincipalsEnv, raw)
		if _, err := loadCapacityMutationPrincipals(nil, nil, nil); err == nil {
			t.Fatalf("invalid inventory accepted: %q", raw)
		}
	}
	p := capacityMutationTestPrincipal(t, token, instance)
	if _, err := loadCapacityMutationPrincipals([]workflowMachinePrincipal{{TokenSHA256: p[0].base.tokenSHA256}}, nil, nil); err == nil {
		t.Fatal("cross-scope credential collision")
	}
	if _, err := loadCapacityMutationPrincipals(nil, []eventPublisherPrincipal{{TokenSHA256: p[0].base.tokenSHA256}}, nil); err == nil {
		t.Fatal("event collision")
	}
	if _, err := loadCapacityMutationPrincipals(nil, nil, []directoryMachinePrincipal{{TokenSHA256: p[0].base.tokenSHA256}}); err == nil {
		t.Fatal("directory collision")
	}
	config := []capacityMutationPrincipalConfig{{PrincipalID: "fixture", Status: "active", ExpiresAt: time.Now().Add(time.Hour), RotationID: "r", TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(token))), IntegrationInstanceID: instance, Capabilities: []string{"ensure_*"}}}
	raw, _ := json.Marshal(config)
	t.Setenv(capacityMutationPrincipalsEnv, string(raw))
	if _, err := loadCapacityMutationPrincipals(nil, nil, nil); err == nil {
		t.Fatal("wildcard capability")
	}
}

func TestCapacityMutationOriginalAWSOperationIsExact(t *testing.T) {
	token, instance := "fixture-private-adapter-token", uuid.NewString()
	load := func(capabilities []string) ([]capacityMutationPrincipal, error) {
		config := []capacityMutationPrincipalConfig{{PrincipalID: "fixture-adapter", Status: "active", ExpiresAt: time.Now().Add(time.Hour), RotationID: "fixture-rotation", TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(token))), IntegrationInstanceID: instance, Capabilities: capabilities}}
		raw, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv(capacityMutationPrincipalsEnv, string(raw))
		return loadCapacityMutationPrincipals(nil, nil, nil)
	}
	for _, capabilities := range [][]string{{"ensure_ec2_instance", "terminate_ec2_instance"}, {"ensure_server", "destroy_server"}} {
		principals, err := load(capabilities)
		if err != nil || len(principals) != 1 || principals[0].instanceID != instance || len(principals[0].capabilities) != 2 {
			t.Fatal("exact original provider pair refused or instance scope changed", err)
		}
		for _, name := range capabilities {
			if !principals[0].capabilities[name] {
				t.Fatal("exact original capability missing", name)
			}
		}
		if len(capabilities) == 2 && capabilities[1] == "terminate_ec2_instance" && (principals[0].capabilities["destroy_server"] || principals[0].capabilities["terminate_rds_instance"]) {
			t.Fatal("AWS operation widened provider capability scope")
		}
	}
	for _, capability := range []string{"terminate_*", "terminate_ec2_instances", "terminate_ec2_instance_extra", "terminate_rds_instance", "Terminate_ec2_instance", " terminate_ec2_instance", "terminate_ec2_instance ", "terminate_ec2_instance/", ""} {
		if _, err := load([]string{"ensure_ec2_instance", capability}); err == nil {
			t.Fatal("non-exact original AWS operation accepted", capability)
		}
	}
	if _, err := load([]string{"terminate_ec2_instance", "terminate_ec2_instance"}); err == nil {
		t.Fatal("duplicate exact original operation accepted")
	}
}

func TestCapacityMutationExactJSON(t *testing.T) {
	for _, body := range []string{`{"grant_id":"x","unexpected":true}`, `{} {}`, strings.Repeat(" ", 32769) + `{}`} {
		r := httptest.NewRequest("POST", capacityMutationBasePath+"/redeem", strings.NewReader(body))
		var value model.CapacityMutationRedeemRequest
		if err := decodeCapacityMutationJSON(httptest.NewRecorder(), r, &value); err == nil {
			t.Fatal("unbounded/ambiguous callback accepted")
		}
	}
}

// This case runs its unchanged real HTTP authentication and callback assertions
// inside a clean source-identified Linux binary. A go test binary lacks native
// VCS build identity and cannot legitimately issue or redeem an original
// Guest grant. The owner provides a private isolated PG17 and the exact binary.
func TestCapacityMutationHTTPPostgres(t *testing.T) {
	if os.Getenv("DB_URL") == "" && os.Getenv("REQUIRE_CAPACITY_POSTGRES") != "true" {
		t.Skip("PostgreSQL callback protocol runs in CI")
	}
	pg, goBinary := os.Getenv("CAPACITY_TEST_PG_BIN"), os.Getenv("CAPACITY_TEST_GO")
	if !filepath.IsAbs(pg) || !filepath.IsAbs(goBinary) {
		t.Fatal("PostgreSQL 17 and Go paths required for the isolated qualification owner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	rootBytes, err := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatal("test source root unavailable", err)
	}
	root := strings.TrimSpace(string(rootBytes))
	if err = exec.CommandContext(ctx, "git", "-C", root, "diff", "--quiet", "HEAD", "--").Run(); err != nil {
		t.Fatal("tracked test source differs from its clean qualification checkout", err)
	}
	headBytes, err := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal("test source revision unavailable", err)
	}
	head := strings.TrimSpace(string(headBytes))
	tmp, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		t.Fatal("temporary owner root unavailable", err)
	}
	if registry := os.Getenv("CAPACITY_TEST_OWNER_ROOT"); registry != "" {
		info, statErr := os.Lstat(registry)
		resolved, resolveErr := filepath.EvalSymlinks(registry)
		if statErr != nil || resolveErr != nil || resolved != registry || filepath.Dir(registry) != tmp || !strings.HasPrefix(filepath.Base(registry), "dk-reg-") || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatal("private fixture owner registry required")
		}
		tmp = registry
	}
	ownerDir, err := os.MkdirTemp(tmp, "dk-own-")
	if err != nil {
		t.Fatal("temporary owner directory unavailable", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			if err := os.RemoveAll(ownerDir); err != nil {
				t.Error(err)
			}
		}
	}()
	clone := filepath.Join(ownerDir, "source")
	if out, err := exec.CommandContext(ctx, "git", "clone", "--quiet", "--no-hardlinks", "--", root, clone).CombinedOutput(); err != nil {
		t.Fatalf("cannot prepare clean qualification checkout: %v %q", err, out)
	}
	cloneHead, err := exec.CommandContext(ctx, "git", "-C", clone, "rev-parse", "HEAD").Output()
	if err != nil || strings.TrimSpace(string(cloneHead)) != head {
		t.Fatal("qualification checkout differs from tested revision", err)
	}
	if os.Getenv("GOWORK") != "off" {
		t.Fatal("GOWORK=off required for the source input comparison")
	}
	compare := exec.CommandContext(ctx, "python3", filepath.Join(clone, "scripts/ci/capacity_fixture_source_equivalence.py"), "--source", root, "--clone", clone, "--go", goBinary, "--package", "./controllers/httpapi")
	if err = compare.Run(); err != nil {
		t.Fatal("test compiler inputs differ from the clean source checkout", err)
	}
	command := exec.Command("python3", filepath.Join(clone, "scripts/ci/capacity_pg17_owned_fixture.py"), "--run-grants")
	command.Dir = clone
	// Pass only toolchain configuration to the owner, never CI credentials or
	// the original database address. It creates and verifies its own socket DB.
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "GOCACHE", "GOMODCACHE", "GOPATH", "GOTOOLCHAIN", "GOPROXY", "GOSUMDB", "CGO_ENABLED", "CC", "CXX", "SDKROOT"} {
		if value, ok := os.LookupEnv(key); ok {
			command.Env = append(command.Env, key+"="+value)
		}
	}
	command.Env = append(command.Env, "CAPACITY_TEST_PG_BIN="+pg, "CAPACITY_TEST_GO="+goBinary, "CAPACITY_TEST_PARENT_DIR="+ownerDir)
	if registry := os.Getenv("CAPACITY_TEST_OWNER_ROOT"); registry != "" {
		command.Env = append(command.Env, "CAPACITY_TEST_OWNER_ROOT="+registry)
	}
	stdout, confirmed, err := capacityfixturetest.Run(ctx, command, ownerDir, 45*time.Second)
	cleanup = confirmed
	if err != nil {
		t.Fatalf("source-owned HTTP scenario failed (cleanup confirmed=%t; owner directory=%s): %v", confirmed, ownerDir, err)
	}
	var result struct {
		Schema       string `json:"schema"`
		CoreSource   string `json:"core_source"`
		Provider     string `json:"provider"`
		HTTP         bool   `json:"synthetic_http_callbacks_passed"`
		ProviderSend bool   `json:"provider_send_attempted"`
		Native       bool   `json:"native_or_production_qualified"`
	}
	if err = json.Unmarshal([]byte(stdout), &result); err != nil || result.Schema != "ci_original_grant_concurrency_result_v1" || result.CoreSource != head || result.Provider != "native-qemu" || !result.HTTP || result.ProviderSend || result.Native {
		t.Fatal("real source-owned HTTP scenario did not complete in the required isolated scope", err)
	}
}
