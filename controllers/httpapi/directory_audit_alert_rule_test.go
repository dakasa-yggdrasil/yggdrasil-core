package httpapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// directoryAuditAlertRulePath is the rule file ADR-0019 cites as the alert
// on withheld directory outcomes, relative to this package.
var directoryAuditAlertRulePath = filepath.Join("..", "..", "monitoring", "prometheus", "yggdrasil-directory-audit-alerts.yaml")

// directoryAuditAlertExpr is the expression ADR-0019 quotes: the plain
// rate() keeps the reason label, so one alert fires per reason series.
const directoryAuditAlertExpr = "rate(yggdrasil_directory_audit_failures_total[5m]) > 0"

type prometheusRuleFile struct {
	Groups []struct {
		Name  string `yaml:"name"`
		Rules []struct {
			Alert       string            `yaml:"alert"`
			Expr        string            `yaml:"expr"`
			For         string            `yaml:"for"`
			Labels      map[string]string `yaml:"labels"`
			Annotations map[string]string `yaml:"annotations"`
		} `yaml:"rules"`
	} `yaml:"groups"`
}

// TestDirectoryAuditAlertRuleNamesTheExposedFamily pins the shipped alert
// rule to what this binary actually renders: every yggdrasil_* family the
// expression names is a TYPE line on /metrics, the expression is the one
// ADR-0019 quotes, and the description names every closed-set reason so a
// renamed or added reason cannot leave the rule text behind. Renaming the
// counter, changing the expression, or deleting the file turns this red.
func TestDirectoryAuditAlertRuleNamesTheExposedFamily(t *testing.T) {
	raw, err := os.ReadFile(directoryAuditAlertRulePath)
	if err != nil {
		t.Fatalf("read rule file: %v", err)
	}
	var file prometheusRuleFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse rule file: %v", err)
	}
	if len(file.Groups) != 1 {
		t.Fatalf("groups=%d, want exactly 1", len(file.Groups))
	}
	group := file.Groups[0]
	if group.Name != "yggdrasil-directory-audit" {
		t.Fatalf("group name=%q, want yggdrasil-directory-audit", group.Name)
	}
	if len(group.Rules) != 1 {
		t.Fatalf("rules=%d, want exactly 1", len(group.Rules))
	}
	rule := group.Rules[0]
	if rule.Alert != "YggdrasilDirectoryAuditWithheld" {
		t.Fatalf("alert=%q, want YggdrasilDirectoryAuditWithheld", rule.Alert)
	}
	if got := strings.TrimSpace(rule.Expr); got != directoryAuditAlertExpr {
		t.Fatalf("expr=%q, want %q (the expression ADR-0019 quotes)", got, directoryAuditAlertExpr)
	}
	if rule.For != "5m" {
		t.Fatalf("for=%q, want 5m (ADR-0019 says the rule pages after five minutes)", rule.For)
	}
	if rule.Labels["severity"] != "page" {
		t.Fatalf("labels.severity=%q, want page", rule.Labels["severity"])
	}
	if rule.Labels["service"] != "yggdrasil-core" {
		t.Fatalf("labels.service=%q, want yggdrasil-core", rule.Labels["service"])
	}
	for _, key := range []string{"summary", "description", "runbook"} {
		if strings.TrimSpace(rule.Annotations[key]) == "" {
			t.Fatalf("annotations.%s is empty", key)
		}
	}

	// The families the expression names must be the ones the binary renders.
	server := &Server{logger: zap.NewNop()}
	recorder := httptest.NewRecorder()
	server.handleMetrics(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	exposition := recorder.Body.String()
	families := regexp.MustCompile(`yggdrasil_[a-z0-9_]+`).FindAllString(rule.Expr, -1)
	if len(families) == 0 {
		t.Fatalf("expr %q names no yggdrasil_* family", rule.Expr)
	}
	for _, family := range families {
		if !strings.Contains(exposition, "# TYPE "+family+" counter\n") {
			t.Fatalf("expr names %q but /metrics does not render it as a counter:\n%s", family, exposition)
		}
	}

	// The description explains every reason the counter can carry, and no
	// reason outside the closed set.
	for reason := range metrics.DirectoryAuditFailuresSnapshot() {
		if !strings.Contains(rule.Annotations["description"], reason+":") {
			t.Fatalf("description does not explain reason %q:\n%s", reason, rule.Annotations["description"])
		}
	}
	for _, reason := range regexp.MustCompile(`\b(store_[a-z_]+|insert_[a-z_]+)\b`).FindAllString(rule.Annotations["description"], -1) {
		if _, known := metrics.DirectoryAuditFailuresSnapshot()[reason]; !known {
			t.Fatalf("description names %q, which is not a closed-set reason", reason)
		}
	}

	// The runbook is the ADR that owns the contract, and it exists.
	runbook := rule.Annotations["runbook"]
	const adr = "docs/adr/0019-scope-directory-machine-principals-to-exact-collaborator-read-routes.md"
	if !strings.HasSuffix(runbook, adr) {
		t.Fatalf("runbook=%q, want a link ending in %s", runbook, adr)
	}
	if _, err := os.Stat(filepath.Join("..", "..", adr)); err != nil {
		t.Fatalf("runbook target %s: %v", adr, err)
	}
}
