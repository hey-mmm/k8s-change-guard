package guard

// Tests for the Go port of change_guard.engine. The frozen 151-case Python
// oracle lives in migration_oracle_test.go; these tests cover the report
// schema, security fail-closed behavior, redaction, and malformed inputs that
// the decision-only oracle cannot pin down.

import (
	"encoding/json"
	"math"
	"sort"
	"strings"
	"testing"
)

const engTestDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func engTestClone(v M) M {
	b, err := CanonicalJSON(v)
	if err != nil {
		panic(err)
	}
	var out M
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return out
}

// engTestFixture returns a complete, healthy release evaluation (PASS).
func engTestFixture() ([]M, []M, M, M, M, M) {
	deployment := func(version string) M {
		return M{
			"apiVersion": "apps/v1",
			"kind":       "Deployment",
			"metadata": M{
				"name":      "demo",
				"namespace": "demo",
			},
			"spec": M{
				"replicas": float64(1),
				"strategy": M{
					"type": "RollingUpdate",
					"rollingUpdate": M{
						"maxSurge":       float64(1),
						"maxUnavailable": float64(0),
					},
				},
				"selector": M{
					"matchLabels": M{"app": "demo"},
				},
				"template": M{
					"metadata": M{"labels": M{"app": "demo"}},
					"spec": M{
						"automountServiceAccountToken": false,
						"securityContext": M{
							"runAsNonRoot": true,
							"runAsUser":    float64(10001),
							"seccompProfile": M{
								"type": "RuntimeDefault",
							},
						},
						"containers": []any{
							M{
								"name":  "demo-service",
								"image": "ghcr.io/hey-mmm/observability-demo@" + engTestDigest,
								"env": []any{
									M{"name": "APP_VERSION", "value": version},
									M{"name": "DEMO_ERROR_RATE", "value": "0"},
									M{"name": "DEMO_LATENCY_MS", "value": "0"},
									M{"name": "DEMO_STARTUP_FAIL", "value": "false"},
								},
								"readinessProbe": M{
									"httpGet":             M{"path": "/readyz", "port": "http"},
									"initialDelaySeconds": float64(2),
									"periodSeconds":       float64(5),
									"timeoutSeconds":      float64(2),
									"failureThreshold":    float64(3),
								},
								"livenessProbe": M{
									"httpGet":             M{"path": "/healthz", "port": "http"},
									"initialDelaySeconds": float64(5),
									"periodSeconds":       float64(10),
									"timeoutSeconds":      float64(2),
									"failureThreshold":    float64(3),
								},
								"startupProbe": M{
									"httpGet":          M{"path": "/healthz", "port": "http"},
									"periodSeconds":    float64(2),
									"timeoutSeconds":   float64(2),
									"failureThreshold": float64(30),
								},
								"resources": M{
									"requests": M{"cpu": "50m", "memory": "64Mi"},
									"limits":   M{"cpu": "250m", "memory": "192Mi"},
								},
								"securityContext": M{
									"allowPrivilegeEscalation": false,
									"privileged":               false,
									"readOnlyRootFilesystem":   true,
									"runAsNonRoot":             true,
									"runAsUser":                float64(10001),
									"capabilities": M{
										"drop": []any{"ALL"},
									},
								},
							},
						},
					},
				},
			},
		}
	}
	service := M{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   M{"name": "demo", "namespace": "demo"},
		"spec": M{
			"type":     "ClusterIP",
			"selector": M{"app": "demo"},
			"ports": []any{
				M{"name": "http", "port": float64(8080), "targetPort": "http", "protocol": "TCP"},
			},
		},
	}
	old := []M{deployment("0.2.0"), engTestClone(service)}
	newer := []M{deployment("0.2.0"), engTestClone(service)}
	now := float64(1800000000)
	evidence := M{
		"collected_at": now - 10,
		"errors":       []any{},
		"nodes":        []any{},
		"deployment": M{
			"namespace":          "demo",
			"name":               "demo",
			"replicas":           float64(1),
			"ready_replicas":     float64(1),
			"available_replicas": float64(1),
			"containers": []any{
				M{
					"name": "demo-service",
					"resources": M{
						"requests": M{"cpu": "50m", "memory": "64Mi"},
						"limits":   M{"cpu": "250m", "memory": "192Mi"},
					},
				},
			},
		},
		"pods": []any{},
		"metrics": M{
			"memory_working_set_bytes": float64(104857600),
			"request_rate":             float64(1),
			"error_ratio":              float64(0),
			"p95_seconds":              float64(0.1),
			"up":                       float64(1),
			"series_presence": M{
				"up":             true,
				"memory":         true,
				"requests_total": true,
				"latency_bucket": true,
			},
			"alerts": []any{},
			"source_timestamps": M{
				"memory_working_set_bytes": now - 5,
				"request_rate":             now - 5,
				"error_ratio":              now - 5,
				"p95_seconds":              now - 5,
				"up":                       now - 5,
			},
		},
		"capacity": M{
			"available_cpu_millicores":   float64(4000),
			"available_memory_bytes":     float64(4294967296),
			"workers_ready":              float64(1),
			"allocatable_cpu_millicores": float64(4000),
			"allocatable_memory_bytes":   float64(4294967296),
		},
	}
	config := M{
		"namespace":                "demo",
		"deployment":               "demo",
		"allowed_image_repository": "ghcr.io/hey-mmm/observability-demo",
		"require_digest":           true,
		"evidence_ttl_seconds":     float64(300),
		"ai_required":              true,
	}
	context := M{"evaluated_at": now, "pr_number": float64(42)}
	ai := M{
		"status":           "ok",
		"model":            "deepseek-chat",
		"summary":          "no issues",
		"additional_risks": []any{},
		"citations":        []any{},
	}
	return old, newer, evidence, config, context, ai
}

func engTestEvaluate(t *testing.T, old, new []M, evidence, config, context, ai M) M {
	t.Helper()
	result := Evaluate(old, new, evidence, config, context, ai)
	if _, err := CanonicalJSON(result); err != nil {
		t.Fatalf("Evaluate returned non-finite JSON: %v", err)
	}
	return result
}

func engTestRules(result M) []string {
	seen := map[string]bool{}
	for _, raw := range Arr(result["findings"]) {
		rule := S(Obj(raw), "rule_id")
		if rule != "" {
			seen[rule] = true
		}
	}
	out := make([]string, 0, len(seen))
	for rule := range seen {
		out = append(out, rule)
	}
	sort.Strings(out)
	return out
}

func engTestHasRule(result M, rule string) bool {
	for _, candidate := range engTestRules(result) {
		if candidate == rule {
			return true
		}
	}
	return false
}

func engTestFinding(result M, rule string) M {
	for _, raw := range Arr(result["findings"]) {
		finding := Obj(raw)
		if S(finding, "rule_id") == rule {
			return finding
		}
	}
	return nil
}

func engTestDeployment(resources []M) M {
	for _, resource := range resources {
		if S(resource, "kind") == "Deployment" {
			return resource
		}
	}
	return nil
}

func engTestService(resources []M) M {
	for _, resource := range resources {
		if S(resource, "kind") == "Service" {
			return resource
		}
	}
	return nil
}

func engTestContainer(resources []M) M {
	deployment := engTestDeployment(resources)
	spec := Obj(Get(deployment, "spec", "template", "spec"))
	containers := Arr(spec["containers"])
	if len(containers) == 0 {
		return nil
	}
	return Obj(containers[0])
}

func engTestPodSpec(resources []M) M {
	deployment := engTestDeployment(resources)
	return Obj(Get(deployment, "spec", "template", "spec"))
}

func engTestAllRules(result M) string {
	return strings.Join(engTestRules(result), ",")
}

// TestEngineHealthyReleasePinsSchema asserts the complete public report shape
// and the stable policy metadata for a passing release.
func TestEngineHealthyReleasePinsSchema(t *testing.T) {
	old, newer, evidence, config, context, ai := engTestFixture()
	result := engTestEvaluate(t, old, newer, evidence, config, context, ai)
	if decision := S(result, "decision"); decision != engDecisionPass {
		t.Fatalf("decision=%s want PASS; rules=%s; findings=%v", decision, engTestAllRules(result), result["findings"])
	}
	if len(Arr(result["findings"])) != 0 {
		t.Fatalf("healthy release has findings: %v", result["findings"])
	}
	if got := S(result, "rule_version"); got != RuleVersion {
		t.Fatalf("rule_version=%q want %q", got, RuleVersion)
	}
	if got := N(result, "evaluated_at"); got != 1800000000 {
		t.Fatalf("evaluated_at=%v", got)
	}
	// expires_at is anchored to the oldest evidence sample (collected_at is
	// now-10) plus the configured TTL.
	if got := N(result, "expires_at"); got != 1800000290 {
		t.Fatalf("expires_at=%v want 1800000290", got)
	}
	if S(result, "audit", "schema_version") != engSchemaVersion {
		t.Fatalf("schema_version=%v", Get(result, "audit", "schema_version"))
	}
	for _, key := range []string{"decision", "findings", "changes", "context", "render_digest", "old_render_digest", "evaluated_at", "expires_at", "rule_version", "audit"} {
		if _, present := result[key]; !present {
			t.Fatalf("result missing top-level key %q", key)
		}
	}
	for _, key := range []string{"schema_version", "rule_version", "evaluated_at", "checks", "metrics", "capacity", "ai", "changes_count", "pod_template_changed", "render_digest", "old_render_digest"} {
		if _, present := Obj(result["audit"])[key]; !present {
			t.Fatalf("audit missing key %q", key)
		}
	}
	if len(Arr(result["changes"])) != 0 {
		t.Fatalf("identical resources should have no changes: %v", result["changes"])
	}
	if S(result, "render_digest") != S(result, "old_render_digest") {
		t.Fatalf("digests differ for identical renders")
	}
	if S(result, "context", "namespace") != "demo" || S(result, "context", "deployment") != "demo" {
		t.Fatalf("internal context missing: %v", result["context"])
	}
	if B(result, "context", "pod_template_changed") {
		t.Fatalf("pod_template_changed should be false for identical render")
	}
	if got := N(result, "audit", "metrics", "source_timestamps", "memory_working_set_bytes"); got != 1799999995 {
		t.Fatalf("metrics source timestamp=%v", got)
	}
	if S(result, "audit", "capacity", "source") != "evidence.capacity" {
		t.Fatalf("capacity source=%v", Get(result, "audit", "capacity", "source"))
	}
	if got := N(result, "audit", "metrics", "firing_alerts"); got != 0 {
		t.Fatalf("firing_alerts=%v", got)
	}
}

// TestEngineRenderDigestIsOrderIndependent guards the order-independent digest
// used to bind approvals and reports.
func TestEngineRenderDigestIsOrderIndependent(t *testing.T) {
	old, newer, evidence, config, context, ai := engTestFixture()
	forward := engTestEvaluate(t, old, newer, evidence, config, context, ai)
	reversed := make([]M, len(newer))
	for i := range newer {
		reversed[len(newer)-1-i] = newer[i]
	}
	backward := engTestEvaluate(t, old, reversed, evidence, config, context, ai)
	if S(forward, "render_digest") != S(backward, "render_digest") {
		t.Fatalf("render digest depends on resource order")
	}
	if S(forward, "render_digest") != S(forward, "audit", "render_digest") {
		t.Fatalf("audit render_digest mismatch")
	}
	if len(S(forward, "render_digest")) != 64 {
		t.Fatalf("render digest is not sha256 hex: %q", S(forward, "render_digest"))
	}
}

// TestEngineInvalidInputFailsClosed checks the Go-specific contract: malformed
// input yields a non-retryable ERROR report rather than a panic or PASS.
func TestEngineInvalidInputFailsClosed(t *testing.T) {
	cases := []struct {
		name     string
		old, new []M
		config   M
		context  M
	}{
		{"missing-kind", []M{{"metadata": M{"name": "demo"}}}, []M{engTestDeployment(engTestFixtureNew())}, nil, nil},
		{"missing-name", []M{{"kind": "Deployment", "metadata": M{}}}, nil, nil, nil},
		{"list-without-items", []M{{"kind": "List"}}, nil, nil, nil},
		{"invalid-namespace", nil, nil, M{"namespace": "Bad Namespace"}, nil},
		{"invalid-deployment", nil, nil, M{"deployment": "-bad"}, nil},
		{"invalid-ttl", nil, nil, M{"evidence_ttl_seconds": "300"}, nil},
		{"nonpositive-ttl", nil, nil, M{"evidence_ttl_seconds": float64(0)}, nil},
		{"invalid-evaluated-at", nil, nil, nil, M{"evaluated_at": "not-a-time"}},
		{"invalid-allowed-repo", nil, nil, M{"allowed_image_repository": "bad repo"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			newer := tc.new
			if newer == nil {
				newer = []M{engTestDeployment(engTestFixtureNew())}
			}
			old := tc.old
			if old == nil {
				old = []M{}
			}
			context := tc.context
			if context == nil {
				_, _, _, _, validContext, _ := engTestFixture()
				context = validContext
			}
			result := engTestEvaluate(t, old, newer, M{}, tc.config, context, M{})
			if S(result, "decision") != engDecisionError {
				t.Fatalf("decision=%s want ERROR", S(result, "decision"))
			}
			if !engTestHasRule(result, engInvalidInputRule) {
				t.Fatalf("missing %s rule: %v", engInvalidInputRule, result["findings"])
			}
			if got := S(engTestFinding(result, engInvalidInputRule), "field"); got != "input" {
				t.Fatalf("invalid input finding field=%q want input", got)
			}
		})
	}
}

func engTestFixtureNew() []M {
	_, newer, _, _, _, _ := engTestFixture()
	return newer
}

// TestEngineMalformedTypesNeverPanic exercises values Python can reject safely
// but that would panic on unchecked Go interface equality. Every case must
// return a decision; shape-invalid policy fields must not become PASS.
func TestEngineMalformedTypesNeverPanic(t *testing.T) {
	type malformedCase struct {
		wantRule string
		mutate   func(newer []M, evidence, ai M)
	}
	cases := map[string]malformedCase{
		"service-type-list": {wantRule: "SERVICE_EXPOSURE", mutate: func(newer []M, _ M, _ M) {
			engTestService(newer)["spec"].(M)["type"] = []any{"ClusterIP"}
		}},
		"service-type-map": {wantRule: "SERVICE_EXPOSURE", mutate: func(newer []M, _ M, _ M) {
			engTestService(newer)["spec"].(M)["type"] = M{"x": "y"}
		}},
		"strategy-type-list": {wantRule: "ROLLOUT_STRATEGY_INVALID", mutate: func(newer []M, _ M, _ M) {
			engTestDeployment(newer)["spec"].(M)["strategy"].(M)["type"] = []any{"RollingUpdate"}
		}},
		"strategy-type-null": {wantRule: "ROLLOUT_STRATEGY_INVALID", mutate: func(newer []M, _ M, _ M) {
			engTestDeployment(newer)["spec"].(M)["strategy"].(M)["type"] = nil
		}},
		"probe-scheme-map": {wantRule: "PROBE_INVALID", mutate: func(newer []M, _ M, _ M) {
			engTestContainer(newer)["readinessProbe"].(M)["httpGet"].(M)["scheme"] = M{"x": "y"}
		}},
		"seccomp-type-list": {wantRule: "SECCOMP_PROFILE_MISSING", mutate: func(newer []M, _ M, _ M) {
			engTestPodSpec(newer)["securityContext"].(M)["seccompProfile"] = M{"type": []any{"Unconfined"}}
		}},
		"ai-status-map": {wantRule: "AI_INVALID_RESULT", mutate: func(_ []M, _ M, ai M) {
			ai["status"] = M{"unexpected": true}
		}},
		"ai-status-list": {wantRule: "AI_INVALID_RESULT", mutate: func(_ []M, _ M, ai M) {
			ai["status"] = []any{"ok"}
		}},
		"alert-severity-map": {mutate: func(_ []M, evidence, _ M) {
			evidence["metrics"].(M)["alerts"] = []any{
				M{"name": "A", "state": "firing", "labels": M{"severity": M{"x": "y"}}},
			}
		}},
		"phase-map": {mutate: func(_ []M, evidence, _ M) {
			evidence["nodes"] = []any{M{"name": "w1", "ready": true}}
			evidence["pods"] = []any{M{"node": "w1", "phase": M{"x": "y"},
				"spec": M{"containers": []any{M{"resources": M{"requests": M{"cpu": "1", "memory": "1Gi"}}}}}}}
		}},
		"condition-type-map": {mutate: func(_ []M, evidence, _ M) {
			evidence["nodes"] = []any{M{"name": "w1", "status": M{"conditions": []any{
				M{"type": M{"x": "y"}, "status": "True"},
			}}}}
		}},
		"taint-effect-map": {mutate: func(_ []M, evidence, _ M) {
			evidence["nodes"] = []any{M{"name": "w1", "ready": true,
				"taints": []any{M{"effect": M{"x": "y"}}}}}
		}},
	}
	old, newer, evidence, config, context, ai := engTestFixture()
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			o := []M{engTestClone(old[0]), engTestClone(old[1])}
			n := []M{engTestClone(newer[0]), engTestClone(newer[1])}
			e := engTestClone(evidence)
			a := engTestClone(ai)
			tc.mutate(n, e, a)
			result := engTestEvaluate(t, o, n, e, engTestClone(config), engTestClone(context), a)
			if S(result, "decision") == "" {
				t.Fatalf("no decision")
			}
			if tc.wantRule != "" && !engTestHasRule(result, tc.wantRule) {
				t.Fatalf("missing rule %s for malformed input; findings=%v", tc.wantRule, result["findings"])
			}
		})
	}
}

// TestEngineQuantityAndTimestampParsing covers the numeric parsers that gate
// capacity and TTL decisions.
func TestEngineQuantityAndTimestampParsing(t *testing.T) {
	quantities := []struct {
		value any
		want  float64
		ok    bool
	}{
		{"50m", 0.05, true},
		{"1", 1, true},
		{"1.5Gi", 1610612736, true},
		{"500Ki", 512000, true},
		{"1e3", 1000, true},
		{"-1", -1, true},
		{"bad", 0, false},
		{"1MiB", 0, false},
		{"NaN", 0, false},
		{"Inf", 0, false},
		{true, 0, false},
		{float64(math.NaN()), 0, false},
	}
	for _, tc := range quantities {
		if got, ok := engParseQuantity(tc.value); got != tc.want || ok != tc.ok {
			t.Fatalf("engParseQuantity(%#v)=%v,%v want %v,%v", tc.value, got, ok, tc.want, tc.ok)
		}
	}
	if got, ok := engCPUMillicores("50m"); !ok || got != 50 {
		t.Fatalf("cpu 50m=%v,%v", got, ok)
	}
	if got, ok := engMemoryBytes("64Mi"); !ok || got != 64*1024*1024 {
		t.Fatalf("memory 64Mi=%v,%v", got, ok)
	}
	timestamps := []struct {
		value any
		want  float64
		ok    bool
	}{
		{float64(1800000000), 1800000000, true},
		{"1800000000", 1800000000, true},
		{"1800000000000", 1800000000, true},
		{"2027-01-15T08:00:00Z", 1800000000, true},
		{"2027-01-15T08:00:00", 1800000000, true},
		{true, 0, false},
		{"NaN", 0, false},
		{"not-a-time", 0, false},
	}
	for _, tc := range timestamps {
		if got, ok := engTimestamp(tc.value); got != tc.want || ok != tc.ok {
			t.Fatalf("engTimestamp(%#v)=%v,%v want %v,%v", tc.value, got, ok, tc.want, tc.ok)
		}
	}
}

// TestEngineStrategySurge pins the rollout surge model, including explicit
// null/invalid strategy types which must not fall back to the default.
func TestEngineStrategySurge(t *testing.T) {
	deployment := func(strategy any) M {
		spec := M{"replicas": float64(4)}
		if strategy != nil {
			spec["strategy"] = strategy
		}
		return M{"spec": spec}
	}
	cases := []struct {
		name     string
		strategy any
		want     int64
		valid    bool
	}{
		{"missing", nil, 1, true},
		{"recreate", M{"type": "Recreate"}, 0, true},
		{"rolling-default", M{"type": "RollingUpdate"}, 1, true},
		{"explicit-percent", M{"type": "RollingUpdate", "rollingUpdate": M{"maxSurge": "50%"}}, 2, true},
		{"explicit-zero", M{"type": "RollingUpdate", "rollingUpdate": M{"maxSurge": float64(0)}}, 0, true},
		{"explicit-int", M{"type": "RollingUpdate", "rollingUpdate": M{"maxSurge": "3"}}, 3, true},
		{"absolute-negative", M{"type": "RollingUpdate", "rollingUpdate": M{"maxSurge": "-1"}}, 0, false},
		{"bad-percent", M{"type": "RollingUpdate", "rollingUpdate": M{"maxSurge": "abc%"}}, 0, false},
		{"bool", M{"type": "RollingUpdate", "rollingUpdate": M{"maxSurge": true}}, 0, false},
		{"null-type", M{"type": nil}, 0, false},
		{"empty-type", M{"type": ""}, 0, false},
		{"unknown-type", M{"type": "BlueGreen"}, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, valid := engStrategySurge(deployment(tc.strategy), 4)
			if got != tc.want || valid != tc.valid {
				t.Fatalf("surge=%d,%v want %d,%v", got, valid, tc.want, tc.valid)
			}
		})
	}
}

// TestEngineSensitiveDiffRedaction ensures diff/audit artifacts never echo
// secret values or arbitrary env literals.
func TestEngineSensitiveDiffRedaction(t *testing.T) {
	old, newer, evidence, config, context, ai := engTestFixture()
	oldContainer := engTestContainer(old)
	newContainer := engTestContainer(newer)
	oldContainer["env"] = []any{M{"name": "TOKEN", "value": "old-secret-value"}}
	newContainer["env"] = []any{M{"name": "TOKEN", "value": "new-secret-value"}}
	newContainer["securityContext"].(M)["capabilities"] = M{"drop": []any{"ALL"}}
	newContainer["resources"].(M)["limits"] = M{"cpu": "500m", "memory": "256Mi"}
	result := engTestEvaluate(t, old, newer, evidence, config, context, ai)
	encoded, err := CanonicalJSON(result["changes"])
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, "old-secret-value") || strings.Contains(text, "new-secret-value") {
		t.Fatalf("diff leaked env literal: %s", text)
	}
	if !strings.Contains(text, "<redacted>") {
		t.Fatalf("diff did not redact env literal: %s", text)
	}
	// A sensitive context key is redacted in the returned context.
	context["client_secret"] = "super-secret"
	result = engTestEvaluate(t, old, newer, evidence, config, context, ai)
	if S(result, "context", "client_secret") != "<redacted>" {
		t.Fatalf("context secret not redacted: %v", result["context"])
	}
}

// TestEngineDecisionPriorityAndAICap verifies BLOCK > ERROR > REVIEW > PASS and
// that model output can never weaken a hard block.
func TestEngineDecisionPriorityAndAICap(t *testing.T) {
	old, newer, evidence, config, context, ai := engTestFixture()
	// Hard block: privileged container.
	engTestContainer(newer)["securityContext"].(M)["privileged"] = true
	ai = M{"status": "ok", "summary": "looks safe", "additional_risks": []any{}, "citations": []any{}}
	result := engTestEvaluate(t, old, newer, evidence, config, context, ai)
	if S(result, "decision") != engDecisionBlock {
		t.Fatalf("decision=%s want BLOCK", S(result, "decision"))
	}
	if !engTestHasRule(result, "PRIVILEGED_CONTAINER") {
		t.Fatalf("missing PRIVILEGED_CONTAINER: %v", result["findings"])
	}
	// AI failure must produce ERROR, not PASS, on an otherwise clean release.
	old, newer, evidence, config, context, _ = engTestFixture()
	ai = M{"status": "error", "error": "timeout"}
	result = engTestEvaluate(t, old, newer, evidence, config, context, ai)
	if S(result, "decision") != engDecisionError || !engTestHasRule(result, "AI_UNAVAILABLE") {
		t.Fatalf("AI failure did not fail closed: decision=%s findings=%v", S(result, "decision"), result["findings"])
	}
	// Model-added risks are capped at REVIEW.
	old, newer, evidence, config, context, _ = engTestFixture()
	ai = M{
		"status":           "ok",
		"summary":          "risk",
		"additional_risks": []any{M{"title": "risky", "detail": "because"}},
		"citations":        []any{},
	}
	result = engTestEvaluate(t, old, newer, evidence, config, context, ai)
	if S(result, "decision") != engDecisionReview || !engTestHasRule(result, "AI_ADDITIONAL_RISK") {
		t.Fatalf("AI risk not capped at REVIEW: decision=%s findings=%v", S(result, "decision"), result["findings"])
	}
	// Missing required AI result is an ERROR.
	old, newer, evidence, config, context, _ = engTestFixture()
	result = engTestEvaluate(t, old, newer, evidence, config, context, nil)
	if S(result, "decision") != engDecisionError || !engTestHasRule(result, "AI_REQUIRED_UNAVAILABLE") {
		t.Fatalf("missing required AI did not fail closed: decision=%s findings=%v", S(result, "decision"), result["findings"])
	}
}
