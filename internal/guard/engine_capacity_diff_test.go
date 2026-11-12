package guard

// Capacity, scheduling, diff and truncation tests for the engine port.

import (
	"strings"
	"testing"
)

func TestEngineComputedCapacityFromNodesAndPods(t *testing.T) {
	old, newer, evidence, config, context, ai := engTestFixture()
	delete(evidence, "capacity")
	evidence["nodes"] = []any{
		M{"name": "master-1", "ready": true, "labels": M{"node-role.kubernetes.io/control-plane": ""},
			"allocatable_cpu_millicores": float64(8000), "allocatable_memory_bytes": float64(1 << 34)},
		M{"name": "worker-b", "ready": true,
			"allocatable_cpu_millicores": float64(2000), "allocatable_memory_bytes": float64(1 << 31)},
		M{"name": "worker-a", "ready": true,
			"allocatable_cpu_millicores": float64(2000), "allocatable_memory_bytes": float64(1 << 31)},
		M{"name": "worker-down", "ready": false,
			"allocatable_cpu_millicores": float64(2000), "allocatable_memory_bytes": float64(1 << 31)},
	}
	evidence["pods"] = []any{
		M{"node": "worker-a", "phase": "Running", "spec": M{"containers": []any{
			M{"resources": M{"requests": M{"cpu": "100m", "memory": "128Mi"}}},
		}}},
		M{"node": "worker-b", "phase": "Succeeded", "spec": M{"containers": []any{
			M{"resources": M{"requests": M{"cpu": "1000m", "memory": "1Gi"}}},
		}}},
		M{"node": "master-1", "phase": "Running", "spec": M{"containers": []any{
			M{"resources": M{"requests": M{"cpu": "1000m", "memory": "1Gi"}}},
		}}},
	}
	result := engTestEvaluate(t, old, newer, evidence, config, context, ai)
	capacity := Obj(Get(result, "audit", "capacity"))
	if S(capacity, "source") != "nodes+pods" {
		t.Fatalf("capacity source=%q want nodes+pods; capacity=%v", S(capacity, "source"), capacity)
	}
	if N(capacity, "workers_ready") != 2 {
		t.Fatalf("workers_ready=%v want 2", capacity["workers_ready"])
	}
	if N(capacity, "allocatable_cpu_millicores") != 4000 {
		t.Fatalf("allocatable cpu=%v want 4000", capacity["allocatable_cpu_millicores"])
	}
	if N(capacity, "allocatable_memory_bytes") != 4*(1<<30) {
		t.Fatalf("allocatable memory=%v want %v", capacity["allocatable_memory_bytes"], 4*(1<<30))
	}
	if N(capacity, "existing_pods_requests_cpu_millicores") != 100 {
		t.Fatalf("existing cpu=%v want 100", capacity["existing_pods_requests_cpu_millicores"])
	}
	if N(capacity, "available_cpu_millicores") != 3900 {
		t.Fatalf("available cpu=%v want 3900", capacity["available_cpu_millicores"])
	}
	names := Arr(capacity["worker_names"])
	if len(names) != 2 || Str(names[0]) != "worker-a" || Str(names[1]) != "worker-b" {
		t.Fatalf("worker_names=%v want [worker-a worker-b]", names)
	}
	if engTestHasRule(result, "CAPACITY_NODE_DATA_INCOMPLETE") || engTestHasRule(result, "CAPACITY_POD_REQUESTS_INVALID") {
		t.Fatalf("unexpected capacity finding: %v", result["findings"])
	}
	if S(result, "decision") == engDecisionBlock {
		t.Fatalf("healthy computed capacity should not block: %v", result["findings"])
	}
}

func TestEngineDiffOperationsAndPodTemplateFlag(t *testing.T) {
	old, newer, evidence, config, context, ai := engTestFixture()
	oldDeployment := engTestDeployment(old)
	newDeployment := engTestDeployment(newer)
	oldMeta := Get(oldDeployment, "spec", "template", "metadata").(M)
	newMeta := Get(newDeployment, "spec", "template", "metadata").(M)
	oldMeta["annotations"] = M{"keep": "same", "remove": "old"}
	newMeta["annotations"] = M{"keep": "same", "add": "new"}
	newDeployment["spec"].(M)["replicas"] = float64(2)
	engTestContainer(newer)["env"] = []any{
		M{"name": "APP_VERSION", "value": "0.2.0"},
		M{"name": "EXTRA", "value": "literal"},
	}
	result := engTestEvaluate(t, old, newer, evidence, config, context, ai)
	operations := map[string]bool{}
	podTemplate := false
	for _, raw := range Arr(result["changes"]) {
		change := Obj(raw)
		operations[S(change, "operation")] = true
		if B(change, "pod_template") {
			podTemplate = true
		}
	}
	for _, operation := range []string{"add", "remove", "replace"} {
		if !operations[operation] {
			t.Fatalf("missing %s diff operation: %v", operation, result["changes"])
		}
	}
	if !podTemplate {
		t.Fatalf("pod template change flag was not set: %v", result["changes"])
	}
	if !B(result, "audit", "pod_template_changed") {
		t.Fatalf("audit.pod_template_changed=false")
	}
}

func TestEngineDiffRedactsSecretData(t *testing.T) {
	old, newer, evidence, config, context, ai := engTestFixture()
	secret := func(value string) M {
		return M{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata":   M{"name": "demo-secret", "namespace": "demo"},
			"data":       M{"password": value},
		}
	}
	old = append(old, secret("b2xkLXNlY3JldA=="))
	newer = append(newer, secret("bmV3LXNlY3JldA=="))
	result := engTestEvaluate(t, old, newer, evidence, config, context, ai)
	encoded, err := CanonicalJSON(result["changes"])
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, "b2xkLXNlY3JldA==") || strings.Contains(text, "bmV3LXNlY3JldA==") {
		t.Fatalf("secret diff leaked: %s", text)
	}
	if !strings.Contains(text, "<redacted>") {
		t.Fatalf("secret diff was not redacted: %s", text)
	}
	if !engTestHasRule(result, "UNEXPECTED_RESOURCE") {
		t.Fatalf("unknown Secret kind should still be blocked by scope checks")
	}
}

func TestEngineDiffRedactsRemovedEnvEntry(t *testing.T) {
	old, newer, evidence, config, context, ai := engTestFixture()
	engTestContainer(old)["env"] = append(Arr(engTestContainer(old)["env"]),
		M{"name": "REMOVED", "value": "supersecret"})
	engTestContainer(newer)["env"] = Arr(engTestContainer(newer)["env"])
	result := engTestEvaluate(t, old, newer, evidence, config, context, ai)
	encoded, err := CanonicalJSON(result["changes"])
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, "supersecret") {
		t.Fatalf("removed env entry leaked its literal: %s", text)
	}
	removed := false
	for _, raw := range Arr(result["changes"]) {
		change := Obj(raw)
		if S(change, "operation") == "remove" && strings.Contains(S(change, "path"), ".env[") {
			removed = true
			if got := S(Obj(change["old"]), "value"); got != "<redacted>" {
				t.Fatalf("removed env entry not redacted: %v", change)
			}
		}
	}
	if !removed {
		t.Fatalf("removed env change not found: %v", result["changes"])
	}
}

func TestEngineChangesTruncatedIsReview(t *testing.T) {
	old, newer, evidence, config, context, ai := engTestFixture()
	oldAnnotations := M{}
	newAnnotations := M{}
	for i := 0; i < 1005; i++ {
		key := "example.com/" + strings.Repeat("k", 3) + string(rune('a'+i%26)) + string(rune('a'+i/26))
		oldAnnotations[key] = "old"
		newAnnotations[key] = "new"
	}
	Get(engTestDeployment(old), "spec", "template", "metadata").(M)["annotations"] = oldAnnotations
	Get(engTestDeployment(newer), "spec", "template", "metadata").(M)["annotations"] = newAnnotations
	result := engTestEvaluate(t, old, newer, evidence, config, context, ai)
	if !engTestHasRule(result, "CHANGES_TRUNCATED") {
		t.Fatalf("missing CHANGES_TRUNCATED: decision=%s", S(result, "decision"))
	}
	if got := len(Arr(result["changes"])); got > engMaxDiffEntriesPerResource {
		t.Fatalf("changes not truncated: %d", got)
	}
	if N(result, "audit", "changes_count") > engMaxDiffEntriesPerResource {
		t.Fatalf("audit changes_count not truncated")
	}
	finding := engTestFinding(result, "CHANGES_TRUNCATED")
	if S(finding, "severity") != engDecisionReview {
		t.Fatalf("CHANGES_TRUNCATED severity=%q want REVIEW", S(finding, "severity"))
	}
}
