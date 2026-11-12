// Synthetic scenario matrix for the Go evaluation kernel.
//
// The matrix is reproducible regression evidence built from synthetic manifests,
// synthetic evidence, and explicit AI stubs.  It is not a claim of live cluster
// or live model experiments; those are recorded separately by the operator.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/hey-mmm/k8s-change-guard/internal/guard"
)

type cgScenario struct {
	name      string
	expected  string
	operation string
	value     any
}

func cgScenarioList() []cgScenario {
	return []cgScenario{
		{"normal-digest", "PASS", "image", nil},
		{"zero-replicas", "BLOCK", "replicas", float64(0)},
		{"readiness-deleted", "BLOCK", "readiness", nil},
		{"startup-failure", "BLOCK", "env", [2]string{"DEMO_STARTUP_FAIL", "true"}},
		{"error-injection", "BLOCK", "env", [2]string{"DEMO_ERROR_RATE", "1"}},
		{"latency-injection", "BLOCK", "env", [2]string{"DEMO_LATENCY_MS", "3000"}},
		{"unapproved-image", "BLOCK", "bad_image", nil},
		{"mutable-tag", "BLOCK", "tag", nil},
		{"memory-below-measured-use", "BLOCK", "memory", "64Mi"},
		{"large-cpu-reduction", "REVIEW", "cpu", "100m"},
		{"current-error-rate", "REVIEW", "metric", [2]any{"error_ratio", float64(0.2)}},
		{"current-slow-service", "REVIEW", "metric", [2]any{"p95_seconds", float64(2)}},
		{"rolling-capacity-shortage", "REVIEW", "capacity", nil},
		{"replica-capacity-growth", "REVIEW", "replicas", float64(100)},
		{"metrics-unavailable", "ERROR", "metric", [2]any{"memory_working_set_bytes", nil}},
		{"stale-raw-sample", "ERROR", "stale", nil},
		{"missing-counter-series", "ERROR", "series", nil},
		{"nonfinite-memory", "ERROR", "metric", [2]any{"memory_working_set_bytes", math.NaN()}},
		{"model-timeout", "ERROR", "ai_error", nil},
		{"model-error-cannot-lower-block", "BLOCK", "block_ai_error", nil},
		{"model-new-risk", "REVIEW", "ai_risk", nil},
		{"unexpected-sidecar", "BLOCK", "sidecar", nil},
		{"envfrom-fault-reference", "BLOCK", "envfrom", nil},
		{"deployment-deleted", "BLOCK", "delete", nil},
		{"privileged-container", "BLOCK", "privileged", nil},
	}
}

func cgScenarioDeployment(version string) guard.M {
	return guard.M{
		"apiVersion": "apps/v1",
		"kind":       "Deployment",
		"metadata": guard.M{
			"name":      "demo",
			"namespace": "demo",
		},
		"spec": guard.M{
			"replicas": float64(1),
			"strategy": guard.M{
				"type": "RollingUpdate",
				"rollingUpdate": guard.M{
					"maxSurge":       float64(1),
					"maxUnavailable": float64(0),
				},
			},
			"selector": guard.M{
				"matchLabels": guard.M{"app": "demo"},
			},
			"template": guard.M{
				"metadata": guard.M{"labels": guard.M{"app": "demo"}},
				"spec": guard.M{
					"automountServiceAccountToken": false,
					"securityContext": guard.M{
						"runAsNonRoot": true,
						"runAsUser":    float64(10001),
						"seccompProfile": guard.M{
							"type": "RuntimeDefault",
						},
					},
					"containers": []any{
						guard.M{
							"name":  "demo-service",
							"image": "ghcr.io/hey-mmm/observability-demo@sha256:" + cgScenarioDigest("a"),
							"env": []any{
								guard.M{"name": "APP_VERSION", "value": version},
								guard.M{"name": "DEMO_ERROR_RATE", "value": "0"},
								guard.M{"name": "DEMO_LATENCY_MS", "value": "0"},
								guard.M{"name": "DEMO_STARTUP_FAIL", "value": "false"},
							},
							"readinessProbe": guard.M{
								"httpGet":             guard.M{"path": "/readyz", "port": "http"},
								"initialDelaySeconds": float64(2),
								"periodSeconds":       float64(5),
								"timeoutSeconds":      float64(2),
								"failureThreshold":    float64(3),
							},
							"livenessProbe": guard.M{
								"httpGet":             guard.M{"path": "/healthz", "port": "http"},
								"initialDelaySeconds": float64(5),
								"periodSeconds":       float64(10),
								"timeoutSeconds":      float64(2),
								"failureThreshold":    float64(3),
							},
							"startupProbe": guard.M{
								"httpGet":          guard.M{"path": "/healthz", "port": "http"},
								"periodSeconds":    float64(2),
								"timeoutSeconds":   float64(2),
								"failureThreshold": float64(30),
							},
							"resources": guard.M{
								"requests": guard.M{"cpu": "50m", "memory": "64Mi"},
								"limits":   guard.M{"cpu": "250m", "memory": "192Mi"},
							},
							"securityContext": guard.M{
								"allowPrivilegeEscalation": false,
								"privileged":               false,
								"readOnlyRootFilesystem":   true,
								"runAsNonRoot":             true,
								"runAsUser":                float64(10001),
								"capabilities": guard.M{
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

func cgScenarioDigest(character string) string {
	out := ""
	for index := 0; index < 64; index++ {
		out += character
	}
	return out
}

func cgScenarioService() guard.M {
	return guard.M{
		"apiVersion": "v1",
		"kind":       "Service",
		"metadata":   guard.M{"name": "demo", "namespace": "demo"},
		"spec": guard.M{
			"type":     "ClusterIP",
			"selector": guard.M{"app": "demo"},
			"ports": []any{
				guard.M{"name": "http", "port": float64(8080), "targetPort": "http", "protocol": "TCP"},
			},
		},
	}
}

func cgScenarioResources() []guard.M {
	return []guard.M{cgScenarioDeployment("0.2.0"), cgScenarioService()}
}

func cgScenarioEvidence(now float64) guard.M {
	return guard.M{
		"collected_at": now - 10,
		"errors":       []any{},
		"nodes":        []any{},
		"deployment": guard.M{
			"namespace":          "demo",
			"name":               "demo",
			"replicas":           float64(1),
			"ready_replicas":     float64(1),
			"available_replicas": float64(1),
			"containers": []any{
				guard.M{
					"name": "demo-service",
					"resources": guard.M{
						"requests": guard.M{"cpu": "50m", "memory": "64Mi"},
						"limits":   guard.M{"cpu": "250m", "memory": "192Mi"},
					},
				},
			},
		},
		"pods": []any{},
		"metrics": guard.M{
			"memory_working_set_bytes": float64(104857600),
			"request_rate":             float64(1),
			"error_ratio":              float64(0),
			"p95_seconds":              float64(0.1),
			"up":                       float64(1),
			"series_presence": guard.M{
				"up":             true,
				"memory":         true,
				"requests_total": true,
				"latency_bucket": true,
			},
			"alerts": []any{},
			"source_timestamps": guard.M{
				"memory_working_set_bytes": now - 5,
				"request_rate":             now - 5,
				"error_ratio":              now - 5,
				"p95_seconds":              now - 5,
				"up":                       now - 5,
			},
		},
		"capacity": guard.M{
			"available_cpu_millicores":   float64(4000),
			"available_memory_bytes":     float64(4294967296),
			"workers_ready":              float64(1),
			"allocatable_cpu_millicores": float64(4000),
			"allocatable_memory_bytes":   float64(4294967296),
		},
	}
}

func cgScenarioConfig(aiRequired bool) guard.M {
	return guard.M{
		"namespace":                "demo",
		"deployment":               "demo",
		"allowed_image_repository": "ghcr.io/hey-mmm/observability-demo",
		"require_digest":           true,
		"evidence_ttl_seconds":     float64(300),
		"ai_required":              aiRequired,
	}
}

func cgScenarioContext(now float64) guard.M {
	return guard.M{"evaluated_at": now, "pr_number": float64(42)}
}

func cgScenarioAI() guard.M {
	return guard.M{
		"status":           "ok",
		"model":            "deepseek-chat",
		"summary":          "no issues",
		"additional_risks": []any{},
		"citations":        []any{},
	}
}

func cgScenarioClone(value any) any {
	encoded, err := guard.CanonicalJSON(value)
	if err != nil {
		panic(err)
	}
	var out any
	if err := json.Unmarshal(encoded, &out); err != nil {
		panic(err)
	}
	return out
}

func cgScenarioCloneResources(resources []guard.M) []guard.M {
	raw := cgScenarioClone(resources)
	list := guard.Arr(raw)
	out := make([]guard.M, 0, len(list))
	for _, item := range list {
		out = append(out, guard.Obj(item))
	}
	return out
}

func cgScenarioDeploymentIn(resources []guard.M) guard.M {
	for _, resource := range resources {
		if guard.Str(resource["kind"]) == "Deployment" {
			return resource
		}
	}
	return nil
}

func cgScenarioContainer(resources []guard.M) guard.M {
	deployment := cgScenarioDeploymentIn(resources)
	containers := guard.Arr(guard.Get(deployment, "spec", "template", "spec", "containers"))
	if len(containers) == 0 {
		return nil
	}
	return guard.Obj(containers[0])
}

func cgScenarioSetEnv(container guard.M, name, value string) {
	for _, item := range guard.Arr(container["env"]) {
		entry := guard.Obj(item)
		if guard.Str(entry["name"]) == name {
			entry["value"] = value
			return
		}
	}
}

func cgScenarioFindings(result guard.M) []any {
	var out []any
	for _, item := range guard.Arr(result["findings"]) {
		finding := guard.Obj(item)
		out = append(out, guard.M{
			"rule_id":  finding["rule_id"],
			"severity": finding["severity"],
			"field":    finding["field"],
		})
	}
	return out
}

func cgBuildScenarioMatrix() (guard.M, error) {
	now := float64(time.Now().Unix())
	records := make([]any, 0, len(cgScenarioList()))
	passed := 0
	for _, scenario := range cgScenarioList() {
		oldResources := cgScenarioResources()
		newResources := cgScenarioCloneResources(oldResources)
		deployment := cgScenarioDeploymentIn(newResources)
		container := cgScenarioContainer(newResources)
		evidence := cgScenarioEvidence(now)
		ai := cgScenarioAI()
		config := cgScenarioConfig(true)
		switch scenario.operation {
		case "image":
			container["image"] = "ghcr.io/hey-mmm/observability-demo@sha256:" + cgScenarioDigest("b")
		case "replicas":
			deployment["spec"].(guard.M)["replicas"] = scenario.value
		case "readiness":
			delete(container, "readinessProbe")
		case "env":
			values := scenario.value.([2]string)
			cgScenarioSetEnv(container, values[0], values[1])
		case "bad_image":
			container["image"] = "ghcr.io/evil/app@sha256:" + cgScenarioDigest("a")
		case "tag":
			container["image"] = "ghcr.io/hey-mmm/observability-demo:latest"
		case "memory":
			guard.Obj(container["resources"])["limits"].(guard.M)["memory"] = scenario.value
		case "cpu":
			guard.Obj(container["resources"])["limits"].(guard.M)["cpu"] = scenario.value
		case "metric":
			pair := scenario.value.([2]any)
			guard.Obj(evidence["metrics"])[pair[0].(string)] = pair[1]
		case "capacity":
			guard.Obj(evidence["capacity"])["available_cpu_millicores"] = float64(10)
		case "stale":
			guard.Obj(guard.Obj(evidence["metrics"])["source_timestamps"])["memory_working_set_bytes"] = now - 600
		case "series":
			guard.Obj(guard.Obj(evidence["metrics"])["series_presence"])["requests_total"] = false
		case "ai_error":
			ai = guard.M{"status": "error", "model": "deepseek-chat", "error": "simulated timeout"}
		case "block_ai_error":
			deployment["spec"].(guard.M)["replicas"] = float64(0)
			ai = guard.M{"status": "error", "model": "deepseek-chat", "error": "simulated timeout"}
		case "ai_risk":
			ai["additional_risks"] = []any{
				guard.M{"title": "Additional rollout concern", "detail": "Synthetic model-risk test"},
			}
		case "sidecar":
			sidecar := cgScenarioClone(container).(map[string]any)
			sidecar["name"] = "sidecar"
			sidecar["command"] = []any{"/bin/sh", "-c", "id"}
			podSpec := guard.Obj(guard.Get(deployment, "spec", "template", "spec"))
			containers := guard.Arr(podSpec["containers"])
			podSpec["containers"] = append(containers, sidecar)
		case "envfrom":
			container["envFrom"] = []any{guard.M{"configMapRef": guard.M{"name": "faults"}}}
		case "delete":
			kept := make([]guard.M, 0, len(newResources))
			for _, resource := range newResources {
				if guard.Str(resource["kind"]) != "Deployment" {
					kept = append(kept, resource)
				}
			}
			newResources = kept
		case "privileged":
			guard.Obj(container["securityContext"])["privileged"] = true
		default:
			return nil, fmt.Errorf("unknown scenario operation %q", scenario.operation)
		}
		ruleConfig := cgScenarioConfig(false)
		ruleResult := guard.Evaluate(oldResources, newResources, evidence, ruleConfig, cgScenarioContext(now), nil)
		final := guard.Evaluate(oldResources, newResources, evidence, config, cgScenarioContext(now), ai)
		actual := guard.Str(final["decision"])
		ok := actual == scenario.expected
		if ok {
			passed++
		}
		records = append(records, guard.M{
			"scenario":      scenario.name,
			"expected":      scenario.expected,
			"rule_decision": ruleResult["decision"],
			"ai_status":     ai["status"],
			"ai_risks":      ai["additional_risks"],
			"actual":        actual,
			"passed":        ok,
			"findings":      cgScenarioFindings(final),
		})
	}
	if passed != len(records) {
		return guard.M{
			"generated_at":  int64(now),
			"evidence_kind": "synthetic regression; AI stubs are intentional",
			"total":         len(records),
			"passed":        passed,
			"scenarios":     records,
		}, nil
	}
	return guard.M{
		"generated_at":  int64(now),
		"evidence_kind": "synthetic regression; AI stubs are intentional",
		"total":         len(records),
		"passed":        passed,
		"scenarios":     records,
	}, nil
}

func cgScenarioMatrix(args []string) int {
	flags := cgFlagSet("scenario")
	output := flags.String("output", "", "write JSON atomically instead of stdout")
	if err := flags.Parse(args); err != nil {
		return cgExitError
	}
	if flags.NArg() != 0 {
		return cgFail(errors.New("scenario does not accept positional arguments"))
	}
	result, err := cgBuildScenarioMatrix()
	if err != nil {
		return cgFail(err)
	}
	if err := cgWrite(result, *output); err != nil {
		return cgFail(err)
	}
	total := guard.N(result, "total")
	passed := guard.N(result, "passed")
	fmt.Fprintf(os.Stderr, "scenario matrix: %d/%d passed\n", int(passed), int(total))
	if int(passed) != int(total) {
		return cgExitReview
	}
	return cgExitPass
}
