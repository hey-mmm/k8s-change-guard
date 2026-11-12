package guard

// Rule-focused tests for engine paths that the frozen Python oracle does not
// exercise individually. Every case starts from the healthy fixture so the
// absence of unrelated findings is meaningful.

import (
	"math"
	"testing"
)

type engTestRuleCase struct {
	want   string
	mutate func(old, newer []M, evidence, config, context, ai M)
}

func TestEngineRuleEdges(t *testing.T) {
	cases := map[string]engTestRuleCase{
		"service-no-spec": {want: "SERVICE_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestService(newer)["spec"] = nil
		}},
		"service-external-ips": {want: "SERVICE_EXPOSURE", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestService(newer)["spec"].(M)["externalIPs"] = []any{"203.0.113.10"}
		}},
		"service-node-port": {want: "SERVICE_EXPOSURE", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestService(newer)["spec"].(M)["ports"] = []any{
				M{"port": float64(8080), "nodePort": float64(30080)},
			}
		}},
		"service-extra":         {want: "UNEXPECTED_RESOURCE"},
		"service-missing":       {want: "SERVICE_MISSING"},
		"service-removed":       {want: "SERVICE_REMOVED"},
		"forbidden-workload":    {want: "FORBIDDEN_RESOURCE_KIND"},
		"duplicate-resource":    {want: "DUPLICATE_RESOURCE"},
		"unexpected-deployment": {want: "UNEXPECTED_WORKLOAD"},
		"argocd-kind":           {want: "ARGOCD_RESOURCE_CHANGE"},
		"image-repository": {want: "IMAGE_REPOSITORY_NOT_ALLOWED", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["image"] = "docker.io/evil/demo@" + engTestDigest
		}},
		"image-digest-invalid": {want: "IMAGE_DIGEST_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["image"] = "ghcr.io/hey-mmm/observability-demo@sha256:deadbeef"
		}},
		"image-mutable-latest": {want: "IMAGE_MUTABLE_TAG", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["image"] = "ghcr.io/hey-mmm/observability-demo:latest"
		}},
		"image-no-tag": {want: "IMAGE_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["image"] = "ghcr.io/hey-mmm/observability-demo"
		}},
		"image-tag-only": {want: "IMAGE_TAG_ONLY", mutate: func(_, newer []M, _, config, _, _ M) {
			engTestContainer(newer)["image"] = "ghcr.io/hey-mmm/observability-demo:1.2.3"
			config["require_digest"] = false
		}},
		"image-empty": {want: "IMAGE_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["image"] = " "
		}},
		"env-invalid": {want: "ENV_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["env"] = M{"name": "A", "value": "B"}
		}},
		"env-from-invalid": {want: "ENV_FROM_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["envFrom"] = "bad"
		}},
		"env-name-invalid": {want: "ENV_NAME_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["env"] = []any{M{"name": "BAD-NAME", "value": "x"}}
		}},
		"duplicate-env": {want: "DUPLICATE_ENV", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["env"] = []any{
				M{"name": "A", "value": "1"}, M{"name": "A", "value": "2"},
			}
		}},
		"fault-value-from": {want: "FAULT_VALUE_FROM", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["env"] = []any{
				M{"name": "DEMO_ERROR_RATE", "valueFrom": M{"secretKeyRef": M{"name": "s", "key": "k"}}},
			}
		}},
		"fault-env-invalid": {want: "FAULT_ENV_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["env"] = []any{M{"name": "DEMO_LATENCY_MS"}}
		}},
		"fault-error-rate": {want: "FAULT_INJECTION", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["env"] = []any{M{"name": "DEMO_ERROR_RATE", "value": "0.5"}}
		}},
		"fault-latency": {want: "FAULT_INJECTION", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["env"] = []any{M{"name": "DEMO_LATENCY_MS", "value": "50"}}
		}},
		"fault-startup": {want: "FAULT_INJECTION", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["env"] = []any{M{"name": "DEMO_STARTUP_FAIL", "value": "true"}}
		}},
		"probe-scheme": {want: "PROBE_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["readinessProbe"].(M)["httpGet"].(M)["scheme"] = "FTP"
		}},
		"probe-path": {want: "PROBE_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["readinessProbe"].(M)["httpGet"].(M)["path"] = float64(1)
		}},
		"probe-port": {want: "PROBE_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["readinessProbe"].(M)["httpGet"].(M)["port"] = float64(70000)
		}},
		"probe-exec-disallowed": {want: "PROBE_EXEC_COMMAND_NOT_ALLOWED", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["readinessProbe"] = M{"exec": M{"command": []any{"sh", "-c", "curl evil"}}}
		}},
		"probe-exec-allowed": {mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["readinessProbe"] = M{"exec": M{"command": []any{"/bin/true"}}}
		}},
		"probe-period-zero": {want: "PROBE_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["readinessProbe"].(M)["periodSeconds"] = float64(0)
		}},
		"security-allow-escalation": {want: "PRIVILEGE_ESCALATION_ALLOWED", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["securityContext"].(M)["allowPrivilegeEscalation"] = true
		}},
		"security-run-as-root": {want: "RUN_AS_ROOT", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["securityContext"].(M)["runAsUser"] = float64(0)
		}},
		"security-nonroot": {want: "RUN_AS_NONROOT_REQUIRED", mutate: func(_, newer []M, _, _, _, _ M) {
			delete(engTestPodSpec(newer)["securityContext"].(M), "runAsNonRoot")
			delete(engTestContainer(newer)["securityContext"].(M), "runAsNonRoot")
		}},
		"security-cap-add": {want: "CAPABILITIES_ADDED", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["securityContext"].(M)["capabilities"] = M{
				"add": []any{"NET_ADMIN"}, "drop": []any{"ALL"},
			}
		}},
		"security-cap-drop-missing": {want: "CAPABILITIES_NOT_DROPPED", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["securityContext"].(M)["capabilities"] = M{"drop": []any{}}
		}},
		"security-readonly-root": {want: "ROOT_FILESYSTEM_WRITABLE", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["securityContext"].(M)["readOnlyRootFilesystem"] = false
		}},
		"security-seccomp-unconfined": {want: "SECCOMP_UNCONFINED", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["securityContext"].(M)["seccompProfile"] = M{"type": "Unconfined"}
		}},
		"security-hostport": {want: "HOST_PORT", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["ports"] = []any{M{"containerPort": float64(8080), "hostPort": float64(8080)}}
		}},
		"security-host-network": {want: "POD_HOST_NAMESPACE", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestPodSpec(newer)["hostNetwork"] = true
		}},
		"security-shared-process": {want: "SHARED_PROCESS_NAMESPACE", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestPodSpec(newer)["shareProcessNamespace"] = true
		}},
		"security-automount-token": {want: "SERVICE_ACCOUNT_TOKEN_AUTOMOUNT", mutate: func(_, newer []M, _, _, _, _ M) {
			delete(engTestPodSpec(newer), "automountServiceAccountToken")
		}},
		"security-hostpath": {want: "HOST_PATH_VOLUME", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestPodSpec(newer)["volumes"] = []any{M{"name": "h", "hostPath": M{"path": "/"}}}
		}},
		"security-secret-volume": {want: "SENSITIVE_VOLUME", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestPodSpec(newer)["volumes"] = []any{M{"name": "s", "secret": M{"secretName": "s"}}}
		}},
		"deployment-invalid": {want: "DEPLOYMENT_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestDeployment(newer)["spec"] = nil
		}},
		"deployment-replicas-invalid": {want: "REPLICAS_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestDeployment(newer)["spec"].(M)["replicas"] = float64(-1)
		}},
		"deployment-template-missing": {want: "POD_TEMPLATE_MISSING", mutate: func(_, newer []M, _, _, _, _ M) {
			delete(engTestDeployment(newer)["spec"].(M), "template")
		}},
		"deployment-selector-invalid": {want: "SELECTOR_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestDeployment(newer)["spec"].(M)["selector"] = M{}
		}},
		"deployment-selector-mismatch": {want: "SELECTOR_MISMATCH", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestDeployment(newer)["spec"].(M)["selector"] = M{"matchLabels": M{"app": "other"}}
		}},
		"deployment-selector-changed": {want: "SELECTOR_CHANGED", mutate: func(old, newer []M, _, _, _, _ M) {
			engTestDeployment(old)["spec"].(M)["selector"] = M{"matchLabels": M{"app": "demo", "tier": "old"}}
			engTestDeployment(newer)["spec"].(M)["selector"] = M{"matchLabels": M{"app": "demo", "tier": "new"}}
			engTestPodSpec(newer)["metadata"] = M{"labels": M{"app": "demo", "tier": "new"}}
		}},
		"deployment-containers-missing": {want: "CONTAINERS_MISSING", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestPodSpec(newer)["containers"] = []any{}
		}},
		"deployment-two-containers": {want: "CONTAINER_SET_NOT_ALLOWED", mutate: func(_, newer []M, _, _, _, _ M) {
			container := engTestClone(engTestContainer(newer))
			container["name"] = "demo-service-2"
			engTestPodSpec(newer)["containers"] = []any{
				engTestContainer(newer), container,
			}
		}},
		"deployment-init-container": {want: "INIT_CONTAINER_NOT_ALLOWED", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestPodSpec(newer)["initContainers"] = []any{
				M{"name": "init", "image": "ghcr.io/hey-mmm/observability-demo@" + engTestDigest},
			}
		}},
		"deployment-name-invalid": {want: "CONTAINER_NAME_NOT_ALLOWED", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["name"] = "other"
		}},
		"deployment-command": {want: "CONTAINER_COMMAND_NOT_ALLOWED", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["command"] = []any{"/bin/sh"}
		}},
		"deployment-lifecycle": {want: "LIFECYCLE_NOT_ALLOWED", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["lifecycle"] = M{"preStop": M{"exec": M{"command": []any{"true"}}}}
		}},
		"deployment-container-name-missing": {want: "CONTAINER_NAME_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			delete(engTestContainer(newer), "name")
		}},
		"deployment-container-name-duplicate": {want: "CONTAINER_NAME_DUPLICATE", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestPodSpec(newer)["initContainers"] = []any{
				M{"name": "demo-service", "image": "ghcr.io/hey-mmm/observability-demo@" + engTestDigest},
			}
		}},
		"deployment-resources-missing": {want: "RESOURCE_REQUESTS_MISSING", mutate: func(_, newer []M, _, _, _, _ M) {
			delete(engTestContainer(newer), "resources")
		}},
		"deployment-invalid-quantity": {want: "INVALID_RESOURCE_QUANTITY", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["resources"].(M)["requests"] = M{"cpu": "not-a-quantity", "memory": "64Mi"}
		}},
		"deployment-limit-below-request": {want: "RESOURCE_LIMIT_BELOW_REQUEST", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["resources"].(M)["limits"] = M{"cpu": "10m", "memory": "192Mi"}
		}},
		"capacity-missing": {want: "CAPACITY_MISSING", mutate: func(_, _ []M, evidence, _, _, _ M) {
			delete(evidence, "capacity")
			evidence["nodes"] = []any{}
		}},
		"capacity-no-worker": {want: "NO_SCHEDULABLE_WORKER", mutate: func(_, _ []M, evidence, _, _, _ M) {
			evidence["capacity"].(M)["workers_ready"] = float64(0)
		}},
		"capacity-overcommitted": {want: "CAPACITY_OVERCOMMITTED", mutate: func(_, _ []M, evidence, _, _, _ M) {
			evidence["capacity"].(M)["overcommitted"] = true
		}},
		"capacity-insufficient": {want: "CAPACITY_INSUFFICIENT", mutate: func(_, _ []M, evidence, _, _, _ M) {
			evidence["capacity"].(M)["available_cpu_millicores"] = float64(1)
			evidence["capacity"].(M)["available_memory_bytes"] = float64(1)
		}},
		"capacity-strategy-invalid": {want: "ROLLOUT_STRATEGY_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestDeployment(newer)["spec"].(M)["strategy"] = M{"type": "BlueGreen"}
		}},
		"capacity-requests-invalid": {want: "CAPACITY_REQUESTS_INVALID", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["resources"].(M)["requests"] = M{"cpu": "Bad", "memory": "64Mi"}
		}},
		"capacity-requests-unreserved": {want: "CAPACITY_REQUESTS_UNRESERVED", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["resources"] = M{"limits": M{"cpu": "250m", "memory": "192Mi"}}
		}},
		"capacity-node-incomplete": {want: "CAPACITY_NODE_DATA_INCOMPLETE", mutate: func(_, _ []M, evidence, _, _, _ M) {
			delete(evidence, "capacity")
			evidence["nodes"] = []any{M{"name": "w1", "ready": true}}
			evidence["pods"] = []any{}
		}},
		"capacity-pod-requests-invalid": {want: "CAPACITY_POD_REQUESTS_INVALID", mutate: func(_, _ []M, evidence, _, _, _ M) {
			delete(evidence, "capacity")
			evidence["nodes"] = []any{M{
				"name": "w1", "ready": true,
				"allocatable_cpu_millicores": 4000, "allocatable_memory_bytes": 4294967296,
			}}
			evidence["pods"] = []any{M{"node": "w1", "spec": M{"containers": []any{
				M{"resources": M{"requests": M{"cpu": "bad", "memory": "1Gi"}}},
			}}}}
		}},
		"capacity-pod-requests-unreserved": {want: "CAPACITY_POD_REQUESTS_UNRESERVED", mutate: func(_, _ []M, evidence, _, _, _ M) {
			delete(evidence, "capacity")
			evidence["nodes"] = []any{M{
				"name": "w1", "ready": true,
				"allocatable_cpu_millicores": 4000, "allocatable_memory_bytes": 4294967296,
			}}
			evidence["pods"] = []any{M{"node": "w1", "spec": M{"containers": []any{
				M{"resources": M{"limits": M{"cpu": "1", "memory": "1Gi"}}},
			}}}}
		}},
		"capacity-control-plane-selector": {want: "CONTROL_PLANE_SCHEDULING", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestPodSpec(newer)["nodeSelector"] = M{"node-role.kubernetes.io/control-plane": "true"}
		}},
		"capacity-selector-unverified": {want: "SCHEDULING_UNVERIFIED", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestPodSpec(newer)["nodeSelector"] = M{"disktype": "ssd"}
		}},
		"capacity-affinity-unverified": {want: "SCHEDULING_UNVERIFIED", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestPodSpec(newer)["affinity"] = M{"nodeAffinity": M{"requiredDuringSchedulingIgnoredDuringExecution": M{}}}
		}},
		"capacity-control-plane-toleration": {want: "CONTROL_PLANE_TOLERATION", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestPodSpec(newer)["tolerations"] = []any{
				M{"key": "node-role.kubernetes.io/control-plane", "operator": "Exists"},
			}
		}},
		"metrics-collected-at-missing": {want: "EVIDENCE_TIMESTAMP_MISSING", mutate: func(_, _ []M, evidence, _, _, _ M) {
			delete(evidence, "collected_at")
		}},
		"metrics-collected-at-future": {want: "EVIDENCE_TIMESTAMP_FUTURE", mutate: func(_, _ []M, evidence, _, _, _ M) {
			evidence["collected_at"] = float64(1800001000)
		}},
		"metrics-missing": {want: "METRICS_MISSING", mutate: func(_, _ []M, evidence, _, _, _ M) {
			delete(evidence, "metrics")
		}},
		"metrics-evidence-error": {want: "EVIDENCE_ERROR", mutate: func(_, _ []M, evidence, _, _, _ M) {
			evidence["errors"] = []any{"collection failed"}
		}},
		"metrics-target-missing": {want: "TARGET_EVIDENCE_MISSING", mutate: func(_, _ []M, evidence, _, _, _ M) {
			delete(evidence, "deployment")
		}},
		"metrics-target-health-missing": {want: "TARGET_HEALTH_MISSING", mutate: func(_, _ []M, evidence, _, _, _ M) {
			delete(evidence["deployment"].(M), "ready_replicas")
		}},
		"metrics-target-degraded": {want: "TARGET_DEGRADED", mutate: func(_, _ []M, evidence, _, _, _ M) {
			evidence["deployment"].(M)["replicas"] = float64(2)
			evidence["deployment"].(M)["ready_replicas"] = float64(1)
			evidence["deployment"].(M)["available_replicas"] = float64(1)
		}},
		"metrics-memory-nan": {want: "METRIC_MISSING_OR_INVALID", mutate: func(_, _ []M, evidence, _, _, _ M) {
			evidence["metrics"].(M)["memory_working_set_bytes"] = math.NaN()
		}},
		"metrics-up-missing": {want: "TARGET_UP_MISSING", mutate: func(_, _ []M, evidence, _, _, _ M) {
			delete(evidence["metrics"].(M), "up")
		}},
		"metrics-up-down": {want: "TARGET_UP_NOT_READY", mutate: func(_, _ []M, evidence, _, _, _ M) {
			evidence["metrics"].(M)["up"] = float64(0)
		}},
		"metrics-series-missing": {want: "METRIC_SOURCE_MISSING", mutate: func(_, _ []M, evidence, _, _, _ M) {
			delete(evidence["metrics"].(M)["series_presence"].(M), "requests_total")
		}},
		"metrics-alerts-missing": {want: "ALERTS_MISSING", mutate: func(_, _ []M, evidence, _, _, _ M) {
			delete(evidence["metrics"].(M), "alerts")
		}},
		"metrics-timestamp-missing": {want: "METRIC_TIMESTAMP_MISSING", mutate: func(_, _ []M, evidence, _, _, _ M) {
			delete(evidence["metrics"].(M)["source_timestamps"].(M), "memory_working_set_bytes")
		}},
		"metrics-stale": {want: "METRIC_STALE", mutate: func(_, _ []M, evidence, _, _, _ M) {
			evidence["metrics"].(M)["source_timestamps"].(M)["memory_working_set_bytes"] = float64(1700000000)
		}},
		"metrics-timestamp-future": {want: "METRIC_TIMESTAMP_FUTURE", mutate: func(_, _ []M, evidence, _, _, _ M) {
			evidence["metrics"].(M)["source_timestamps"].(M)["memory_working_set_bytes"] = float64(1800001000)
		}},
		"metrics-low-traffic": {want: "LOW_TRAFFIC", mutate: func(_, _ []M, evidence, _, _, _ M) {
			evidence["metrics"].(M)["request_rate"] = float64(0.01)
		}},
		"metrics-high-error-ratio": {want: "HIGH_ERROR_RATIO", mutate: func(_, _ []M, evidence, _, _, _ M) {
			evidence["metrics"].(M)["error_ratio"] = float64(0.5)
		}},
		"metrics-high-p95": {want: "HIGH_P95_LATENCY", mutate: func(_, _ []M, evidence, _, _, _ M) {
			evidence["metrics"].(M)["p95_seconds"] = float64(2)
		}},
		"metrics-firing-alert": {want: "FIRING_ALERTS", mutate: func(_, _ []M, evidence, _, _, _ M) {
			evidence["metrics"].(M)["alerts"] = []any{
				M{"name": "DemoDown", "state": "firing",
					"labels": M{"namespace": "demo", "deployment": "demo"}},
			}
		}},
		"metrics-memory-limit-missing": {want: "MEMORY_LIMIT_MISSING", mutate: func(_, newer []M, _, _, _, _ M) {
			delete(engTestContainer(newer)["resources"].(M), "limits")
		}},
		"metrics-memory-limit-low": {want: "MEMORY_LIMIT_TOO_LOW", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["resources"].(M)["limits"] = M{"cpu": "250m", "memory": "100Mi"}
		}},
		"resource-reduction": {want: "RESOURCE_REDUCTION", mutate: func(_, newer []M, _, _, _, _ M) {
			engTestContainer(newer)["resources"].(M)["requests"] = M{"cpu": "10m", "memory": "64Mi"}
			engTestContainer(newer)["resources"].(M)["limits"] = M{"cpu": "250m", "memory": "192Mi"}
		}},
		"tree-argo-source": {want: "ARGOCD_SOURCE_CHANGED", mutate: func(_, _ []M, _, _, context, _ M) {
			context["argo_source_changed"] = true
		}},
		"tree-argo-manifest": {want: "ARGOCD_MANIFEST_CHANGE", mutate: func(_, _ []M, _, _, context, _ M) {
			context["tree_changes"] = []any{"gitops/argocd/application.yaml"}
		}},
		"tree-null-falls-back-to-changed-paths": {want: "ARGOCD_MANIFEST_CHANGE", mutate: func(_, _ []M, _, _, context, _ M) {
			context["tree_changes"] = nil
			context["changed_paths"] = []any{"gitops/argocd/project.yaml"}
		}},
		"tree-template": {want: "TEMPLATE_FILE_CHANGE", mutate: func(_, _ []M, _, _, context, _ M) {
			context["tree_changes"] = []any{"charts/demo/templates/deployment.yaml"}
		}},
		"ai-unavailable": {want: "AI_UNAVAILABLE", mutate: func(_, _ []M, _, _, _, ai M) {
			ai["status"] = "error"
			ai["error"] = "timeout"
		}},
		"ai-invalid-status": {want: "AI_INVALID_RESULT", mutate: func(_, _ []M, _, _, _, ai M) {
			ai["status"] = "weird"
		}},
		"ai-empty-summary": {want: "AI_INVALID_RESULT", mutate: func(_, _ []M, _, _, _, ai M) {
			ai["summary"] = " "
		}},
		"ai-risks-not-list": {want: "AI_INVALID_RESULT", mutate: func(_, _ []M, _, _, _, ai M) {
			ai["additional_risks"] = "risk"
		}},
		"ai-bad-citation": {want: "AI_INVALID_RESULT", mutate: func(_, _ []M, _, _, _, ai M) {
			ai["citations"] = []any{M{"case_id": "", "quote": "q"}}
		}},
		"ai-additional-risk": {want: "AI_ADDITIONAL_RISK", mutate: func(_, _ []M, _, _, _, ai M) {
			ai["additional_risks"] = []any{M{"title": "risk", "detail": "why"}}
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			old, newer, evidence, config, context, ai := engTestFixture()
			switch name {
			case "service-extra":
				service := engTestClone(engTestService(newer))
				service["metadata"].(M)["name"] = "extra"
				newer = append(newer, service)
			case "service-missing", "service-removed":
				newer = engTestWithoutKind(newer, "Service")
			case "forbidden-workload":
				newer = append(newer, M{"kind": "Pod", "metadata": M{"name": "evil", "namespace": "demo"}})
			case "duplicate-resource":
				newer = append(newer, engTestClone(engTestService(newer)))
			case "unexpected-deployment":
				deployment := engTestClone(engTestDeployment(newer))
				deployment["metadata"].(M)["name"] = "other"
				newer = append(newer, deployment)
			case "argocd-kind":
				newer = append(newer, M{"kind": "Application", "metadata": M{"name": "app", "namespace": "demo"}})
			default:
				tc.mutate(old, newer, evidence, config, context, ai)
			}
			result := engTestEvaluate(t, old, newer, evidence, config, context, ai)
			if tc.want != "" && !engTestHasRule(result, tc.want) {
				t.Fatalf("missing %s; decision=%s rules=%s", tc.want, S(result, "decision"), engTestAllRules(result))
			}
		})
	}
}

func engTestWithoutKind(resources []M, kind string) []M {
	out := make([]M, 0, len(resources))
	for _, resource := range resources {
		if S(resource, "kind") != kind {
			out = append(out, resource)
		}
	}
	return out
}
