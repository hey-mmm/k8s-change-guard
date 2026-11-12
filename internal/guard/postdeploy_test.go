package guard

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const (
	pdTestNow   = 1800000000
	pdTestSHA   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	pdTestImage = "ghcr.io/hey-mmm/observability-demo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pdTestPodID = "docker-pullable://ghcr.io/hey-mmm/observability-demo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func pdTestConfig() M {
	return M{
		"namespace":                  "demo",
		"deployment":                 "demo",
		"argocd_namespace":           "argocd",
		"argo_application":           "demo",
		"demo_url":                   "http://10.104.233.119:8080",
		"version_path":               "/version",
		"ready_path":                 "/readyz",
		"container_name":             "demo",
		"pod_label_selector":         "app.kubernetes.io/name=demo,app.kubernetes.io/instance=demo",
		"allowed_image_repository":   "ghcr.io/hey-mmm/observability-demo",
		"require_digest":             true,
		"require_pod_image_id":       true,
		"strict_image_id_digest":     false,
		"postdeploy_timeout_seconds": 2,
		"postdeploy_poll_seconds":    1,
		"observation_seconds":        0,
		"max_error_ratio":            0.05,
		"max_p95_seconds":            0.5,
		"min_request_rate":           0.1,
		"kubectl":                    "/usr/bin/kubectl",
		"kubeconfig":                 "/etc/change-guard/kubeconfig",
		"use_proxy_env":              false,
		"evidence_ttl_seconds":       300,
	}
}

func pdTestArgo(revision, sync, health, phase string) M {
	return M{
		"metadata": M{"name": "demo", "namespace": "argocd"},
		"status": M{
			"sync":           M{"revision": revision, "status": sync},
			"health":         M{"status": health},
			"operationState": M{"phase": phase},
		},
	}
}

func pdTestDeployment(image string, replicas int, ready int) M {
	return M{
		"metadata": M{"name": "demo", "namespace": "demo", "generation": 2},
		"spec": M{
			"replicas": replicas,
			"template": M{"spec": M{"containers": []any{
				M{"name": "demo", "image": image},
			}}},
		},
		"status": M{
			"observedGeneration": 2,
			"updatedReplicas":    ready,
			"readyReplicas":      ready,
			"availableReplicas":  ready,
		},
	}
}

func pdTestPods(imageID string, ready bool) M {
	return M{
		"items": []any{
			M{
				"metadata": M{"name": "demo-abc", "namespace": "demo"},
				"spec": M{
					"nodeName":   "worker",
					"containers": []any{M{"name": "demo", "image": pdTestImage}},
				},
				"status": M{
					"phase":      "Running",
					"conditions": []any{M{"type": "Ready", "status": map[bool]string{true: "True", false: "False"}[ready]}},
					"containerStatuses": []any{
						M{"name": "demo", "ready": ready, "image": pdTestImage, "imageID": imageID},
					},
				},
			},
		},
	}
}

func pdTestEndpoints(ready bool) M {
	addresses := []any{}
	notReady := []any{}
	if ready {
		addresses = append(addresses, M{"ip": "10.244.0.10"})
	} else {
		notReady = append(notReady, M{"ip": "10.244.0.10"})
	}
	return M{"subsets": []any{M{"addresses": addresses, "notReadyAddresses": notReady}}}
}

func pdTestMetrics(rate, ratio, p95 float64, alerts []any, errorsFound []any) M {
	return M{
		"collected_at": pdTestNow,
		"errors":       errorsFound,
		"metrics": M{
			"request_rate": rate,
			"error_ratio":  ratio,
			"p95_seconds":  p95,
			"alerts":       alerts,
		},
	}
}

type pdTestRunner struct {
	payloads map[string]M
	calls    [][]string
}

func (runner *pdTestRunner) run(args []string, _ int) (any, error) {
	runner.calls = append(runner.calls, append([]string(nil), args...))
	for name, payload := range runner.payloads {
		for _, arg := range args {
			if arg == name {
				return payload, nil
			}
		}
	}
	return nil, errors.New("unexpected kubectl arguments")
}

func pdTestHTTP(path string, _ int) (int, []byte, error) {
	switch path {
	case "/version":
		return 200, []byte(`{"gitSha":"` + pdTestSHA + `","version":"1.0"}`), nil
	case "/readyz":
		return 200, []byte("ok"), nil
	}
	return 0, nil, errors.New("unexpected path " + path)
}

type pdTestClock struct {
	value float64
}

func (clock *pdTestClock) now() float64 {
	clock.value++
	return clock.value
}

func TestPDValidateConfigAndURLImageRules(t *testing.T) {
	cfg, err := pdValidateConfig(pdTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	if Str(cfg["namespace"]) != "demo" || Str(cfg["ready_path"]) != "/readyz" || Str(cfg["container_name"]) != "demo" {
		t.Fatalf("unexpected validated config: %#v", cfg)
	}

	broken := pdTestConfig()
	broken["demo_url"] = "http://user:password@example.invalid"
	if _, err := pdValidateConfig(broken); err == nil {
		t.Fatal("credential-bearing URL accepted")
	}
	broken = pdTestConfig()
	broken["version_path"] = "/../etc/passwd"
	if _, err := pdValidateConfig(broken); err == nil {
		t.Fatal("traversal version_path accepted")
	}
	broken = pdTestConfig()
	broken["allowed_image_repository"] = "ghcr.io/other/demo"
	if _, err := pdValidateExpectedImage(pdTestImage, broken); err == nil {
		t.Fatal("non-allowlisted repository accepted")
	}
	if _, err := pdValidateExpectedImage("ghcr.io/hey-mmm/observability-demo:latest", pdTestConfig()); err == nil {
		t.Fatal("unpinned image accepted")
	}
	validated, err := pdValidateExpectedImage(pdTestImage, pdTestConfig())
	if err != nil || validated != pdTestImage {
		t.Fatalf("valid image rejected: %v", err)
	}
}

func TestPDRedactsSecretLikeKeys(t *testing.T) {
	value := Obj(pdRedact(M{
		"kubeconfig": "apiVersion: v1",
		"nested":     M{"token": "x"},
		"normal":     "ok",
	}, 0, ""))
	if Str(value["kubeconfig"]) != "<redacted>" {
		t.Fatalf("kubeconfig not redacted: %#v", value)
	}
	if Str(Obj(value["nested"])["token"]) != "<redacted>" {
		t.Fatalf("nested token not redacted: %#v", value)
	}
	if Str(value["normal"]) != "ok" {
		t.Fatalf("normal value changed: %#v", value)
	}
}

func TestPDOnlyReadOnlyKubectlGetsWithJSON(t *testing.T) {
	if err := pdAssertReadOnlyKubectlArgs([]string{"-n", "demo", "get", "deployment", "demo", "-o", "json"}); err != nil {
		t.Fatalf("valid read rejected: %v", err)
	}
	bad := [][]string{
		{"-n", "demo", "delete", "deployment", "demo", "-o", "json"},
		{"-n", "demo", "get", "secrets", "-o", "json"},
		{"-n", "demo", "get", "pods/log", "-o", "json"},
		{"-n", "demo", "get", "pods", "-o", "yaml"},
		{"get", "pods", "--token=secret", "-o", "json"},
		{"config", "view", "-o", "json"},
	}
	for _, args := range bad {
		if err := pdAssertReadOnlyKubectlArgs(args); err == nil {
			t.Fatalf("forbidden kubectl args accepted: %v", args)
		}
	}
	command, err := pdKubectlCommand(pdTestConfig(), []string{"-n", "demo", "get", "pods", "-l", "a=b", "-o", "json"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(command, " ")
	if !strings.Contains(joined, "--kubeconfig=/etc/change-guard/kubeconfig") ||
		!strings.Contains(joined, "--request-timeout=2s") {
		t.Fatalf("unexpected kubectl command: %s", joined)
	}
}

func TestPDArgoChecksSyncHealthRevision(t *testing.T) {
	config, _ := pdValidateConfig(pdTestConfig())
	runner := &pdTestRunner{payloads: map[string]M{"application": pdTestArgo(pdTestSHA, "Synced", "Healthy", "Succeeded")}}
	result, err := pdCheckArgo(config, pdTestSHA, runner.run)
	if err != nil || Str(result["status"]) != "pass" {
		t.Fatalf("expected argo pass, got %#v err=%v", result, err)
	}
	runner = &pdTestRunner{payloads: map[string]M{"application": pdTestArgo("cccccccccccccccccccccccccccccccccccccccc", "OutOfSync", "Degraded", "Failed")}}
	result, err = pdCheckArgo(config, pdTestSHA, runner.run)
	if err != nil || Str(result["status"]) != "fail" {
		t.Fatalf("expected argo fail, got %#v err=%v", result, err)
	}
	detail := Str(result["detail"])
	if !strings.Contains(detail, "revision") || !strings.Contains(detail, "OutOfSync") {
		t.Fatalf("missing failure detail: %s", detail)
	}
}

func TestPDDeploymentChecksImageAndReplicas(t *testing.T) {
	config, _ := pdValidateConfig(pdTestConfig())
	runner := &pdTestRunner{payloads: map[string]M{"deployment": pdTestDeployment(pdTestImage, 1, 1)}}
	result, err := pdCheckDeployment(config, pdTestImage, runner.run)
	if err != nil || Str(result["status"]) != "pass" {
		t.Fatalf("expected deployment pass, got %#v err=%v", result, err)
	}
	runner = &pdTestRunner{payloads: map[string]M{"deployment": pdTestDeployment("other", 1, 0)}}
	result, err = pdCheckDeployment(config, pdTestImage, runner.run)
	if err != nil || Str(result["status"]) != "fail" || !strings.Contains(Str(result["detail"]), "image") {
		t.Fatalf("expected deployment image failure, got %#v err=%v", result, err)
	}
}

func TestPDPodsReadinessImageIDAndMultiarchCaveat(t *testing.T) {
	config, _ := pdValidateConfig(pdTestConfig())
	runner := &pdTestRunner{payloads: map[string]M{"pods": pdTestPods(pdTestPodID, true)}}
	result, err := pdCheckPods(config, pdTestImage, runner.run)
	if err != nil || Str(result["status"]) != "pass" {
		t.Fatalf("expected pods pass, got %#v err=%v", result, err)
	}

	different := "docker-pullable://ghcr.io/hey-mmm/observability-demo@sha256:" + strings.Repeat("d", 64)
	runner = &pdTestRunner{payloads: map[string]M{"pods": pdTestPods(different, true)}}
	result, err = pdCheckPods(config, pdTestImage, runner.run)
	if err != nil || Str(result["status"]) != "pass" {
		t.Fatalf("multi-arch caveat should pass: %#v err=%v", result, err)
	}
	if len(pdList(result["evidence"].(map[string]any)["digest_caveats"])) == 0 {
		t.Fatal("expected digest caveat evidence")
	}

	strict := pdTestConfig()
	strict["strict_image_id_digest"] = true
	strictConfig, _ := pdValidateConfig(strict)
	runner = &pdTestRunner{payloads: map[string]M{"pods": pdTestPods(different, true)}}
	result, err = pdCheckPods(strictConfig, pdTestImage, runner.run)
	if err != nil || Str(result["status"]) != "fail" {
		t.Fatalf("strict digest should fail: %#v err=%v", result, err)
	}

	runner = &pdTestRunner{payloads: map[string]M{"pods": pdTestPods(pdTestPodID, false)}}
	result, err = pdCheckPods(config, pdTestImage, runner.run)
	if err != nil || Str(result["status"]) != "fail" {
		t.Fatalf("not-ready pod should fail: %#v err=%v", result, err)
	}
}

func TestPDContainerdConfigIDIsNotManifestReference(t *testing.T) {
	config, _ := pdValidateConfig(pdTestConfig())
	payload := pdTestPods(pdTestPodID, true)
	status := Obj(Obj(pdList(payload["items"])[0])["status"])
	containerStatus := Obj(pdList(status["containerStatuses"])[0])
	containerStatus["image"] = "sha256:" + strings.Repeat("c", 64)
	runner := &pdTestRunner{payloads: map[string]M{"pods": payload}}
	result, err := pdCheckPods(config, pdTestImage, runner.run)
	if err != nil || Str(result["status"]) != "pass" {
		t.Fatalf("config ID runtime image should pass: %#v err=%v", result, err)
	}

	spec := Obj(Obj(pdList(payload["items"])[0])["spec"])
	containers := pdList(spec["containers"])
	containers[0] = M{"name": "demo", "image": strings.Replace(pdTestImage, strings.Repeat("a", 64), strings.Repeat("d", 64), 1)}
	spec["containers"] = containers
	runner = &pdTestRunner{payloads: map[string]M{"pods": payload}}
	result, err = pdCheckPods(config, pdTestImage, runner.run)
	if err != nil || Str(result["status"]) != "fail" {
		t.Fatalf("spec image mismatch should fail: %#v err=%v", result, err)
	}
}

func TestPDEndpointsRequireReadyAddress(t *testing.T) {
	config, _ := pdValidateConfig(pdTestConfig())
	runner := &pdTestRunner{payloads: map[string]M{"endpoints": pdTestEndpoints(true)}}
	result, err := pdCheckEndpoints(config, runner.run)
	if err != nil || Str(result["status"]) != "pass" {
		t.Fatalf("expected endpoints pass: %#v err=%v", result, err)
	}
	runner = &pdTestRunner{payloads: map[string]M{"endpoints": pdTestEndpoints(false)}}
	result, err = pdCheckEndpoints(config, runner.run)
	if err != nil || Str(result["status"]) != "fail" {
		t.Fatalf("expected endpoints fail: %#v err=%v", result, err)
	}
}

func TestPDHTTPChecksProvenanceAndReadiness(t *testing.T) {
	config, _ := pdValidateConfig(pdTestConfig())
	result, err := pdCheckHTTP(config, pdTestSHA, pdTestHTTP)
	if err != nil || Str(result["status"]) != "pass" {
		t.Fatalf("expected http pass: %#v err=%v", result, err)
	}
	wrongVersion := func(path string, _ int) (int, []byte, error) {
		return 200, []byte(`{"gitSha":"cccccccccccccccccccccccccccccccccccccccc"}`), nil
	}
	result, err = pdCheckHTTP(config, pdTestSHA, wrongVersion)
	if err != nil || Str(result["status"]) != "fail" || !strings.Contains(Str(result["detail"]), "gitSha") {
		t.Fatalf("expected gitSha failure: %#v err=%v", result, err)
	}
	missingReady := func(path string, timeout int) (int, []byte, error) {
		if path == "/version" {
			return pdTestHTTP(path, timeout)
		}
		return 404, []byte("no"), nil
	}
	result, err = pdCheckHTTP(config, pdTestSHA, missingReady)
	if err != nil || Str(result["status"]) != "fail" {
		t.Fatalf("expected readiness failure: %#v err=%v", result, err)
	}
}

func TestPDMetricsRequireTrafficAndBoundedSLO(t *testing.T) {
	config, _ := pdValidateConfig(pdTestConfig())
	provider := func(M) M { return pdTestMetrics(1, 0, 0.1, nil, nil) }
	result, err := pdCheckMetrics(config, provider, 0)
	if err != nil || Str(result["status"]) != "pass" {
		t.Fatalf("expected metrics pass: %#v err=%v", result, err)
	}
	failing := []M{
		pdTestMetrics(0, 0, 0.1, nil, nil),
		pdTestMetrics(1, 0.5, 0.1, nil, nil),
		pdTestMetrics(1, 0, 2.0, nil, nil),
		pdTestMetrics(1, 0, 0.1, []any{M{"name": "HighErrorRate", "state": "firing", "labels": M{"namespace": "demo"}}}, nil),
		pdTestMetrics(1, 0, 0.1, nil, []any{"prometheus query failed"}),
		pdTestMetrics(1, 0, 0.1, nil, []any{"source timestamp for request_rate is stale"}),
	}
	for index, payload := range failing {
		captured := payload
		provider = func(M) M { return captured }
		result, err = pdCheckMetrics(config, provider, 60)
		if err != nil || Str(result["status"]) != "fail" {
			t.Fatalf("metrics case %d should fail: %#v err=%v", index, result, err)
		}
	}
}

func TestPDGitOpsRevisionAndImageSourceRevisionAreDistinct(t *testing.T) {
	releaseSHA := strings.Repeat("d", 40)
	config, _ := pdValidateConfig(pdTestConfig())
	runner := &pdTestRunner{payloads: map[string]M{
		"application": pdTestArgo(releaseSHA, "Synced", "Healthy", "Succeeded"),
		"deployment":  pdTestDeployment(pdTestImage, 1, 1),
		"pods":        pdTestPods(pdTestPodID, true),
		"endpoints":   pdTestEndpoints(true),
	}}
	clock := &pdTestClock{value: pdTestNow}
	options := pdOptions{
		kubectlRunner:   runner.run,
		httpGet:         pdTestHTTP,
		metricsProvider: func(M) M { return pdTestMetrics(1, 0, 0.1, nil, nil) },
		clock:           clock.now,
		sleep:           func(float64) {},
	}
	result := pdVerify(config, releaseSHA, pdTestImage, pdTestSHA, options)
	if Str(result["status"]) != "ok" {
		t.Fatalf("expected ok: %#v", result)
	}
	if Str(result["expected_sha"]) != releaseSHA || Str(result["expected_app_sha"]) != pdTestSHA {
		t.Fatalf("release and app revisions collapsed: %#v", result)
	}
	wrongApp := pdVerify(config, releaseSHA, pdTestImage, strings.Repeat("c", 40), options)
	if Str(wrongApp["status"]) != "failed" {
		t.Fatalf("expected failure for distinct app SHA: %#v", wrongApp)
	}
	recommendation := Obj(wrongApp["recommendation"])
	if !pdContainsString(pdList(recommendation["failing_checks"]), "http_version") {
		t.Fatalf("http_version not reported as failing: %#v", recommendation)
	}
}

func TestPDOKReportContainsAllSixChecks(t *testing.T) {
	config, _ := pdValidateConfig(pdTestConfig())
	runner := &pdTestRunner{payloads: map[string]M{
		"application": pdTestArgo(pdTestSHA, "Synced", "Healthy", "Succeeded"),
		"deployment":  pdTestDeployment(pdTestImage, 1, 1),
		"pods":        pdTestPods(pdTestPodID, true),
		"endpoints":   pdTestEndpoints(true),
	}}
	result := pdVerify(config, pdTestSHA, pdTestImage, "", pdOptions{
		kubectlRunner:   runner.run,
		httpGet:         pdTestHTTP,
		metricsProvider: func(M) M { return pdTestMetrics(1, 0, 0.1, nil, nil) },
		clock:           (&pdTestClock{value: pdTestNow}).now,
		sleep:           func(float64) {},
	})
	if Str(result["status"]) != "ok" {
		t.Fatalf("expected ok: %#v", result)
	}
	var names []string
	for _, item := range pdList(result["checks"]) {
		names = append(names, Str(Obj(item)["name"]))
	}
	expected := []string{"argo", "deployment", "pods", "endpoints", "http_version", "metrics"}
	if strings.Join(names, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected check names: %v", names)
	}
	if result["recommendation"] != nil {
		t.Fatalf("ok report has a recommendation: %#v", result["recommendation"])
	}
	if Str(result["expected_app_sha"]) != pdTestSHA {
		t.Fatalf("expected_app_sha should default to expected_sha only when omitted: %#v", result)
	}
}

func TestPDFailureReturnsRevertRecommendationWithoutMutation(t *testing.T) {
	config, _ := pdValidateConfig(pdTestConfig())
	runner := &pdTestRunner{payloads: map[string]M{
		"application": pdTestArgo(pdTestSHA, "Synced", "Healthy", "Succeeded"),
		"deployment":  pdTestDeployment(pdTestImage, 1, 0),
		"pods":        pdTestPods(pdTestPodID, true),
		"endpoints":   pdTestEndpoints(true),
	}}
	result := pdVerify(config, pdTestSHA, pdTestImage, "", pdOptions{
		kubectlRunner:   runner.run,
		httpGet:         pdTestHTTP,
		metricsProvider: func(M) M { return pdTestMetrics(1, 0, 0.1, nil, nil) },
		clock:           (&pdTestClock{value: pdTestNow}).now,
		sleep:           func(float64) {},
	})
	if Str(result["status"]) != "failed" {
		t.Fatalf("expected failed: %#v", result)
	}
	recommendation := Obj(result["recommendation"])
	if Str(recommendation["action"]) != "open_revert_pr" {
		t.Fatalf("unexpected recommendation: %#v", recommendation)
	}
	if !pdContainsString(pdList(recommendation["failing_checks"]), "deployment") {
		t.Fatalf("deployment not reported as failing: %#v", recommendation)
	}
	if !strings.Contains(Str(recommendation["note"]), "read-only") {
		t.Fatalf("recommendation does not state read-only: %#v", recommendation)
	}
	for _, call := range runner.calls {
		if len(call) <= 2 || call[2] != "get" {
			t.Fatalf("non-get kubectl call: %v", call)
		}
	}
	for _, call := range runner.calls {
		if len(call) >= 2 && call[0] == "-n" && call[1] == "demo" {
			return
		}
	}
	t.Fatal("no namespaced demo kubectl call")
}

func TestPDMetricsFailureIsReported(t *testing.T) {
	config, _ := pdValidateConfig(pdTestConfig())
	runner := &pdTestRunner{payloads: map[string]M{
		"application": pdTestArgo(pdTestSHA, "Synced", "Healthy", "Succeeded"),
		"deployment":  pdTestDeployment(pdTestImage, 1, 1),
		"pods":        pdTestPods(pdTestPodID, true),
		"endpoints":   pdTestEndpoints(true),
	}}
	result := pdVerify(config, pdTestSHA, pdTestImage, "", pdOptions{
		kubectlRunner:   runner.run,
		httpGet:         pdTestHTTP,
		metricsProvider: func(M) M { return pdTestMetrics(0, 0, 0.1, nil, nil) },
		clock:           (&pdTestClock{value: pdTestNow}).now,
		sleep:           func(float64) {},
	})
	if Str(result["status"]) != "failed" {
		t.Fatalf("expected failed: %#v", result)
	}
	if !pdContainsString(pdList(Obj(result["recommendation"])["failing_checks"]), "metrics") {
		t.Fatalf("metrics not reported as failing: %#v", result)
	}
}

func TestPDSetupErrorsAreFailClosed(t *testing.T) {
	result := pdVerify(pdTestConfig(), "not-a-sha", pdTestImage, "", pdOptions{})
	if Str(result["status"]) != "error" {
		t.Fatalf("expected error for invalid SHA: %#v", result)
	}
	result = pdVerify(pdTestConfig(), pdTestSHA, "ghcr.io/hey-mmm/observability-demo:latest", "", pdOptions{})
	if Str(result["status"]) != "error" {
		t.Fatalf("expected error for unpinned image: %#v", result)
	}
}

func TestPDExpectedImageFromReport(t *testing.T) {
	report := M{"deployment_images": []any{
		M{"container": "demo", "init": false, "image": pdTestImage},
	}}
	image, err := pdExpectedImageFromReport(report, pdTestConfig())
	if err != nil || image != pdTestImage {
		t.Fatalf("unexpected expected image: %q err=%v", image, err)
	}
	config, _ := pdValidateConfig(pdTestConfig())
	runner := &pdTestRunner{payloads: map[string]M{
		"application": pdTestArgo(pdTestSHA, "Synced", "Healthy", "Succeeded"),
		"deployment":  pdTestDeployment(pdTestImage, 1, 1),
		"pods":        pdTestPods(pdTestPodID, true),
		"endpoints":   pdTestEndpoints(true),
	}}
	result := pdVerify(config, pdTestSHA, "", "", pdOptions{
		report:          report,
		kubectlRunner:   runner.run,
		httpGet:         pdTestHTTP,
		metricsProvider: func(M) M { return pdTestMetrics(1, 0, 0.1, nil, nil) },
		clock:           (&pdTestClock{value: pdTestNow}).now,
		sleep:           func(float64) {},
	})
	if Str(result["status"]) != "ok" {
		t.Fatalf("expected report-derived image to pass: %#v", result)
	}
	if _, err := pdExpectedImageFromReport(M{"deployment_images": []any{}}, pdTestConfig()); err == nil {
		t.Fatal("empty report images accepted")
	}
	if _, err := pdExpectedImageFromReport(M{"deployment_images": []any{
		M{"container": "demo", "image": pdTestImage},
		M{"container": "demo", "image": strings.Replace(pdTestImage, "a", "b", 1)},
	}}, pdTestConfig()); err == nil {
		t.Fatal("ambiguous report images accepted")
	}
}

func TestPDJSONBodyRejectsNonObjects(t *testing.T) {
	for _, payload := range []string{`[]`, `null`, `"text"`, `{`, "\xff"} {
		if _, err := pdJSONBody([]byte(payload)); err == nil {
			t.Fatalf("invalid JSON body accepted: %q", payload)
		}
	}
	if _, err := pdJSONBody([]byte(`{"ok":true}`)); err != nil {
		t.Fatalf("valid JSON object rejected: %v", err)
	}
}

func TestPDParseImageID(t *testing.T) {
	repository, digest := pdParseImageID(pdTestPodID)
	if repository != "ghcr.io/hey-mmm/observability-demo" ||
		digest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("unexpected imageID parse: %q %q", repository, digest)
	}
	repository, digest = pdParseImageID("containerd://sha256:" + strings.Repeat("c", 64))
	if repository != "" || digest != "sha256:"+strings.Repeat("c", 64) {
		t.Fatalf("unexpected config-id parse: %q %q", repository, digest)
	}
}

func TestPDRedactsCredentialLikeDetail(t *testing.T) {
	result := pdCheckResult("x", "fail", "Bearer abcdefghijklmnop and ghp_abcdefghijk", M{"token": "secret"})
	if strings.Contains(Str(result["detail"]), "abcdefghijklmnop") {
		t.Fatalf("bearer token leaked: %s", Str(result["detail"]))
	}
	if Str(Obj(result["evidence"])["token"]) != "<redacted>" {
		t.Fatalf("token evidence leaked: %#v", result["evidence"])
	}
}

func TestPDResultIsJSONSafe(t *testing.T) {
	config, _ := pdValidateConfig(pdTestConfig())
	result := pdErrorResult(errors.New("boom"), 1)
	result["checks"] = []M{pdCheckResult("metrics", "fail", "bad", M{"value": mathNaN()})}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("result is not JSON safe: %v", err)
	}
	if !strings.Contains(string(encoded), `"status":"error"`) {
		t.Fatalf("unexpected encoded result: %s", encoded)
	}
	_ = config
}

func mathNaN() float64 {
	var zero float64
	return zero / zero
}

func pdContainsString(values []any, target string) bool {
	for _, value := range values {
		if Str(value) == target {
			return true
		}
	}
	return false
}
