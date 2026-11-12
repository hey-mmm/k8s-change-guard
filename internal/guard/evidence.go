package guard

// Read-only Kubernetes and Prometheus evidence collection.
//
// Only fixed "kubectl get" commands and fixed PromQL expressions are used. There
// is no shell, no arbitrary command execution, no exec, no logs, and no write
// operation. Kubeconfig credentials are passed to kubectl but never included in
// the returned evidence.
//
// The returned structure follows the implementation contract:
//
//	{
//	  "collected_at": <unix seconds>,
//	  "errors": [...],
//	  "nodes": [...], "deployment": {...}, "pods": [...],
//	  "metrics": {
//	    "memory_working_set_bytes": <max_over_time 15m>,
//	    "request_rate": <rate 5m>,
//	    "error_ratio": <5m>, "p95_seconds": <5m>,
//	    "alerts": [...],
//	    "source_timestamps": {...}
//	  },
//	  "capacity": {
//	    "available_cpu_millicores": ..., "available_memory_bytes": ...
//	  },
//	  "sources": {...}
//	}

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	evdDefaultKubectlTimeout     = 20
	evdDefaultPrometheusTimeout  = 10
	evdDefaultMaxResponseBytes   = 16 * 1024 * 1024
	evdDefaultMaxPromBytes       = 2 * 1024 * 1024
	evdMaxRawQueryBytes          = 32 * 1024
	evdMaxPods                   = 2000
	evdMaxNodes                  = 500
	evdMaxAlerts                 = 100
	evdEvidenceVersion           = "1.0"
	evdClockSkewToleranceSeconds = 120
)

var evdQuantityRE = regexp.MustCompile(
	`^([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)([a-zA-Z]*)$`)
var evdSafeLabelKeys = map[string]bool{
	"alertname": true, "namespace": true, "deployment": true, "app": true,
	"app_kubernetes_io_name": true, "severity": true, "job": true, "pod": true,
}

// EvidenceError is raised for invalid collector configuration.
type EvidenceError struct{ Message string }

func (e *EvidenceError) Error() string { return e.Message }

func evdErr(format string, args ...any) *EvidenceError {
	return &EvidenceError{Message: fmt.Sprintf(format, args...)}
}

// Test seams: unit tests replace these boundaries instead of executing kubectl
// or contacting a Prometheus server.
var (
	evdRunKubectl = evdRunKubectlImpl
	evdPromQuery  = evdPromQueryImpl
	evdPromAlerts = evdPromAlertsImpl
)

// evdPyStr mirrors Python str() for scalar values returned by JSON/YAML.
func evdPyStr(value any) string {
	switch v := value.(type) {
	case nil:
		return "None"
	case string:
		return v
	case bool:
		if v {
			return "True"
		}
		return "False"
	case int:
		return strconv.Itoa(v)
	case int8:
		return strconv.FormatInt(int64(v), 10)
	case int16:
		return strconv.FormatInt(int64(v), 10)
	case int32:
		return strconv.FormatInt(int64(v), 10)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint:
		return strconv.FormatUint(uint64(v), 10)
	case uint8:
		return strconv.FormatUint(uint64(v), 10)
	case uint16:
		return strconv.FormatUint(uint64(v), 10)
	case uint32:
		return strconv.FormatUint(uint64(v), 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case float32:
		return strconv.FormatFloat(float64(v), 'g', -1, 32)
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}

func evdTruthy(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case int:
		return v != 0
	case int64:
		return v != 0
	case float64:
		return v != 0 && !math.IsNaN(v)
	case []any:
		return len(v) > 0
	case []M:
		return len(v) > 0
	case M:
		return len(v) > 0
	default:
		return true
	}
}

func evdAsMap(value any) (M, bool) {
	if mapping, ok := value.(map[string]any); ok && mapping != nil {
		return mapping, true
	}
	return nil, false
}

func evdAsList(value any) ([]any, bool) {
	switch list := value.(type) {
	case []any:
		return list, true
	case []M:
		out := make([]any, len(list))
		for i, item := range list {
			out[i] = item
		}
		return out, true
	case []string:
		out := make([]any, len(list))
		for i, item := range list {
			out[i] = item
		}
		return out, true
	}
	return nil, false
}

func evdFloatValue(value any) (float64, bool) {
	switch v := value.(type) {
	case bool:
		return 0, false
	case int:
		return float64(v), true
	case int8:
		return float64(v), true
	case int16:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint8:
		return float64(v), true
	case uint16:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float32:
		f := float64(v)
		return f, !math.IsNaN(f) && !math.IsInf(f, 0)
	case float64:
		return v, !math.IsNaN(v) && !math.IsInf(v, 0)
	case json.Number:
		if f, err := v.Float64(); err == nil {
			return f, !math.IsNaN(f) && !math.IsInf(f, 0)
		}
	}
	return 0, false
}

// evdNative converts integral JSON floats to int64 so the Go result keeps the
// Python baseline's int/float distinction for raw pass-through values.
func evdNative(value any) any {
	switch v := value.(type) {
	case nil:
		return nil
	case bool, string, int, int64:
		return v
	case float64:
		if !math.IsNaN(v) && !math.IsInf(v, 0) && math.Trunc(v) == v &&
			v >= math.MinInt64 && v <= math.MaxInt64 {
			return int64(v)
		}
		return v
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = evdNative(item)
		}
		return out
	case []M:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = evdNative(item)
		}
		return out
	case M:
		out := M{}
		for key, item := range v {
			out[key] = evdNative(item)
		}
		return out
	default:
		return v
	}
}

func evdConfigString(config M, key, fallback string) string {
	raw, present := config[key]
	if !present {
		return fallback
	}
	return evdPyStr(raw)
}

func evdBoundedInt(config M, key string, def, minimum, maximum int) (int, error) {
	raw, present := config[key]
	if !present {
		return def, nil
	}
	value, ok := rndIntValue(raw)
	if !ok || value < minimum || value > maximum {
		return 0, evdErr("%s must be an integer between %d and %d", key, minimum, maximum)
	}
	return value, nil
}

func evdSafeName(value, field string) (string, error) {
	if len(value) > 63 || !rndDNSLabelRE.MatchString(value) {
		return "", evdErr("%s is not a valid Kubernetes DNS label", field)
	}
	return value, nil
}

func evdNowFloat() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

// ---------------------------------------------------------------------------
// Python-compatible JSON rendering used for canonical pod-template hashes and
// bounded raw query snapshots.

func evdJSONEscape(text string, ensureASCII bool) string {
	var builder strings.Builder
	builder.WriteByte('"')
	for _, r := range text {
		switch r {
		case '"':
			builder.WriteString(`\"`)
		case '\\':
			builder.WriteString(`\\`)
		case '\b':
			builder.WriteString(`\b`)
		case '\f':
			builder.WriteString(`\f`)
		case '\n':
			builder.WriteString(`\n`)
		case '\r':
			builder.WriteString(`\r`)
		case '\t':
			builder.WriteString(`\t`)
		default:
			if r < 0x20 || (ensureASCII && r > 0x7e) {
				if r > 0xffff {
					high, low := utf16.EncodeRune(r)
					builder.WriteString(fmt.Sprintf(`\u%04x\u%04x`, high, low))
				} else {
					builder.WriteString(fmt.Sprintf(`\u%04x`, r))
				}
			} else {
				builder.WriteRune(r)
			}
		}
	}
	builder.WriteByte('"')
	return builder.String()
}

func evdPythonJSON(value any, ensureASCII bool) (string, error) {
	var builder strings.Builder
	var encode func(any) error
	var encodeMap func(map[string]any) error
	encode = func(item any) error {
		switch v := item.(type) {
		case nil:
			builder.WriteString("null")
		case bool:
			if v {
				builder.WriteString("true")
			} else {
				builder.WriteString("false")
			}
		case string:
			builder.WriteString(evdJSONEscape(v, ensureASCII))
		case int:
			builder.WriteString(strconv.Itoa(v))
		case int8:
			builder.WriteString(strconv.FormatInt(int64(v), 10))
		case int16:
			builder.WriteString(strconv.FormatInt(int64(v), 10))
		case int32:
			builder.WriteString(strconv.FormatInt(int64(v), 10))
		case int64:
			builder.WriteString(strconv.FormatInt(v, 10))
		case uint:
			builder.WriteString(strconv.FormatUint(uint64(v), 10))
		case uint8:
			builder.WriteString(strconv.FormatUint(uint64(v), 10))
		case uint16:
			builder.WriteString(strconv.FormatUint(uint64(v), 10))
		case uint32:
			builder.WriteString(strconv.FormatUint(uint64(v), 10))
		case uint64:
			builder.WriteString(strconv.FormatUint(v, 10))
		case float32:
			return encode(float64(v))
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return errors.New("non-finite number")
			}
			text := strconv.FormatFloat(v, 'g', -1, 64)
			if !strings.ContainsAny(text, ".eE") {
				text += ".0"
			}
			builder.WriteString(text)
		case json.Number:
			if integer, err := v.Int64(); err == nil {
				builder.WriteString(strconv.FormatInt(integer, 10))
			} else if f, err := v.Float64(); err == nil {
				return encode(f)
			} else {
				return err
			}
		case []any:
			builder.WriteByte('[')
			for index, child := range v {
				if index > 0 {
					builder.WriteByte(',')
				}
				if err := encode(child); err != nil {
					return err
				}
			}
			builder.WriteByte(']')
		case []M:
			builder.WriteByte('[')
			for index, child := range v {
				if index > 0 {
					builder.WriteByte(',')
				}
				if err := encode(child); err != nil {
					return err
				}
			}
			builder.WriteByte(']')
		case []string:
			builder.WriteByte('[')
			for index, child := range v {
				if index > 0 {
					builder.WriteByte(',')
				}
				if err := encode(child); err != nil {
					return err
				}
			}
			builder.WriteByte(']')
		case M:
			return encodeMap(v)
		default:
			return fmt.Errorf("unsupported JSON value %T", item)
		}
		return nil
	}
	encodeMap = func(mapping map[string]any) error {
		keys := make([]string, 0, len(mapping))
		for key := range mapping {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		builder.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				builder.WriteByte(',')
			}
			builder.WriteString(evdJSONEscape(key, ensureASCII))
			builder.WriteByte(':')
			if err := encode(mapping[key]); err != nil {
				return err
			}
		}
		builder.WriteByte('}')
		return nil
	}
	if err := encode(value); err != nil {
		return "", err
	}
	return builder.String(), nil
}

// ---------------------------------------------------------------------------
// Kubernetes parsing

func evdMetadata(item M) M {
	if metadata, ok := evdAsMap(item["metadata"]); ok {
		return metadata
	}
	return M{}
}

func evdConditionReady(status M) bool {
	conditions, ok := evdAsList(status["conditions"])
	if !ok {
		return false
	}
	for _, raw := range conditions {
		condition, ok := evdAsMap(raw)
		if !ok {
			continue
		}
		if evdPyStr(condition["type"]) == "Ready" {
			return strings.ToLower(evdPyStr(condition["status"])) == "true"
		}
	}
	return false
}

func evdFloat(value any) (float64, bool) {
	switch v := value.(type) {
	case bool:
		return 0, false
	case nil:
		return 0, false
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return 0, false
		}
		return v, true
	case float32:
		f := float64(v)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, json.Number:
		return evdFloatValue(v)
	case string:
		text := strings.TrimSpace(v)
		lower := strings.ToLower(text)
		if lower == "nan" || lower == "inf" || lower == "+inf" || lower == "-inf" {
			return 0, false
		}
		parsed, err := strconv.ParseFloat(text, 64)
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return 0, false
		}
		return parsed, true
	}
	return 0, false
}

func evdQuantity(value any) (float64, bool) {
	if _, isBool := value.(bool); isBool || value == nil {
		return 0, false
	}
	if number, ok := evdFloatValue(value); ok {
		return number, true
	}
	text, ok := value.(string)
	if !ok {
		return 0, false
	}
	match := evdQuantityRE.FindStringSubmatch(strings.TrimSpace(text))
	if match == nil {
		return 0, false
	}
	number, err := strconv.ParseFloat(match[1], 64)
	if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, false
	}
	multipliers := map[string]float64{
		"": 1, "n": 1e-9, "u": 1e-6, "m": 1e-3,
		"k": 1e3, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18,
		"Ki": 1024, "Mi": 1024 * 1024, "Gi": 1024 * 1024 * 1024,
		"Ti": 1024 * 1024 * 1024 * 1024, "Pi": 1024 * 1024 * 1024 * 1024 * 1024,
		"Ei": 1024 * 1024 * 1024 * 1024 * 1024 * 1024,
	}
	multiplier, ok := multipliers[match[2]]
	if !ok {
		return 0, false
	}
	return number * multiplier, true
}

func evdCPU(value any) (float64, bool) {
	parsed, ok := evdQuantity(value)
	if !ok {
		return 0, false
	}
	return parsed * 1000.0, true
}

func evdMemory(value any) (float64, bool) {
	return evdQuantity(value)
}

func evdNodeInfo(node M) M {
	metadata := evdMetadata(node)
	labels, _ := evdAsMap(metadata["labels"])
	if labels == nil {
		labels = M{}
	}
	spec, _ := evdAsMap(node["spec"])
	if spec == nil {
		spec = M{}
	}
	status, _ := evdAsMap(node["status"])
	if status == nil {
		status = M{}
	}
	ready := evdConditionReady(status)
	controlPlane := evdTruthy(labels["node-role.kubernetes.io/control-plane"]) ||
		evdTruthy(labels["node-role.kubernetes.io/master"])
	taints, _ := evdAsList(spec["taints"])
	noSchedule := false
	taintList := []any{}
	for _, raw := range taints {
		taint, ok := evdAsMap(raw)
		if !ok {
			continue
		}
		taintList = append(taintList, M{"key": evdNative(taint["key"]), "effect": evdNative(taint["effect"])})
		if taint["effect"] == "NoSchedule" {
			noSchedule = true
		}
	}
	unschedulable := evdTruthy(spec["unschedulable"])
	schedulable := ready && !controlPlane && !unschedulable && !noSchedule
	safeLabels := M{}
	for key, value := range labels {
		if strings.HasPrefix(key, "node-role.kubernetes.io/") ||
			key == "kubernetes.io/hostname" || key == "topology.kubernetes.io/zone" {
			safeLabels[key] = evdPyStr(value)
		}
	}
	allocatable, _ := evdAsMap(status["allocatable"])
	if allocatable == nil {
		allocatable = M{}
	}
	capacity, _ := evdAsMap(status["capacity"])
	if capacity == nil {
		capacity = M{}
	}
	allocCPU, allocCPUOK := evdCPU(allocatable["cpu"])
	allocMemory, allocMemoryOK := evdMemory(allocatable["memory"])
	return M{
		"name":          evdPyStr(metadata["name"]),
		"ready":         ready,
		"control_plane": controlPlane,
		"schedulable":   schedulable,
		"unschedulable": unschedulable,
		"taints":        taintList,
		"labels":        safeLabels,
		"allocatable": M{
			"cpu": evdNative(allocatable["cpu"]), "memory": evdNative(allocatable["memory"]),
		},
		"allocatable_cpu_millicores": nilableFloat(allocCPU, allocCPUOK),
		"allocatable_memory_bytes":   nilableFloat(allocMemory, allocMemoryOK),
		"capacity": M{
			"cpu": evdNative(capacity["cpu"]), "memory": evdNative(capacity["memory"]),
		},
	}
}

func nilableFloat(value float64, ok bool) any {
	if !ok {
		return nil
	}
	return value
}

func evdContainerResources(container M) M {
	resources, _ := evdAsMap(container["resources"])
	if resources == nil {
		resources = M{}
	}
	requests, _ := evdAsMap(resources["requests"])
	if requests == nil {
		requests = M{}
	}
	limits, _ := evdAsMap(resources["limits"])
	if limits == nil {
		limits = M{}
	}
	return M{
		"name":  evdPyStr(container["name"]),
		"image": evdPyStr(container["image"]),
		"resources": M{
			"requests": M{"cpu": evdNative(requests["cpu"]), "memory": evdNative(requests["memory"])},
			"limits":   M{"cpu": evdNative(limits["cpu"]), "memory": evdNative(limits["memory"])},
		},
	}
}

func evdPodInfo(pod M) M {
	metadata := evdMetadata(pod)
	spec, _ := evdAsMap(pod["spec"])
	if spec == nil {
		spec = M{}
	}
	status, _ := evdAsMap(pod["status"])
	if status == nil {
		status = M{}
	}
	var ownerInfo any
	if owners, ok := evdAsList(metadata["ownerReferences"]); ok && len(owners) > 0 {
		if first, ok := evdAsMap(owners[0]); ok {
			ownerInfo = M{"kind": evdNative(first["kind"]), "name": evdNative(first["name"])}
		}
	}
	ready := evdConditionReady(status)
	containers, _ := evdAsList(spec["containers"])
	initContainers, _ := evdAsList(spec["initContainers"])
	containerSpecs := []any{}
	containerNames := []any{}
	for _, raw := range containers {
		container, ok := evdAsMap(raw)
		if !ok {
			continue
		}
		containerSpecs = append(containerSpecs, evdContainerResources(container))
		containerNames = append(containerNames, evdPyStr(container["name"]))
	}
	initSpecs := []any{}
	for _, raw := range initContainers {
		container, ok := evdAsMap(raw)
		if !ok {
			continue
		}
		initSpecs = append(initSpecs, evdContainerResources(container))
	}
	overhead, _ := evdAsMap(spec["overhead"])
	if overhead == nil {
		overhead = M{}
	}
	restartCount := int64(0)
	if statuses, ok := evdAsList(status["containerStatuses"]); ok {
		for _, raw := range statuses {
			containerStatus, ok := evdAsMap(raw)
			if !ok {
				continue
			}
			rawCount := containerStatus["restartCount"]
			if _, isBool := rawCount.(bool); isBool {
				continue
			}
			if count, ok := rndIntValue(rawCount); ok {
				restartCount += int64(count)
			}
		}
	}
	return M{
		"namespace": evdPyStr(metadata["namespace"]),
		"name":      evdPyStr(metadata["name"]),
		"node":      evdPyStr(spec["nodeName"]),
		"phase":     evdPyStr(status["phase"]),
		"ready":     ready,
		"deleting":  evdTruthy(metadata["deletionTimestamp"]),
		"owner":     ownerInfo,
		"spec": M{
			"containers":     containerSpecs,
			"initContainers": initSpecs,
			"overhead":       evdNative(overhead),
		},
		"container_names": containerNames,
		"restart_count":   restartCount,
	}
}

func evdDeploymentInfo(deployment M) M {
	metadata := evdMetadata(deployment)
	spec, _ := evdAsMap(deployment["spec"])
	if spec == nil {
		spec = M{}
	}
	status, _ := evdAsMap(deployment["status"])
	if status == nil {
		status = M{}
	}
	template, _ := evdAsMap(spec["template"])
	if template == nil {
		template = M{}
	}
	templateSpec, _ := evdAsMap(template["spec"])
	if templateSpec == nil {
		templateSpec = M{}
	}
	containers, _ := evdAsList(templateSpec["containers"])
	images := []any{}
	containerList := []any{}
	for _, raw := range containers {
		container, ok := evdAsMap(raw)
		if !ok {
			continue
		}
		images = append(images, evdPyStr(container["image"]))
		containerList = append(containerList, evdContainerResources(container))
	}
	strategy, _ := evdAsMap(spec["strategy"])
	if strategy == nil {
		strategy = M{}
	}
	selector, _ := evdAsMap(spec["selector"])
	if selector == nil {
		selector = M{}
	}
	templateEncoded, encodeErr := evdPythonJSON(evdNative(template), true)
	if encodeErr != nil {
		templateEncoded = ""
	}
	templateHash := sha256.Sum256([]byte(templateEncoded))
	var readyReplicas any = int64(0)
	if value, present := status["readyReplicas"]; present {
		readyReplicas = evdNative(value)
	}
	var availableReplicas any = int64(0)
	if value, present := status["availableReplicas"]; present {
		availableReplicas = evdNative(value)
	}
	var updatedReplicas any = int64(0)
	if value, present := status["updatedReplicas"]; present {
		updatedReplicas = evdNative(value)
	}
	return M{
		"namespace":           evdPyStr(metadata["namespace"]),
		"name":                evdPyStr(metadata["name"]),
		"replicas":            evdNative(spec["replicas"]),
		"ready_replicas":      readyReplicas,
		"available_replicas":  availableReplicas,
		"updated_replicas":    updatedReplicas,
		"images":              images,
		"containers":          containerList,
		"strategy":            evdNative(strategy),
		"selector":            evdNative(selector),
		"pod_template_sha256": hex.EncodeToString(templateHash[:]),
	}
}

type evdParser func(any) (float64, bool)

func evdContainerValue(container M, resource, section string) any {
	if resources, ok := evdAsMap(container["resources"]); ok {
		if values, ok := evdAsMap(resources[section]); ok {
			return values[resource]
		}
	}
	if values, ok := evdAsMap(container[section]); ok {
		return values[resource]
	}
	return nil
}

func evdPodRequestsTyped(pod M, resource, section string, parser evdParser) (float64, int) {
	spec, _ := evdAsMap(pod["spec"])
	if spec == nil {
		spec = M{}
	}
	containers, _ := evdAsList(spec["containers"])
	initContainers, _ := evdAsList(spec["initContainers"])
	missing := 0
	total := 0.0
	for _, raw := range containers {
		container, ok := evdAsMap(raw)
		if !ok {
			missing++
			continue
		}
		value := evdContainerValue(container, resource, section)
		parsed := 0.0
		if value != nil {
			var parsedOK bool
			parsed, parsedOK = parser(value)
			if !parsedOK {
				missing++
				parsed = 0
			}
		}
		total += parsed
	}
	initMax := 0.0
	for _, raw := range initContainers {
		container, ok := evdAsMap(raw)
		if !ok {
			missing++
			continue
		}
		value := evdContainerValue(container, resource, section)
		parsed := 0.0
		if value != nil {
			var parsedOK bool
			parsed, parsedOK = parser(value)
			if !parsedOK {
				missing++
				parsed = 0
			}
		}
		if parsed > initMax {
			initMax = parsed
		}
	}
	overhead, _ := evdAsMap(spec["overhead"])
	if overhead == nil {
		overhead = M{}
	}
	overheadValue, _ := parser(overhead[resource])
	return math.Max(total, initMax) + overheadValue, missing
}

func evdComputeCapacity(nodes, pods []M, addError func(string)) M {
	workers := []M{}
	for _, node := range nodes {
		if evdTruthy(node["ready"]) && evdTruthy(node["schedulable"]) {
			workers = append(workers, node)
		}
	}
	workerNames := map[string]bool{}
	for _, node := range workers {
		name := evdPyStr(node["name"])
		if name != "" {
			workerNames[name] = true
		}
	}
	names := make([]string, 0, len(workerNames))
	for name := range workerNames {
		names = append(names, name)
	}
	sort.Strings(names)
	allocCPU := 0.0
	allocMemory := 0.0
	for _, node := range workers {
		if value, ok := evdFloatValue(node["allocatable_cpu_millicores"]); ok {
			allocCPU += value
		}
		if value, ok := evdFloatValue(node["allocatable_memory_bytes"]); ok {
			allocMemory += value
		}
	}
	usedCPU := 0.0
	usedMemory := 0.0
	missing := 0
	for _, pod := range pods {
		phase := evdPyStr(pod["phase"])
		if phase == "Succeeded" || phase == "Failed" {
			continue
		}
		if !workerNames[evdPyStr(pod["node"])] {
			continue
		}
		cpu, cpuMissing := evdPodRequestsTyped(pod, "cpu", "requests", evdCPU)
		memory, memoryMissing := evdPodRequestsTyped(pod, "memory", "requests", evdMemory)
		usedCPU += cpu
		usedMemory += memory
		missing += cpuMissing + memoryMissing
	}
	if missing > 0 {
		addError(fmt.Sprintf("%d scheduled Pod resource requests are missing; free capacity cannot be proven", missing))
	}
	availableCPU := allocCPU - usedCPU
	availableMemory := allocMemory - usedMemory
	return M{
		"available_cpu_millicores":              math.Max(0, availableCPU),
		"available_memory_bytes":                math.Max(0, availableMemory),
		"allocatable_cpu_millicores":            allocCPU,
		"allocatable_memory_bytes":              allocMemory,
		"existing_pods_requests_cpu_millicores": usedCPU,
		"existing_pods_requests_memory_bytes":   usedMemory,
		"workers_ready":                         len(workers),
		"worker_names":                          names,
		"overcommitted":                         availableCPU < 0 || availableMemory < 0,
	}
}

// ---------------------------------------------------------------------------
// kubectl boundary

func evdKubectlCommand(config M, args []string) ([]string, error) {
	kubectl := evdConfigString(config, "kubectl", "/usr/bin/kubectl")
	kubeconfig := evdConfigString(config, "kubeconfig", "")
	timeout, err := evdBoundedInt(config, "kubectl_timeout_seconds", evdDefaultKubectlTimeout, 1, 120)
	if err != nil {
		return nil, err
	}
	command := []string{kubectl}
	if kubeconfig != "" {
		command = append(command, "--kubeconfig="+kubeconfig)
	}
	command = append(command, fmt.Sprintf("--request-timeout=%ds", timeout))
	command = append(command, args...)
	return command, nil
}

func evdKubectlEnv(config M, home string) []string {
	env := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + home,
		"XDG_CACHE_HOME=" + filepath.Join(home, "cache"),
		"XDG_CONFIG_HOME=" + filepath.Join(home, "config"),
		"LANG=C",
		"LC_ALL=C",
	}
	if kubeconfig := evdConfigString(config, "kubeconfig", ""); kubeconfig != "" {
		env = append(env, "KUBECONFIG="+kubeconfig)
	}
	return env
}

type evdLimitedBuffer struct {
	builder  strings.Builder
	limit    int
	exceeded bool
}

func (b *evdLimitedBuffer) Write(data []byte) (int, error) {
	if b.builder.Len()+len(data) > b.limit {
		b.exceeded = true
		remaining := b.limit - b.builder.Len()
		if remaining > 0 {
			b.builder.Write(data[:remaining])
		}
		return len(data), nil
	}
	return b.builder.Write(data)
}

func (b *evdLimitedBuffer) String() string { return b.builder.String() }

func evdRunKubectlImpl(args []string, config M, home string, maxBytes, timeout int) (any, string) {
	kubectl := evdConfigString(config, "kubectl", "/usr/bin/kubectl")
	if kubectl == "" {
		return nil, "kubectl path is not configured"
	}
	resolved := kubectl
	if !filepath.IsAbs(kubectl) {
		found, err := exec.LookPath(kubectl)
		if err != nil {
			return nil, "kubectl executable was not found"
		}
		resolved = found
	}
	kubeconfig := evdConfigString(config, "kubeconfig", "")
	if kubeconfig != "" {
		if _, err := os.Stat(kubeconfig); err != nil {
			return nil, "kubeconfig file does not exist"
		}
	}
	runConfig := M{}
	for key, value := range config {
		runConfig[key] = value
	}
	runConfig["kubectl"] = resolved
	command, err := evdKubectlCommand(runConfig, args)
	if err != nil {
		return nil, err.Error()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	process := exec.CommandContext(ctx, command[0], command[1:]...)
	process.Env = evdKubectlEnv(config, home)
	process.Stdin = nil
	stdout := &evdLimitedBuffer{limit: maxBytes}
	stderr := &evdLimitedBuffer{limit: maxBytes}
	process.Stdout = stdout
	process.Stderr = stderr
	runErr := process.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, "kubectl timed out"
	}
	if stdout.exceeded || stderr.exceeded {
		return nil, "kubectl output exceeded the configured size limit"
	}
	if runErr != nil {
		var exitError *exec.ExitError
		if !errors.As(runErr, &exitError) {
			return nil, fmt.Sprintf("kubectl could not start: %v", runErr)
		}
		message := strings.Split(strings.TrimSpace(strings.ToValidUTF8(stderr.String(), "\uFFFD")), "\n")
		detail := "no stderr"
		if len(message) > 0 {
			start := len(message) - 2
			if start < 0 {
				start = 0
			}
			parts := []string{}
			for _, line := range message[start:] {
				parts = append(parts, strings.TrimSpace(line))
			}
			detail = strings.Join(parts, " ")
			if runes := []rune(detail); len(runes) > 600 {
				detail = string(runes[:600])
			}
		}
		return nil, fmt.Sprintf("kubectl exited %d: %s", exitError.ExitCode(), detail)
	}
	raw := stdout.String()
	if !utf8.ValidString(raw) {
		return nil, "kubectl returned non-UTF-8 output"
	}
	var payload any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return nil, fmt.Sprintf("kubectl returned invalid JSON: %v", err)
	}
	return payload, ""
}

// ---------------------------------------------------------------------------
// Prometheus boundary

func evdPrometheusBaseURL(config M) (string, error) {
	raw, present := config["prometheus_url"]
	if !present {
		return "", evdErr("prometheus_url is not configured")
	}
	text, ok := raw.(string)
	if !ok || strings.TrimSpace(text) == "" {
		return "", evdErr("prometheus_url is not configured")
	}
	parsed, err := url.Parse(strings.TrimSpace(text))
	if err != nil || parsed == nil {
		return "", evdErr("prometheus_url must be an http(s) URL")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if (scheme != "http" && scheme != "https") || parsed.Hostname() == "" {
		return "", evdErr("prometheus_url must be an http(s) URL")
	}
	if parsed.User != nil {
		return "", evdErr("prometheus_url must not contain credentials")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", evdErr("prometheus_url must not contain a query or fragment")
	}
	base := scheme + "://" + parsed.Host + strings.TrimRight(parsed.Path, "/")
	return base, nil
}

func evdNewHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout: 3 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func evdReadBounded(response *http.Response, maxBytes int) ([]byte, error) {
	if contentLength := response.Header.Get("Content-Length"); contentLength != "" {
		if parsed, err := strconv.ParseInt(contentLength, 10, 64); err == nil && parsed > int64(maxBytes) {
			return nil, evdErr("Prometheus response exceeded the size limit")
		}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBytes {
		return nil, evdErr("Prometheus response exceeded the size limit")
	}
	return raw, nil
}

func evdPromQueryImpl(client *http.Client, baseURL, expression string, timeout, maxBytes int) (M, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	queryValues := url.Values{"query": []string{expression}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		baseURL+"/api/v1/query?"+queryValues.Encode(), nil)
	if err != nil {
		return nil, evdErr("Prometheus query request could not be built: %v", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "change-guard-evidence/1")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, evdErr("Prometheus returned HTTP %d", response.StatusCode)
	}
	raw, err := evdReadBounded(response, maxBytes)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(raw) {
		return nil, evdErr("Prometheus returned invalid JSON: invalid UTF-8")
	}
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, evdErr("Prometheus returned invalid JSON: %v", err)
	}
	mapping, ok := evdAsMap(payload)
	if !ok {
		return nil, evdErr("Prometheus returned a non-object response")
	}
	if mapping["status"] != "success" {
		errorText := evdPyStr(mapping["error"])
		if runes := []rune(errorText); len(runes) > 300 {
			errorText = string(runes[:300])
		}
		return nil, evdErr("Prometheus query failed: %s", errorText)
	}
	return mapping, nil
}

func evdPromAlertsImpl(client *http.Client, baseURL string, timeout, maxBytes int) ([]M, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/api/v1/alerts", nil)
	if err != nil {
		return nil, evdErr("Prometheus alerts request could not be built: %v", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "change-guard-evidence/1")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, evdErr("Prometheus alerts endpoint returned HTTP %d", response.StatusCode)
	}
	raw, err := evdReadBounded(response, maxBytes)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBytes {
		return nil, evdErr("Prometheus alerts response exceeded the size limit")
	}
	if !utf8.Valid(raw) {
		return nil, evdErr("Prometheus alerts returned invalid JSON: invalid UTF-8")
	}
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, evdErr("Prometheus alerts returned invalid JSON: %v", err)
	}
	mapping, ok := evdAsMap(payload)
	if !ok || mapping["status"] != "success" {
		return nil, evdErr("Prometheus alerts query failed")
	}
	data, _ := evdAsMap(mapping["data"])
	rawAlerts, ok := evdAsList(data["alerts"])
	if !ok {
		return nil, evdErr("Prometheus alerts response has no alerts list")
	}
	alerts := []M{}
	for index, raw := range rawAlerts {
		if index >= evdMaxAlerts {
			break
		}
		alert, ok := evdAsMap(raw)
		if !ok {
			continue
		}
		labels, _ := evdAsMap(alert["labels"])
		if labels == nil {
			labels = M{}
		}
		safeLabels := M{}
		for key, value := range labels {
			if evdSafeLabelKeys[evdPyStr(key)] {
				safeLabels[evdPyStr(key)] = evdPyStr(value)
			}
		}
		var state any
		if value, present := alert["state"]; present {
			state = value
		} else if value, present := alert["status"]; present {
			state = value
		} else {
			state = "firing"
		}
		alerts = append(alerts, M{
			"name":     evdPyStr(safeLabels["alertname"]),
			"state":    evdPyStr(state),
			"activeAt": evdNative(alert["activeAt"]),
			"labels":   safeLabels,
		})
	}
	return alerts, nil
}

type evdPoint struct {
	timestamp float64
	value     float64
}

func evdPromResultValues(payload M) ([]evdPoint, string) {
	data, ok := evdAsMap(payload["data"])
	if !ok {
		return nil, ""
	}
	resultType := evdPyStr(data["resultType"])
	result := data["result"]
	values := []evdPoint{}
	addPair := func(raw any) {
		pair, ok := evdAsList(raw)
		if !ok || len(pair) != 2 {
			return
		}
		timestamp, timestampOK := evdFloat(pair[0])
		value, valueOK := evdFloat(pair[1])
		if timestampOK && valueOK {
			values = append(values, evdPoint{timestamp: timestamp, value: value})
		}
	}
	switch resultType {
	case "vector":
		if seriesList, ok := evdAsList(result); ok {
			for _, raw := range seriesList {
				series, ok := evdAsMap(raw)
				if !ok {
					continue
				}
				addPair(series["value"])
			}
		}
	case "scalar":
		if resultMap, ok := evdAsMap(result); ok {
			addPair(resultMap["value"])
		}
	case "matrix":
		if seriesList, ok := evdAsList(result); ok {
			for _, raw := range seriesList {
				series, ok := evdAsMap(raw)
				if !ok {
					continue
				}
				points, ok := evdAsList(series["values"])
				if !ok || len(points) == 0 {
					continue
				}
				addPair(points[len(points)-1])
			}
		}
	}
	return values, resultType
}

func evdBoundedRaw(payload M) M {
	data, _ := evdAsMap(payload["data"])
	if data == nil {
		data = M{}
	}
	result := data["result"]
	boundedResult := result
	truncated := false
	if list, ok := evdAsList(result); ok && len(list) > 20 {
		boundedResult = list[:20]
		truncated = true
	}
	document := M{
		"status": payload["status"],
		"data": M{
			"resultType": data["resultType"],
			"result":     boundedResult,
		},
	}
	encoded, err := evdPythonJSON(document, false)
	if err != nil {
		encoded = `{"truncated":true}`
		truncated = true
	}
	if len(encoded) > evdMaxRawQueryBytes {
		cut := evdMaxRawQueryBytes - 20
		for cut > 0 && !utf8.RuneStart(encoded[cut]) {
			cut--
		}
		encoded = encoded[:cut]
		encoded += `,"truncated":true}`
		truncated = true
	}
	var decoded any
	if err := json.Unmarshal([]byte(encoded), &decoded); err != nil {
		decoded = M{"truncated": true}
	}
	resultMap, ok := evdAsMap(decoded)
	if !ok {
		resultMap = M{"truncated": true}
	}
	if truncated {
		resultMap["_truncated"] = true
	}
	return resultMap
}

// ---------------------------------------------------------------------------
// Collection

type evdSettings struct {
	namespace    string
	deployment   string
	kubectlTO    int
	promTO       int
	ttl          int
	maxKubeBytes int
	maxPromBytes int
}

func evdValidateCollectConfig(config M) (evdSettings, error) {
	namespace, err := evdSafeName(evdConfigString(config, "namespace", "demo"), "namespace")
	if err != nil {
		return evdSettings{}, err
	}
	deployment, err := evdSafeName(evdConfigString(config, "deployment", "demo"), "deployment")
	if err != nil {
		return evdSettings{}, err
	}
	kubectlTO, err := evdBoundedInt(config, "kubectl_timeout_seconds", evdDefaultKubectlTimeout, 1, 120)
	if err != nil {
		return evdSettings{}, err
	}
	promTO, err := evdBoundedInt(config, "prometheus_timeout_seconds", evdDefaultPrometheusTimeout, 1, 60)
	if err != nil {
		return evdSettings{}, err
	}
	ttl, err := evdBoundedInt(config, "evidence_ttl_seconds", 300, 1, 86400)
	if err != nil {
		return evdSettings{}, err
	}
	maxKubeBytes, err := evdBoundedInt(config, "kubectl_max_output_bytes",
		evdDefaultMaxResponseBytes, 4096, 128*1024*1024)
	if err != nil {
		return evdSettings{}, err
	}
	maxPromBytes, err := evdBoundedInt(config, "prometheus_max_response_bytes",
		evdDefaultMaxPromBytes, 4096, 16*1024*1024)
	if err != nil {
		return evdSettings{}, err
	}
	return evdSettings{
		namespace: namespace, deployment: deployment,
		kubectlTO: kubectlTO, promTO: promTO, ttl: ttl,
		maxKubeBytes: maxKubeBytes, maxPromBytes: maxPromBytes,
	}, nil
}

func evdDefaultMetrics() M {
	return M{
		"memory_working_set_bytes": nil,
		"request_rate":             nil,
		"error_ratio":              nil,
		"p95_seconds":              nil,
		"alerts":                   []M{},
		"source_timestamps":        M{},
	}
}

func evdErrorResult(startedAt float64, message string) M {
	return M{
		"schema_version": evdEvidenceVersion,
		"collected_at":   int64(evdNowFloat()),
		"errors":         []string{message},
		"nodes":          []M{},
		"deployment":     M{},
		"pods":           []M{},
		"metrics":        evdDefaultMetrics(),
		"capacity":       M{},
		"sources": M{
			"schema_version":        evdEvidenceVersion,
			"collection_started_at": int64(startedAt),
			"kubernetes": M{
				"kubeconfig_path": "", "commands": []any{}, "timestamps": M{},
			},
			"prometheus": M{
				"url": nil, "queries": M{}, "raw": M{},
			},
		},
	}
}

func evdTimestampFrom(values []evdPoint) (float64, bool) {
	best := 0.0
	found := false
	for _, point := range values {
		if point.value > 0 && point.value > best {
			best = point.value
			found = true
		}
	}
	return best, found
}

func evdNumberFrom(values []evdPoint) (float64, bool) {
	best := 0.0
	found := false
	for _, point := range values {
		if !found || point.value > best {
			best = point.value
			found = true
		}
	}
	return best, found
}

func evdSeriesCount(raw M) int {
	data, _ := evdAsMap(raw["data"])
	if data == nil {
		return 0
	}
	result := data["result"]
	if list, ok := evdAsList(result); ok {
		return len(list)
	}
	if evdTruthy(result) {
		return 1
	}
	return 0
}

func evdMaxPointByTimestamp(values []evdPoint) (evdPoint, bool) {
	if len(values) == 0 {
		return evdPoint{}, false
	}
	best := values[0]
	for _, point := range values[1:] {
		if point.timestamp > best.timestamp {
			best = point
		}
	}
	return best, true
}

func evdMaxPointByValue(values []evdPoint) (evdPoint, bool) {
	if len(values) == 0 {
		return evdPoint{}, false
	}
	best := values[0]
	for _, point := range values[1:] {
		if point.value > best.value {
			best = point
		}
	}
	return best, true
}

// Collect gathers real Kubernetes and Prometheus evidence using read-only calls.
func Collect(config M) M {
	startedAt := evdNowFloat()
	if config == nil {
		return evdErrorResult(startedAt, "evidence config must be a mapping")
	}
	settings, err := evdValidateCollectConfig(config)
	if err != nil {
		return evdErrorResult(startedAt, err.Error())
	}

	errorsList := []string{}
	errorSet := map[string]bool{}
	addError := func(message string) {
		text := strings.ReplaceAll(message, "\n", " ")
		text = strings.TrimSpace(text)
		if runes := []rune(text); len(runes) > 800 {
			text = string(runes[:800])
		}
		if text != "" && !errorSet[text] {
			errorSet[text] = true
			errorsList = append(errorsList, text)
		}
	}

	nodes := []M{}
	pods := []M{}
	deployment := M{}
	var capacity M
	nodesOK := false
	podsOK := false
	deploymentOK := false
	metrics := evdDefaultMetrics()
	promQueries := M{}
	rawQueries := M{}
	kubectlCommands := []any{}
	kubeTimestamps := M{}
	var promURL any = nil

	home, tempErr := os.MkdirTemp("", "change-guard-evidence-")
	if tempErr == nil {
		defer os.RemoveAll(home)
		if err := os.MkdirAll(filepath.Join(home, "cache"), 0700); err == nil {
			_ = os.MkdirAll(filepath.Join(home, "config"), 0700)
		}
	} else {
		addError(fmt.Sprintf("evidence collector could not create a temporary home: %v", tempErr))
		home = ""
	}

	nodesArgs := []string{"get", "nodes", "-o", "json"}
	nodesPayload, kubectlErr := evdRunKubectl(nodesArgs, config, home, settings.maxKubeBytes, settings.kubectlTO)
	kubectlCommands = append(kubectlCommands, []any{"get", "nodes", "-o", "json"})
	if kubectlErr != "" {
		addError(kubectlErr)
	} else if payload, ok := evdAsMap(nodesPayload); ok {
		if items, ok := evdAsList(payload["items"]); ok {
			for index, item := range items {
				if index >= evdMaxNodes {
					break
				}
				node, ok := evdAsMap(item)
				if ok {
					nodes = append(nodes, evdNodeInfo(node))
				}
			}
		}
		nodesOK = true
		kubeTimestamps["nodes"] = evdNowFloat()
	}

	deploymentArgs := []string{"-n", settings.namespace, "get", "deployment", settings.deployment, "-o", "json"}
	deploymentPayload, kubectlErr := evdRunKubectl(deploymentArgs, config, home, settings.maxKubeBytes, settings.kubectlTO)
	kubectlCommands = append(kubectlCommands, []any{"-n", settings.namespace, "get", "deployment", settings.deployment, "-o", "json"})
	if kubectlErr != "" {
		addError(kubectlErr)
	} else if payload, ok := evdAsMap(deploymentPayload); ok {
		deployment = evdDeploymentInfo(payload)
		deploymentOK = true
		kubeTimestamps["deployment"] = evdNowFloat()
	}

	podsArgs := []string{"get", "pods", "--all-namespaces", "-o", "json"}
	podsPayload, kubectlErr := evdRunKubectl(podsArgs, config, home, settings.maxKubeBytes, settings.kubectlTO)
	kubectlCommands = append(kubectlCommands, []any{"get", "pods", "--all-namespaces", "-o", "json"})
	if kubectlErr != "" {
		addError(kubectlErr)
	} else if payload, ok := evdAsMap(podsPayload); ok {
		if items, ok := evdAsList(payload["items"]); ok {
			for index, item := range items {
				if index >= evdMaxPods {
					break
				}
				pod, ok := evdAsMap(item)
				if ok {
					pods = append(pods, evdPodInfo(pod))
				}
			}
		}
		podsOK = true
		kubeTimestamps["pods"] = evdNowFloat()
	}

	if nodesOK && podsOK {
		capacity = evdComputeCapacity(nodes, pods, addError)
	} else {
		if !nodesOK {
			addError("node capacity evidence is unavailable")
		}
		if !podsOK {
			addError("scheduled Pod evidence is unavailable")
		}
	}

	promBase, promErr := evdPrometheusBaseURL(config)
	if promErr != nil {
		addError(promErr.Error())
	} else {
		promURL = promBase
	}

	if promBase != "" {
		client := evdNewHTTPClient()
		defer client.CloseIdleConnections()
		selector := fmt.Sprintf(`namespace="%s",pod=~"%s-.*"`,
			settings.namespace, evdPyReEscape(settings.deployment))
		expressions := []struct {
			name string
			expr string
		}{
			{"memory_working_set_bytes",
				"max_over_time((sum by (pod) " +
					fmt.Sprintf(`(container_memory_working_set_bytes{%s,container!=""}))[15m:])`, selector)},
			{"request_rate",
				fmt.Sprintf(`sum(rate(demo_http_requests_total{namespace="%s",route="/work"}[5m]))`, settings.namespace)},
			{"error_numerator",
				fmt.Sprintf(`sum(rate(demo_http_requests_total{namespace="%s",route="/work",status=~"5.."}[5m]))`, settings.namespace)},
			{"p95_seconds",
				"histogram_quantile(0.95, sum by (le) " +
					fmt.Sprintf(`(rate(demo_http_request_duration_seconds_bucket{namespace="%s",route="/work"}[5m])))`, settings.namespace)},
			{"up", fmt.Sprintf(`max(up{%s})`, selector)},
			{"up_source", fmt.Sprintf(`max(timestamp(up{%s}))`, selector)},
			{"memory_source", fmt.Sprintf(`max(timestamp(container_memory_working_set_bytes{%s,container!=""}))`, selector)},
			{"request_counter_source",
				fmt.Sprintf(`max(timestamp(demo_http_requests_total{namespace="%s",route="/work"}))`, settings.namespace)},
			{"latency_bucket_source",
				fmt.Sprintf(`max(timestamp(demo_http_request_duration_seconds_bucket{namespace="%s",route="/work"}))`, settings.namespace)},
		}
		queryValues := M{}
		for _, item := range expressions {
			queryStarted := evdNowFloat()
			payload, queryErr := evdPromQuery(client, promBase, item.expr, settings.promTO, settings.maxPromBytes)
			if queryErr != nil {
				addError(fmt.Sprintf("Prometheus query %s failed: %v", item.name, queryErr))
				promQueries[item.name] = M{
					"expr": item.expr, "timestamp": int64(queryStarted), "status": "error",
				}
				continue
			}
			values, resultType := evdPromResultValues(payload)
			raw := evdBoundedRaw(payload)
			queryValues[item.name] = M{
				"values": values, "query_time": queryStarted,
				"raw": raw, "result_type": resultType,
			}
			promQueries[item.name] = M{
				"expr": item.expr, "timestamp": int64(queryStarted),
				"status": "success", "result_type": resultType, "series_count": len(values),
			}
			rawQueries[item.name] = raw
		}

		valuesFor := func(name string) []evdPoint {
			entry, ok := evdAsMap(queryValues[name])
			if !ok {
				return nil
			}
			values, _ := entry["values"].([]evdPoint)
			return values
		}
		rawFor := func(name string) M {
			entry, ok := evdAsMap(queryValues[name])
			if !ok {
				return M{}
			}
			raw, _ := entry["raw"].(M)
			return raw
		}

		upValue, upFound := evdNumberFrom(valuesFor("up"))
		upSourceTS, upSourceFound := evdTimestampFrom(valuesFor("up_source"))
		memorySourceTS, memorySourceFound := evdTimestampFrom(valuesFor("memory_source"))
		counterSourceTS, counterSourceFound := evdTimestampFrom(valuesFor("request_counter_source"))
		bucketSourceTS, bucketSourceFound := evdTimestampFrom(valuesFor("latency_bucket_source"))
		presence := M{
			"up": upSourceFound, "memory": memorySourceFound,
			"requests_total": counterSourceFound, "latency_bucket": bucketSourceFound,
		}
		if upFound {
			metrics["up"] = upValue
		} else {
			metrics["up"] = nil
		}
		metrics["series_presence"] = presence
		metrics["source_timestamps"].(M)["up"] = nil
		if upSourceFound {
			metrics["source_timestamps"].(M)["up"] = upSourceTS
		}
		if !upSourceFound {
			addError("target up metric is missing or has no raw scrape timestamp")
		}

		memorySamples := valuesFor("memory_working_set_bytes")
		if len(memorySamples) > 0 {
			point, _ := evdMaxPointByValue(memorySamples)
			if point.value >= 0 {
				metrics["memory_working_set_bytes"] = point.value
				if memorySourceFound {
					metrics["source_timestamps"].(M)["memory_working_set_bytes"] = memorySourceTS
				} else {
					addError("memory source series has no raw sample timestamp")
				}
			} else {
				addError("memory measurement is non-finite")
			}
		} else {
			addError("memory max_over_time query returned no samples")
		}
		if !memorySourceFound {
			addError("memory source series is missing")
		}

		rateSamples := valuesFor("request_rate")
		rateRaw := rawFor("request_rate")
		rateSeriesCount := evdSeriesCount(rateRaw)
		if len(rateSamples) > 0 {
			point, _ := evdMaxPointByTimestamp(rateSamples)
			if point.value < 0 {
				addError("request rate is negative")
			} else {
				metrics["request_rate"] = point.value
				if counterSourceFound {
					metrics["source_timestamps"].(M)["request_rate"] = counterSourceTS
				}
			}
		} else if queryStatus(promQueries, "request_rate") == "success" {
			if rateSeriesCount == 0 && counterSourceFound {
				metrics["request_rate"] = 0.0
				metrics["source_timestamps"].(M)["request_rate"] = counterSourceTS
			} else if rateSeriesCount > 0 {
				addError("request rate query returned a non-finite value")
			} else {
				addError("request counter series is missing; zero rate cannot be established")
			}
		}
		if metrics["request_rate"] != nil && !counterSourceFound {
			addError("request counter source series is missing")
		}

		rateValue, rateOK := evdFloatValue(metrics["request_rate"])
		errorQueryOK := queryStatus(promQueries, "error_numerator") == "success"
		errorSamples := valuesFor("error_numerator")
		errorSeriesCount := evdSeriesCount(rawFor("error_numerator"))
		if len(errorSamples) > 0 && rateOK && rateValue > 0 {
			point, _ := evdMaxPointByTimestamp(errorSamples)
			ratio := point.value / rateValue
			if !math.IsNaN(ratio) && !math.IsInf(ratio, 0) && ratio >= 0 && ratio <= 1 {
				metrics["error_ratio"] = ratio
				if counterSourceFound {
					metrics["source_timestamps"].(M)["error_ratio"] = counterSourceTS
				}
			} else {
				addError("error ratio is non-finite or outside [0,1]")
			}
		} else if errorQueryOK && rateOK && rateValue > 0 && errorSeriesCount == 0 {
			metrics["error_ratio"] = 0.0
			if counterSourceFound {
				metrics["source_timestamps"].(M)["error_ratio"] = counterSourceTS
			}
		} else if errorQueryOK && rateOK && rateValue > 0 {
			addError("error numerator query returned a non-finite value")
		} else if rateOK && rateValue <= 0 {
			metrics["error_ratio"] = nil
		} else if !errorQueryOK {
			addError("error ratio evidence is unavailable because the query failed")
		}

		p95Samples := valuesFor("p95_seconds")
		p95SeriesCount := evdSeriesCount(rawFor("p95_seconds"))
		sourceReady := upFound && upValue == 1 && upSourceFound && counterSourceFound && bucketSourceFound
		if bucketSourceFound {
			metrics["source_timestamps"].(M)["p95_seconds"] = bucketSourceTS
		}
		if len(p95Samples) > 0 {
			point, _ := evdMaxPointByTimestamp(p95Samples)
			if point.value >= 0 {
				metrics["p95_seconds"] = point.value
			} else {
				addError("p95 latency is non-finite")
			}
		} else if queryStatus(promQueries, "p95_seconds") != "success" {
			addError("p95 latency evidence is unavailable")
		} else if rateOK && rateValue == 0 && sourceReady && p95SeriesCount >= 0 {
			metrics["p95_seconds"] = nil
		} else if p95SeriesCount > 0 {
			addError("p95 latency query returned a non-finite value")
		} else if rateOK && rateValue == 0 {
			addError("p95 histogram source series is missing or target is not up")
		} else {
			addError("p95 latency query returned no samples at non-low traffic")
		}

		if rateOK && rateValue == 0 {
			if !counterSourceFound {
				addError("request counter source series is missing at zero rate")
			}
			if !bucketSourceFound {
				addError("latency histogram source series is missing at zero rate")
			}
			if !upFound || upValue != 1 || !upSourceFound {
				addError("target up scrape is missing or not healthy at zero rate")
			}
		}

		alerts, alertsErr := evdPromAlerts(client, promBase, settings.promTO, settings.maxPromBytes)
		if alertsErr != nil {
			addError(fmt.Sprintf("Prometheus alerts query failed: %v", alertsErr))
			promQueries["alerts"] = M{
				"endpoint": "/api/v1/alerts", "timestamp": int64(evdNowFloat()), "status": "error",
			}
		} else {
			metrics["alerts"] = alerts
			metrics["source_timestamps"].(M)["alerts"] = evdNowFloat()
			promQueries["alerts"] = M{
				"endpoint": "/api/v1/alerts", "timestamp": int64(evdNowFloat()),
				"status": "success", "count": len(alerts),
			}
		}
	}

	collectedAt := evdNowFloat()
	for key, timestampRaw := range metrics["source_timestamps"].(M) {
		timestamp, ok := evdFloatValue(timestampRaw)
		if !ok {
			addError(fmt.Sprintf("source timestamp for %s is invalid", key))
			continue
		}
		if collectedAt-timestamp > float64(settings.ttl) {
			addError(fmt.Sprintf("source timestamp for %s is stale", key))
		}
		if timestamp-collectedAt > evdClockSkewToleranceSeconds {
			addError(fmt.Sprintf("source timestamp for %s is in the future", key))
		}
	}

	if !deploymentOK && len(deployment) == 0 {
		deployment = M{}
		addError("deployment evidence is unavailable")
	}
	if metrics["memory_working_set_bytes"] == nil {
		addError("memory evidence is missing")
	}
	if metrics["request_rate"] == nil {
		addError("request rate evidence is missing")
	}
	if rate, ok := evdFloatValue(metrics["request_rate"]); ok && rate > 0.1 {
		if metrics["error_ratio"] == nil {
			addError("error ratio evidence is missing at non-low traffic")
		}
		if metrics["p95_seconds"] == nil {
			addError("p95 evidence is missing at non-low traffic")
		}
	}
	alertsTimestamp, alertsTimestampPresent := metrics["source_timestamps"].(M)["alerts"]
	if !alertsTimestampPresent || alertsTimestamp == nil {
		addError("alert evidence is missing")
	}
	if capacity == nil {
		addError("capacity evidence is missing")
	}

	if len(errorsList) > 50 {
		errorsList = errorsList[:50]
	}
	kubeTimestampsNative := M{}
	for key, value := range kubeTimestamps {
		if timestamp, ok := evdFloatValue(value); ok {
			kubeTimestampsNative[key] = int64(timestamp)
		}
	}
	capacityOut := capacity
	if capacityOut == nil {
		capacityOut = M{}
	}
	promURLOut := promURL
	sources := M{
		"schema_version":        evdEvidenceVersion,
		"collection_started_at": int64(startedAt),
		"kubernetes": M{
			"kubeconfig_path": evdConfigString(config, "kubeconfig", ""),
			"commands":        kubectlCommands,
			"timestamps":      kubeTimestampsNative,
		},
		"prometheus": M{
			"url": promURLOut, "queries": promQueries, "raw": rawQueries,
		},
	}
	return M{
		"schema_version": evdEvidenceVersion,
		"collected_at":   int64(collectedAt),
		"errors":         errorsList,
		"nodes":          nodes,
		"deployment":     deployment,
		"pods":           pods,
		"metrics":        metrics,
		"capacity":       capacityOut,
		"sources":        sources,
	}
}

func queryStatus(queries M, name string) string {
	entry, ok := evdAsMap(queries[name])
	if !ok {
		return ""
	}
	return evdPyStr(entry["status"])
}

// evdPyReEscape approximates Python re.escape for regex metacharacters used in
// fixed PromQL selectors.
func evdPyReEscape(text string) string {
	special := map[rune]bool{
		'(': true, ')': true, '[': true, ']': true, '{': true, '}': true,
		'?': true, '*': true, '+': true, '-': true, '|': true, '^': true,
		'$': true, '\\': true, '.': true, '&': true, '~': true, '#': true,
		' ': true, '\t': true, '\n': true, '\r': true, '\v': true, '\f': true,
	}
	var builder strings.Builder
	for _, r := range text {
		if special[r] {
			builder.WriteByte('\\')
		}
		builder.WriteRune(r)
	}
	return builder.String()
}
