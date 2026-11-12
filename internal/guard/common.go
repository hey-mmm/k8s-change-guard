package guard

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const Version = "0.3.2"
const RuleVersion = "go-2026-11-12.1"

type M = map[string]any

func Obj(v any) M {
	if m, ok := v.(map[string]any); ok && m != nil {
		return m
	}
	return M{}
}
func Arr(v any) []any {
	switch a := v.(type) {
	case []any:
		return a
	case []M:
		out := make([]any, len(a))
		for i, m := range a {
			out[i] = m
		}
		return out
	case []string:
		out := make([]any, len(a))
		for i, s := range a {
			out[i] = s
		}
		return out
	}
	return nil
}
func Str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
func Num(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case int32:
		return float64(n)
	case uint64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	}
	return 0
}
func Bool(v any) bool { b, _ := v.(bool); return b }
func Get(v any, path ...string) any {
	for _, p := range path {
		switch node := v.(type) {
		case map[string]any:
			v = node[p]
		case []any:
			i, e := strconv.Atoi(p)
			if e != nil || i < 0 || i >= len(node) {
				return nil
			}
			v = node[i]
		case []M:
			i, e := strconv.Atoi(p)
			if e != nil || i < 0 || i >= len(node) {
				return nil
			}
			v = node[i]
		default:
			return nil
		}
	}
	return v
}
func S(v any, path ...string) string  { return Str(Get(v, path...)) }
func N(v any, path ...string) float64 { return Num(Get(v, path...)) }
func B(v any, path ...string) bool    { return Bool(Get(v, path...)) }
func Clone(v M) M {
	b, e := CanonicalJSON(v)
	if e != nil {
		return M{}
	}
	var out M
	if json.Unmarshal(b, &out) != nil {
		return M{}
	}
	return out
}
func CanonicalJSON(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'}), nil
}
func Hash(v any) string {
	b, e := CanonicalJSON(v)
	if e != nil {
		return ""
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func Now() int64 { return time.Now().Unix() }
func CfgString(c M, key, fallback string) string {
	if s, ok := c[key].(string); ok {
		return s
	}
	return fallback
}
func CfgNum(c M, key string, fallback float64) float64 {
	v, ok := c[key]
	if !ok {
		return fallback
	}
	switch v.(type) {
	case int, int32, int64, float32, float64, json.Number:
		n := Num(v)
		if !math.IsNaN(n) && !math.IsInf(n, 0) {
			return n
		}
	}
	return fallback
}
func ReadJSON(path string) (M, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, 16*1024*1024+1))
	if e != nil {
		return nil, e
	}
	if len(data) > 16*1024*1024 {
		return nil, errors.New("JSON input exceeds limit")
	}
	var out M
	if e = json.Unmarshal(data, &out); e != nil {
		return nil, e
	}
	if out == nil {
		return nil, errors.New("JSON input must be an object")
	}
	return out, nil
}
func WriteJSON(path string, value any) error {
	data, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if e = os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(dir, ".guard-*.tmp")
	if e != nil {
		return e
	}
	temp := f.Name()
	defer os.Remove(temp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(temp, path)
}
func Token(config M, prefix string) (string, error) {
	var value string
	if path := CfgString(config, prefix+"_token_file", ""); path != "" {
		data, e := os.ReadFile(path)
		if e != nil {
			return "", fmt.Errorf("cannot read %s credential file", prefix)
		}
		if len(data) > 16384 {
			return "", errors.New("credential exceeds limit")
		}
		value = strings.TrimSpace(strings.TrimPrefix(string(data), "\ufeff"))
	} else {
		env := CfgString(config, prefix+"_token_env", map[string]string{"github": "GITHUB_TOKEN", "deepseek": "DEEPSEEK_API_KEY"}[prefix])
		value = strings.TrimSpace(os.Getenv(env))
	}
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("invalid or missing %s credential", prefix)
	}
	return value, nil
}
