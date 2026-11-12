package guard

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"regexp"
)

func LoadConfig(path string) (M, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 1024*1024 {
		return nil, errors.New("config exceeds 1 MiB")
	}
	var c M
	if err = yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("invalid config YAML: %w", err)
	}
	if c == nil {
		return nil, errors.New("config must contain a mapping")
	}
	for _, key := range []string{"namespace", "deployment", "release_name", "argocd_namespace", "argo_application"} {
		if v, ok := c[key]; ok {
			if !regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`).MatchString(Str(v)) {
				return nil, fmt.Errorf("invalid %s", key)
			}
		}
	}
	return c, nil
}
