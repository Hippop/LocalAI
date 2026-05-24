package privacygateway

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Config extends built-in deterministic detectors with user/project-specific
// policy. It intentionally supports only deterministic rules.
type Config struct {
	CustomDetectors []CustomDetector `json:"custom_detectors,omitempty"`
	BlockKeywords   []string         `json:"block_keywords,omitempty"`
	MaskKeywords    []string         `json:"mask_keywords,omitempty"`
}

type CustomDetector struct {
	Name        string `json:"name"`
	Pattern     string `json:"pattern"`
	Level       string `json:"level"`
	Action      string `json:"action"`
	Placeholder string `json:"placeholder,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		return Config{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func NewPolicyEngineWithConfig(cfg Config) (*PolicyEngine, error) {
	scanner, err := NewScannerWithConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &PolicyEngine{Scanner: scanner}, nil
}

func NewScannerWithConfig(cfg Config) (*Scanner, error) {
	scanner := NewScanner()
	for _, keyword := range cfg.BlockKeywords {
		keyword = strings.TrimSpace(keyword)
		if keyword == "" {
			continue
		}
		scanner.detectors = append(scanner.detectors, detector{
			name:    "custom_block_keyword",
			level:   PrivacyLevelSensitive,
			action:  "block",
			block:   true,
			pattern: regexp.MustCompile(regexp.QuoteMeta(keyword)),
		})
	}
	for _, keyword := range cfg.MaskKeywords {
		keyword = strings.TrimSpace(keyword)
		if keyword == "" {
			continue
		}
		scanner.detectors = append(scanner.detectors, detector{
			name:        "custom_mask_keyword",
			level:       PrivacyLevelSensitive,
			action:      "placeholder",
			placeholder: "CUSTOM",
			pattern:     regexp.MustCompile(regexp.QuoteMeta(keyword)),
		})
	}
	for _, custom := range cfg.CustomDetectors {
		d, err := custom.toDetector()
		if err != nil {
			return nil, err
		}
		scanner.detectors = append(scanner.detectors, d)
	}
	return scanner, nil
}

func (c CustomDetector) toDetector() (detector, error) {
	name := strings.TrimSpace(c.Name)
	if name == "" {
		return detector{}, fmt.Errorf("custom detector name is required")
	}
	pattern := strings.TrimSpace(c.Pattern)
	if pattern == "" {
		return detector{}, fmt.Errorf("custom detector %s pattern is required", name)
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return detector{}, fmt.Errorf("custom detector %s pattern is invalid: %w", name, err)
	}
	action := strings.ToLower(strings.TrimSpace(c.Action))
	if action == "" {
		action = "placeholder"
	}
	if action != "placeholder" && action != "block" {
		return detector{}, fmt.Errorf("custom detector %s action must be placeholder or block", name)
	}
	level := parsePrivacyLevel(c.Level)
	placeholder := strings.TrimSpace(c.Placeholder)
	if placeholder == "" {
		placeholder = strings.ToUpper(name)
	}
	return detector{
		name:        name,
		level:       level,
		action:      action,
		placeholder: placeholder,
		pattern:     compiled,
		block:       action == "block",
	}, nil
}

func parsePrivacyLevel(value string) PrivacyLevel {
	switch strings.TrimSpace(value) {
	case string(PrivacyLevelSecret), "P4", "secret":
		return PrivacyLevelSecret
	case string(PrivacyLevelSensitive), "P3", "sensitive":
		return PrivacyLevelSensitive
	case string(PrivacyLevelPersonal), "P2", "personal":
		return PrivacyLevelPersonal
	case string(PrivacyLevelPreference), "P1", "preference":
		return PrivacyLevelPreference
	default:
		return PrivacyLevelSensitive
	}
}
