package privacygateway

import "strings"

// Rehydrate replaces redacted placeholders with local-only raw values. This must
// only run in the private zone after external content passes response checking.
func Rehydrate(content string, bindings []PlaceholderBinding) string {
	result := content
	for _, binding := range bindings {
		if binding.Placeholder == "" || binding.RawValue == "" {
			continue
		}
		result = strings.ReplaceAll(result, binding.Placeholder, binding.RawValue)
	}
	return result
}
