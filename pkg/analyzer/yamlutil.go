package analyzer

import (
	"regexp"
	"strings"
)

// simpleYAMLMap parses a flat or shallow YAML document into a map of string keys
// to string values. This handles the common case of top-level key: value pairs
// found in agent configuration files (which are scrubbed and simplified in flares).
// For nested keys, it returns "parent.child" dotted paths.
// This is intentionally simple — no dependency on external YAML libraries.
func simpleYAMLMap(data []byte) map[string]string {
	result := make(map[string]string)
	lines := strings.Split(string(data), "\n")

	var currentParent string
	parentIndent := -1

	for _, line := range lines {
		// Skip comments and empty lines
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Detect indentation
		indent := len(line) - len(strings.TrimLeft(line, " "))

		// Parse key: value
		colonIdx := strings.Index(trimmed, ":")
		if colonIdx < 0 {
			continue
		}

		key := strings.TrimSpace(trimmed[:colonIdx])
		value := strings.TrimSpace(trimmed[colonIdx+1:])

		// Remove quotes from value
		value = strings.Trim(value, `"'`)

		if indent == 0 {
			// Top-level key
			currentParent = key
			parentIndent = 0
			if value != "" {
				result[key] = value
			}
		} else if indent > parentIndent && currentParent != "" {
			// Nested key
			fullKey := currentParent + "." + key
			if value != "" {
				result[fullKey] = value
			}
		}
	}

	return result
}

// yamlHasKey checks if a YAML document has a specific top-level key.
func yamlHasKey(data []byte, key string) bool {
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `\s*:`)
	return re.Match(data)
}

// yamlGetValue gets a top-level value from a YAML document.
func yamlGetValue(data []byte, key string) (string, bool) {
	// Use [ \t]* instead of \s* after colon to avoid consuming newlines
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `[ \t]*:[ \t]*(.*)$`)
	m := re.FindSubmatch(data)
	if len(m) > 1 {
		val := strings.TrimSpace(string(m[1]))
		val = strings.Trim(val, `"'`)
		return val, true
	}
	return "", false
}

// yamlGetNestedValue gets a nested value like "parent.child" from YAML.
func yamlGetNestedValue(data []byte, parent, child string) (string, bool) {
	content := string(data)
	// Find the parent section
	parentRe := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(parent) + `\s*:\s*$`)
	loc := parentRe.FindStringIndex(content)
	if loc == nil {
		return "", false
	}

	// Search in the indented block after the parent
	remaining := content[loc[1]:]
	lines := strings.Split(remaining, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Check if we've left the indented block
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 && trimmed != "" {
			break // Back to top level
		}

		colonIdx := strings.Index(trimmed, ":")
		if colonIdx < 0 {
			continue
		}
		k := strings.TrimSpace(trimmed[:colonIdx])
		if k == child {
			v := strings.TrimSpace(trimmed[colonIdx+1:])
			v = strings.Trim(v, `"'`)
			return v, true
		}
	}
	return "", false
}

// yamlCountListItems counts the number of items in a YAML list under a key.
func yamlCountListItems(data []byte, key string) int {
	content := string(data)
	keyRe := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `\s*:\s*$`)
	loc := keyRe.FindStringIndex(content)
	if loc == nil {
		// Check inline list
		inlineRe := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(key) + `\s*:\s*\[(.+)\]`)
		if m := inlineRe.FindStringSubmatch(content); len(m) > 1 {
			return len(strings.Split(m[1], ","))
		}
		return 0
	}

	remaining := content[loc[1]:]
	lines := strings.Split(remaining, "\n")
	count := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 && trimmed != "" {
			break
		}
		if strings.HasPrefix(trimmed, "- ") {
			count++
		}
	}
	return count
}
