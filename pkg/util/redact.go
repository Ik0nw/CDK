package util

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
)

var (
	jwtLikePattern  = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	secretKVKey     = regexp.MustCompile(`(?i)(token|secret|password|passwd|authorization|access[_-]?key|api[_-]?key|private[_-]?key)`)
	secretKVPattern = regexp.MustCompile(`(?i)\b(token|secret|password|passwd|authorization|access[_-]?key|api[_-]?key|private[_-]?key)\b\s*[:=]\s*([^\s,;]+)`)
)

func HashPrefix(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", sum[:6])
}

func RedactedValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "<redacted:empty>"
	}
	return "<redacted:" + HashPrefix(value) + ">"
}

func RedactSensitive(value string) string {
	out := jwtLikePattern.ReplaceAllStringFunc(value, RedactedValue)
	out = secretKVPattern.ReplaceAllStringFunc(out, func(match string) string {
		parts := regexp.MustCompile(`[:=]`).Split(match, 2)
		if len(parts) != 2 {
			return RedactedValue(match)
		}
		sep := "="
		if strings.Contains(match, ":") && !strings.Contains(match, "=") {
			sep = ":"
		}
		return strings.TrimSpace(parts[0]) + sep + RedactedValue(parts[1])
	})
	return out
}

func RedactEnvLine(env string) string {
	key, value, ok := strings.Cut(env, "=")
	if !ok {
		return RedactSensitive(env)
	}
	return key + "=" + RedactedValue(value)
}
