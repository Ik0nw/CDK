package util

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func WriteAuditManifest(kind, name, content string) string {
	safeKind := strings.ToLower(strings.ReplaceAll(kind, " ", "-"))
	safeName := strings.ToLower(strings.ReplaceAll(name, " ", "-"))
	out := fmt.Sprintf("cdk-audit-%s-%s-%d.json", safeKind, safeName, time.Now().Unix())
	if err := os.WriteFile(out, []byte(content), 0600); err != nil {
		fmt.Printf("\taudit manifest write failed: %v\n", err)
		return ""
	}
	fmt.Printf("\taudit manifest saved: %s\n", out)
	fmt.Printf("\tcleanup command: kubectl delete -f %s\n", out)
	return out
}
