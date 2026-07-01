package cli

import (
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"
)

var auditLogSetup bool

func setupAuditLog() {
	if auditLogSetup {
		return
	}
	auditLogSetup = true
	dir := os.Getenv("CDK_AUDIT_OUTPUT_DIR")
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0750); err != nil {
		log.Printf("audit log disabled: cannot create output dir %q: %v", dir, err)
		return
	}
	name := "cdk-audit-" + time.Now().UTC().Format("20060102T150405Z") + ".log"
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("audit log disabled: cannot open %q: %v", path, err)
		return
	}
	currentOut := log.Writer()
	if currentOut == nil {
		currentOut = os.Stderr
	}
	log.SetOutput(io.MultiWriter(currentOut, f))
	log.Printf("[audit] log_file=%s", path)
	log.Printf("[audit] start_time=%s", time.Now().UTC().Format(time.RFC3339))
	log.Printf("[audit] argv=%s", strings.Join(os.Args, " "))
	log.Printf("[audit] operator=%s auth_id=%s host=%s binary_sha256=%s",
		auditOperator(), envOrUnset("CDK_AUDIT_AUTH_ID"), auditHostname(), auditBinaryHash())
}

func auditOperator() string {
	if v := os.Getenv("CDK_RT_OPERATOR"); v != "" {
		return v
	}
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "unknown"
}

func auditHostname() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "unknown"
	}
	return host
}

func auditBinaryHash() string {
	exe, err := os.Executable()
	if err != nil {
		return "unknown"
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		return "unknown"
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func envOrUnset(key string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return "unset"
}
