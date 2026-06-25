package evaluate

import (
	"path/filepath"
	"testing"
)

// overrideEnvRoot installs a temporary directory as the root for all
// /proc /sys /etc reads inside env.go during a single test.
//
// Implementation note: detection helpers use a package-level `envRoot`
// variable (initialised to "/") as prefix for all absolute paths.
// overrideEnvRoot returns a cleanup func that restores it.
func overrideEnvRoot(t *testing.T, fixtureDir string) func() {
	t.Helper()
	orig := envRoot
	abs, err := filepath.Abs(fixtureDir)
	if err != nil {
		t.Fatalf("abs fixtureDir: %v", err)
	}
	envRoot = abs
	return func() { envRoot = orig }
}

// ensure envRoot variable compiles (defined in env.go).
var _ = envRoot

// ---- Tests are added in Task 2; initial file must compile. ----
func TestEnv_NoPanic(t *testing.T) {
	// DetectEnv on the *real* host (darwin) must not panic and should
	// yield all flags = false (we are not inside a Linux container).
	env := DetectEnv()
	if env == nil {
		t.Fatal("DetectEnv returned nil")
	}
	if env.InContainer {
		t.Logf("warning: darwin reports InContainer=true — double-check?")
	}
}

func TestMissingPrereqs_NilEnv(t *testing.T) {
	m := MissingPrereqs(nil, []string{"InContainer", "HasDockerSock"})
	if len(m) != 2 {
		t.Fatalf("expected 2 missing, got %v: %v", len(m), m)
	}
}

func TestMissingPrereqs_Known(t *testing.T) {
	env := &Env{InContainer: true, HasDockerSock: false}
	m := MissingPrereqs(env, []string{"InContainer", "HasDockerSock"})
	if len(m) != 1 || m[0] != "HasDockerSock" {
		t.Fatalf("want [HasDockerSock], got %v", m)
	}
}

func TestMissingPrereqs_Unknown(t *testing.T) {
	env := &Env{InContainer: true}
	m := MissingPrereqs(env, []string{"InContainer", "NoSuchFlag"})
	if len(m) != 1 || m[0] != "NoSuchFlag?" {
		t.Fatalf("want [NoSuchFlag?], got %v", m)
	}
}
