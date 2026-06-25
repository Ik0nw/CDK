package evaluate

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"os"
	"strings"
	"testing"
)

func newTestContext() (*Context, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	ctx := NewContext(log.New(buf, "", 0))
	return ctx, buf
}

// TestEngine_GatingSkipsMissingPrereqs builds a mini profile with 2
// checks (one gated, one not) and asserts behaviour for both missing and
// satisfied prereqs.
func TestEngine_GatingSkipsMissingPrereqs(t *testing.T) {
	ran := map[string]int{}
	mkCheck := func(id string, prereqs []string) Check {
		return Check{
			ID:      id,
			Title:   "check " + id,
			Prereqs: prereqs,
			Run: func(c *Context) error {
				ran[id]++
				return nil
			},
		}
	}

	// Scenario A: HasDockerSock=false → check_a SKIPPED, check_b runs.
	ctx, _ := newTestContext()
	ctx.Env = &Env{InContainer: true, HasDockerSock: false}
	cat := Category{
		ID:    "demo",
		Title: "Demo",
		Checks: []Check{
			mkCheck("check_a", []string{"InContainer", "HasDockerSock"}),
			mkCheck("check_b", []string{"InContainer"}),
		},
	}
	profile := Profile{ID: "test", Title: "t", Categories: []Category{cat}}
	ev := &Evaluator{profiles: map[string]Profile{"test": profile}}
	if err := ev.RunProfile("test", ctx); err != nil {
		t.Fatalf("RunProfile: %v", err)
	}
	if ran["check_a"] != 0 {
		t.Errorf("check_a should not have run (HasDockerSock=false), ran %d times", ran["check_a"])
	}
	if ran["check_b"] != 1 {
		t.Errorf("check_b should have run once, got %d", ran["check_b"])
	}
	if len(ctx.Skipped) != 1 || ctx.Skipped[0].CheckID != "check_a" {
		t.Errorf("expected 1 skip (check_a), got %+v", ctx.Skipped)
	}
	// Summary includes missing prereq mention.
	if !strings.Contains(ctx.Skipped[0].Missing[0], "HasDockerSock") {
		t.Errorf("skip missing field = %v, want HasDockerSock", ctx.Skipped[0].Missing)
	}

	// Scenario B: flip flags → check_a runs too.
	ran = map[string]int{}
	ctx2, _ := newTestContext()
	ctx2.Env = &Env{InContainer: true, HasDockerSock: true}
	ev2 := &Evaluator{profiles: map[string]Profile{"test": profile}}
	if err := ev2.RunProfile("test", ctx2); err != nil {
		t.Fatalf("RunProfile B: %v", err)
	}
	if ran["check_a"] != 1 || ran["check_b"] != 1 {
		t.Errorf("both checks should run when prereqs met; got %+v", ran)
	}
	if len(ctx2.Skipped) != 0 {
		t.Errorf("no skips expected, got %+v", ctx2.Skipped)
	}
}

// TestEngine_NoGatingFlag runs everything regardless.
func TestEngine_NoGatingFlag(t *testing.T) {
	called := 0
	cat := Category{
		ID:    "demo",
		Title: "D",
		Checks: []Check{{
			ID:      "x",
			Title:   "x",
			Prereqs: []string{"InCloud", "Privileged"}, // all absent by default
			Run:     func(c *Context) error { called++; return nil },
		}},
	}
	profile := Profile{ID: "test", Categories: []Category{cat}}

	// Default: skipped
	ctx, _ := newTestContext()
	ctx.Env = &Env{}
	ev := &Evaluator{profiles: map[string]Profile{"test": profile}}
	_ = ev.RunProfile("test", ctx)
	if called != 0 {
		t.Errorf("expected 0 calls when gating active, got %d", called)
	}

	// --no-gating: runs
	called = 0
	ctx2, _ := newTestContext()
	ctx2.NoGating = true
	ctx2.Env = &Env{}
	ev2 := &Evaluator{profiles: map[string]Profile{"test": profile}}
	_ = ev2.RunProfile("test", ctx2)
	if called != 1 {
		t.Errorf("expected 1 call with NoGating, got %d", called)
	}
}

// TestEngine_UnknownPrereqFailClosed confirms unknown prereq name "?"
// suffix in Missing list and the check is NOT executed.
func TestEngine_UnknownPrereqFailClosed(t *testing.T) {
	called := 0
	cat := Category{
		ID: "demo", Title: "D",
		Checks: []Check{{
			ID: "x", Title: "x",
			Prereqs: []string{"WeirdMagicFlag"},
			Run:     func(c *Context) error { called++; return nil },
		}},
	}
	profile := Profile{ID: "test", Categories: []Category{cat}}
	ctx, buf := newTestContext()
	ctx.Env = &Env{InContainer: true}
	ev := &Evaluator{profiles: map[string]Profile{"test": profile}}
	_ = ev.RunProfile("test", ctx)
	if called != 0 {
		t.Errorf("unknown-prereq check must not run, called=%d", called)
	}
	if !strings.Contains(ctx.Skipped[0].Missing[0], "WeirdMagicFlag") {
		t.Errorf("missing should include WeirdMagicFlag, got %+v", ctx.Skipped)
	}
	// Logger should have emitted WARNING line.
	if !strings.Contains(buf.String(), "WARNING") ||
		!strings.Contains(buf.String(), "WeirdMagicFlag") {
		t.Errorf("logger should warn about unknown prereq. got log: %q", buf.String())
	}
}

// captureStdout returns all bytes written to os.Stdout during fn().
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	_ = w.Close()
	return <-done
}

func TestEngine_JSONOutput(t *testing.T) {
	ran := map[string]int{}
	mkCheck := func(id string, prereqs []string, errOut error) Check {
		return Check{
			ID:          id,
			Title:       "check " + id,
			Description: "desc-" + id,
			Prereqs:     prereqs,
			Run: func(c *Context) error {
				ran[id]++
				log.Printf("check %s printed something", id)
				return errOut
			},
		}
	}
	cat := Category{
		ID:    "demo",
		Title: "Demo Category",
		Checks: []Check{
			mkCheck("ok", []string{"InContainer"}, nil),
			mkCheck("skip", []string{"Privileged"}, nil),
		},
	}
	profile := Profile{ID: "test_json", Title: "TJ", Categories: []Category{cat}}
	ev := &Evaluator{profiles: map[string]Profile{"test_json": profile}}

	ctx, _ := newTestContext()
	ctx.JSON = true
	ctx.Env = &Env{InContainer: true}

	raw := captureStdout(t, func() {
		if err := ev.RunProfile("test_json", ctx); err != nil {
			t.Fatalf("RunProfile JSON: %v", err)
		}
	})

	var rep JSONReport
	if err := json.Unmarshal([]byte(raw), &rep); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput=%q", err, raw)
	}
	if rep.Version != 1 || rep.Tool != "cdk" {
		t.Errorf("envelope metadata: %+v", rep)
	}
	if rep.Profile.ID != "test_json" {
		t.Errorf("profile id = %q", rep.Profile.ID)
	}
	if rep.Ran != 1 || rep.Skipped != 1 {
		t.Errorf("ran/skipped counts = %d/%d want 1/1", rep.Ran, rep.Skipped)
	}
	if rep.Env == nil || !rep.Env.InContainer {
		t.Errorf("env not propagated: %+v", rep.Env)
	}
	if len(rep.Categories) != 1 {
		t.Fatalf("categories count = %d want 1", len(rep.Categories))
	}
	if rep.Categories[0].ID != "demo" {
		t.Errorf("cat id = %q", rep.Categories[0].ID)
	}
	checks := rep.Categories[0].Checks
	if len(checks) != 2 {
		t.Fatalf("checks count = %d want 2", len(checks))
	}
	for _, c := range checks {
		switch c.ID {
		case "ok":
			if c.Ran == nil || c.Skipped != nil {
				t.Errorf("check ok: expected ran=true got %+v", c)
			} else if !strings.Contains(c.Ran.Output, "check ok printed something") {
				t.Errorf("check ok output missing capture: %q", c.Ran.Output)
			}
		case "skip":
			if c.Skipped == nil || c.Ran != nil {
				t.Errorf("check skip: expected skipped=true got %+v", c)
			} else if len(c.Skipped.MissingPrereqs) != 1 ||
				c.Skipped.MissingPrereqs[0] != "Privileged" {
				t.Errorf("check skip missing_prereqs = %v", c.Skipped.MissingPrereqs)
			}
		default:
			t.Errorf("unexpected check id %q", c.ID)
		}
	}
	if rep.Summary["Privileged"] != 1 {
		t.Errorf("summary tally: %+v want Privileged=1", rep.Summary)
	}
	if ran["ok"] != 1 || ran["skip"] != 0 {
		t.Errorf("side-effect counters wrong: %+v", ran)
	}
}
