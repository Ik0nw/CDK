package evaluate

import (
	"bytes"
	"log"
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
