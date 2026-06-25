package evaluate

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/cdk-team/CDK/pkg/util"
)

const (
	ProfileBasic      = "basic"
	ProfileExtended   = "extended"
	ProfileAdditional = "additional"
)

// Context carries shared dependencies for evaluation checks.
type Context struct {
	Logger *log.Logger

	// Env holds the preflight environment detection result.  Populated
	// automatically by Evaluator.RunProfile if nil; tests may inject one.
	Env *Env

	// NoGating disables prereq-based skipping (the --no-gating CLI flag).
	NoGating bool

	// Skipped accumulates skip reasons during the profile run.  Read via
	// printSkipSummary once profile finishes.
	Skipped []SkipReason

	// ran counts checks that actually executed.  Incremented in
	// Category.run; reset in RunProfile.
	ran int
}

// SkipReason records a check that was not run and which prereqs were
// missing.  Unknown prereq names appear as "<name>?" (trailing qmark)
// per MissingPrereqs contract.
type SkipReason struct {
	CheckID string
	Missing []string
}

// NewContext constructs a Context instance with a default logger when none is provided.
func NewContext(logger *log.Logger) *Context {
	if logger == nil {
		logger = log.New(os.Stderr, "", log.LstdFlags)
	}
	return &Context{Logger: logger}
}

// CheckFunc represents the executable unit for a security check.
type CheckFunc func(*Context) error

// Check describes an actionable evaluation task.
type Check struct {
	ID          string
	Title       string
	Description string
	Run         CheckFunc
	// Prereqs are the names of Env flags (see flagByName in env.go) that
	// must ALL be true for this check to execute.  Empty/nil means the
	// check runs unconditionally.
	Prereqs []string
}

func (c Check) execute(ctx *Context) error {
	if c.Run == nil {
		return nil
	}
	return c.Run(ctx)
}

// Category groups related checks under a shared heading.
type Category struct {
	ID     string
	Title  string
	Checks []Check
}

func (c Category) run(ctx *Context) {
	util.PrintH2(c.Title)
	logger := loggerFromContext(ctx)
	for _, check := range c.Checks {
		label := readableCheckLabel(check)
		if !ctx.NoGating {
			missing := MissingPrereqs(ctx.Env, check.Prereqs)
			if len(missing) > 0 {
				ctx.Skipped = append(ctx.Skipped, SkipReason{
					CheckID: check.ID,
					Missing: missing,
				})
				// Log "unknown prereq" entries distinctly.
				for _, m := range missing {
					if strings.HasSuffix(m, "?") {
						logger.Printf("WARNING: check %s has unknown prereq %q; skipping",
							label, strings.TrimSuffix(m, "?"))
					}
				}
				logger.Printf("skip %s: prereqs not met: %v", label, missing)
				continue
			}
		}
		if err := check.execute(ctx); err != nil {
			logger.Printf("check %s failed: %v", label, err)
		}
		ctx.ran++
	}
}

// Profile combines categories into a runnable unit.
type Profile struct {
	ID         string
	Title      string
	Categories []Category
}

func (p Profile) run(ctx *Context) {
	for _, category := range p.Categories {
		category.run(ctx)
	}
}

// Evaluator coordinates profile registration and execution.
type Evaluator struct {
	profiles map[string]Profile
}

// NewEvaluator returns an Evaluator with the default profiles registered.
func NewEvaluator() *Evaluator {
	e := &Evaluator{profiles: make(map[string]Profile)}
	for _, profile := range defaultProfiles() {
		e.RegisterProfile(profile)
	}
	return e
}

// RegisterProfile adds or replaces a profile definition.
func (e *Evaluator) RegisterProfile(profile Profile) {
	if e.profiles == nil {
		e.profiles = make(map[string]Profile)
	}
	e.profiles[profile.ID] = profile
}

// Profile returns a copy of the profile and a boolean indicating whether it exists.
func (e *Evaluator) Profile(id string) (Profile, bool) {
	profile, ok := e.profiles[id]
	return profile, ok
}

// Profiles returns the registered profiles sorted by their identifier.
func (e *Evaluator) Profiles() []Profile {
	out := make([]Profile, 0, len(e.profiles))
	for _, profile := range e.profiles {
		out = append(out, profile)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

// RunProfile executes every category within the selected profile.
func (e *Evaluator) RunProfile(id string, ctx *Context) error {
	profile, ok := e.profiles[id]
	if !ok {
		return fmt.Errorf("unknown profile %q", id)
	}
	if ctx == nil {
		ctx = NewContext(nil)
	}
	ctx.ran = 0
	ctx.Skipped = nil
	if ctx.Env == nil {
		ctx.Env = DetectEnv()
	}
	profile.run(ctx)
	printSkipSummary(ctx)
	return nil
}

func loggerFromContext(ctx *Context) *log.Logger {
	if ctx != nil && ctx.Logger != nil {
		return ctx.Logger
	}
	return log.Default()
}

func readableCheckLabel(check Check) string {
	if check.ID != "" {
		return fmt.Sprintf("%s (%s)", check.Title, check.ID)
	}
	return check.Title
}

// printSkipSummary emits a one-line summary of skipped checks to stdout.
// It also needs the total number of checks that actually ran; that count
// is tracked on Context.Ran (see Category.run's execute branch below).
func printSkipSummary(ctx *Context) {
	if ctx == nil {
		return
	}
	// Increment counter in Category.run → add a Ran field to Context.
	// (We patch Context once more below.)
	ran := ctx.ran
	total := ran + len(ctx.Skipped)
	if total == 0 {
		return
	}
	counts := map[string]int{}
	for _, s := range ctx.Skipped {
		for _, m := range s.Missing {
			counts[m]++
		}
	}
	pairs := make([]string, 0, len(counts))
	for k, v := range counts {
		pairs = append(pairs, fmt.Sprintf("%s×%d", k, v))
	}
	sort.Strings(pairs)
	fmt.Fprintf(os.Stdout,
		"[✓] %d checks ran, [⏭] %d skipped (missing: %s)\n",
		ran, len(ctx.Skipped), strings.Join(pairs, ", "))
}
