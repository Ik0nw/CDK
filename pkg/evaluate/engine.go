package evaluate

import (
	"bytes"
	"fmt"
	"log"
	"math/rand"
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

	// JSON enables structured JSON report output instead of the default
	// human-readable stdout/stderr stream.  The framework still prints
	// findings in real time (to original stdout/stderr); a single JSON
	// object is emitted at the end to stdout.
	JSON bool

	// Skipped accumulates skip reasons during the profile run.  Read via
	// printSkipSummary once profile finishes.
	Skipped []SkipReason

	// Stealth enables OPSEC-conscious behavior:
	//   - adds 15-45ms jitter between checks to avoid bursty I/O patterns
	//   - skips network probes (socket escape, K8s API) to reduce netflow visibility
	//   - skips eBPF/io_uring/landlock raw syscall probes to avoid eBPF trace visibility
	Stealth bool

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

func (c Category) run(ctx *Context, jc *jsonCollector, catOut *JSONCategory) {
	var headingOut string
	if jc != nil {
		// In JSON mode the heading text becomes catOut.Output and must
		// not leak before the JSON envelope.  Capture heading exactly
		// like per-check output.
		hBuf := jc.startCapture()
		util.PrintH2(c.Title)
		headingOut = jc.stopCapture(hBuf)
	} else {
		util.PrintH2(c.Title)
	}
	if catOut != nil {
		catOut.Output = headingOut
	}
	logger := loggerFromContext(ctx)

	// In stealth mode, randomize check order to avoid creating a
	// deterministic access pattern that HIDS/EDR behavioral analysis
	// can signature (e.g. "process always reads /proc/kallsyms then
	// /proc/modules then /dev/mem in that exact order").
	checks := c.Checks
	if ctx.Stealth {
		checks = make([]Check, len(c.Checks))
		copy(checks, c.Checks)
		shuffleChecks(checks)
	}

	for _, check := range checks {
		// Stealth mode: add jitter between checks to avoid bursty I/O
		// patterns that HIDS/EDR behavioral analysis flags.
		if ctx.Stealth {
			util.DefaultJitter()
		}

		label := readableCheckLabel(check)
		jsonCheck := JSONCheck{
			ID:          check.ID,
			Title:       check.Title,
			Description: check.Description,
			Prereqs:     append([]string(nil), check.Prereqs...),
		}

		// In stealth mode, skip checks that are too "loud": network probes,
		// raw syscall probes, etc.
		if ctx.Stealth && isStealthIncompatible(check.ID) {
			logger.Printf("skip %s: stealth mode (loud check suppressed)", label)
			ctx.Skipped = append(ctx.Skipped, SkipReason{
				CheckID: check.ID,
				Missing: []string{"stealth-mode"},
			})
			jsonCheck.Skipped = &JSONSkipped{MissingPrereqs: []string{"stealth-mode"}}
			if catOut != nil {
				catOut.Checks = append(catOut.Checks, jsonCheck)
			}
			continue
		}

		if !ctx.NoGating {
			missing := MissingPrereqs(ctx.Env, check.Prereqs)
			if len(missing) > 0 {
				ctx.Skipped = append(ctx.Skipped, SkipReason{
					CheckID: check.ID,
					Missing: missing,
				})
				for _, m := range missing {
					if strings.HasSuffix(m, "?") {
						logger.Printf("WARNING: check %s has unknown prereq %q; skipping",
							label, strings.TrimSuffix(m, "?"))
					}
				}
				logger.Printf("skip %s: prereqs not met: %v", label, missing)
				jsonCheck.Skipped = &JSONSkipped{MissingPrereqs: missing}
				if catOut != nil {
					catOut.Checks = append(catOut.Checks, jsonCheck)
				}
				continue
			}
		}

		var (
			runBuf *bytes.Buffer
			outStr string
		)
		if jc != nil {
			runBuf = jc.startCapture()
		}
		var runErr error
		if err := check.execute(ctx); err != nil {
			logger.Printf("check %s failed: %v", label, err)
			runErr = err
		}
		ctx.ran++
		if jc != nil {
			outStr = jc.stopCapture(runBuf)
		}
		jsonCheck.Ran = &JSONRan{Output: outStr}
		if runErr != nil {
			jsonCheck.Ran.Error = runErr.Error()
		}
		if catOut != nil {
			catOut.Checks = append(catOut.Checks, jsonCheck)
		}
	}
}

// Profile combines categories into a runnable unit.
type Profile struct {
	ID         string
	Title      string
	Categories []Category
}

func (p Profile) run(ctx *Context, jc *jsonCollector) {
	for _, category := range p.Categories {
		var catOut *JSONCategory
		if jc != nil {
			catOut = jc.addCategory(category.ID, category.Title, "")
		}
		category.run(ctx, jc, catOut)
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

	var jc *jsonCollector
	if ctx.JSON {
		jc = beginJSON(profile.ID, profile.Title, ctx.Env)
	}

	profile.run(ctx, jc)

	if jc != nil {
		// When JSON is on, printSkipSummary is absorbed into the JSON
		// envelope (report.Ran / report.Skipped / report.Summary); no
		// need for a separate text line.
		blob, err := jc.finalize(ctx.ran, ctx.Skipped)
		if err != nil {
			return err
		}
		// Emit the JSON object as the only structured output to stdout.
		// Keep trailing newline so operators piping to `jq` are happy.
		fmt.Fprintf(os.Stdout, "%s\n", blob)
	} else {
		printSkipSummary(ctx)
	}
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

// stealthIncompatibleChecks lists check IDs that are too "loud" for stealth
// mode.  These checks make network connections, raw syscalls that eBPF
// tracers flag, or other high-signal operations that increase the chance
// of HIDS/EDR detection.
//
// When ctx.Stealth is true, these checks are skipped with a "stealth-mode"
// prereq-missing reason, keeping the audit profile low-noise.
var stealthIncompatibleChecks = map[string]bool{
	// Network probes — connect to unix sockets, make HTTP requests
	"security.socket_escape":         true,
	"security.dbus_systemd_escape":   true,
	"k8s.privileged_service_account": true,
	"k8s.anonymous_login":            true,
	"cloud.metadata_api":             true,
	"dns.service_discovery":          true,

	// Raw syscall probes — visible in eBPF tracepoints
	"security.ebpf_recon":            true,
	"system.io_uring":                true,
	"security.landlock_deep":         true,
	"security.seccomp_deep_inspect":  true,
	"security.userns_escape":         true,
	"cgroups.escape_landscape":       true, // mkdir + cgroup.procs write

	// Execs child processes — visible in execve tracing
	"kernel.exploits":                true,
}

// isStealthIncompatible returns true if the given check ID is in the
// stealth-incompatible set.  These checks are suppressed when ctx.Stealth
// is true to keep the audit profile low-noise.
func isStealthIncompatible(checkID string) bool {
	return stealthIncompatibleChecks[checkID]
}

// shuffleChecks randomizes the order of checks in-place using Fisher-Yates.
// Used in stealth mode to avoid creating a deterministic file-access
// pattern that HIDS/EDR behavioral analysis can signature.
func shuffleChecks(checks []Check) {
	for i := len(checks) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		checks[i], checks[j] = checks[j], checks[i]
	}
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
