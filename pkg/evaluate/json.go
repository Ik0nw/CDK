/*
Copyright 2022 The Authors of https://github.com/CDK-TEAM/CDK .

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package evaluate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// JSONReport is the top-level envelope for --json output.
//
// Design: existing checks write findings to plain stdout/stderr.
// Rather than forcing every 16 check files to adopt a new return-value
// contract (large diff, risky regressions), we capture stdout + stderr
// per category and per check into byte buffers and replay them into
// the "output" field of each JSON node.  This gives downstream
// consumers fully structured metadata (profile, env, per-check status)
// PLUS the exact human-readable evidence text that operators already
// know how to read.
//
// Fields are deliberately stable across versions.  Add new fields at
// the end; never remove or rename an existing field.
type JSONReport struct {
	Version    int             `json:"version"`           // schema version, bump on breaking change
	Tool       string          `json:"tool"`              // "cdk"
	Timestamp  time.Time       `json:"timestamp"`         // when the run started
	Profile    JSONProfileInfo `json:"profile"`           // which profile
	Env        *Env            `json:"env,omitempty"`     // preflight env flags + ids
	Categories []JSONCategory  `json:"categories"`        // category → checks
	Ran        int             `json:"ran"`               // checks actually executed
	Skipped    int             `json:"skipped"`           // prereq-gated skips
	Summary    map[string]int  `json:"summary,omitempty"` // per-missing-prereq tally, F33
}

// JSONProfileInfo identifies which profile produced the report.
type JSONProfileInfo struct {
	ID    string `json:"id"`
	Title string `json:"title,omitempty"`
}

// JSONCategory is one "category heading" bucket.
type JSONCategory struct {
	ID     string      `json:"id"`
	Title  string      `json:"title"`
	Output string      `json:"output,omitempty"` // heading + any framework-level prints for this cat
	Checks []JSONCheck `json:"checks"`
}

// JSONCheck records one check's execution.
// Exactly one of Skipped or Ran will be populated with non-zero data.
type JSONCheck struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	Prereqs     []string `json:"prereqs,omitempty"`

	// Skipped reasons; non-empty iff the check did not run.
	Skipped *JSONSkipped `json:"skipped"`

	// Execution outcome; non-nil iff the check ran.
	Ran *JSONRan `json:"ran"`
}

// JSONSkipped records prereq-gating decisions (F33 asks for names not just counts).
type JSONSkipped struct {
	MissingPrereqs []string `json:"missing_prereqs"` // unknown names suffixed "?"
}

// JSONRan records an executed check's runtime evidence.
type JSONRan struct {
	Error  string `json:"error"`  // if Run returned non-nil
	Output string `json:"output"` // merged stdout+stderr captured during the check
}

// JSON machinery lives in a single package-level struct because check
// bodies do not receive "write to json" callbacks — they print to OS
// fds directly.  We therefore swap os.Stdout / os.Stderr at the fd
// level around each check (and each category heading block), then
// merge the captured bytes into the corresponding report node.
//
// A global lock serialises check execution from the POV of the JSON
// collector even if, in future, checks go concurrent.  Today Category.run
// is strictly serial so the lock is mostly defensive.
type jsonCollector struct {
	mu sync.Mutex

	report *JSONReport

	// Per-check capture state.
	captureBuf    *bytes.Buffer
	captureStdout *os.File
	captureStderr *os.File
	origStdout    *os.File
	origStderr    *os.File
	// log output also goes somewhere — we re-point ctx.Logger AND the
	// default logger at captureBuf via an io.Writer adapter.  The
	// default-logger swap is global so we save/restore it too.
	origLogFlags  int
	origLogPrefix string
	origLogOut    io.Writer
}

var globalJSONCollector *jsonCollector

// beginJSON installs a fresh JSON collector and globally captures
// stdout/stderr/default-log output until endJSON returns the report.
// Must be called exactly once per RunProfile invocation that has
// ctx.JSON==true; paired with exactly one endJSON call.
func beginJSON(profileID, profileTitle string, env *Env) *jsonCollector {
	rep := &JSONReport{
		Version:   1,
		Tool:      "cdk",
		Timestamp: time.Now().UTC(),
		Profile:   JSONProfileInfo{ID: profileID, Title: profileTitle},
		Env:       env,
		Summary:   make(map[string]int),
	}
	jc := &jsonCollector{report: rep}
	jc.origStdout = os.Stdout
	jc.origStderr = os.Stderr
	jc.origLogFlags = log.Flags()
	jc.origLogPrefix = log.Prefix()
	jc.origLogOut = log.Writer()
	globalJSONCollector = jc
	return jc
}

// startCapture redirects os.Stdout + os.Stderr + default log writer
// into a fresh buffer; the buffer is returned to the caller so it can
// be drained into a report node via stopCapture.
func (jc *jsonCollector) startCapture() *bytes.Buffer {
	jc.mu.Lock()
	defer jc.mu.Unlock()

	buf := new(bytes.Buffer)
	jc.captureBuf = buf

	// Pipe pairs for stdout/stderr so we can drain them async into buf.
	rOut, wOut, err := os.Pipe()
	if err != nil {
		// fall back: write directly to buf; capture will be partial
		// but we must not crash.
		wOut = nil
		rOut = nil
		jc.teeDirect(buf)
		return buf
	}
	rErr, wErr, errE := os.Pipe()
	if errE != nil {
		_ = rOut.Close()
		_ = wOut.Close()
		jc.teeDirect(buf)
		return buf
	}
	jc.captureStdout = wOut
	jc.captureStderr = wErr
	os.Stdout = wOut
	os.Stderr = wErr
	log.SetOutput(io.MultiWriter(jc.origLogOut, buf))

	// Drain pipes into buf in background.  stopCapture closes the
	// write ends which terminates these goroutines.
	go drainPipe(rOut, buf)
	go drainPipe(rErr, buf)
	return buf
}

// teeDirect swaps to minimal non-pipe capture when pipe() fails.  We
// capture only log output (which is >80% of CDK's output) and let the
// small amount of fmt.Printf leak to original fds.
func (jc *jsonCollector) teeDirect(buf *bytes.Buffer) {
	log.SetOutput(io.MultiWriter(jc.origLogOut, buf))
}

func drainPipe(r *os.File, buf *bytes.Buffer) {
	_, _ = io.Copy(buf, r)
	_ = r.Close()
}

// stopCapture closes the capture pipes, restores os.Stdout/Stderr,
// resets the default logger, and returns the captured buffer.
func (jc *jsonCollector) stopCapture(buf *bytes.Buffer) string {
	jc.mu.Lock()
	defer jc.mu.Unlock()

	if jc.captureStdout != nil {
		_ = jc.captureStdout.Close()
		jc.captureStdout = nil
	}
	if jc.captureStderr != nil {
		_ = jc.captureStderr.Close()
		jc.captureStderr = nil
	}
	os.Stdout = jc.origStdout
	os.Stderr = jc.origStderr
	log.SetOutput(jc.origLogOut)
	log.SetFlags(jc.origLogFlags)
	log.SetPrefix(jc.origLogPrefix)

	s := buf.String()
	// Strip the per-frame trailing newline so JSON string consumers
	// don't see a trailing \\n in every node unless there was real
	// content.  Keep internal newlines intact.
	s = strings.TrimRight(s, "\r\n")
	return s
}

// addCategory appends a JSONCategory to the report and returns a
// pointer to it so callers can stuff Checks and Output.
func (jc *jsonCollector) addCategory(id, title, headingOutput string) *JSONCategory {
	jc.report.Categories = append(jc.report.Categories, JSONCategory{
		ID:     id,
		Title:  title,
		Output: headingOutput,
	})
	return &jc.report.Categories[len(jc.report.Categories)-1]
}

// finalize writes the summary and serialises the report to os.Stdout
// as a single JSON object.  Consumes jc; jc must not be used after.
func (jc *jsonCollector) finalize(ran int, skipped []SkipReason) ([]byte, error) {
	jc.report.Ran = ran
	jc.report.Skipped = len(skipped)
	// F33: emit per-prereq-name counts in summary too (consistent with
	// the text-mode summary line).
	for _, s := range skipped {
		for _, m := range s.Missing {
			jc.report.Summary[m]++
		}
	}
	out, err := json.MarshalIndent(jc.report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal json report: %w", err)
	}
	globalJSONCollector = nil
	return out, nil
}
