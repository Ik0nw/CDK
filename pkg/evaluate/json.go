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
	"io/ioutil"
	"log"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/fatih/color"
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
	captureStdout *os.File // memfd-backed fake stdout (or nil fallback)
	captureStderr *os.File // memfd-backed fake stderr (or nil fallback)
	origStdout    *os.File
	origStderr    *os.File
	// fatih/color has its own package-level Output/Error globals that
	// bypass the os.Stdout / os.Stderr variables we swap below.  Save and
	// restore them alongside the OS variables; write them to our pipe
	// writers during capture.
	origColorOutput io.Writer
	origColorError  io.Writer
	// log output also goes somewhere — we re-point ctx.Logger AND the
	// default logger at captureBuf via an io.Writer adapter.  The
	// default-logger swap is global so we save/restore it too.
	origLogFlags  int
	origLogPrefix string
	origLogOut    io.Writer

	// bufMu guards captureBuf against concurrent writers: stopCapture's
	// memfd-reader and the jcMutexWriter log adapter both append to it.
	// bytes.Buffer is NOT safe for concurrent writes; without the
	// mutex Go 1.16+ emits race-detector warnings and, in practice,
	// data gets silently truncated.
	bufMu sync.Mutex
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
	jc.origColorOutput = color.Output
	jc.origColorError = color.Error
	jc.origLogFlags = log.Flags()
	jc.origLogPrefix = log.Prefix()
	jc.origLogOut = log.Writer()
	globalJSONCollector = jc
	return jc
}

// startCapture redirects os.Stdout + os.Stderr + default log writer
// into a fresh buffer; the buffer is returned to the caller so it can
// be drained into a report node via stopCapture.
//
// Implementation note: we use memfd_create(2) anonymous-memory files,
// NOT os.Pipe() pipes, for capture.  Pipes have a critical flaw in
// this process: CDK's own CVE-2026-31431 proof-of-attempt probe does
// a ForkExec of CDK itself (a self-fork) to test the copy-fail kernel
// bug.  Fork-exec duplicates every fd in the parent, including any
// open pipe-write ends.  Even with FD_CLOEXEC flag set, fork() happens
// BEFORE execve() so children briefly inherit the fds — and more
// importantly, sibling processes that survive for any length of time
// keep the pipe's write-end referenced, which means the drain-reader
// goroutine never sees EOF, and stopCapture's drainWg.Wait() hangs
// forever.  That hang is 100% reproducible on the F34 check.
//
// memfd-backed files don't have this problem: they are regular
// anonymous files with no reader/writer lifecycle.  When the check
// returns we just lseek to offset 0 and read everything the check
// (and any subprocesses) wrote.  Sibling references to the same
// inode don't block us at all.
func (jc *jsonCollector) startCapture() *bytes.Buffer {
	jc.mu.Lock()
	defer jc.mu.Unlock()

	buf := new(bytes.Buffer)
	jc.captureBuf = buf

	memOut, err := memfdCreate("cdk-cap-stdout")
	if err != nil {
		jc.teeDirect(buf)
		return buf
	}
	memErr, err := memfdCreate("cdk-cap-stderr")
	if err != nil {
		_ = memOut.Close()
		jc.teeDirect(buf)
		return buf
	}
	jc.captureStdout = memOut
	jc.captureStderr = memErr
	// Swap os.Stdout / os.Stderr package-level variables so every
	// subsequent fmt.Print / fmt.Fprintf(os.Stdout, ...) call inside
	// the check body lands in the memfd.
	os.Stdout = memOut
	os.Stderr = memErr
	// fatih/color's own globals must be redirected too; they are
	// initialised once at package-import time to the ORIGINAL os.File
	// references, so reassigning os.Stdout alone does not redirect
	// fatih/color output.
	color.Output = memOut
	color.Error = memErr
	// Default-logger output: route through a mutex-protected adapter
	// that appends to captureBuf (shared with the memfd reader code in
	// stopCapture) and optionally tees to origLogOut for operators
	// that redirect stderr separately from JSON stdout.
	log.SetOutput(&jcMutexWriter{jc: jc, tee: jc.origLogOut})
	return buf
}

// memfdCreate wraps the Linux memfd_create(2) syscall with
// MFD_CLOEXEC set so exec'd subprocesses don't inherit the fd
// (fork still duplicates it, which is harmless for memfd capture
// and the whole point of using memfd instead of pipe).
//
// Note on syscall numbers: Go's deprecated syscall package only
// defines SYS_MEMFD_CREATE on linux/arm64.  For amd64, 386 and
// arm we use the raw NRs from linux/uapi/asm/unistd.h.
// Runtime detection (ENOSYS errno) covers unknown arches.
func memfdCreate(name string) (*os.File, error) {
	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	const MFD_CLOEXEC = 0x0001
	const MFD_ALLOW_SEALING = 0x0002 // unused, but harmless
	fd, _, errno := syscall.Syscall6(
		memfdCreateNR,
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(MFD_CLOEXEC|MFD_ALLOW_SEALING),
		0, 0, 0, 0,
	)
	if errno != 0 {
		return nil, fmt.Errorf("memfd_create(%q): %w", name, errno)
	}
	return os.NewFile(fd, name), nil
}

// jcMutexWriter serialises log-writer access to the capture buffer so it
// can safely share the buffer with stopCapture's memfd drain code.
type jcMutexWriter struct {
	jc  *jsonCollector
	tee io.Writer
}

func (w *jcMutexWriter) Write(p []byte) (int, error) {
	w.jc.bufMu.Lock()
	if w.jc.captureBuf != nil {
		w.jc.captureBuf.Write(p)
	}
	w.jc.bufMu.Unlock()
	if w.tee != nil {
		_, _ = w.tee.Write(p)
	}
	return len(p), nil
}

// teeDirect falls back to log-only capture when memfd creation fails
// (e.g. kernel < 3.17, or a seccomp profile blocking memfd_create on
// this architecture).  The check's fmt.Print output leaks to the
// original stdout/stderr; log lines (the vast majority of CDK's
// operator output) are still captured.
func (jc *jsonCollector) teeDirect(buf *bytes.Buffer) {
	log.SetOutput(&jcMutexWriter{jc: jc, tee: jc.origLogOut})
}

// stopCapture restores os.Stdout/Stderr, reads everything written
// into the two memfd capture files back into the shared capture
// buffer (under the buffer mutex, so concurrent log-writer writes
// don't interleave), then returns the concatenated string.
//
// If memfd wasn't available (teeDirect fallback) we still return the
// log-only contents of captureBuf so the report is not empty.
func (jc *jsonCollector) stopCapture(buf *bytes.Buffer) string {
	jc.mu.Lock()
	defer jc.mu.Unlock()

	// 1. Restore the global output variables *before* draining the
	// memfds so that drain-time logging (if any) does not scribble
	// into the capture window.
	if jc.captureStdout != nil {
		os.Stdout = jc.origStdout
	}
	if jc.captureStderr != nil {
		os.Stderr = jc.origStderr
	}
	color.Output = jc.origColorOutput
	color.Error = jc.origColorError
	log.SetOutput(jc.origLogOut)
	log.SetFlags(jc.origLogFlags)
	log.SetPrefix(jc.origLogPrefix)

	// 2. Drain stdout then stderr memfd into captureBuf.  Any
	// subprocess/self-fork sibling that still holds a write
	// reference can keep writing — those writes will simply be
	// lost because the variable has already been swapped back,
	// which is exactly the desired "end of capture window"
	// semantics.
	for _, f := range []*os.File{jc.captureStdout, jc.captureStderr} {
		if f == nil {
			continue
		}
		if _, err := f.Seek(0, io.SeekStart); err == nil {
			blob, _ := ioutil.ReadAll(f)
			if len(blob) > 0 {
				jc.bufMu.Lock()
				jc.captureBuf.Write(blob)
				jc.bufMu.Unlock()
			}
		}
		_ = f.Close()
	}
	jc.captureStdout = nil
	jc.captureStderr = nil

	// 3. Snapshot final buffer contents.
	jc.bufMu.Lock()
	s := buf.String()
	jc.bufMu.Unlock()

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
