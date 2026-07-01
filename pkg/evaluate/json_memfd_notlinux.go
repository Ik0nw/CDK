// Non-Linux fallback (darwin, windows, wasm, …).  memfd_create is a
// Linux-only syscall.  json.go uses a temporary file instead on these
// platforms so tests and IDE tooling still capture stdout/stderr.

//go:build !linux
// +build !linux

package evaluate

// memfdCreateNR is unused on non-Linux; provide a placeholder value so
// json.go compiles on darwin for IDEs / `go vet` host runs.
var memfdCreateNR uintptr = 0
