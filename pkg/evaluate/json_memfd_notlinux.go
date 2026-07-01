// Non-Linux fallback (darwin, windows, wasm, …).  memfd_create is a
// Linux-only syscall.  On these platforms the evaluate package will
// compile — the JSON capture path falls back to log-only via
// teeDirect when memfdCreate returns an error — but runtime behavior
// is best-effort and the check bodies themselves are Linux-only.

//go:build !linux
// +build !linux

package evaluate

// memfdCreateNR is unused on non-Linux; provide a placeholder value
// so json.go compiles on darwin for IDEs / `go vet` host runs.
var memfdCreateNR uintptr = 0
