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

package util

import (
	"math/rand"
	"time"
)

// JitterSleep sleeps for a random duration between minMs and maxMs
// milliseconds.  This is used between security checks to avoid creating
// a uniform timing signature that HIDS/EDR behavioral analysis might
// flag (e.g. "process opens 20 files in rapid succession with no
// thinking time between them").
//
// The jitter is intentionally small (default 10-50ms) so it doesn't
// noticeably slow down the audit, but enough to break uniform patterns.
func JitterSleep(minMs, maxMs int) {
	if minMs <= 0 || maxMs <= 0 || minMs >= maxMs {
		return
	}
	delay := time.Duration(minMs+rand.Intn(maxMs-minMs)) * time.Millisecond
	time.Sleep(delay)
}

// DefaultJitter is the standard jitter used between checks: 15-45ms.
func DefaultJitter() {
	JitterSleep(15, 45)
}

// HeavyJitter is used after "loud" operations (socket connects, mount
// probes): 50-200ms.
func HeavyJitter() {
	JitterSleep(50, 200)
}

// RateLimiter helps pace a series of operations to avoid bursty I/O
// patterns that trigger HIDS/EDR rate-based alerts.
type RateLimiter struct {
	lastOp  time.Time
	minGap  time.Duration // minimum gap between operations
	jitter  time.Duration // extra random jitter on top of minGap
	opCount int           // total operations performed
}

// NewRateLimiter creates a RateLimiter with the given minimum gap
// between operations (in milliseconds) and additional jitter (also ms).
func NewRateLimiter(minGapMs, jitterMs int) *RateLimiter {
	return &RateLimiter{
		lastOp: time.Now(),
		minGap: time.Duration(minGapMs) * time.Millisecond,
		jitter: time.Duration(jitterMs) * time.Millisecond,
	}
}

// Wait blocks until enough time has passed since the last operation
// to satisfy the rate limit.  Call this before each operation.
func (rl *RateLimiter) Wait() {
	if rl == nil {
		return
	}
	elapsed := time.Since(rl.lastOp)
	needed := rl.minGap
	if rl.jitter > 0 {
		needed += time.Duration(rand.Int63n(int64(rl.jitter)))
	}
	if elapsed < needed {
		time.Sleep(needed - elapsed)
	}
	rl.lastOp = time.Now()
	rl.opCount++
}

// OpCount returns the number of Wait() calls made.
func (rl *RateLimiter) OpCount() int {
	if rl == nil {
		return 0
	}
	return rl.opCount
}

// FileReadRateLimiter is a pre-configured rate limiter suitable for
// file-read operations (the most common audit action).
//
// 30ms min gap + 20ms jitter = ~30-50ms between reads, which looks
// like a normal process doing lazy I/O rather than a scanner.
var FileReadRateLimiter = NewRateLimiter(30, 20)

// NetworkProbeRateLimiter is a pre-configured rate limiter for network
// probes (socket connects, HTTP requests).  These are "louder" so we
// use a longer gap.
var NetworkProbeRateLimiter = NewRateLimiter(100, 150)
