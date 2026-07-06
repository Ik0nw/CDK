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
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cdk-team/CDK/pkg/util"
)

// cgroupEscapeChecks lists the classic cgroup-v1-only escape primitives that
// the CDK "run" plugin registry (and most public container-escape tooling)
// depend on.  Each entry documents:
//
//   - Mechanism: short name, matches "cdk run <what>" / community write-ups
//   - Needed hierarchy: which cgroup v1 controller must be mountable
//   - Needed knob:  which file the escape writes to
//
// A container on cgroup v2 has NONE of these files exposed by the kernel
// for a container-owned cgroup (v2 uses a unified hierarchy, no release_agent,
// no separate devices.allow, no net_cls.classid writable from inside a non-
// privileged cgroup namespace).  Warn operators loudly when those primitives
// are unavailable — because the usual playbook will 404.
type cgroupEscapeCheck struct {
	Mechanism        string
	Controller       string // v1 controller name, e.g. "devices", "memory"
	KnobFile         string // path below the cgroup dir, e.g. "release_agent"
	Brief            string // one-line description
	RequiresPrivCaps bool   // true = also needs mount / CAP_SYS_ADMIN etc.
}

var classicV1Escapes = []cgroupEscapeCheck{
	{
		Mechanism:        "release_agent (notify_on_release)",
		Controller:       "rdma", // any controller is fine; pick one commonly present
		KnobFile:         "release_agent",
		Brief:            "write cmdline to host /sbin release_agent then trigger via empty cgroup exit",
		RequiresPrivCaps: true,
	},
	{
		Mechanism:        "devices.allow (bypass /dev/null + device mknod)",
		Controller:       "devices",
		KnobFile:         "devices.allow",
		Brief:            "permit block/char device access from inside container; combined with mknod gives host disk access",
		RequiresPrivCaps: true,
	},
	{
		Mechanism:        "net_cls.classid / net_prio.prioidx (tc-based traffic exfil)",
		Controller:       "net_cls",
		KnobFile:         "net_cls.classid",
		Brief:            "classid-based tc rules running in host netns; need adjacent CAP_NET_ADMIN",
		RequiresPrivCaps: false,
	},
	{
		Mechanism:        "hugetlb cgroup mount + page-size side channel",
		Controller:       "hugetlb",
		KnobFile:         "hugetlb.1GB.limit_in_bytes",
		Brief:            "used by some exploits to leak host-side allocation info",
		RequiresPrivCaps: true,
	},
	{
		Mechanism:        "perf_event per-cpu sample injection",
		Controller:       "perf_event",
		KnobFile:         "tasks",
		Brief:            "cgroup + perf_event FD → host-wide sampling (depends on kernel.perf_event_paranoid)",
		RequiresPrivCaps: false,
	},
	{
		Mechanism:        "RDMA cgroup resource rewriting",
		Controller:       "rdma",
		KnobFile:         "rdma.max",
		Brief:            "rare; requires rdma controller in host cgroup config",
		RequiresPrivCaps: true,
	},
}

// probeCgroupWritable tests whether we can create a leaf cgroup under our
// current cgroup path.  Returns:
//
//	writable:  true = we created (and removed) a test child cgroup
//	mountPath: absolute host path of the cgroupfs mount for the named controller
//	selfPath:  our cgroup path inside that mount (the container's leaf dir)
func probeCgroupWritable(controller, selfRel string) (writable bool, mountPath, selfPath string) {
	// Locate the cgroupfs mount for the controller.  /proc/mounts lists
	// cgroup v1 mounts as: "cgroup /sys/fs/cgroup/<controller> cgroup rw,nosuid,<controller> ..."
	// v2 mount is: "cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid..."
	mounts := readFileLines("proc/mounts")
	for _, ln := range mounts {
		fields := strings.Fields(ln)
		if len(fields) < 4 {
			continue
		}
		fsType := fields[2]
		mountP := fields[1]
		if controller != "" && fsType == "cgroup" {
			opts := fields[3]
			// Controller name is one of the comma-separated mount options.
			for _, o := range strings.Split(opts, ",") {
				if o == controller {
					mountPath = mountP
					break
				}
			}
			if mountPath != "" {
				break
			}
		} else if controller == "" {
			// cgroup v2 unified mount.  Kernels + runtimes disagree on the
			// f_type name: some report "cgroup2", some (notably Docker
			// Desktop LinuxKit) mount it as "cgroup" with no per-controller
			// option string.  Accept both, keyed off the canonical mount
			// path "/sys/fs/cgroup".
			if fsType == "cgroup2" ||
				(fsType == "cgroup" && mountP == util.CgroupRoot()) {
				mountPath = mountP
				break
			}
		}
	}
	if mountPath == "" {
		return false, "", ""
	}
	selfPath = filepath.Join(mountPath, selfRel)

	// Write test: create a leaf cgroup + immediately remove it.  We never
	// "exploit"; we just confirm that the kernel allows mkdir under the
	// container's own cgroup directory.  (Exactly this mkdir is step 1 of
	// every release_agent / device-allow escape.)
	testDir := filepath.Join(selfPath, "cdk-writability-probe-"+randHex8())
	defer os.RemoveAll(testDir) // even if mkdir fails, RemoveAll is no-op.
	// cgroupfs mkdir(2) is the permission gate.
	err := os.Mkdir(testDir, 0o755)
	if err != nil {
		return false, mountPath, selfPath
	}
	// For cgroup v2, a mkdir alone is not enough evidence of exploit
	// utility — we also need to write a cgroup.procs entry in the child
	// to create a writable subtree_control.  For v1 just mkdir suffices.
	if controller == "" {
		sc := filepath.Join(testDir, "cgroup.procs")
		if f, e2 := os.OpenFile(sc, os.O_WRONLY, 0); e2 == nil {
			_, _ = f.WriteString("0\n")
			_ = f.Close()
		} else {
			return false, mountPath, selfPath
		}
	}
	return true, mountPath, selfPath
}

// randHex8 returns an 8-char lowercase hex string.  Uses crypto-free RNG
// because we only need filesystem non-collision inside this single dir.
func randHex8() string {
	fd, err := util.StealthOpen(util.DevUrandomPath(), 0)
	if err != nil {
		// fall back: pid + timestamp — still unique enough
		return fmt.Sprintf("p%d%x", os.Getpid(), os.Getpid()*31)
	}
	defer util.StealthClose(fd)
	var b [4]byte
	_, _ = util.StealthRead(fd, b[:])
	return fmt.Sprintf("%02x%02x%02x%02x", b[0], b[1], b[2], b[3])
}

// cgroupSelfRel returns our relative path for the given v1 controller
// (controller="" yields the v2 single-hierarchy path).
func cgroupSelfRel(controller string) string {
	lines := readFileLines("proc/self/cgroup")
	parse := func(partsPath string) string {
		// Docker Desktop (LinuxKit) binds /sys/fs/cgroup from the host
		// 1:1 into the container, but /proc/self/cgroup still lists the
		// host-side path like "/docker/<hex>".  We therefore walk UP from
		// "/sys/fs/cgroup/<controller>" (or the unified mount) and see
		// which suffix of the cgroup path actually exists on the VFS.
		// This collapses "wrong /proc path" / "bind-mount mismatch" into a
		// single real dir: we just try every path-suffix length against
		// the mount and return the longest one that exists.
		mounts := readFileLines("proc/mounts")
		var mountPath string
		for _, ln := range mounts {
			f := strings.Fields(ln)
			if len(f) < 3 {
				continue
			}
			if controller != "" {
				if f[2] == "cgroup" && strings.Contains(f[3], controller) {
					mountPath = f[1]
					break
				}
			} else {
				if f[2] == "cgroup2" ||
					(f[2] == "cgroup" && f[1] == "/sys/fs/cgroup") {
					mountPath = f[1]
					break
				}
			}
		}
		if mountPath == "" {
			// Fall back to raw procfs path — caller will handle "mount not found".
			return strings.TrimPrefix(partsPath, "/")
		}
		segments := strings.Split(strings.Trim(partsPath, "/"), "/")
		// Try longest suffix first (most specific = best match).
		for n := len(segments); n >= 0; n-- {
			suffix := strings.Join(segments[len(segments)-n:], "/")
			candidate := filepath.Join(mountPath, suffix)
			// Stat via real os.Stat because mountPath is already absolute
			// inside envRoot.  We never cross envRoot boundary here — this
			// function is for evaluate-path use only.
			if _, err := os.Stat(candidate); err == nil {
				return suffix
			}
		}
		// Worst case: return the procfs path.  probe will mkdir-probe and fail
		// cleanly (no crash).
		return strings.TrimPrefix(partsPath, "/")
	}
	if controller == "" {
		for _, l := range lines {
			parts := strings.SplitN(l, ":", 3)
			if len(parts) == 3 && parts[0] == "0" {
				return parse(parts[2])
			}
		}
		return ""
	}
	for _, l := range lines {
		parts := strings.SplitN(l, ":", 3)
		if len(parts) < 3 {
			continue
		}
		for _, c := range strings.Split(parts[1], ",") {
			if c == controller {
				return parse(parts[2])
			}
		}
	}
	return ""
}

// CgroupEscapeLandscape reports:
//
//  1. Whether the container is on cgroup v1 or v2.
//  2. For every well-known v1-only escape mechanism, whether the
//     required controller is PRESENT and the leaf dir is WRITABLE.
//  3. An operator-level WARNING when on v2 because 90% of public CDK
//     / Traitor / deepce-style exploit chains silently no-op there.
//
// OPSEC: touches ONLY files under /proc/self and /sys/fs/cgroup (reads + a
// single mkdir/rmdir probe). No shell, no child processes, no network.
func CgroupEscapeLandscape(ctx *Context) error {
	env := ctx.Env
	if env == nil {
		env = DetectEnv()
	}
	// ------- Hierarchy banner ---------------------------------------
	switch {
	case env.HasCgroupV1:
		log.Printf("cgroup hierarchy: v1 (classic per-controller)")
	case env.HasCgroupV2:
		log.Printf("cgroup hierarchy: v2 (unified hierarchy — DEFAULT ON modern clusters)")
	default:
		log.Printf("cgroup hierarchy: undetectable (no /proc/self/cgroup parsable)")
	}

	// ------- Classic v1 escape surface audit ------------------------
	//
	// For each classic v1 mechanism we check the SAME two things a red
	// team operator would check before running an exploit:
	//   (a) is the controller mounted on the host?
	//   (b) can we mkdir a child cgroup under OUR container's leaf dir?
	// If both are true we mark it GREEN (usable).  Either missing → AMBER
	// with the specific blocker named.
	//
	// On v2 the controller list will be empty anyway (no v1 mounts), so
	// every mechanism simply reports "not applicable — v2 unified".
	log.Printf("classic v1-only escape mechanisms:")
	v1Total := 0
	v1Usable := 0
	for _, mech := range classicV1Escapes {
		v1Total++
		rel := cgroupSelfRel(mech.Controller)
		// For v2, there's no per-controller cgroup line in /proc/self/cgroup.
		if rel == "" && env.HasCgroupV2 && !env.HasCgroupV1 {
			fmt.Printf("\t[AMBER] %-40s — v2 unified hierarchy: no %q controller mount\n",
				mech.Mechanism, mech.Controller)
			continue
		}
		writable, mount, self := probeCgroupWritable(mech.Controller, rel)
		if mount == "" {
			fmt.Printf("\t[AMBER] %-40s — host has no %q cgroup mount\n",
				mech.Mechanism, mech.Controller)
			continue
		}
		needPrivNote := ""
		if mech.RequiresPrivCaps {
			needPrivNote = " (also needs CAP_SYS_ADMIN-style host caps)"
		}
		if !writable {
			fmt.Printf("\t[AMBER] %-40s — leaf %s NOT writable from inside%s\n",
				mech.Mechanism, self, needPrivNote)
			continue
		}
		v1Usable++
		fmt.Printf("\t[GREEN] %-40s — %s writable at %s%s\n    knob: %s  —  %s\n",
			mech.Mechanism, mech.Controller,
			self,
			needPrivNote,
			mech.KnobFile, mech.Brief)
	}

	// ------- v2 writability (unified) audit --------------------------
	//
	// v2 rules are stricter, but the kernel still allows a container with
	// CAP_SYS_ADMIN inside a delegated subtree to:
	//   - mkdir cgroups
	//   - set subtree_control
	//   - move processes
	//   - write cgroup.type = "threaded" (rarely useful, but indicator)
	//   - write io.max, memory.max etc.
	// None of these = escape on their own, but "v2 leaf writable" is the
	// prerequisite for newer v2-native chains (e.g. exploiting device filters
	// via ebpf + cgroup-bpf hooks, or LSM-unaware fd forwarding).  We
	// therefore test it explicitly and report separately.
	if env.HasCgroupV2 {
		rel := cgroupSelfRel("")
		writable, mount, self := probeCgroupWritable("", rel)
		switch {
		case mount == "":
			fmt.Printf("\tv2 unified: mount not visible from inside container\n")
		case writable:
			fmt.Printf("\tv2 unified leaf [GREEN] WRITABLE at %s\n"+
				"\t  NOTE: v2 has NO release_agent, devices.allow, net_cls. Run the v2-native\n"+
				"\t  exploit surface, not the classic CDK v1 chains.\n",
				self)
		default:
			fmt.Printf("\tv2 unified leaf [AMBER] NOT writable at %s\n", self)
		}
	}

	// ------- F27 "most exploits v1-only" operator warning -----------
	//
	// Warn once, prominently, when the fleet has migrated to v2 but the
	// operator is about to run v1-only playbooks.
	if env.HasCgroupV2 && !env.HasCgroupV1 {
		fmt.Printf("\n")
		fmt.Printf("\t============================================================\n")
		fmt.Printf("\t  WARNING (F27): container runs on CGROUP V2 ONLY.\n")
		fmt.Printf("\t  90%% of public CDK / Traitor / deepce chains exploit the\n")
		fmt.Printf("\t  v1 release_agent or devices.allow mechanism — those will\n")
		fmt.Printf("\t  SILENTLY NO-OP here.  Use the v2-native surface instead:\n")
		fmt.Printf("\t    - cgroup-bpf hooks (need CAP_BPF)\n")
		fmt.Printf("\t    - eBPF + cgroup device filters (need CAP_BPF + CAP_NET_ADMIN)\n")
		fmt.Printf("\t    - userfaultfd + v2 anon memory accounting games\n")
		fmt.Printf("\t    - io.max/memory.max misconfig in delegated subtree\n")
		fmt.Printf("\t  ran=%d v1 mechs usable=%d / %d this container.\n",
			v1Total, v1Usable, v1Total)
		fmt.Printf("\t============================================================\n")
	} else if v1Total > 0 && v1Usable == 0 {
		fmt.Printf("\n\tINFO: v1 present but 0/%d classic mechs are usable from inside this container.\n",
			v1Total)
	} else if v1Usable > 0 {
		fmt.Printf("\n\tINFO: %d/%d classic v1 escape mechs usable — step 1 (mkdir) already works.\n",
			v1Usable, v1Total)
	}

	return nil
}

func init() {
	RegisterContextPrereqCheck(CategoryCgroups, "cgroups.escape_landscape",
		"Cgroup v1/v2 writability + v1-classic/v2-native exploit-surface report (F2+F3+F27)",
		[]string{"InContainer"},
		CgroupEscapeLandscape)
}
