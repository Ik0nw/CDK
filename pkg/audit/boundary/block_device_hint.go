package escaping

import (
	"fmt"
	"os/exec"
	"strings"
)

type toolLookupFunc func(string) bool

func runtimeBlockDeviceBrowseHint(fsType, devicePath string) string {
	return blockDeviceBrowseHint(fsType, devicePath, toolExists)
}

func blockDeviceBrowseHint(fsType, devicePath string, hasTool toolLookupFunc) string {
	fsType = strings.ToLower(fsType)
	mountHint := blockDeviceMountHint(fsType, devicePath)

	preferredToolHint := ""
	switch fsType {
	case "ext2", "ext3", "ext4":
		if hasTool("debugfs") {
			preferredToolHint = fmt.Sprintf("run 'debugfs -w %s' to browse host files", devicePath)
		}
	case "xfs":
		if hasTool("xfs_db") {
			preferredToolHint = fmt.Sprintf("use 'xfs_db -x -c \"inode 128\" -c \"ls\" %s' to inspect the host filesystem", devicePath)
		}
	}

	if preferredToolHint != "" {
		if hasTool("mount") {
			return fmt.Sprintf("now, %s. If that tool is inconvenient, try '%s'.", preferredToolHint, mountHint)
		}
		return fmt.Sprintf("now, %s.", preferredToolHint)
	}

	if hasTool("mount") {
		if fsType != "" {
			return fmt.Sprintf("now, host filesystem type is %q. Try '%s' to inspect it.", fsType, mountHint)
		}
		return fmt.Sprintf("now, try '%s' to inspect the host filesystem.", mountHint)
	}

	if fsType != "" {
		return fmt.Sprintf("host filesystem type is %q. A block device was created at %s; inspect it with tooling available in the container.", fsType, devicePath)
	}
	return fmt.Sprintf("a block device was created at %s; inspect it with tooling available in the container.", devicePath)
}

func blockDeviceMountHint(fsType, devicePath string) string {
	if fsType != "" {
		return fmt.Sprintf("mkdir -p /tmp/cdkmnt && mount -t %s -o ro %s /tmp/cdkmnt", fsType, devicePath)
	}
	return fmt.Sprintf("mkdir -p /tmp/cdkmnt && mount -o ro %s /tmp/cdkmnt", devicePath)
}

func toolExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
