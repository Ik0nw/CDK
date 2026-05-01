package escaping

import (
	"strings"
	"testing"
)

func TestExploitSpecificBlockDeviceHints(t *testing.T) {
	tests := []struct {
		name     string
		fsType   string
		device   string
		expected []string
	}{
		{
			name:   "rewrite cgroup devices ext4",
			fsType: "ext4",
			device: "cdk_mknod_result",
			expected: []string{
				"debugfs -w cdk_mknod_result",
				"mount -t ext4 -o ro cdk_mknod_result /tmp/cdkmnt",
			},
		},
		{
			name:   "rewrite cgroup devices xfs",
			fsType: "xfs",
			device: "cdk_mknod_result",
			expected: []string{
				`xfs_db -x -c "inode 128" -c "ls" cdk_mknod_result`,
				"mount -t xfs -o ro cdk_mknod_result /tmp/cdkmnt",
			},
		},
		{
			name:   "lxcfs rw ext4",
			fsType: "ext4",
			device: "host_dev",
			expected: []string{
				"debugfs -w host_dev",
				"mount -t ext4 -o ro host_dev /tmp/cdkmnt",
			},
		},
		{
			name:   "lxcfs rw xfs",
			fsType: "xfs",
			device: "host_dev",
			expected: []string{
				`xfs_db -x -c "inode 128" -c "ls" host_dev`,
				"mount -t xfs -o ro host_dev /tmp/cdkmnt",
			},
		},
		{
			name:   "cgroup2 ebpf bypass ext4",
			fsType: "ext4",
			device: "./cdk_mknod_v2_result",
			expected: []string{
				"debugfs -w ./cdk_mknod_v2_result",
				"mount -t ext4 -o ro ./cdk_mknod_v2_result /tmp/cdkmnt",
			},
		},
		{
			name:   "cgroup2 ebpf bypass xfs",
			fsType: "xfs",
			device: "./cdk_mknod_v2_result",
			expected: []string{
				`xfs_db -x -c "inode 128" -c "ls" ./cdk_mknod_v2_result`,
				"mount -t xfs -o ro ./cdk_mknod_v2_result /tmp/cdkmnt",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := blockDeviceBrowseHint(tt.fsType, tt.device, func(name string) bool {
				return name == "debugfs" || name == "xfs_db" || name == "mount"
			})
			for _, want := range tt.expected {
				if !strings.Contains(got, want) {
					t.Fatalf("blockDeviceBrowseHint(%q, %q) = %q, want substring %q", tt.fsType, tt.device, got, want)
				}
			}
		})
	}
}
