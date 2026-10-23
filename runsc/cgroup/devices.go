// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cgroup

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// DeviceAny matches any device major or minor number in a DeviceRule.
const DeviceAny = -1

// DeviceRule allows access to a device from a cgroup that otherwise denies
// access to all devices.
type DeviceRule struct {
	// Type is "c" for character devices or "b" for block devices.
	Type string `json:"type"`
	// Major is the device's major number, or DeviceAny.
	Major int64 `json:"major"`
	// Minor is the device's minor number, or DeviceAny.
	Minor int64 `json:"minor"`
	// Access is any combination of 'r' (read), 'w' (write) and 'm' (mknod).
	Access string `json:"access"`
}

// String returns the rule in the devices cgroup's "type major:minor access"
// format.
func (r DeviceRule) String() string {
	return r.device() + " " + r.access()
}

func (r DeviceRule) device() string {
	num := func(n int64) string {
		if n == DeviceAny {
			return "*"
		}
		return strconv.FormatInt(n, 10)
	}
	return fmt.Sprintf("%s %s:%s", r.Type, num(r.Major), num(r.Minor))
}

// access returns r.Access in the order the kernel lists permissions.
func (r DeviceRule) access() string {
	return accessIntersect("rwm", r.Access)
}

// accessIntersect returns the permissions in both a and b, in the order the
// kernel lists them.
func accessIntersect(a, b string) string {
	var out strings.Builder
	for _, c := range "rwm" {
		if strings.ContainsRune(a, c) && strings.ContainsRune(b, c) {
			out.WriteRune(c)
		}
	}
	return out.String()
}

// accessMinus returns the permissions in a that are not in b.
func accessMinus(a, b string) string {
	var out strings.Builder
	for _, c := range "rwm" {
		if strings.ContainsRune(a, c) && !strings.ContainsRune(b, c) {
			out.WriteRune(c)
		}
	}
	return out.String()
}

// SetDevices implements Cgroup.SetDevices.
func (c *cgroupV1) SetDevices(rules []DeviceRule) error {
	path := c.MakePath("devices")
	list, err := getValue(path, "devices.list")
	if err != nil {
		return err
	}
	for _, w := range devicesV1Writes(list, rules) {
		if err := setValue(path, w.file, w.value); err != nil {
			return err
		}
	}
	return nil
}

type cgroupWrite struct {
	file  string
	value string
}

// devicesV1Writes returns the writes to devices.allow and devices.deny that
// take a devices cgroup from the state described by its devices.list to
// allowing exactly rules.
func devicesV1Writes(list string, rules []DeviceRule) []cgroupWrite {
	var writes []cgroupWrite
	current := make(map[string]string)
	for _, line := range strings.Split(list, "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		if strings.HasPrefix(line, "a ") {
			// The cgroup allows all devices, which is the default for a new
			// cgroup. Deny them all so that only the rules below apply.
			writes = append(writes, cgroupWrite{"devices.deny", "a"})
			clear(current)
			break
		}
		i := strings.LastIndexByte(line, ' ')
		current[line[:i]] = line[i+1:]
	}
	want := make(map[string]string)
	for _, r := range rules {
		want[r.device()] = accessIntersect("rwm", want[r.device()]+r.Access)
	}
	for _, dev := range slices.Sorted(maps.Keys(want)) {
		if add := accessMinus(want[dev], current[dev]); add != "" {
			writes = append(writes, cgroupWrite{"devices.allow", dev + " " + add})
		}
	}
	for _, dev := range slices.Sorted(maps.Keys(current)) {
		if rm := accessMinus(current[dev], want[dev]); rm != "" {
			writes = append(writes, cgroupWrite{"devices.deny", dev + " " + rm})
		}
	}
	return writes
}

// SetDevices implements Cgroup.SetDevices.
func (c *cgroupV2) SetDevices(rules []DeviceRule) error {
	insns, err := deviceFilter(rules)
	if err != nil {
		return err
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.CGroupDevice,
		Instructions: insns,
		License:      "Apache",
	})
	if err != nil {
		return fmt.Errorf("loading device filter: %w", err)
	}
	defer prog.Close()

	dir, err := os.Open(c.MakePath(""))
	if err != nil {
		return err
	}
	defer dir.Close()
	target := int(dir.Fd())
	old, err := link.QueryPrograms(link.QueryOptions{Target: target, Attach: ebpf.AttachCGroupDevice})
	if err != nil {
		return fmt.Errorf("querying device filters: %w", err)
	}
	// Every attached filter must allow an access, so attaching the new filter
	// before detaching the old ones never allows more than either does.
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  target,
		Program: prog,
		Attach:  ebpf.AttachCGroupDevice,
		Flags:   unix.BPF_F_ALLOW_MULTI,
	}); err != nil {
		return fmt.Errorf("attaching device filter: %w", err)
	}
	for _, ap := range old.Programs {
		oldProg, err := ebpf.NewProgramFromID(ap.ID)
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				// An LSM keeps the filter out of reach; it can only deny
				// accesses that the new filter allows.
				continue
			}
			return fmt.Errorf("opening old device filter: %w", err)
		}
		err = link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  target,
			Program: oldProg,
			Attach:  ebpf.AttachCGroupDevice,
		})
		oldProg.Close()
		if err != nil {
			return fmt.Errorf("detaching old device filter: %w", err)
		}
	}
	return nil
}

// deviceFilter returns a BPF_PROG_TYPE_CGROUP_DEVICE program that allows
// exactly the accesses matched by rules.
func deviceFilter(rules []DeviceRule) (asm.Instructions, error) {
	// The program is called with a struct bpf_cgroup_dev_ctx, whose 32-bit
	// fields are the access type (the device type in the low 16 bits and the
	// access in the high 16 bits), the major number and the minor number.
	insns := asm.Instructions{
		asm.LoadMem(asm.R2, asm.R1, 0, asm.Word),
		asm.And.Imm32(asm.R2, 0xffff),
		asm.LoadMem(asm.R3, asm.R1, 0, asm.Word),
		asm.RSh.Imm32(asm.R3, 16),
		asm.LoadMem(asm.R4, asm.R1, 4, asm.Word),
		asm.LoadMem(asm.R5, asm.R1, 8, asm.Word),
	}
	const allAccess = unix.BPF_DEVCG_ACC_READ | unix.BPF_DEVCG_ACC_WRITE | unix.BPF_DEVCG_ACC_MKNOD
	for i, r := range rules {
		var typ int32
		switch r.Type {
		case "c":
			typ = unix.BPF_DEVCG_DEV_CHAR
		case "b":
			typ = unix.BPF_DEVCG_DEV_BLOCK
		default:
			return nil, fmt.Errorf("invalid device type in rule %q", r)
		}
		var access int32
		for _, c := range r.Access {
			switch c {
			case 'r':
				access |= unix.BPF_DEVCG_ACC_READ
			case 'w':
				access |= unix.BPF_DEVCG_ACC_WRITE
			case 'm':
				access |= unix.BPF_DEVCG_ACC_MKNOD
			default:
				return nil, fmt.Errorf("invalid device access in rule %q", r)
			}
		}
		if access == 0 || r.Major > math.MaxInt32 || r.Minor > math.MaxInt32 {
			return nil, fmt.Errorf("invalid device rule %q", r)
		}
		// Each rule is a block that jumps to the next block on mismatch.
		next := fmt.Sprintf("rule%d", i+1)
		insns = append(insns, asm.JNE.Imm(asm.R2, typ, next).WithSymbol(fmt.Sprintf("rule%d", i)))
		if access != allAccess {
			insns = append(insns,
				asm.Mov.Reg32(asm.R1, asm.R3),
				asm.And.Imm32(asm.R1, access),
				asm.JNE.Reg(asm.R1, asm.R3, next))
		}
		if r.Major != DeviceAny {
			insns = append(insns, asm.JNE.Imm(asm.R4, int32(r.Major), next))
		}
		if r.Minor != DeviceAny {
			insns = append(insns, asm.JNE.Imm(asm.R5, int32(r.Minor), next))
		}
		insns = append(insns, asm.Mov.Imm32(asm.R0, 1), asm.Return())
	}
	return append(insns,
		asm.Mov.Imm32(asm.R0, 0).WithSymbol(fmt.Sprintf("rule%d", len(rules))),
		asm.Return()), nil
}
