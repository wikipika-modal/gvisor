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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestDevicesV1Writes(t *testing.T) {
	rules := []DeviceRule{
		{Type: "c", Major: 1, Minor: 3, Access: "rw"},
		{Type: "c", Major: 136, Minor: DeviceAny, Access: "rw"},
		{Type: "c", Major: 0, Minor: 0, Access: "m"},
	}
	for _, tc := range []struct {
		name  string
		list  string
		rules []DeviceRule
		want  []cgroupWrite
	}{
		{
			name:  "new cgroup",
			list:  "a *:* rwm\n",
			rules: rules,
			want: []cgroupWrite{
				{"devices.deny", "a"},
				{"devices.allow", "c 0:0 m"},
				{"devices.allow", "c 136:* rw"},
				{"devices.allow", "c 1:3 rw"},
			},
		},
		{
			name:  "already set",
			list:  "c 1:3 rw\nc 136:* rw\nc 0:0 m\n",
			rules: rules,
			want:  nil,
		},
		{
			name:  "update",
			list:  "c 1:3 rwm\nc 136:* rw\nc 10:229 rw\n",
			rules: rules,
			want: []cgroupWrite{
				{"devices.allow", "c 0:0 m"},
				{"devices.deny", "c 10:229 rw"},
				{"devices.deny", "c 1:3 m"},
			},
		},
		{
			name: "merged accesses",
			list: "",
			rules: []DeviceRule{
				{Type: "c", Major: 1, Minor: 3, Access: "w"},
				{Type: "c", Major: 1, Minor: 3, Access: "mr"},
			},
			want: []cgroupWrite{{"devices.allow", "c 1:3 rwm"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := devicesV1Writes(tc.list, tc.rules)
			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(cgroupWrite{}), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("devicesV1Writes() diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDeviceFilter(t *testing.T) {
	insns, err := deviceFilter([]DeviceRule{
		{Type: "c", Major: 1, Minor: 3, Access: "rw"},
		{Type: "b", Major: 8, Minor: DeviceAny, Access: "rwm"},
		{Type: "c", Major: DeviceAny, Minor: DeviceAny, Access: "m"},
	})
	if err != nil {
		t.Fatalf("deviceFilter(): %v", err)
	}
	want := `	 0: LdXMemW dst: r2 src: r1 off: 0 imm: 0
	 1: AndImm32 dst: r2 imm: 65535
	 2: LdXMemW dst: r3 src: r1 off: 0 imm: 0
	 3: RShImm32 dst: r3 imm: 16
	 4: LdXMemW dst: r4 src: r1 off: 4 imm: 0
	 5: LdXMemW dst: r5 src: r1 off: 8 imm: 0
rule0:
	 6: JNEImm dst: r2 off: -1 imm: 2 <rule1>
	 7: MovReg32 dst: r1 src: r3
	 8: AndImm32 dst: r1 imm: 6
	 9: JNEReg dst: r1 off: -1 src: r3 <rule1>
	10: JNEImm dst: r4 off: -1 imm: 1 <rule1>
	11: JNEImm dst: r5 off: -1 imm: 3 <rule1>
	12: MovImm32 dst: r0 imm: 1
	13: Exit
rule1:
	14: JNEImm dst: r2 off: -1 imm: 1 <rule2>
	15: JNEImm dst: r4 off: -1 imm: 8 <rule2>
	16: MovImm32 dst: r0 imm: 1
	17: Exit
rule2:
	18: JNEImm dst: r2 off: -1 imm: 2 <rule3>
	19: MovReg32 dst: r1 src: r3
	20: AndImm32 dst: r1 imm: 1
	21: JNEReg dst: r1 off: -1 src: r3 <rule3>
	22: MovImm32 dst: r0 imm: 1
	23: Exit
rule3:
	24: MovImm32 dst: r0 imm: 0
	25: Exit
`
	if got := insns.String(); got != want {
		t.Errorf("deviceFilter() program:\n%s\nwant:\n%s", got, want)
	}
}

func TestDeviceFilterInvalid(t *testing.T) {
	for _, r := range []DeviceRule{
		{Type: "a", Major: 1, Minor: 3, Access: "rw"},
		{Type: "c", Major: 1, Minor: 3, Access: "rx"},
		{Type: "c", Major: 1, Minor: 3, Access: ""},
		{Type: "c", Major: 1 << 40, Minor: 3, Access: "rw"},
	} {
		if _, err := deviceFilter([]DeviceRule{r}); err == nil {
			t.Errorf("deviceFilter(%q) succeeded, want error", r)
		}
	}
}
