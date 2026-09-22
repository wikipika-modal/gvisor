// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"fmt"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// FsMutationLog implements subcommands.Command for the "fsmutationlog" command.
type FsMutationLog struct {
	containerLoader
	path     string
	sinceGen uint64
}

// Name implements subcommands.Command.Name.
func (*FsMutationLog) Name() string {
	return "fsmutationlog"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*FsMutationLog) Synopsis() string {
	return "drain an ordered mutation-log segment of the overlay upper layer (experimental)"
}

// Usage implements subcommands.Command.Usage.
func (*FsMutationLog) Usage() string {
	return `fsmutationlog [flags] <container id>:
	Briefly pauses the container, finishes the FMLG mutation-log segment in the
	persistent log file the sentry adopted at boot (records were written during
	execution; the pause only re-emits mmap-tracked files and writes the header),
	and resumes. Prints "generation=<n> length=<bytes>". The caller reflinks the log file
	and the filestore while paused (for mutual consistency) and reads [0, length).
	There is no full baseline: once the log overflows its bounds the command fails
	with a discernible "mutation log overflowed" error (permanently, for that mount),
	and a since-gen mismatch fails likewise; the caller must then fall back to a
	full-walk snapshot. Requires runsc --overlay2 medium "self" or "dir=" and
	--fsmutationlog(-path).
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *FsMutationLog) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.path, "path", "/", "mount path inside the container whose overlay upper layer is journaled")
	f.Uint64Var(&c.sinceGen, "since-gen", 0, "emit only changes since this generation (from a previous call's reported generation); 0 drains the full history of a mount not yet drained")
}

// FetchSpec implements util.SubCommand.FetchSpec.
func (c *FsMutationLog) FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error) {
	cont, err := c.loadContainer(conf, f, container.LoadOpts{})
	if err != nil {
		return "", nil, fmt.Errorf("loading container: %w", err)
	}
	return cont.ID, cont.Spec, nil
}

// Execute implements subcommands.Command.Execute.
func (c *FsMutationLog) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	conf := args[0].(*config.Config)

	cont, err := c.loadContainer(conf, f, container.LoadOpts{})
	if err != nil {
		util.Fatalf("loading container: %v", err)
	}

	generation, length, err := cont.FsMutationLog(c.path, c.sinceGen)
	if err != nil {
		util.Fatalf("fs mutation log failed: %v", err)
	}
	// Machine-readable line for the caller (modal-runtime) to capture the generation to
	// pass as -since-gen next time and the segment length to read from the (reflinked)
	// log file.
	fmt.Printf("generation=%d length=%d\n", generation, length)

	return subcommands.ExitSuccess
}
