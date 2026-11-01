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

package kernel

import (
	"bytes"
	"io"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/state/stateio/stateiotest"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

func TestVDSOParamPageWaitsForEarlyResumeSave(t *testing.T) {
	ctx := contexttest.Context(t)
	mf := pgalloc.MemoryFileFromContext(ctx)
	fr, err := mf.Allocate(hostarch.PageSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	params := NewVDSOParamPage(mf, fr)
	write := func(base int64) {
		if err := params.Write(func() vdsoParams {
			return vdsoParams{monotonicReady: 1, monotonicBaseCycles: base}
		}); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	write(1)
	bs, err := mf.MapInternal(fr, hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	want := bytes.Clone(bs.Head().ToSlice())

	w := stateiotest.NewHeldWriter(200 * time.Millisecond)
	done := make(chan error, 1)
	apfs, err := pgalloc.StartAsyncPagesFileSave(w, func(err error) { done <- err })
	if err != nil {
		t.Fatalf("StartAsyncPagesFileSave: %v", err)
	}
	if err := apfs.EnableEarlyResume(); err != nil {
		t.Fatalf("EnableEarlyResume: %v", err)
	}
	if err := mf.SaveTo(ctx, io.Discard, &pgalloc.SaveOpts{PagesFile: apfs}); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	apfs.MemoryFilesDone()

	write(2)
	if err := <-done; err != nil {
		t.Fatalf("saving failed: %v", err)
	}
	if got := w.Saved(fr.Start); !bytes.Equal(got, want) {
		t.Errorf("saved param page differs from the page when saving began")
	}
}
