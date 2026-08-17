// Copyright 2024 The gVisor Authors.
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

package xemu

import (
	"fmt"
	"sync"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/hostarch"
)

// errDonorDead is returned by createBind when the donor is known to be
// unresponsive, so concurrent callers fast-fail instead of each waiting out the
// receive timeout.
var errDonorDead = fmt.Errorf("xemu: mm donor is unresponsive")

// donor is a long-lived helper process that binds a fresh mm to each new
// address space. It is forked once, lazily, on the first address-space creation
// -- after the sentry installs its seccomp filter (which the donor inherits) but
// before the sentry maps guest memory, so its mm stays small. Binding from the
// donor rather than re-forking the whole sentry per address space avoids copying
// the sentry's (eventually multi-GB) page tables and the write-protect /
// TLB-shootdown storm that inflicts on the other sentry threads.
//
// The donor has its own fd table, pruned at startup to just its end of sock
// (the fork snapshots the sentry's whole table, and a donor stuck exiting must
// not pin a dead sandbox's address spaces or guest memory). The sentry creates
// each address-space fd and sends it over sock as SCM_RIGHTS rights data; the
// donor forks a grandchild that binds its (small, copy-of-donor) mm to the
// received fd and exits, then closes its copy of the fd. A SOCK_SEQPACKET
// socketpair gives the exchange message boundaries so each side reads a whole
// request/response in one call.
//
// Because the sentry keeps the donor's peer end open (a re-forked donor must
// be able to inherit it), a dead donor never yields EOF/EPIPE. So the socket
// has a receive timeout (SO_RCVTIMEO) and each request carries a monotonic
// sequence number that the reply echoes: a timeout marks the donor dead
// (dropDonor re-forks a fresh one), and a reply left buffered by a timed-out
// request is skipped by sequence rather than desyncing the reused socket.
//
// The donor holds a copy-on-write snapshot of the sentry's early-boot mm for the
// sandbox's lifetime: sentry pages that existed at fork time and are later
// written or freed stay alive (COW) in the donor. This is expected retention,
// not a leak, and is bounded by the small early-boot RSS.
type donor struct {
	// mu serializes requests: a single donor handles them one at a time.
	mu   sync.Mutex
	sock int
	// dead is set once a request times out so that callers queued behind it on
	// mu return immediately instead of each waiting the full timeout.
	dead atomicbitops.Bool
}

// createBind asks the donor to bind a fresh mm to asfd, tagging the request with
// seq. A non-nil commErr means the donor is unusable and must be dropped; status
// is the bind errno otherwise.
func (d *donor) createBind(seq uint32, asfd int) (status int, commErr error) {
	if d.dead.Load() {
		return 0, errDonorDead
	}
	// req[4:8] is reserved; the fd travels as SCM_RIGHTS rights data, since a
	// bare fd number would be meaningless in the donor's own fd table.
	var req [8]byte
	hostarch.ByteOrder.PutUint32(req[0:4], seq)

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dead.Load() {
		return 0, errDonorDead
	}

	if err := unix.Sendmsg(d.sock, req[:], unix.UnixRights(asfd), nil, 0); err != nil {
		d.dead.Store(true)
		return 0, fmt.Errorf("xemu: donor request: %w", err)
	}
	for {
		var resp [8]byte
		n, err := unix.Read(d.sock, resp[:])
		if err == unix.EINTR {
			continue // signal-interrupted read, not a timeout: retry
		}
		// SO_RCVTIMEO fires as EAGAIN; that, any other error, or a short read
		// (framing lost) all mean the donor is dead or hung.
		if err == nil && n != len(resp) {
			err = fmt.Errorf("short read (%d bytes)", n)
		}
		if err != nil {
			d.dead.Store(true)
			return 0, fmt.Errorf("xemu: donor response: %w", err)
		}
		if rseq := hostarch.ByteOrder.Uint32(resp[0:4]); rseq != seq {
			continue // stale reply from an earlier, timed-out request
		}
		return int(hostarch.ByteOrder.Uint32(resp[4:8])), nil
	}
}

// getDonor returns the platform's donor, forking it on first use. A failed
// fork is not remembered, so a later call retries rather than failing every
// subsequent address-space creation for the sandbox's life.
func (p *XEMU) getDonor() (*donor, error) {
	p.donorMu.Lock()
	defer p.donorMu.Unlock()
	if p.donorInst != nil {
		return p.donorInst, nil
	}
	d, err := startDonor(p.donorSock, p.donorParentPid)
	if err != nil {
		return nil, err
	}
	p.donorInst = d
	return d, nil
}

// dropDonor discards an unresponsive donor so the next getDonor re-forks a fresh
// one. The dead donor (if it is somehow still alive) is left to be reaped with
// the sandbox; the reused socket is resynchronized by request sequence numbers.
func (p *XEMU) dropDonor(d *donor) {
	p.donorMu.Lock()
	if p.donorInst == d {
		p.donorInst = nil
	}
	p.donorMu.Unlock()
}
