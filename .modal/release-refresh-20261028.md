# Release 20261019 refresh, October 28, 2026

Original branch tip: `0005844502d89fdec5e844b64350b19671c3a8dd`. Upstream base remains `760b80785dc53311d4c87bd2de167525a99709c1` (October 19 Pacific).

The refresh replaces nine recorded source revisions, adds #16619 and #16565 (with its merged prerequisite #16557), and retains the ordered merged/open/proprietary patch stack. XEMU is preserved. The fsmutationlog commit is replaced with the latest branch revision, including FULL-segment dumps, journal resync, and FULL-segment fallback on failed journal finalization. No release tag or deployment is created.

## Updated release inputs

| Input | Previous source | Refreshed source | Status |
| --- | --- | --- | --- |
| [#16407](https://github.com/google/gvisor/pull/16407) | `31d3873e5044` | `e8a2a28891ba` | Merged |
| [#16009](https://github.com/google/gvisor/pull/16009) | `653d273c978d` | `d05ab617afed` | Merged |
| [#16130](https://github.com/google/gvisor/pull/16130) | `b01a51651375` | `bddc7f55c929` | Merged |
| [#16104](https://github.com/google/gvisor/pull/16104) | `2681903228a5` | `25209dc532d3` | Merged |
| [#16402](https://github.com/google/gvisor/pull/16402) | `f1cc03692c11` | `540cd026e986` | Merged |
| [#15741](https://github.com/google/gvisor/pull/15741) | `495fbd903055` | `0e77f9e6e8bd` | Open |
| [#16485](https://github.com/google/gvisor/pull/16485) | `55be3a5e0603` | `49f7d320e71e` | Open |
| [#16425](https://github.com/google/gvisor/pull/16425) | `9707039014a4` | `d8dce512365e` | Open |
| [fsmutationlog](https://github.com/modal-labs/gvisor/commit/a56829cf03a5d2f5fafca65f59040697d0d356a6) | `8ebd5dd1a82de` | `a56829cf03a5` | Proprietary |

Merged sources were checked against the actual first-parent merge diff. #15999 and #16130 include integration-time tests missing from the original PR heads. Other merged PR-head patches match their merge diffs. #16117 retains its three commits. The device-cgroup entry moves from private Modal PR #44 to upstream PR #16485.

Backports retain the release’s environment storage, credential fields, and container StateFile locking APIs. #16619’s restore test uses the release’s boolean direct-I/O argument. NVIDIA command registrations from overlapping PRs are retained together.

#16565 is included from open PR head `7a8074c01b9fec337d5d6c3acb75c9ce0dad61e1`. It requires [#16557](https://github.com/google/gvisor/pull/16557), which is included from the first-parent diff of its merged commit `ffc048011e1bbedc458a20f734228f1477c74f82`. The prerequisite supplies the range-based internal-mapping API, the async-load mapping bound, and the initial regression test. Its test uses the release’s three-argument `StartAsyncPagesFileLoad` API; production code applies unchanged. #16565 then permits uncached mappings under the read lock so one thread waiting for async page loading does not block I/O by other threads. The prerequisite is ordered with the other non-Modal upstream fixes, and #16565 precedes the proprietary commits.

## Modal PRs opened or merged since October 25

Dates below are Pacific time. The search covered all pages of opened and merged PRs, and deduplicated upstream Copybara mirrors. Author affiliation was checked against repository authorship and public profiles, including both Samridh accounts.

| PR | Author | Opened | Merged / state | Release disposition |
| --- | --- | --- | --- | --- |
| [#16009: nvproxy: hugepage-align application memory mirrors](https://github.com/google/gvisor/pull/16009) | sam10ridh | Oct 19 | Merged Oct 27 | Included (existing patch refreshed/retained) |
| [#16104: pgalloc: recycle hugepage-aligned ranges for huge allocations](https://github.com/google/gvisor/pull/16104) | ayushr2 | Oct 21 | Merged Oct 27 | Included (existing patch refreshed/retained) |
| [#16130: Restrict /proc/gvisor/spec_environ to the container's user](https://github.com/google/gvisor/pull/16130) | ayushr2 | Oct 21 | Merged Oct 26 | Included (existing patch refreshed/retained) |
| [#16187: pgalloc: don't merge memAcct from UpdateUsage() during MemoryFile.SaveTo()](https://github.com/google/gvisor/pull/16187) | ayushr2 | Oct 22 | Merged Oct 25 | Included (existing patch refreshed/retained) |
| [#16360: Resolve symlinks in device paths before mounting them in the gofer](https://github.com/google/gvisor/pull/16360) | ayushr2 | Oct 24 | Merged Oct 25 | Included (existing patch refreshed/retained) |
| [#16386: tmpfs: support the huge mount option](https://github.com/google/gvisor/pull/16386) | ayushr2 | Oct 25 | Merged Oct 25 | Included (existing patch refreshed/retained) |
| [#16390: overlay: Skip copy-up for chown that does not change the owner](https://github.com/google/gvisor/pull/16390) | wikipika-modal | Oct 25 | Merged Oct 26 | Included (existing patch refreshed/retained) |
| [#16399: Default runsc restore to --background and --direct-io=auto](https://github.com/google/gvisor/pull/16399) | ayushr2 | Oct 25 | Merged Oct 26 | Listed only; not added |
| [#16402: tmpfs: let huge page fills recycle waste pages](https://github.com/google/gvisor/pull/16402) | ayushr2 | Oct 25 | Merged Oct 26 | Included (existing patch refreshed/retained) |
| [#16418: Add missing NVIDIA controls to nvproxy](https://github.com/google/gvisor/pull/16418) | botirkhaltaev | Oct 26 | Open | Listed only; not added |
| [#16422: pgalloc: reject inconsistent async page saves](https://github.com/google/gvisor/pull/16422) | botirkhaltaev | Oct 26 | Merged Oct 26 | Listed only; not added |
| [#16423: runsc: fail background restore on page load errors](https://github.com/google/gvisor/pull/16423) | botirkhaltaev | Oct 26 | Open | Listed only; not added |
| [#16425: Add a control RPC to drain filesystem dentry caches](https://github.com/google/gvisor/pull/16425) | danielnorberg | Oct 26 | Open | Included (existing patch refreshed/retained) |
| [#16469: Pass host inode numbers through the gofer client](https://github.com/google/gvisor/pull/16469) | ayushr2 | Oct 26 | Open | Listed only; not added |
| [#16478: overlay: keep the upper parent non-empty while replacing files](https://github.com/google/gvisor/pull/16478) | samridh10exe | Oct 26 | Open | Listed only; not added |
| [#16485: Confine the sandbox to a device cgroup](https://github.com/google/gvisor/pull/16485) | ayushr2 | Oct 27 | Open | Included (existing patch refreshed/retained) |
| [#16504: Distinguish checkpoint rejection errors](https://github.com/google/gvisor/pull/16504) | botirkhaltaev | Oct 27 | Open | Listed only; not added |
| [#16509: Undo checkpoint preparation on failure](https://github.com/google/gvisor/pull/16509) | botirkhaltaev | Oct 27 | Open | Listed only; not added |
| [#16510: Reject unsavable device state](https://github.com/google/gvisor/pull/16510) | botirkhaltaev | Oct 27 | Open | Listed only; not added |
| [#16565: mm: get uncached internal mappings in the read-locked I/O fast path](https://github.com/google/gvisor/pull/16565) | ayushr2 | Oct 27 | Open | Included (new; requires #16557) |
| [#16568: overlay: Add metacopy copy-up behind --overlay2=root:...,metacopy=on](https://github.com/google/gvisor/pull/16568) | wikipika-modal | Oct 27 | Closed, unmerged | Listed only; not added |
| [#16619: runsc: do not account memory of disk backed private MemoryFiles](https://github.com/google/gvisor/pull/16619) | ayushr2 | Oct 28 | Open | Included (new) |

## Validation

Before the fsmutationlog replacement, the following seven unit-test targets passed in the gVisor builder image (`84dbb1f09a14`):

- `//pkg/sentry/pgalloc:pgalloc_test`
- `//pkg/sentry/fsimpl/tmpfs:tmpfs_test`
- `//pkg/sentry/fsimpl/gofer:gofer_test`
- `//pkg/sentry/fsimpl/proc:proc_test`
- `//pkg/sentry/kernel:kernel_test`
- `//pkg/sentry/devices/nvproxy:nvproxy_test`
- `//runsc/cgroup:cgroup_test`

`//runsc/container:container_test`, filtered to `TestUsageDiskBackedOverlay`, passed with the systrap platform (1.7 seconds). The log confirms the test created a disk-backed overlay, checkpointed the container, restored it, and checked memory usage. Building this target also built the runsc release binaries and sidecars. The test was adapted to the release's boolean direct-I/O argument.

After replacing fsmutationlog with `a56829cf03a5d2f5fafca65f59040697d0d356a6`, the tmpfs, kernel, and runsc config unit-test targets passed. The tmpfs suite includes the new FULL-segment dump, resync, overflow recovery, and failure-path tests. `//runsc/boot:boot_test`, filtered to `TestRunFinalizesMutationLog`, passed. `//runsc/container:container_test`, filtered to `TestDestroyFilestoreCleanup|TestUsageDiskBackedOverlay`, passed with systrap (1.5 seconds), rebuilding the runsc release binaries and sidecars. Test logs confirm runtime journal finalization, filestore preservation and cleanup, and checkpoint/restore execution. The fsmutationlog source branch was rechecked and still points to the selected commit. The source patch applied without conflicts; the existing device-cgroup changes remain intact.

After adding #16557 and #16565, `//pkg/sentry/mm:mm_test` passed, including `TestIODuringAsyncPageLoad` with concurrent blocked and unblocked I/O. `//pkg/sentry/pgalloc:pgalloc_test` also passed (cached). The prerequisite’s regression test initially failed to compile against the older async-load API; removing its newer options argument resolved that incompatibility. `//runsc/container:container_test`, filtered to `TestUsageDiskBackedOverlay`, passed with systrap (1.5 seconds), rebuilding the runsc release binaries and sidecars. Its log confirms checkpoint and restore execution. A range-diff verifies that the prior release code patches remain unchanged, and the manifest’s 32 source entries match the ordered commit stack. #16565’s open head was rechecked after validation and remains `7a8074c01b9fec337d5d6c3acb75c9ce0dad61e1`.

`git diff --check` passed. All selected open PR head SHAs were rechecked after validation and were unchanged. The host-only build lacked ARM64 libc headers; validation succeeded in the builder container. Full release qualification and GPU hardware tests were not run.
