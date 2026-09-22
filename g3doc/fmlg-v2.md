# FMLG v2: epoch framing and exit finalization

FMLG records mutations to a tmpfs overlay upper. Version 2 puts each record in
a committed frame so a reader can identify a valid prefix after sentry process
death. All integers are little-endian. Readers operate on a
stable capture or after the sentry has died, not concurrently with an overwriting
writer. This is not a host-crash durability protocol.

## Header

The mount truncates the donated file before initialization, writes this header,
and commits the first BEGIN before enabling mutation hooks.

| Offset | Type | Meaning |
| --- | --- | --- |
| 0 | bytes[4] | `FMLG` |
| 4 | u16 | Version: 2 |
| 6 | u16 | Required feature flags: 0 |
| 8 | u64 | Root inode |
| 16 | u64 | Initial epoch: 1, immutable |
| 24 | u64 | Sticky failure: 0 healthy, 1 overflow, 2 journal I/O/internal failure |

The header is 32 bytes. Only the failure word changes after initialization; its
first nonzero value is published atomically and retained. Unknown versions,
required flags, or failure codes must not be treated as healthy v2 input.
Version 1 uses the same magic but a 24-byte header and unframed records; its field
at offset 16 is the captured generation, not the initial epoch.

## Frames

Frames start at offset 32 and are aligned to 8 bytes. Each frame contains exactly
one record. Its tag is in the frame header; the payload has no nested tag,
record count, or batch wrapper.

| Frame offset | Type | Meaning |
| --- | --- | --- |
| 0 | u64 | Committed epoch; zero means unpublished |
| 8 | u32 | Payload byte length |
| 12 | u32 | Record tag (see below) |
| 16 | u32 | Sequence, starting at 0 for BEGIN |
| 20 | u32 | CRC32C |
| 24 | bytes[length] | Payload |
| after payload | bytes[0..7] | Zero padding to an 8-byte boundary |

CRC32C uses the Castagnoli polynomial and Go's `hash/crc32` convention. Feed bytes
`[0,20)` and the payload, in that order, with the intended nonzero
epoch in the first word. The checksum field and padding are excluded.

The frame header is 24 bytes. The 64 MiB journal cap keeps the number of frames
per epoch well below the u32 sequence limit; the writer also checks for overflow
before encoding a sequence.

Publication is serialized by `logMu`: ensure mapping capacity, atomically store
zero to the publication word, copy the remaining header and payload, zero the
padding, then atomically store the epoch. The aligned sequentially consistent
stores order invalidation before overwrite and publication after payload writes
on the supported little-endian amd64 and arm64 hosts. CRC is an additional
corruption check, not the synchronization mechanism.

### Record tags and payloads

| Tag | Record | Payload |
| --- | --- | --- |
| 0 | Legacy CREATE | Reserved; never emitted or accepted in v2 |
| 1 | RENAME | `ino u64, oldParent u64, oldName str, newParent u64, newName str` |
| 2 | UNLINK | `ino u64, parent u64, name str` |
| 3 | NODESTATE | `ino u64, state` |
| 4 | CREATE_WITH_STATE | `ino u64, parent u64, name str, ftype u8, identity, state` |
| 5 | BEGIN | `previous_epoch u64` |
| 6 | END | `end_offset u64, frame_count u64, reason u64` |

CREATE_WITH_STATE has a fresh tag, 4, so the tag alone distinguishes it from the
legacy CREATE (0). All tag assignments are explicit. RENAME, UNLINK and NODESTATE
keep their field layouts; their tag is carried by the frame instead of a leading
payload byte. No generic MUTATIONS frame exists.

`str` and byte strings are `length u32` followed by that many bytes. `ftype` is
0 regular file, 1 directory, 2 symlink, or 3 device. `identity` is empty for regular
files/directories, a target `str` for symlinks, and `major u32, minor u32` for
devices. The shared state fields are:

```
mode u32, uid u32, gid u32, mtime_seconds i64, size u64,
segment_count u32, segment_count * (start u64, end u64, value u64),
xattr_count u32, xattr_count * (key str, value bytes)
```

CREATE_WITH_STATE encodes the inode number once and includes this state directly;
there is no embedded NODESTATE record or duplicate inode number. It also creates
hardlink directory entries, carrying the existing inode's current state.
NODESTATE describes later updates. Each frame's payload must decode to exactly
one record, with no trailing bytes. Frame commitment does not make multiple
filesystem operations one transaction.

BEGIN requires `previous_epoch == epoch - 1` and sequence zero. END's offset is
the absolute byte immediately after its padding. Count includes BEGIN and END;
reason is 0 for a live snapshot and 1 for graceful exit.

This v2 format is unpublished. Its 24-byte frame headers replace the earlier
local 32-byte frame headers; consumers must use the matching layout.
The earlier local batch-framing prototype also
used header version 2, but used BEGIN tag 0; a reader requiring BEGIN tag 5 rejects
it immediately. There is no compatibility interpretation of tag 0 as the new
CREATE_WITH_STATE.

## Epoch and shutdown lifecycle

The file retains one epoch, not the sandbox's entire history. A consumer needs
the state through BEGIN's `previous_epoch`; the first epoch starts from empty.

A live drain reconciles open writers and writable mappings, appends END, and
returns the epoch and byte length. The host must capture the journal and
filestore while writers remain paused. The completed segment stays intact until
the next append or drain initializes the next BEGIN at offset 32. Older tail
bytes remain but their epoch differs. A crash during BEGIN replacement can leave
no recoverable active epoch; this format does not retain a second slot.

`Loader.WaitExit` finalizes after all guest tasks exit, before loader destruction.
The kernel pauses/quiesces asynchronous work and serializes with other kernel
capture operations. Each enabled mount reconciles content state, appends a
graceful END, disables hooks, unmaps the journal, then truncates to the committed
offset. Repeated finalization returns the original result. A failed journal is
trimmed to its committed prefix without a successful END. A truncate failure is
reported; a valid END may still bound a file with excess capacity.

## Recovery

Require a valid BEGIN and the expected prior cursor. Read only consecutive
frames with the same epoch, increasing sequence, valid lengths, tags and CRCs.
Bound all lengths/counts before allocating and validate each record payload.
Stop at the first invalid, unpublished, truncated, or wrong-epoch frame. Never
scan ahead for a plausible next frame. END validates its own offset and count;
bytes after it are not records.

Distinguish a complete epoch from a partial committed prefix and from a failed
journal. A graceful END with exact EOF proves successful journal finalization
and trimming. Missing END is partial even when the last frame ends exactly at
EOF. A nonzero failure word prevents reporting a healthy snapshot, even if a
prior END is present. The failure word cannot report a crash that happened
before its store.

An END for a live snapshot is not evidence that subsequent guest writes are
captured: open-writer and mmap changes may not emit records until reconciliation.
Partial recovery does not guarantee a point-in-time filesystem image, and inode
segments do not preserve the old contents of overwritten/reused filestore pages.

## Pending work (not implemented here)

### Dump tool: `apoorva/fss/fsmutationlog-dump-tool`

The tool exists at `tools/fmlgdump/{main.go,main_test.go,BUILD}` on that branch.
Its decoder currently expects v1's flat stream and prints through EOF. Keep this
work pending until separately authorized:

- [ ] Add version dispatch after the common magic/version prefix. Preserve v1
  decoding and its legacy FULL-flag interpretation only in the v1 path.
- [ ] Decode the v2 header and print version, root, initial epoch and failure
  status; reject unsupported versions/required flags.
- [ ] Add a bounded frame reader validating publication, epoch, sequence,
  lengths, CRC32C, BEGIN and END fields. Dispatch directly on the frame tag;
  decode exactly one bounded payload and reject trailing bytes before printing.
- [ ] Add CREATE_WITH_STATE (tag 4), sharing inode-state decoding with NODESTATE.
  Reserve tag 0 for legacy CREATE; accept it only in the v1 decoder. BEGIN and
  END are tags 5 and 6. Do not retain the batch-prototype MUTATIONS wrapper.
- [ ] Print frame offsets, epoch, sequence, previous epoch, END reason and
  committed length. Keep `-v` for segment/xattr detail; count frames and mutations
  separately.
- [ ] Stop at END instead of parsing capacity/stale bytes. For graceful END,
  report whether the file is trimmed exactly; distinguish extra capacity from
  a malformed frame.
- [ ] Add explicit recovery mode that prints only the validated prefix and
  reports stop offset/reason. Default mode requires a complete epoch. Partial
  recovery and sticky journal failure must have distinguishable nonzero exit
  statuses; neither may look like a complete successful dump.
- [ ] Document that RPC stdout is `generation=... length=...`, not FMLG bytes;
  the tool takes the captured journal or a dead sentry's journal file. V1 still
  requires the caller to bound input to the RPC-provided length.
- [ ] Add v1 regression fixtures, v2 complete/partial/failed examples, stale-tail
  and partial-BEGIN cases, every-byte truncations, checksum/sequence failures,
  legacy CREATE rejection in v2, single-record/trailing-byte validation, unknown
  versions and oversized count tests.
  Add fuzz coverage for both readers and update usage documentation.

### Runtime integration dependencies

- [ ] Teach modal-runtime to consume v2 before selecting this sentry build;
  existing v1 consumers cannot decode it.
- [ ] Coordinate exit with the host-side reflink following a live drain. Kernel
  serialization covers the RPC, not the host's subsequent capture: an exit
  during that window must not silently pair different epochs or filestores.
- [ ] Preserve/capture the filestore before destructive cleanup. Private memory
  files are configured with `DecommitOnDestroy`, and inode release can also
  reclaim their ranges; journal finalization alone does not preserve file data.
- [ ] Retain/retry the consumer cursor across upload failures and decide what
  partial recovery means for a user-visible exit snapshot.
