# Memory Audit Findings (PICARD-2172 / PICARD-2530)

Investigation using the opt-in `--debug-opts=memory` instrumentation
(`picard/util/memprofile.py`). Enable and reproduce, then read the
`memprofile[session]` / `memprofile[album]` lines in the debug log.

## Method

- `analyze_session_footprint()` walks the whole Tagger state (albums, tracks,
  files) and counts `Metadata` objects + their deep size.
- `analyze_album_footprint()` breaks a single album down by component.
- `scripts/profile_bulk_metadata.py` measures the data layer headlessly at
  scale.

## Measured evidence

Real load: 31 albums, ~600 tracks, 583 files (one session).

| tracks | files | Metadata objects | metadata total | retained release nodes |
|-------:|------:|-----------------:|---------------:|-----------------------:|
| 8      | 8     | 42               | 313 KiB        | 42 KiB                 |
| 302    | 583   | 2,134            | 17.9 MiB       | 6.0 MiB                |
| 595    | 583   | 3,013            | 25.0 MiB       | 9.7 MiB                |

Key conclusions:

1. **Metadata storage is linear at ~8.5 KiB per `Metadata` object**
   (~18-21 KiB per file+track). No super-linear storage blowup. The multi-GB
   reports are **object-count driven** — a ~50k-track collection projects to
   ~1.5-2 GB in `Metadata` alone, before Qt overhead. Levers: reduce the number
   of `Metadata` objects (2/file + 3/track).

2. **Cover art is NOT a RAM cost.** `coverart.image.DataHash` stores bytes in
   temp files and content-deduplicates via a blake2b-keyed
   `WeakValueDictionary`. In-memory image objects are just hash + filename.

3. **Retained raw release nodes are pure, growing waste.**
   `Album` stores the full raw MB release JSON in `_release_node_cache` at load
   (`album.py`) and **never frees it**. It is read only by
   `session_exporter._export_mb_cache`, and only when `session_include_mb_data`
   is set and the user actually exports a session. ~313 KiB/album; 9.7 MiB at
   31 albums; hundreds of MiB at collection scale.

## Proposed fix for the release node (highest value)

The restore path (`session_loader._build_from_cache` → `album._parse_release`)
needs the *full* node, so it cannot be slimmed by dropping fields. But it does
not need to be a live Python dict tree in RAM.

Store `_release_node_cache` as a **lazily-serialized gzipped-JSON blob** and
deserialize only when the exporter reads it. Measured on a representative
12-track node with artist credits/rels/aliases:

- live dict tree: 60.0 KiB
- JSON bytes:      17.3 KiB
- gzipped JSON:     0.8 KiB  (**~76x smaller than the live tree**)

This preserves offline session restore and data fidelity, adds only a small
CPU cost at the (rare) save time, and cuts resident release-node memory ~75x.

Alternative (smaller win): only retain the node when
`session_include_mb_data` is enabled. It defaults to True, so this helps only
users who disable it.

## Secondary target

`Track.scripted_metadata` is a third full `Metadata` copy per track. Dropping
or lazily deriving it would cut per-track `Metadata` object count by a third.
Needs an investigation of its consumers before changing.
