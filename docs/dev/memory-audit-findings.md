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

Before the release-node fix:

| tracks | files | Metadata objects | metadata total | retained release nodes |
|-------:|------:|-----------------:|---------------:|-----------------------:|
| 8      | 8     | 42               | 313 KiB        | 42 KiB                 |
| 302    | 583   | 2,134            | 17.9 MiB       | 6.0 MiB                |
| 595    | 583   | 3,013            | 25.0 MiB       | 9.7 MiB                |

After the release-node fix (same collection):

| tracks | files | Metadata objects | metadata total | retained release nodes |
|-------:|------:|-----------------:|---------------:|-----------------------:|
| 254    | 583   | 1,990            | 17.8 MiB       | 242 KiB                |
| 579    | 583   | 2,965            | 25.8 MiB       | 433 KiB                |

Key conclusions:

1. **Metadata storage is linear at ~8.5-9 KiB per `Metadata` object**
   (~18-21 KiB per file+track). No super-linear storage blowup. The multi-GB
   reports are **object-count driven** — a ~50k-track collection projects to
   ~1.5-2 GB in `Metadata` alone, before Qt overhead. Levers: reduce the number
   of `Metadata` objects (2/file + 3/track).

2. **Cover art is NOT a RAM cost.** `coverart.image.DataHash` stores bytes in
   temp files and content-deduplicates via a blake2b-keyed
   `WeakValueDictionary`. In-memory image objects are just hash + filename.

3. **Retained raw release nodes were pure, growing waste — now fixed.**
   `Album` stored the full raw MB release JSON in `_release_node_cache` at load
   (`album.py`) and never freed it. It is read only by
   `session_exporter._export_mb_cache`, and only when `session_include_mb_data`
   is set and the user actually exports a session. This grew to ~313 KiB/album
   (9.7 MiB at 31 albums) and is now stored compressed (see below).

## Release-node compression fix (implemented, verified)

**Problem.** `Album` stored the full raw MB release JSON in
`_release_node_cache` as a live Python dict tree for the whole session, even
though it is read only by `session_exporter._export_mb_cache` (and only when
`session_include_mb_data` is set and the user exports a session). It was never
freed, so it grew with the collection.

**Fix.** The restore path (`session_loader._build_from_cache` →
`album._parse_release`) needs the *full* node, so it cannot be slimmed by
dropping fields — but it does not need to be a live dict tree in RAM. The node
is now stored compressed (gzipped JSON) in `_release_node_cache_blob`, exposed
via a `_release_node_cache` property that (de)serializes on demand.
Deserialization happens only at the rare session-export time; all readers are
unchanged. Preserves offline session restore and data fidelity.

**Verified impact (real session, before vs after the fix):**

At the fully-loaded state (31 albums, ~580 tracks, 583 files):

| retained release nodes | before | after |
|------------------------|-------:|------:|
| at 31 albums loaded    | 9.7 MiB | 433 KiB |

That is a **~23x reduction on real data** (the synthetic-node microbenchmark
showed ~76-99x; real nodes compress less because they have more entropy —
real IDs, varied titles, richer relations). The growth curve as albums loaded
also flattened from a runaway 2.2 → 6.0 → 8.2 → 9.7 MiB to a gentle
20 → 96 → 242 → 375 → 433 KiB. No errors, decode failures, or regressions in
the real load path (223 album-load events succeeded).

## Secondary target

`Track.scripted_metadata` is a third full `Metadata` copy per track. At the
fully-loaded state above, per-track metadata is ~15 MiB (3 copies) and
file-side metadata ~10.9 MiB (2 copies/file). Dropping or lazily deriving
`scripted_metadata` would cut per-track `Metadata` object count by a third.
Needs an investigation of its consumers before changing.
