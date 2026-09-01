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

## Secondary target analysis: `scripted_metadata` (investigated — do NOT compress)

`Track.scripted_metadata` is a third full `Metadata` copy per track. At the
fully-loaded state above, per-track metadata is ~15 MiB (3 copies) and
file-side metadata ~10.9 MiB (2 copies/file), so on paper it looks like a large
target. Investigation shows it is **not** a safe compression/lazy-derivation
target, unlike the release node:

- **It is semantically load-bearing.** `scripted_metadata` is the snapshot of a
  track's metadata right after the tagger scripts ran, before user edits.
  `track.metadata.diff(track.scripted_metadata)` therefore equals *the user's
  manual UI edits*. That diff is used to (a) re-apply user edits on top of
  freshly-scripted metadata when a file is matched to the track
  (`track.py` `add_file`), and (b) persist per-track overrides on session
  export (`session_exporter`). It cannot simply be dropped.

- **It is on the CPU-sensitive hot path.** The `add_file` diff runs once per
  file-to-track match, i.e. once per file across a whole collection — exactly
  the kind of per-recording operation PICARD-2530 reports as slow. Storing it
  compressed (as we did for the release node) or lazily re-deriving it by
  re-running scripts would trade memory for CPU *on the path that is already a
  performance complaint*. Wrong trade-off here.

Recommendation: leave `scripted_metadata` as a live `Metadata`. Memory
reduction for the per-track/per-file `Metadata` objects, if pursued, should
come from reducing object *overhead* or count in ways that do not add hot-path
CPU (e.g. interning repeated tag-value strings/keys, or a lighter internal
representation), not from compressing this specific field.

## String interning of tag keys/values (investigated, benchmarked — low value)

`Metadata` stores tag keys and values as plain Python strings, and the same
values repeat massively across a collection (album, album artist, genre, date,
release type, media) — and every `copy()` (e.g. metadata → orig_metadata)
creates fresh string objects. So interning at the `Metadata._set` chokepoint
(which both direct sets and copies go through) looked promising.

Benchmarking told a more sober story. Attribution of a realistic 16-tag
`Metadata` object:

| component | share |
|-----------|------:|
| containers (store dict + per-tag lists) | ~52% |
| keys (strings) | ~24% |
| values (strings) | ~26% |

Only the strings (~48%) are dedupable; the containers are not (every `Metadata`
needs its own dict + per-tag lists). And an isolated build/retain benchmark of
interning keys (`sys.intern`) + values (bounded dedup cache) measured:

- memory saved: **~4-15%** (far less than the raw "duplicated content" figure,
  because container overhead dominates and CPython already stores short strings
  compactly)
- time cost: **~+55%** on the build/`_set` path

That is a bad trade: a small memory win for a large CPU cost on the exact
per-file/per-track path PICARD-2530 flags as slow. **Not recommended as-is.**

If pursued later, the only defensible variant is interning *keys only*
(`sys.intern` on the tag name in `_set`): the tag vocabulary is small and
bounded, so the cache cannot grow unbounded, and it removes the ~24% key
duplication at minimal lookup cost. Values should not be interned on the hot
path. This still leaves the ~52% container cost untouched.

## Where the memory actually goes, and the realistic levers

The dominant cost at scale is the **number of `Metadata` objects** (2 per file
plus 3 per track) and their **container overhead** (dict + per-tag lists), not
the string payload. The two structural sources the user identified:

- **copy() duplicating everything (metadata → orig_metadata).** This creates a
  second full set of containers. It cannot be shared/COW-ed trivially because
  `orig_metadata` (on-disk values) and `metadata` (edited values) must diverge
  independently.
- **tracks/albums sharing strings.** Real but small in realized bytes (the ~26%
  value share), and interning it costs hot-path CPU (above).

Realistic future levers, in rough order of value vs risk, all needing their own
benchmarking:

1. **Reduce container overhead per `Metadata` — IMPLEMENTED.** In a realistic
   16-tag object, 15 tags are single-valued and their 1-element list wrappers
   were 94% of all list overhead (~24% of the whole object). `Metadata` now
   stores a single value as a bare `str` internally (multiple values still as a
   `list[str]`); all public accessors (`getall`, `getraw`, `rawitems`, `items`,
   `get`) keep presenting values as lists, so the external contract is
   unchanged. The `copy()`/`_update_from_metadata` path was optimized to copy
   the internal store directly, sharing immutable bare strings instead of
   copying 1-element lists.

   Measured on a 16-tag object: **deep size 5559 B → 4239 B (−24%)**, and a
   build+read+copy cycle went **984 → 883 ms (−10% CPU)** — a rare win on both
   the memory (PICARD-2172) and CPU (PICARD-2530) axes, because the faster copy
   path more than offsets the small getall list-wrapping cost. Verified by the
   full test suite (5935 passed).
2. Intern tag keys only (bounded, cheap) — attacks ~24%. Not yet done.
3. Avoid materializing `Metadata` copies that are never diverged from
   (structural sharing with copy-on-write) — attacks container count; higher
   design risk.
