# Sessions: MusicBrainz data and caches

Three kinds of data make restore fast: the MusicBrainz release data, per-file
tag data, and cover-art bytes.

## MusicBrainz release data

Every album's release node is stored in the session as `album.release_blob`
(gzip JSON) together with `blob_format` and `fetched_at`.

Why it is always stored:

- Restore and crash recovery work offline and without network waits.
  MusicBrainz is rate limited (the default minimum delay is 1000 ms per host in
  `picard/webservice/ratecontrol.py`, and nothing in Picard lowers it for
  MusicBrainz), so fetching 1500 albums takes about 25
  minutes or more, against local parse time with stored data.
- One restore path instead of four combinations of two options.
- The size cost is small: about 2.6 KiB gzipped per release (measured in
  PICARD-3409), so about 4 MB per 1500 albums.

Restore choice (`session_restore_use_stored_mb_data`):

| Value | Behavior |
|---|---|
| on (default) | Build albums from stored data. No MusicBrainz requests. |
| off | Load each album from MusicBrainz, then reapply placements and edits. What no longer matches is reported. Stored data is the fallback when offline. |

Never both: stored data is not used and then re-fetched.

Staleness: `fetched_at` is stored and shown. Stored data may differ from
MusicBrainz now. A per-album "Refresh from MusicBrainz" action is a possible
later addition.

Parse failures: a stored node that does not parse leads to a network load, or
an error row when offline. It never leaves a half-built album.

A "save without MusicBrainz data" export is an explicit choice, not a persistent
option. Files saved that way restore albums from the network.

### Option migration

`@upgrade_settings(...)` in `config_upgrade_hooks.py` (it also covers profile
overrides and imported profiles) maps the old options:

| `session_include_mb_data` | `session_no_mb_requests_on_load` | New `session_restore_use_stored_mb_data` |
|---|---|---|
| on | on | on (same behavior) |
| on | off | off (the old code used the stored node and fetched anyway) |
| off | any | off (old files had no stored data and always used the network) |

Session files saved before the change with the include option off contain no
stored data; their albums load from the network whatever the choice is.

## Per-file tag cache (phase 4b)

Purpose: avoid re-reading files on restore, mainly on network filesystems where
each open and read has latency.

Table `file_cache` (see [FORMAT.md](FORMAT.md#schema-v1)) stores each file's
original metadata, including file-info tags (length, bitrate, format), next to
its identity.

Restore flow, in a worker pool:

1. `os.stat` each path (one round trip, run in parallel to hide latency).
2. If `size` and `mtime_ns` match, and the `cache_key` matches: hit. Build the
   `File` from cached metadata without opening it.
3. Otherwise: normal load.

Rules:

- A hit means "unchanged since saved". It is never an assumption. Any mismatch
  is a miss.
- `ino` is not required to match (unstable on SMB).
- Modification times are compared at the filesystem's granularity (for
  example 2 seconds on FAT). When in doubt: miss.
- `cache_key` covers the Picard version, the mutagen version and the settings
  that influence parsing. Any change invalidates the cache.
- Files with unsaved edits restore the delta on top of the cached original.
- A "Reload from disk" action forces a miss.
- The cache is passed in by the session restore only, through an injectable
  `FileTagCache`; the normal add-files path is unchanged at first.

### Embedded cover art

Most files embed cover art, so images must be handled. Image identity in
Picard is the content hash (`CoverArtImage.__eq__` uses `datahash`, a blake2b of
the bytes, plus types). Album and cluster aggregation compares hashes. Bytes
are needed only to display, save or compare content.

The tag cache stores image descriptors only (hash, mime, size, dimensions,
types, comment). Image data is lazy:

- `CoverArtImage.data` knows its hash and how to obtain the bytes.
- Lookup order: live `DataHash` temp file, then the persistent cover-art cache,
  then a re-read from the audio file.
- Bytes read from a file are verified against the recorded hash. A mismatch
  means the file changed: the cache entry is dropped and the file reloads
  normally.
- Saving never sees `data is None`: saving materializes the bytes first.

This needs lazy support in `CoverArtImage` / `DataHash`, both core classes.
Phase 4b starts with a spike on a real SMB mount that measures the bytes read
per file (tags versus images) and counts the call sites of
`CoverArtImage.data` during a plain restore. If lazy images prove too
invasive, the scope is re-evaluated before any code lands.

## Persistent cover-art cache (phase 4c)

Today image bytes live in `DataHash` temp files that are deleted at exit. A
persistent layer sits behind the lazy fetch:

| Aspect | Design |
|---|---|
| Key | blake2b hash, the same as `DataHash`. |
| Location | `cache_folder()`, hash-sharded directories, one file per image. Always local. |
| Writes | Temporary file then `os.replace`. Images are already compressed; no extra compression. |
| Index | Small local SQLite DB `(hash, size, last_used)`, so eviction does not scan the directory. |
| Limit | `cover_art_cache_max_mb`, default 512, 0 disables the persistent layer. Least recently used entries are evicted when the total exceeds the limit. |
| Populated by | Images of files when they load, images saved with a session, and images fetched lazily. |
| Eviction | Costs a re-read from the audio file. A file missing on disk is a miss. |
| Instances | Atomic writes are enough; racing evictions degrade to a miss. |
| UI | A "Clear cache" button in the options page. |

The cache holds copies of the user's cover art in the cache directory. This is
documented in the user docs, and clearing it is one click.

## What is not stored in v1

AcoustID lookup and fingerprint task state, cover-art search results, selection
and scroll state. Fingerprints that are real tags are stored like any other tag
when the tag cache is on.
