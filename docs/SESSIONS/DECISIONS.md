# Sessions: decisions, targets and roadmap

## Problem

PR #2731 (PICARD-3118) saves sessions as gzip-compressed YAML. Reading the code:

1. Every save is a full, synchronous export on the UI thread: all files twice,
   every track diffed against its scripted metadata, pure-Python `yaml.dump`,
   then gzip. The same path serves the autosave timer and the exit backup.
2. Exporting stored release data reads each album's temp file, gunzips,
   parses JSON, dumps YAML, and gzips again. Import uses pure-Python
   `yaml.safe_load`.
3. Restore polls: one 150 ms `QTimer` chain per file; each tick rebuilds a
   track dictionary (files x tracks per tick).
4. In `MetadataHandler.apply_tag_deltas_if_any` and
   `apply_saved_metadata_if_any` the retry condition `len(pending) == 0` can
   never become true, so retries never run and the timer reschedules forever.
   Files still loading after the single 200 ms attempt lose their unsaved
   edits. This follows from the code (the closure never sees `pending`
   change); a failing test comes before the fix and confirms it.
5. Crash recovery depends on an off-by-default timer and an exit hook that does
   not run on a crash or power loss.
6. Instances share `last_session_path` and `session_autosave_path` and can
   overwrite each other.

These findings come from code reading; phase 0 measures them.

## Decisions

| # | Decision | Reason |
|---|---|---|
| 1 | One SQLite file per session. | Copyable, shareable, atomic to replace, safe to back up. |
| 2 | Extension `.mbps.db`. | Distinct from `.mbps.gz`; the file type is detected by magic bytes. |
| 3 | Working DB journals continuously; Save is a snapshot. | Cost proportional to changes; crash loses seconds. |
| 4 | Working DB is always local; per instance. | WAL and locks are unreliable on network filesystems; removes most multi-instance conflicts. |
| 5 | Conflicts only at Save, detected with `save_id`. | Works on every filesystem; no reliance on mtime or inode. |
| 6 | Target working set: 20k files. | Bounds the benchmark and the Qt/File memory model; 1M files is for a future library index, not for session restore. |
| 7 | Always store release data; remove `session_include_mb_data`. | Offline restore, one code path, recovery without re-fetching. |
| 8 | Tag cache with lazy cover art and a bounded persistent cover-art cache. | Skip reading files on network filesystems without storing image bytes in sessions. |
| 9 | Network folders supported, with a warning. | Local working DB plus atomic saved file make it safe. |
| 10 | Session code is UI-free (QtCore only), store has no Qt. | Headless and a future CLI session manager. |
| 11 | CLI in phase 1 is store-only; live commands with the command engine. | `HeadlessTagger` is scoped to the file pipeline; no live workspace in one-shot commands. |
| 12 | Options carried: current three, extensible registry. | Overlay or profile-based options are a larger design. |
| 13 | Missing files are kept and reported, never dropped silently. | Offline drives must not lose session content. |
| 14 | Legacy `.mbps.gz` remains readable. | Existing user files keep working. |
| 15 | Schema ready for a future library index (identity columns, tombstones, roots). | Avoids a rewrite if Picard grows into a library manager. |

## Library-manager readiness

Not built now. The session schema and `identity.py` are designed so that a
future `library.db` can reuse them.

Sync model for such an index:

- **Internal operations** (save, rename, move by Picard) update the row in the
  same transaction as the event (`File._saving_finished` knows old and new path).
- **External changes** are found by a reconcile scan on a worker thread: walk
  roots with `os.scandir`, compare `(ino, size, mtime_ns)`. Directory mtime is
  not trusted. Classify: unchanged, modified (re-read lazily), missing, new,
  moved (a missing row and a new file sharing `(dev, ino)` or
  `(size, fast_hash)`).
- **Deletions** are tombstones (`missing_since`). A root that is offline is
  marked `online=0` and its files are never marked missing. Pruning is explicit.
- **No filesystem watchers** as a requirement: `inotify` watch limits and
  `QFileSystemWatcher` do not scale to 1M files and lose events. A watcher may
  accelerate an open session only.
- **Scale rules:** `WITHOUT ROWID` or covering indexes for path lookups, a few
  indexed columns (artist, album, title, MBIDs) plus a compact tag blob, never
  one row per tag; batched transactions of 10k to 50k rows; `ANALYZE` after bulk
  loads; reconcile progress is persisted so an interrupted scan resumes; paged
  SQL queries, never load the library into Python.

## Acceptance targets

Reference set: 20k files, about 1500 albums, local SSD unless stated. Numbers
are starting points and are calibrated after the phase 0 baseline. Sizes are
estimates until measured.

| Area | Target |
|---|---|
| UI responsiveness | No single UI-thread slice longer than 50 ms during save, journal flush or restore (the `process_in_batches` default budget). |
| Journal flush | Typical dirty set (up to 200 rows): 20 ms or less on the UI thread. Bulk set (20k rows): spread over slices of 50 ms or less. |
| Durability | After `kill -9`, at most 3 s of work lost; `integrity_check` passes. |
| Explicit save | UI never blocked; 3 s or less wall time. |
| Restore overhead | Everything except file loading: 2 s or less; no polling timers remain. |
| Restore total | No more than 10% slower than a plain `add_files` of the same files. |
| MusicBrainz requests | Zero when restoring from stored data. |
| Session size | 15 MB or less without tag cache; 80 MB or less with descriptor-only tag cache. |
| Tag cache | At least 5x faster at 5 ms simulated latency per file; real SMB: reported, no fixed target before the spike. |
| Memory | Peak extra RSS during save 50 MB or less; no new per-album resident data. |
| Instances | A second instance detects a held lock in 100 ms or less and never writes; no silent clobber in the two-process test. |
| Startup | Orphan scan adds 50 ms or less with 10 working DBs. |

## Roadmap

Each phase is a separate PR with small commits.

| Phase | Content | Exit criteria |
|---|---|---|
| 0 | Benchmark script (20k files, 500+ albums; export, import, UI-thread blocking, exit, via `DebugOpt.TIMINGS`). Failing test for the never-firing retry, then the fix. Track dictionary built once per album. | Baseline recorded; bug test red then green. |
| 1 | `picard/session/store/` (schema, model, store, legacy importer, identity, lock). `SessionManager` and the sinks, so nothing in `picard/session/` touches `Tagger`, `ui_item` or `window`. `.mbps.db` written. Store-only `picard-cli session` commands. | Round-trip tests; legacy file opens; two-process lock and conflict tests; import-lint test; full cycle under `HeadlessTagger`. |
| 2 | Event-driven restore; remove polling. | No polling timer left in `picard/session/`. |
| 3 | Dirty tracking, journal writer, working DB, recovery prompt; remove the autosave timer and the exit hook. | Flush within targets; `kill -9` recovery test. |
| 4 | Release blobs always stored; options migration; parse-failure fallback; evaluate dropping the album `DataHash`. | Memory not worse than PICARD-3409; no half-built albums. |
| 4b | Spike (real SMB bytes, `CoverArtImage.data` call sites), then tag cache with lazy cover art. | Measured gain; hit/miss correctness tests. |
| 4c | Persistent size-limited cover-art cache. | Eviction and concurrency tests. |
| 5 | Remove the YAML writer; options page; user docs (picard-docs PR); NEWS. | |
| later | Live `picard-cli session` commands with the command engine; opening a session from a command-line argument; library index. | |

## Testing

- Follow `test/README.md`. Match the style of each test file; use
  `subtest_cases` for table tests on `PicardTestCase`; never create a local
  `QApplication`.
- Store tests are pure (no Qt) and use temporary directories.
- Multi-process tests (`multiprocessing`): lock, WAL concurrency, conflict at
  Save.
- Crash test: write the journal, `kill -9` a child, reopen, verify rows and
  orphan detection.
- Migration test for every `user_version` bump; saved-file test asserting no
  `-wal`/`-shm` and the header journal mode.
- Existing `test/session/` tests: keep those of reused pure parts (location
  detector, metadata handler, item grouper); replace those of removed classes
  (retry helper, track mover, UI state manager, exporter/loader internals);
  keep the YAML fixtures for legacy import tests.
- Import-lint test: nothing under `picard/session/` imports `QtWidgets`,
  `picard.ui` or `picard.tagger`.
- Reconcile tests for the library index can wait: rename, cross-directory move,
  delete, offline root, case-only rename, inode reuse.

## Pre-merge tasks

- New ticket for the rework (humans create tickets and PRs).
- Config-upgrade version string for the option migration (current
  `PICARD_VERSION` is `3.1.0dev3`), per the maintainers' release practice.
- User documentation in the picard-docs repository.
- NEWS entry.
- Document `PICARD_SESSION_WORK_DIR` in `docs/EnvironmentVariables.md`.
- i18n: strings defined under `picard/const/` use `gettext_constants()`.
