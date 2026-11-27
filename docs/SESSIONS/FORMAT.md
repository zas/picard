# Sessions: file format

Extension: `.mbps.db`. A SQLite 3 database, one file per session.

- `PRAGMA application_id` = a Picard session constant (32-bit integer, value
  allocated when the store is implemented) that identifies the file type
  without relying on the extension.
- `PRAGMA user_version` = schema version (integer). Migrations are keyed on it.
- Minimum SQLite version: 3.24 (UPSERT). Checked at import time with
  `sqlite3.sqlite_version_info`. Packaged builds bundle SQLite (PICARD-3444).
- Connections set `PRAGMA foreign_keys=ON` (the `ON DELETE CASCADE` clauses
  below depend on it).
- Saved files use rollback-journal mode (`journal_mode=DELETE`) and have no
  `-wal` / `-shm` sidecars. Working DBs use WAL.

Reading by magic bytes: `SQLite format 3\0` is a session DB; gzip magic
`1f 8b` is a legacy YAML session.

## Schema v1

The `file_cache` table at the end is not part of v1; it is added by the v2
migration when the tag cache lands (phase 4b).

```sql
CREATE TABLE meta (
  key   TEXT PRIMARY KEY,
  value TEXT
) WITHOUT ROWID;
-- keys: format_version, picard_version, created_at, save_id, revision,
--       saved_revision, clean_shutdown, options (JSON), instance_id

CREATE TABLE root (
  id        INTEGER PRIMARY KEY,
  path      TEXT NOT NULL,        -- native path of the root directory
  volume_id TEXT,
  online    INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE file (
  id            INTEGER PRIMARY KEY,
  root_id       INTEGER REFERENCES root(id),
  relpath       TEXT NOT NULL,    -- '/'-separated, relative to root
  relpath_raw   BLOB,             -- os.fsencode() bytes, only if not valid Unicode
  loc_type      TEXT NOT NULL,    -- unclustered | cluster | album_unmatched | track | nat
  album_id      TEXT,
  recording_id  TEXT,
  cluster_title TEXT,
  cluster_artist TEXT,
  dev INTEGER, ino INTEGER,       -- identity, best effort
  size INTEGER, mtime_ns INTEGER,
  fast_hash BLOB,
  missing_since INTEGER,          -- unix time, NULL if present
  delta BLOB,                     -- unsaved tag edits (compact JSON), NULL if saved
  UNIQUE (root_id, relpath)
);

CREATE TABLE album (
  id           TEXT PRIMARY KEY,  -- release MBID
  expanded     INTEGER NOT NULL DEFAULT 0,
  release_blob BLOB,              -- gzip(JSON) release node
  blob_format  INTEGER,           -- node format version
  fetched_at   INTEGER
) WITHOUT ROWID;

CREATE TABLE album_override (
  album_id TEXT NOT NULL REFERENCES album(id) ON DELETE CASCADE,
  track_id TEXT,                  -- NULL = album-level edits
  tags     BLOB NOT NULL,         -- compact JSON {tag: [values]}
  PRIMARY KEY (album_id, track_id)
);

-- added by the schema v2 migration in phase 4b (tag cache):
CREATE TABLE file_cache (
  file_id    INTEGER PRIMARY KEY REFERENCES file(id) ON DELETE CASCADE,
  cache_key  TEXT NOT NULL,       -- picard + mutagen version + parse-affecting settings
  tags       BLOB NOT NULL,       -- original metadata incl. file info tags, no image bytes
  images     BLOB                 -- image descriptors: hash, mime, size, dims, types, comment
);

CREATE INDEX file_album ON file(album_id);
```

Notes:

- An unmatched album is derived: an `album` row with no file and no override.
- Deltas and overrides are blobs, not one row per tag, so the row count stays
  proportional to the number of files and albums, and a session holds edits
  only, not full tag sets.
- Release blobs are the same gzip(JSON) node `Album` keeps for session export
  today, stored as is (no decode/re-encode).
- No UI order is stored. The views sort.

## Paths

- Stored as `root_id` + `relpath` so a remounted drive or a moved collection
  is re-rooted by editing one `root` row.
- `/` separators in `relpath` on every platform.
- A name that is not valid Unicode (possible on Linux, and with lone
  surrogates on Windows) is stored in `relpath_raw` using `os.fsencode`; Python's
  `sqlite3` cannot store lone surrogates in TEXT. `relpath` then holds a
  lossy display form.
- Lookups use the same normalization as `Workspace.files` (`resolve_fs_path`).
  There is no second definition of "the same file".

## File identity

Used to detect moved or renamed files and, later, to keep a library index in
sync. Tiers, cheapest first:

1. `(dev, ino)` where stable. Not reliable on FAT/exFAT, many network and FUSE
   filesystems, or after a restore from backup.
2. `(size, mtime_ns)` plus `fast_hash` (first and last blocks), the idea
   behind `FileIdentity` in `picard/file.py`; the code is extracted and shared,
   not duplicated.
3. Embedded MusicBrainz IDs or an AcoustID fingerprint as a last-resort relink;
   never part of the default scan.

A hash of the whole file is not an identity: tag edits change the bytes.

## Versioning and compatibility

| Case | Behavior |
|---|---|
| `user_version` older than supported | Migrated in place in the working DB (the source file is untouched). |
| `user_version` newer than supported | Refused: `SessionTooNew`, with the Picard version that wrote it. |
| `application_id` mismatch | Refused as not a Picard session. |
| Gzip magic (`.mbps.gz`) | Imported by `legacy.py` (`yaml.safe_load`), then stored as v1. |
| Unknown `meta.options` keys | Ignored. |
| Unknown `loc_type` | Treated as unclustered. |

Rules for changing the schema: add a migration for `user_version` N to N+1,
add a migration test, never edit a released migration, keep reading all
released versions.

## Security

A session file is untrusted input.

- Open read-only first (`file:...?mode=ro`), check `application_id` and
  `user_version`, run `PRAGMA quick_check`, then copy with `backup()`.
- `PRAGMA trusted_schema=OFF`. When running on Python 3.12 or later,
  `Connection.setconfig(SQLITE_DBCONFIG_DEFENSIVE)` as well.
- Blobs are parsed with `json` only. The legacy importer uses
  `yaml.safe_load`. Nothing is unpickled or evaluated.
- Stored paths are data to load files from; they are never executed.
- Release nodes go through `Album._parse_release` inside a guarded call. A
  parse failure falls back to a network load (or an error row when offline); it
  never leaves a half-built album.
- All SQL uses bound parameters.
