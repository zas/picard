# Sessions

> **Status:** design and implementation guide for the SQLite-backed session
> store (follow-up to PICARD-3118 / PR #2731). The sections marked
> *(phase N)* describe behavior that lands in that phase of the
> [roadmap](DECISIONS.md#roadmap). Until then the YAML implementation in
> `picard/session/` is what ships.

A **session** is the state of Picard's working set: which files are loaded,
where they are placed (unclustered, cluster, album, track, non-album track),
their unsaved tag edits, the MusicBrainz releases they belong to, and a few
options. Sessions let a user stop and resume work, work on several sets of
files, and recover after a crash or power loss.

## Documents

| Document | Content |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Modules, GUI/headless split, journal, save, restore |
| [FORMAT.md](FORMAT.md) | The `.mbps.db` file: schema, versioning, compatibility, security |
| [CONCURRENCY.md](CONCURRENCY.md) | Several instances, locking, crash recovery, network folders |
| [CACHES.md](CACHES.md) | MusicBrainz data, per-file tag cache, cover-art cache |
| [CLI.md](CLI.md) | `picard-cli session ...` |
| [DECISIONS.md](DECISIONS.md) | Why it is built this way, acceptance targets, roadmap |

## Concepts

| Term | Meaning |
|---|---|
| Working set | The files, clusters and albums currently loaded (`Workspace`). |
| Working DB | A local SQLite file that mirrors the working set continuously (the journal). One per running instance. |
| Session file | A saved, self-contained `.mbps.db` file. A snapshot of the working DB made on explicit Save. |
| Named / anonymous | A session is named once it is bound to a session file. A new session is anonymous. |
| Modified | The working set changed since the last Save (`revision != saved_revision`). |
| Recovery DB | A working DB left behind by a crash, or by a clean exit with unsaved changes. |

## User-visible behavior

- **Save / Save as / Quick save:** writes the session file. Quick save reuses
  the current file without asking.
- **Open:** a session file is copied into the instance's working DB and the
  working set is restored from it. Opening the same file in two instances is
  safe; a conflict can only appear when both Save (see
  [CONCURRENCY.md](CONCURRENCY.md#saving-the-same-file-from-two-instances)).
- **New session:** clears the working set, asks to save if modified.
- **Crash recovery:** at the next start Picard offers to restore any recovery
  DB. Work is journaled continuously, so at most a few seconds are lost.
- **Restore choice:** use the stored MusicBrainz data (default, no network
  requests) or refresh from MusicBrainz.
- **Missing files:** files that cannot be found are skipped, reported once and
  kept in the session, never silently dropped.
- **Old sessions:** `.mbps.gz` (YAML) files still open; they are converted on
  load. New saves always write `.mbps.db`.

## Options

| Option | Default | Meaning |
|---|---|---|
| `session_safe_restore` | on | No auto-matching while restoring. |
| `session_load_last_on_startup` | off | Open the last session at startup. |
| `session_backup_on_crash` | on | Keep a recovery DB on crash / unsaved exit. |
| `session_autosave_interval_min` | 0 | Retired in phase 3: the journal replaces the autosave timer. Kept readable for upgrade. |
| `session_restore_use_stored_mb_data` | on | Restore from stored MusicBrainz data; off refreshes from the network. Replaces `session_include_mb_data` and `session_no_mb_requests_on_load` (see [CACHES.md](CACHES.md#option-migration)). |
| `session_folder_path` | `<config>/sessions` | Default folder for session files. May be a network folder. |
| `cover_art_cache_max_mb` | 512 | Size limit of the persistent cover-art cache. 0 disables it. |

## Where files live

| Data | Location | Notes |
|---|---|---|
| Session files | `sessions_folder()` or user-chosen path | Any filesystem, including network shares. |
| Working DBs | `session_work_folder()` (`AppLocalDataLocation`, env `PICARD_SESSION_WORK_DIR`) | Always local. Not a cache folder, not roaming. |
| Cover-art cache | `cache_folder()` | Regenerable. |

## Source map

| Path | Role |
|---|---|
| `picard/session/store/` | SQLite store, schema, migrations, legacy import, locking. No Qt. |
| `picard/session/manager.py` | `SessionManager` service: lifecycle, journal, save, restore. QtCore only. |
| `picard/session/journal.py` | Dirty tracking facade and debounced writer. |
| `picard/session/restore.py` | Event-driven restore into the `Workspace`. |
| `picard/cli/session.py` | `picard-cli session` commands. |
| `picard/ui/options/sessions.py` | Options page (GUI only). |
