# Sessions: architecture

## Layers and dependency rules

```text
 GUI (picard/ui, Tagger)          CLI (picard/cli/session.py)
        |   sinks                        |
        v                                v
 +-----------------------------------------------+
 | SessionManager  (picard/session/manager.py)   |   QtCore only
 |  journal.py   restore.py   exporter.py        |
 +----------------------+------------------------+
                        | plain dataclasses
                        v
 +-----------------------------------------------+
 | SessionStore (picard/session/store/)          |   no Qt at all
 |  schema  connection  model  store  legacy     |
 |  identity  lock                               |
 +-----------------------------------------------+
                        |
                     SQLite
```

Rules, enforced by an import test over `picard/session/`:

1. `picard/session/store/` imports no Qt. It can be used from any script and
   without a running workspace.
2. The rest of `picard/session/` may import `PyQt6.QtCore` (`QObject`,
   signals, `QTimer`), as `picard/util/thread.py` and
   `picard/workspace_events.py` already do under the headless
   `QCoreApplication`.
3. Nothing under `picard/session/` imports `PyQt6.QtWidgets`, `picard.ui` or
   `picard.tagger`, and nothing reads `tagger.window` or `album.ui_item`.
4. The core is reached through `workspace()`, `services()`,
   `workspace_events()` and `notifier()`, never through a `Tagger` instance.
5. Frontend-only state goes through injected sinks (same pattern as
   `picard.notification`, `picard.view_sync`, `picard.view_updates`,
   `picard.view_presentation`).

## Sinks and events

| Facade | Direction | GUI | Headless |
|---|---|---|---|
| `session_view_state()` | core asks frontend | Reads and writes album expansion from `album.ui_item`. | No sink; expanded set is empty. |
| `session_events()` | core emits | Status bar and status indicators subscribe to `progress`, `state_changed`, `error`. | Nothing connected, or the CLI prints progress. |
| `session_journal()` | core calls | Same object in both frontends; no-op until a `SessionManager` is installed. | Same. |

`session_events()` signals: `progress(stage: str, details: dict)`,
`state_changed(state)`, `error(message)`.

## SessionManager

One service owns the lifecycle. It never opens a dialog. Decisions that need a
human are returned or raised, and the frontend decides.

```python
manager = session_manager()  # registered next to the other services

manager.new()  # clear working set, new anonymous session
manager.open(path)  # copy to working DB, restore
manager.save()  # to the bound path, raises SessionNotNamed
manager.save_as(path)
manager.close()
manager.recover(recovery_id)
manager.list_recovery()  # orphan / unsaved-exit working DBs
manager.list_recent()
manager.state  # SessionState(name, path, modified, ...)
```

Exceptions that a frontend maps to UI or flags:

| Exception | GUI | CLI |
|---|---|---|
| `SessionConflict` (target changed since open) | Overwrite / Save as / Cancel | needs `--force` |
| `SessionTooNew` (file format newer than supported) | Error dialog | error |
| `SessionCorrupt` | Error dialog, offer recovery copy | error |
| `SessionNotNamed` | Save as dialog | error |
| `SessionDirty` (new/open while modified) | Save / Discard / Cancel | needs `--discard` |

## Journal (saving)

The working DB mirrors the working set. No full snapshot is taken during
normal use.

1. **Mark.** Core code calls `session_journal().mark_dirty(obj)` from:
   `File.update`, `Track.update`, `Album.update`, the `File.parent_item`
   setter, workspace add/remove, `File._saving_finished` (path change) and
   album load completion. Marking is an O(1) set insert.
2. **Debounce.** A `QTimer` coalesces marks for about 2 seconds.
3. **Snapshot on the main thread.** For the dirty objects only, build plain
   tuples (path, location, delta, album ids, overrides). Qt objects never leave
   the main thread. Large dirty sets are processed with
   `process_in_batches` so no UI slice exceeds its time budget.
4. **Write on a worker.** One writer thread upserts the rows in a single
   transaction. WAL mode, `synchronous=NORMAL`.
5. **Revision.** `meta.revision` increments per flush; the modified flag
   derives from it.

Details that matter:

- File path changes (save with renaming) update the existing row, keyed by its
  stable row id, in the same write.
- Deltas are computed at flush time against the track's scripted metadata (or
  the file's original metadata), excluding internal `~` tags and the excluded
  override tags. This is the logic of the current exporter, reused.
- Nothing is journaled while a restore runs (`restoring_session`); the journal
  resumes when it ends.
- Failures (disk full, read-only folder, corrupted DB) never crash or block.
  The journal logs, notifies once through `notifier()`, marks itself degraded
  and retries at the next flush. A corrupted working DB is moved aside
  (`.corrupt`) and a new one is started.

## Save

`save_as(path)`:

1. Flush the journal.
2. Check the target's `save_id` against the one remembered (conflict check,
   see [CONCURRENCY.md](CONCURRENCY.md)).
3. `sqlite3.Connection.backup()` the working DB into a temporary file in the
   target directory.
4. Reopen the copy: `PRAGMA journal_mode=DELETE`, new `meta.save_id`,
   `saved_revision = revision`, `PRAGMA integrity_check`.
5. `os.replace` over the target. On Windows a `PermissionError` is retried a
   few times, then reported.

The saved file is a single self-contained file with no `-wal` or `-shm`
sidecars. Saving never blocks the UI thread beyond the flush slices; the copy
runs on a worker.

## Open and restore

`open(path)`:

1. Open the source read-only, check `application_id`, `user_version`,
   `PRAGMA quick_check` (see [FORMAT.md](FORMAT.md#security)).
2. If it is a legacy `.mbps.gz` file, import it into a new working DB.
   Otherwise `backup()` it into this instance's working DB.
3. Clear the current working set (same semantics as `clear_session`), set
   `restoring_session` when `session_safe_restore` is on.
4. Restore from the working DB, event-driven:
   - Build albums from the stored release data (or load from the network when
     the user chose Refresh, or when a stored node fails to parse).
   - Load each file; as soon as it finishes loading
     (`Workspace.place_loaded_file` / `file_loaded`), place it at its recorded
     location and apply its delta in the same callback.
   - When an album finishes loading, move its pending files to their tracks in
     one pass over a dictionary built once per album.
   - Apply album and track overrides when their album is loaded
     (`Album.run_when_loaded`).
5. When no file is pending and no request is pending, clear
   `restoring_session` and emit `progress('restored')`. This is a counter and
   a signal, not a polling timer.

The restore uses no polling timers. The old `retry_until` helper and the
delay constants are removed.

### Missing files

A file that is gone is skipped and listed in one report. Its row stays in the
session with `missing_since` set. A relink by file identity is attempted inside
the known roots. Rows are removed only by an explicit action (`session gc`, or
"Forget missing files" in the GUI). Files under an offline root are never
marked missing.

## Lifecycle

```text
          new()                 open(path)
 (none) --------> anonymous ----------------> named
                     | save_as(path)            ^   |
                     +--------------------------+   | save()
                                                    v
                                              named, saved
```

- **Modified** = `revision != saved_revision`.
- **Clean exit, not modified:** the working DB is deleted.
- **Clean exit, modified:** the GUI asks Save / Don't save / Cancel (the
  existing quit confirmation). If not saved, the working DB is kept as a
  recovery DB with `clean_shutdown=1`.
- **Crash:** the working DB stays, `clean_shutdown=0`.
- **Startup:** (1) recovery DBs are offered; (2) otherwise, if
  `session_load_last_on_startup` is on, the last session file is opened.

## Options stored in a session

A `SESSION_OPTIONS` registry lists the options a session carries. v1 carries
`rename_files`, `move_files` and `enable_tag_saving`; restore writes them to the
configuration. Unknown keys in a file are ignored, missing keys leave the
current value. Carrying more options (naming scripts, cover-art options) or an
overlay that does not touch the user's configuration is a possible extension
(`SettingsOverride`, shareable profiles) and is out of scope for v1.

## Extension and plugins

There is no plugin API in v1. Tags set by plugins are stored as ordinary
deltas. Session lifecycle hooks for plugins may be added later as extension
points.
