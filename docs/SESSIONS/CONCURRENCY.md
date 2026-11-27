# Sessions: instances, locking, recovery, network folders

## Why more than one instance can run

`setup_pipe_handler()` in `picard/tagger.py` derives an instance identifier:

| Start | Identifier | Effect |
|---|---|---|
| default | `main` | A second start forwards its arguments to the first instance and exits. |
| `--no-plugins` | `main_NP` | Separate instance, same config and sessions folder. |
| `-c FILE` | hash of the path | Separate instance, separate config. |
| `-s` / `--stand-alone-instance` | random uuid | Always a new instance. |
| pipe permission error | none | No pipe; any number of instances. |

`picard-cli` can also run next to the GUI. Sessions must be safe in all of
these cases.

## Model

```text
 instance A                        instance B
 working DB A (local)              working DB B (local)
      |  Save (atomic replace)          |  Save (atomic replace)
      v                                 v
          session file X.mbps.db  (any filesystem)
```

- Each instance journals into its own local working DB. Nothing is shared
  while working.
- Opening a session copies the file into the instance's working DB. Two
  instances can open the same file at the same time.
- A conflict can only happen when two instances Save to the same file.

### Working DB

Location: `session_work_folder()`, based on `AppLocalDataLocation`, override
with `PICARD_SESSION_WORK_DIR`. It is local and not roaming, and not the cache
folder (cache cleaners may purge it).

Name: `<instance-id>-<process-token>.mbps.db`. The token keeps two processes with
the same identifier (no pipe) apart.

### Ownership lock

Each working DB has a sidecar `<db>.lock` holding an OS advisory lock
(`fcntl.flock` on POSIX, `msvcrt.locking` on Windows) and the text
`{pid, hostname, started}`. The OS releases the lock when the process dies. The
lock only distinguishes live working DBs from orphans. It is always on a local
filesystem, so network lock semantics do not matter. `filelock` is a dev
dependency only and is not used.

### Saving the same file from two instances

Each session file has `meta.save_id`, a uuid regenerated at every save. An
instance remembers the `save_id` it opened or last wrote.

At Save:

1. Read the target's current `save_id` with a read-only open.
2. If it equals the remembered one, or the target does not exist: write
   (temp file in the target directory, then `os.replace`).
3. If it differs: raise `SessionConflict`. GUI: Overwrite / Save as / Cancel.
   CLI: needs `--force`.

The check does not rely on mtime or inode, so it behaves the same on SMB, NFS
and FAT. A small window between the check and the replace remains. It is accepted: in
the worst case one of two near-simultaneous saves overwrites the other, but
the file is never corrupted, because the replace is atomic.

Windows: `os.replace` fails with `PermissionError` if another process holds the
target open. Retry a few times with short sleeps, then report.

## Crash recovery

At startup the work folder is scanned.

| Working DB state | Meaning | Action |
|---|---|---|
| Lock held | Another live instance | Ignore. |
| Lock free, `clean_shutdown=0` | Crash or power loss | Offer recovery. |
| Lock free, `clean_shutdown=1` | Clean exit with unsaved changes | Offer recovery. |
| Not a valid DB | Damaged | Move aside as `.corrupt`. |

Recovery restores the working set from that DB, then archives it. GUI: a dialog
listing each DB with its time and file count. CLI:
`picard-cli session recover --to FILE`. Data loss is bounded by the journal
debounce (about 2 seconds) plus the write.

`session_backup_on_crash` keeps its meaning: when off, recovery DBs are deleted
at exit and not kept after a crash.

## Network folders

Supported. Picard warns that it is slower.

- Working DBs are always local, so WAL and advisory locks never touch a
  network share (neither is reliable on SMB or NFS).
- A saved session is one self-contained file written with an atomic replace.
- Opening from a network path copies the file to local first, then works on
  the local copy.
- Network filesystems are detected with `QStorageInfo.fileSystemType()`
  (`cifs`, `smb3`, `nfs`, `afp`, `sshfs` and similar). The warning is
  non-blocking and says not to Save the same session from two computers at
  once. Unknown types give no warning.
- The `save_id` check still protects against lost updates across hosts, with
  the same small race as above.
- File identity on network filesystems cannot rely on inode numbers; see
  [FORMAT.md](FORMAT.md#file-identity).

## Failure behavior

| Failure | Result |
|---|---|
| Journal write fails (disk full, read-only) | Logged, one notification, journal marked degraded, retried at next flush. Picard keeps running. |
| Save fails | Error returned to the caller. The working DB is unaffected. |
| Working DB corrupted | Moved aside as `.corrupt`; a new working DB starts; the user is told. |
| Session file newer than supported | Refused with the writing Picard version. |
| Session file open in another program | Opening works (it is copied); Save reports the conflict or the permission error. |
