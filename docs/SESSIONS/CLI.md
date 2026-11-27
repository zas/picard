# Sessions: command line

`picard-cli session ...`, implemented in `picard/cli/session.py` following the
other subcommands in `picard/cli/` (`profiles.py`, `plugins.py`), with shell
completion registered through `picard/cli/completions.py`.

## Phase 1: store-only commands

These commands work on session files and the work folder. They need no running
workspace and no GUI, and use `picard/session/store/` directly (no Qt).

| Command | Purpose |
|---|---|
| `session list` | List session files in the sessions folder (name, date, files, albums, Picard version) and recovery DBs. |
| `session info FILE` | Show a session's metadata, options, counts, missing files, size, format version. |
| `session export FILE [--format yaml\|json] [-o OUT]` | Dump a session to a readable form. |
| `session import FILE.mbps.gz [-o OUT]` | Convert a legacy YAML session to `.mbps.db`. |
| `session validate FILE` | Check `application_id`, `user_version`, `quick_check`, referenced albums. Exit code 0 / non-zero. |
| `session gc FILE [--forget-missing]` | Remove rows of files marked missing, drop orphan data, `VACUUM`. Without the flag it only reports. |
| `session recover [ID] --to FILE` | Write a recovery DB out as a session file. Without ID, lists them. |

Conventions:

- `gc` rewrites a session file with the same atomic replace and `save_id`
  conflict check as Save, so it cannot silently overwrite a newer save.
- Output goes through `picard/cli/output.py`; `--json` where it makes sense.
- Exit codes: 0 success, 1 error, 2 usage, 3 conflict (needs `--force`).

## Later: live-workspace commands

`session open`, `session save`, `session close` act on a long-running headless
workspace. They arrive with the command engine and shell (PR #3584), because a
one-shot process that restores and exits has nothing to show. They call the same
`SessionManager` API the GUI uses; `--force` and `--discard` map to
`SessionConflict` and `SessionDirty`.

The manager is already UI-free and is tested against `HeadlessTagger` and
`Workspace` with a mocked `mb_api`. Whether a full album restore works under
`HeadlessTagger` (documented as scoped to the file load/save pipeline) is
verified by that test in phase 1, not assumed.

## Later: command-line file arguments

`picard foo.mbps.db` opening the file as a session, including forwarding to a
running instance through the pipe, is a possible follow-up. It is not part of
v1.
