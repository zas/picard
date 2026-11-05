# Command Engine — design

> STATUS: **In-progress design / target contract.** This settles the design so
> the code written now can grow into it. It is NOT a commitment to implement
> the full vocabulary immediately. The near-term work builds the minimal,
> extensible substrate (see "Current state"); commands, backends, and the
> full selector grammar are added later, incrementally.

## Purpose

A single command vocabulary for driving Picard, usable through one console
frontend, over **two interchangeable execution backends**:

- **Local / headless** — commands run in-process against a `HeadlessTagger` +
  `Workspace` (no GUI).
- **Remote / GUI** — the *same* commands are sent to a already-running GUI
  Picard and executed against its live `Tagger` + `Workspace`; this backend can
  additionally trigger GUI-only actions (views, window, help, menu actions).

A user chooses: full headless, OR drive their running GUI from a console, OR
both. This **replaces the current remote-command system** (flat pipe verbs that
reach into `self.tagger.*`), reusing the pipe/socket as *transport* but with the
noun/verb command registry as the *vocabulary*.

Two consumers of the console layer:
- a **human** at an interactive console (REPL), and
- an **AI agent** over MCP (structured tool calls).

They differ only in rendering/transport. One vocabulary, one engine interface,
thin frontends.

## Architecture

```text
Console REPL ─┐                    ┌─ MCP server          (FRONTENDS: parse in,
(CliOutput)   │                    │  (JSON tools)         render/serialize out)
              ▼                    ▼
          ┌──────── Command layer (shared) ────────┐       commands DECLARED once
          │ registry: name(noun verb), params,      │      (name, params, selector
          │ backend availability, run(session,args)  │       arity, availability);
          │ → serializable Result. Never does I/O.   │       return structured Result
          └───────────────┬─────────────────────────┘
                          ▼
          ┌──────── Session (INTERFACE) ───────────┐        one interface,
          │ resolve selectors · handles · run cmd   │        two implementations
          └───────┬───────────────────────┬─────────┘
                  ▼                        ▼
        LocalSession                 RemoteSession
        HeadlessTagger+Workspace     proxy → pipe/socket → running GUI Picard
        run_until_idle               (GUI executes vs its live Tagger/Workspace,
                                      returns a serialized Result)
                  ▼                        ▼
        Workspace / services / workspace_events / core  (same core both sides)
```

### Hard rules (these make two-backends-one-vocabulary work)

- Commands return **structured, SERIALIZABLE `Result`** objects and never print
  or touch transport. Only frontends render. A Result must survive a
  cross-process hop (RemoteSession), so it is plain data — no live object refs.
- **Handles are the serializable proxy for entities.** A Result references
  entities by handle string (`a1`), never by object. This is what lets the same
  Result cross the pipe and lets `a1` mean "the entity in the engine that owns
  it."
- **Handles live engine-side.** The backend that owns the entities owns the
  `HandleRegistry`; a remote console queries/receives handles. So `a1` is
  meaningful across the boundary and survives multiple consoles / independent
  GUI mutation.
- **`Session` is an interface.** Commands are written against it; they do not
  know whether they run local or remote.

### Async model

A command = mutate the working set → drain async work → return Result. Local:
`run_until_idle()` pumps the event loop until thread pools + pending web
requests settle. Remote: the GUI executes and replies when done. Either way the
caller sees a synchronous-looking command.

## Naming: `<noun> <verb>`

Commands are `noun verb [args]`: `option set`, `tag add`, `album show`,
`cluster remove`, `disc lookup`. Rationale: namespaces cleanly (no `set`/`get`
collision between options and tags), self-groups for help/discovery, and maps
directly to MCP tool names (`album_show`, `tag_add`). Supersedes the older flat
vocabulary (`save a1` → `album save a1` / `file save`).

> The commands implemented so far (see "Current state") still use some flat
> names (`save`, `remove`, `trash`, `scan`, `lookup`) and `disc read` /
> `disc read-log`. The `noun verb` names in this document are the target; the
> final names are not decided yet.

## Backend availability

Every command declares which backend(s) it supports:

- **both** — runs on core/Workspace, backend-agnostic (`file add`, `cluster`,
  `album lookup`, `tag set`, `album save`, `disc lookup`).
- **gui-only** — only meaningful with a GUI backend; unavailable in headless
  (`view metadata show`, `window raise`, `help show`, `play`, and triggering
  any `MainAction` chrome). In a LocalSession these are simply not registered /
  report "requires GUI backend".

The GUI's `MainAction` surface is thus not "out of scope" — it is the gui-only
command set.

## Entity + handle model

Working-set entities get **session-local handles**: a type prefix + a
monotonically increasing ordinal, minted when the entity enters the session.
Handles are STABLE IDS, never positions: removing `a3` then `a4` does NOT
renumber; ids are never reused within a session.

| prefix | entity            | source                       | lifecycle |
|--------|-------------------|------------------------------|-----------|
| `f`    | unclustered file  | `unclustered_files.files`    | session-lifetime; kept across reparenting |
| `c`    | cluster           | `clusters`                   | until removed |
| `a`    | album (incl. NAT) | `albums.values()`            | until removed |
| `t`    | track             | tracks within albums         | with its album |
| `m`    | match candidate   | lookup/scan/search output    | transient (until next lookup of target) |
| `v`    | release version   | release-group versions       | transient (while release-group loaded) |
| `d`    | disc / TOC        | disc lookup                  | transient |
| `k`    | collection        | MB user collections          | while loaded |

Notes:
- `f*` is the UNCLUSTERED bucket only; files matched into albums/clusters are
  reached via their parent. "Every file everywhere" is a separate future token
  (`files:all`).
- A file keeps its handle for its whole session lifetime regardless of parent.
- `m`/`v`/`d` are transient, re-minted per producing operation.
- Backed by weak references so removed entities' handles stop resolving rather
  than leaking. Implemented in `picard/cli/engine/handles.py` (`HandleRegistry`);
  the prefix classifier is injected so new kinds need no registry change.

## Selector grammar

Selectors turn a reference token (console text or an MCP `selector` arg) into a
set of entities, with set algebra.

```ebnf
selector  = term , { "," , term } ;
term      = [ "!" ] , atom ;                 (* ! = exclude *)
atom      = scoped | bare ;
scoped    = prefix , selement ;              (* a1, a1-3, a*  *)
bare      = selement ;                       (* 2, 1-3 — inherits sticky prefix *)
selement  = range | ordinal | "*" ;
range     = ordinal , "-" , ordinal ;        (* a1-3 *)
ordinal   = digit , { digit } ;
prefix    = "f" | "c" | "a" | "t" | "m" | "v" | "d" | "k" ;
```

Resolution → `(entities, unresolved)`:
1. Scan terms left→right tracking a `sticky_prefix` (explicit prefix sets it,
   bare atom uses it; error if a bare atom precedes any prefix).
2. Partition into positives / negatives (leading `!`).
3. Expand: ordinal → `{prefix+n}`; range → `{prefix+m … prefix+n}`; `*` → all
   live ids in that namespace; bare `*` = universal top-level.
4. `result = union(positives) − union(negatives)`.
5. Map ids → entities via HandleRegistry; ids with no live entity → `unresolved`.

Decided semantics:
- Ordinals are stable handle ids, not positions.
- `*` (bare) = all top-level = `f* ∪ c* ∪ a*` (mirrors the two GUI panes:
  unclustered files, clusters, albums/NAT); NOT tracks.
- Exclusion is set-difference over the whole expression (`a*,!3` = all albums
  but a3); bare `!n` inherits sticky prefix, `!a2`/`!c1` explicit.
- Sticky prefix resets on each explicit prefix; mixing types allowed
  (`a1,2,c3,4` → `a1,a2,c3,c4`).
- Reject reversed (`a3-1`) and cross-namespace (`a1-c3`) ranges as parse errors.
- Whitespace around commas allowed; inside a token invalid.
- `!a3` alone → empty set (composable). Duplicates dedupe.
- Reserved future: `prefix where <field>=<value>` metadata selectors.

Implemented subset (`picard/cli/engine/selectors.py`): single handles (`a1`),
type wildcards (`a*`), the universal `*`, paths (below), and comma unions of
those. A union may be written with spaces and arrive as several command-line
tokens (`ls a1, c2` or `ls a1 c2`). Ranges, exclusion and sticky bare ordinals
are rejected with a clear error until they are implemented.

### Handles and paths

Every entity keeps a plain, stable handle (`f7`, `c1`, `a1`, `t12`, `m3`): its
identity, which follows it as it moves (a file keeps its handle from the
unclustered bucket to a cluster to a track) and which a result always reports.
A **path** is a second way to reach the same entities: segments separated by
`.`, each selecting children of the previous one. A path is a *position*, looked
up when the command runs, so it is convenient to type and to scope (`a1.d2`)
but does not follow an entity around. Scripts that keep a reference across
several commands should keep the handle.

| segment | under | selects |
|---|---|---|
| `u` | (start of a path) | the files that are in no cluster |
| `d<n>` | album | disc `n` of the release |
| `t<n>` | album, disc | track `n` (on that disc) |
| `f<n>` | album, disc, track, cluster | the `n`th file (`f*`: all of them) |
| `u` | album | the album's unmatched files |
| `m<n>` | cluster, file | the `n`th lookup candidate |

Examples: `a1.d2.t3`, `a1.d2` (the tracks of disc 2), `a1.t3.f1`, `a1.f*` (every
file of the album, matched or not), `a1.u`, `c1.f*`, `c1.m2`, `u.f*`.

- `*` and numbers work in any segment (`a*.t1`, `a1.d*.t1`).
- Discs and tracks of a release use the numbers MusicBrainz gives them (the
  `discnumber` and `tracknumber` tags), not list positions, so `a1.d2.t3` keeps
  its meaning when the album is reloaded. Other numbers (files, candidates) are
  positions in the order a listing shows.
- A release with one disc may leave the disc out (`a1.t3` is `a1.d1.t3`). With
  several discs the disc must be named: a selector that would otherwise guess
  (and, say, remove the wrong disc's track) is an error that lists the discs.
- Non-album tracks have no disc or track numbers: they are numbered by
  position and have no discs.
- Picard has no disc object, and the unclustered bucket is not a handle-able
  entity. A path ending at either stands for what it contains (a disc: its
  tracks; a bucket: its files), so results only ever hold entities that have a
  plain handle.
- A numbered step that finds nothing is reported as unresolved (`a1.t9`), a
  wildcard that matches nothing is an empty result, and a segment that makes no
  sense under its parent (`f1.t1`) is an error.
- At the top level `d` stays reserved for a disc ID / TOC (see the table
  above); under an album it means a disc of the release.

The console shows the path next to the handle (`t7  a1.d2.t3  listed ...`) and
tab-completes it: `ls a1.<TAB>` offers the segments that can follow `a1`, and so
on down the path. A session provides this through `path_of(handle)` (the path of
an entity) and `path_segments(base)` (what can follow a path).

## Result contract

Selector-taking commands return a per-handle outcome list plus resolution info,
distinguishing "resolved to empty" from "had unresolved tokens". Must be
serializable (RemoteSession).

```text
Result(
  items      = [ ItemResult(handle, path, status, data), ... ],
  resolved   = [handles...],     # what the selector matched
  unresolved = [tokens...],      # tokens matching no live entity (machine-actionable)
  mints      = [handles...],     # newly created handles
  message    = "...",            # optional human summary
)
```

`unresolved` non-empty = the caller under-acted; `resolved == [] and
unresolved == []` = valid, nothing matched.

An item's `handle` is the entity's stable identity. Its `path` (`a1.d2.t3`,
`c1.f2`, `u.f1`, `c1.m2`; empty for albums and clusters, which are reached by
their handle) says where the entity sits *now*. The dispatcher fills it in, so
every command reports it; a consumer that keeps a reference across several
commands should keep the handle, and use the path to read or to type.

## Capability taxonomy (TARGET — build incrementally)

Derived from Picard's full GUI action surface (`picard/const/actions.py`
`MainAction`), so the vocabulary is complete-by-construction. `avail`: both /
gui.

The names below are the TARGET vocabulary. Commands already implemented keep
their current names (see "Current state"): `file save` is `save`,
`file remove` is `remove`, `file trash` is `trash`, `file scan` is `scan`,
`album lookup` is `lookup`, `disc lookup` is `disc read` and `disc from-log` is
`disc read-log`.

### Working-set nouns (backend: both unless noted)

| noun · verb | backing | mints | notes |
|---|---|---|---|
| `file add <paths>` | load files | `f` | ADD_FILES / ADD_DIRECTORY |
| `file save <sel>` | `File.save` | — | SAVE |
| `file remove <sel>` / `file trash <sel>` | Workspace.remove / trash_files | — | REMOVE / TRASH |
| `file move <sel> <target>` | Workspace move | — | |
| `file scan <sel>` | AcoustID fingerprint lookup | `m` | — |
| `file info <sel>` | technical + tag info | — | VIEW_INFO |
| `cluster <sel>` | Workspace clustering | `c` | CLUSTER |
| `cluster remove <sel>` | Workspace.remove_cluster | — | |
| `cluster lookup <sel>` | tag-based lookup | `m` | |
| `cluster submit <sel>` | submit as release | — | SUBMIT_CLUSTER |
| `album lookup <sel>` | metadata lookup | `m` | |
| `album save/remove/refresh <sel>` | File.save / remove_album / reload | — | REFRESH |
| `album versions <sel>` | release-group versions | `v` | ALBUM_OTHER_VERSIONS |
| `album switch <a> <v>` | switch_release_version | — | |
| `track show <sel>` / `track move` | — | — | |
| `tag show <sel>` | Metadata.diff (orig/new/Δ) | — | the metadata-box equivalent |
| `tag set/add/rm <handle> <tag>[=val]` | Metadata set/add/delete | — | multi-value via list, not joiner |
| `cover show/set/rm/export <sel>` | cover art | — | the cover-art-box equivalent |
| `candidate ls/show <sel>` | — | — | produced by lookup/scan/search |
| `match <target> <m>` | apply candidate (move_files_to_album/…) | `a` | |
| `ls [sel]` | session view | — | |

### Identify / submit

| noun · verb | backing | mints | notes |
|---|---|---|---|
| `disc lookup` | read drive (discid) → MB | `m`/`d` | CD_LOOKUP — forces disc headless story |
| `disc from-log <file>` | parse rip log | `m`/`d` | DISCID_FROM_LOGFILE |
| `disc from-tags <sel>` | derive TOC from tags | `m`/`d` | DISCID_FROM_TAGS |
| `search album/track/artist <query>` | MB search | `m` | ALBUM/TRACK_SEARCH |
| `acoustid submit <sel>` | submit fingerprints | — | SUBMIT_ACOUSTID |
| `isrc submit <sel>` / `isrc lookup` | ISRC | — | SUBMIT_ISRC / LOOKUP_ISRC |
| `fingerprint <sel>` / `analyze <sel>` | compute fingerprints | — | GENERATE_FINGERPRINTS / ANALYZE |

### Session / config / collections

| noun · verb | backing | notes |
|---|---|---|
| `session save/load <path>` / `session new` | picard/session + clear_session | SAVE/LOAD/NEW_SESSION |
| `option set/get/unset/ls <key> [val]` | `config.setting[...]` | — |
| `profile ls/use/show <name>` | option profiles | existing CLI machinery |
| `plugin ls/install/remove/update` | plugin manager | existing `picard-cli plugins` |
| `collection ls/add/rm/show` | MB user collections | OPEN_COLLECTION_IN_BROWSER etc. |

### gui-only (avail: gui — RemoteSession only)

`view metadata/coverart/filebrowser show|hide`, `window raise/close`,
`help show`, `play <sel>` / `play external`, `browser lookup <sel>`,
`similar-items search`, plus any remaining `MainAction` chrome
(about/donate/report-bug/check-update). These drive the running GUI; in a
LocalSession they are unavailable.

## Unifying insights

- `lookup` / `scan` / `search` / `disc lookup` all PRODUCE candidates (`m*`),
  auto-applying the top match but leaving the rest addressable; `match` ACCEPTS
  one. `album versions` / `album switch` are the separate same-release-group
  mechanism.
- `tag show` + `tag set/add/rm` are the metadata-box equivalent; `cover …` the
  cover-art-box equivalent. Backed by core `Metadata` (`diff`, `getall`, `set`,
  `add`, `delete`) and the existing serializable tag-diff — so console and GUI
  show the SAME diff. For an agent, `tag show` is "preview exactly what a save
  will change" before `album save`.

## Options model

- Session-global: `option set/get/unset`. Affects the whole session.
- Per-command flags only where an op has a genuine one-shot variant
  (`album save a1 --no-rename`), declared as command params so MCP gets tool
  params and the console gets `--flags`. The long tail stays in `option set`.
- `profile use <name>` reuses existing profile machinery.

## Replacing remote commands

The current `picard/remotecommands/` (flat verbs `CLUSTER`/`LOAD`/… over a
one-way pipe, reaching into `self.tagger.*`) is superseded: its handlers already
retire as the orchestration moved onto `Workspace`. The pipe becomes
`RemoteSession`'s transport (needs a response channel added — currently
one-way). The vocabulary becomes the noun/verb registry. One console can then do
everything the `-e` remote commands did, plus everything headless does.

## Worked examples

Console (local or remote — identical):
```text
picard> file add ~/Music/incoming/*.flac
added 14 files → f1–f14
picard> cluster f*
→ c1 (Radiohead – OK Computer, 12), c2 (unknown, 2)
picard> album lookup c1        # cluster → candidates
c1 → m1 ★auto→a1 (0.94), m2 (0.88), m3 (0.41)
picard> match c1 m2
c1 → a2, 12/12
picard> tag show a2            # the metadata-box equivalent
  title/… orig vs new vs Δ …
picard> tag set t3 title "Paranoid Android"
picard> album save a2
```

MCP (agent):
```jsonc
→ cluster({"selector":"f*"})
← {"mints":["c1","c2"], "items":[{"handle":"c1","title":"OK Computer","file_count":12}, …]}
→ album_lookup({"selector":"c1"})
← {"items":[{"handle":"c1","candidates":[
     {"handle":"m1","mbid":"dd66…","score":0.94,"applied":true,"album":"a1"},
     {"handle":"m2","score":0.88}]}]}
→ tag_show({"selector":"a1"})
← {"items":[{"handle":"t1","tags":{"title":{"orig":["Pyramid Song"],"new":["Airbag"],"status":"changed"}, …}}]}
→ album_save({"selector":"a1"})
← {"items":[{"handle":"a1","saved":12}], "unresolved":[]}
```

## Current state

Home: `picard/cli/engine/`. The console frontend is `picard-cli shell`
(`picard/cli/shell.py`, with `render.py` and `completion.py`).

Substrate, frontend-agnostic:

1. **HandleRegistry** (`handles.py`) — mint/resolve handles, weak references,
   stable ids, injected classifier.
2. **Selector parser + resolver** (`selectors.py`) — the subset described under
   "Selector grammar"; returns `(entities, unresolved)`.
3. **`EngineSession` interface, command declaration/registry, serializable
   `EngineResult`** (`commands.py`, `result.py`). A command declares its name,
   backend availability, positional args, completion hints and whether it is
   `destructive` (an interactive frontend asks before running it).
4. **`LocalEngineSession`** (`session.py`) — owns the handle registry, the
   resolver and the lookup candidates (held weakly per looked-up target), and
   drains async work with `run_until_idle`. A command that stops waiting reports
   it in its result (a message, and a `pending` / `timeout` status where the
   outcome is unknown) instead of looking successful.
5. **Dispatch** (`dispatch.py`) — command line to command invocation, always
   returning an `EngineResult`.

Implemented commands (backend: both):

| command | what it does |
|---|---|
| `ls [sel]` | list top-level entities (or the selection) with their handles |
| `tree [sel]` | the working set as an indented tree, like the GUI panes |
| `file add <paths>` | load files, directories and globs, in filename order like the GUI; applies the GUI's ignore rules and placement policy; skips files already loaded |
| `cluster [sel]` | group files (default: unclustered) into clusters |
| `cluster lookup [sel]` | search MusicBrainz for clusters, auto-apply the best match, expose the alternatives as `m` handles |
| `match <cluster> <m>` | apply another candidate of that cluster |
| `lookup [sel]` | metadata lookup (autotag) of the selected objects |
| `scan [sel]` | identify files by AcoustID fingerprint |
| `album load <mbid\|url>` | load a release as an empty album |
| `disc read [device]` | read the TOC of the CD in a drive and load the matching release |
| `disc read-log <path>` | the same from a CD ripper log file |
| `save [sel]` | write tag changes to disk |
| `move <sources> <destination>` | put files into a track (`a1.d2.t3`), a cluster, an album (matched to its tracks) or a bucket (`u`, `a1.u`), as dropping them in the GUI does; the last word is the destination |
| `option ls [pattern]` | the options not at their default, or those matching a pattern, with where each value comes from |
| `option get <name>` | one option: value, default, type, title and source |
| `option set <name> <value>` | set an option for this session only |
| `option unset <name>` | forget the session's value of an option |
| `option save [names]` | write the options set in this session to the configuration (destructive) |
| `remove <sel>` | drop objects from the working set (never touches disk) |
| `trash <sel>` | move the files of the selection to the system trash (destructive) |

### Options

Behaviour that depends on settings (where `save` puts files and how it names
them, what `file add` ignores, how lookups are scored, ...) is controlled with
the `option` commands. The rule is that **nothing is written to the
configuration unless you ask**: `option set` changes the option for the session
only, so an experiment cannot change the settings the GUI uses, and
`option save` is the one deliberate way to keep a value (it is confirmed by the
console, and written as the GUI would: into the profile that sets the option if
there is one, else into the configuration).

Each option is reported with where its value comes from, which answers "why is
`save` moving my files?": `session`, `profile <title>`, `config` (stored in the
configuration file) or `default`. `option ls` without a pattern lists only the
options that are not at their default.

It reuses the core's own pieces. A session value is held by an in-memory
"session" profile with the top priority, put in front of the user's profiles
with the overrides the options dialog uses, so `config.setting[...]` returns it
like any profile's value and no other code needs to know. The option registry
gives each option's type, default and title, and the option's own conversion and
bounds check the value (`true`/`false` for a yes/no option, a number within its
range, comma-separated items or a JSON array for a list).

This works for the options that take part in profiles (180 of the 192).
Interface and plugin state, the scripts and the AcoustID and fpcalc settings
can be shown but not changed for a session; set them in the configuration
file.

To try things on files without any risk, work on a copy of the files, and start
the shell on a scratch configuration so that no setting of yours applies:
`picard-cli -c /tmp/scratch.ini shell`, then set what is needed with `option
set`. A fresh configuration has none of your settings (for instance the
conversion of punctuation to ASCII), so results can differ from your usual ones.

Not done yet: the rest of the catalog, `RemoteEngineSession` and the pipe
response channel, gui-only commands, release versions, collections, sessions,
options/profiles, the MCP frontend.

Guiding principle: an empty-but-correct registry + resolver + `Session`
interface is the deliverable; features are incremental declarations on top.
Defining `Session` as an interface NOW (even with one implementation) is the one
concession to the two-backend future, so RemoteSession needs no reshaping later.
