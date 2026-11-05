#
# Copyright (C) 2026 Laurent Monin
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <https://www.gnu.org/licenses/>.

"""Built-in engine commands.

Each command is a small adapter over the session / Workspace that returns an
:class:`~picard.cli.engine.result.EngineResult`. Commands never print; a
frontend renders the result.

:func:`register_builtins` populates a registry with the built-in command set;
both frontends call it so they share one vocabulary.
"""

import glob
import os
from typing import Any
from urllib.parse import urlparse

from picard import config
from picard.album import (
    Album,
    NatAlbum,
)
from picard.cli.engine.candidates import Candidate
from picard.cli.engine.commands import (
    EngineCommand,
    EngineCommandRegistry,
    EngineSession,
)
from picard.cli.engine.result import (
    EngineItemResult,
    EngineResult,
)
from picard.cluster import Cluster
import picard.disc
from picard.disc.presentation import disc_presentation
from picard.file import File
from picard.services import services
from picard.track import Track
from picard.util import (
    compile_ignore_regex,
    is_ignored_file,
    iter_files_from_objects,
    mbid_validate,
    normpath,
    resolve_fs_path,
    scan_paths_recursive,
)
from picard.workspace import workspace


# Prefixes shown by a bare ``ls`` (top-level, mirroring the GUI panes).
_LS_PREFIXES = ('f', 'c', 'a')


def _drain(session: EngineSession, timeout: float, notes: list[str]) -> bool:
    """Wait for the session's background work; note a timeout for the result.

    Returns True when everything finished. On a timeout the work may still be
    running, so the command's outcome can be incomplete: a message is added to
    ``notes`` (deduplicated) for the command to put in its result.
    """
    drained = bool(session.run_until_idle(timeout=timeout))
    if not drained:
        note = f"timed out after {timeout:g}s waiting for background work; results may be incomplete"
        if note not in notes:
            notes.append(note)
    return drained


def _message(notes: list[str]) -> str:
    return '; '.join(notes)


def _entity_mb_ref(entity: Any) -> 'tuple[str, str] | tuple[None, None]':
    """Return the ``(entity_type, mbid)`` an entity points at, or ``(None, None)``.

    Uses MusicBrainz entity-type vocabulary (``release`` for albums,
    ``recording`` for tracks/files) so the reference round-trips with the
    MB web service and the ``album load <type>:<mbid>`` style tools. The MBID
    comes from the entity's own identity (Album.id / Track.id) or, for a
    standalone file, its ``musicbrainz_recordingid`` tag.
    """
    if isinstance(entity, Album):
        return ('release', entity.id) if entity.id else (None, None)
    if isinstance(entity, Track):
        return ('recording', entity.id) if entity.id else (None, None)
    if isinstance(entity, File):
        recording_id = entity.metadata['musicbrainz_recordingid']
        return ('recording', recording_id) if recording_id else (None, None)
    return (None, None)


def describe_entity(entity: Any) -> dict[str, Any]:
    """A small, serializable summary of an entity for ``ls`` / item data.

    Uses the entity's own ``column()`` accessors where available (the same
    source the GUI columns use), falling back to a filename for files. A lookup
    :class:`Candidate` is projected via its own ``describe()`` so ``ls m*``
    shows the same release reference/title/score as the lookup listing.
    """
    if isinstance(entity, Candidate):
        return entity.describe()

    data: dict[str, Any] = {}
    entity_type, mbid = _entity_mb_ref(entity)
    if entity_type and mbid:
        data['entity_type'] = entity_type
        data['mbid'] = mbid
    column = getattr(entity, 'column', None)
    if callable(column):
        # Title/artist are the common human labels for albums/clusters/tracks.
        title = column('title')
        if title:
            data['title'] = title
        artist = column('artist') or column('albumartist')
        if artist:
            data['artist'] = artist
    base_filename = getattr(entity, 'base_filename', None)
    if base_filename:
        data['filename'] = base_filename
    # File count for containers (clusters/albums), if cheaply available.
    files = getattr(entity, 'files', None)
    if files is not None:
        try:
            data['file_count'] = len(files)
        except TypeError:
            pass
    return data


def _cmd_ls(session: EngineSession, args: dict[str, Any]) -> EngineResult:
    """List the session's top-level entities with their handles.

    ``ls`` with no selector lists all top-level objects (unclustered files,
    clusters, albums); ``ls <selector>`` lists just the matched entities.
    """
    selector = args.get('selector')
    if selector:
        entities, unresolved = session.resolve(selector)
        items = [
            EngineItemResult(handle=session.handle_for(e), status='listed', data=describe_entity(e)) for e in entities
        ]
        return EngineResult(
            items=items,
            resolved=[it.handle for it in items],
            unresolved=unresolved,
        )

    items = []
    for prefix in _LS_PREFIXES:
        for entity in session.enumerate_prefix(prefix):
            handle = session.handle_for(entity)
            items.append(EngineItemResult(handle=handle, status='listed', data=describe_entity(entity)))
    return EngineResult(items=items, resolved=[it.handle for it in items])


def _tree_item(session: EngineSession, entity: Any, kind: str, depth: int) -> EngineItemResult:
    """Build a depth-tagged tree item for ``entity``.

    ``kind`` is a short structural role ('unclustered', 'cluster', 'album',
    'track', 'file', 'unmatched') shown as the status; ``depth`` drives the
    renderer's indentation.
    """
    data = describe_entity(entity)
    data['depth'] = depth
    return EngineItemResult(handle=session.handle_for(entity), status=kind, data=data)


def _tree_track(session: EngineSession, track: Any, items: list, depth: int = 0) -> None:
    """Append ``track`` and the files matched to it to ``items``."""
    items.append(_tree_item(session, track, 'track', depth))
    for file in track.files:
        items.append(_tree_item(session, file, 'file', depth + 1))


def _tree_album(session: EngineSession, album: Any, items: list, depth: int = 0) -> None:
    """Append ``album`` and its tracks/matched-files/unmatched bucket to ``items``."""
    items.append(_tree_item(session, album, 'album', depth))
    for track in album.tracks:
        _tree_track(session, track, items, depth + 1)
    for file in album.unmatched_files.files:
        items.append(_tree_item(session, file, 'unmatched', depth + 1))


def _tree_cluster(session: EngineSession, cluster: Any, items: list, depth: int = 0) -> None:
    """Append ``cluster`` and its files to ``items``."""
    items.append(_tree_item(session, cluster, 'cluster', depth))
    for file in cluster.files:
        items.append(_tree_item(session, file, 'file', depth + 1))


def _cmd_tree(session: EngineSession, args: dict[str, Any]) -> EngineResult:
    """Show the working set as a tree, mirroring the GUI panes.

    With no selector, renders the three GUI panes as one indented tree:
      - unclustered files (the left pane's loose files),
      - clusters, each with its files,
      - albums, each with its tracks (and the files matched to each), plus any
        files still in the album's unmatched bucket.

    With a selector (e.g. ``tree a1``), renders just the subtree(s) of the
    matched entities: an album with its tracks/files, a cluster with its files,
    or a lone file/track.

    Read-only; every row carries its handle so it can be acted on (match,
    remove, save, ...). Use ``ls`` for a flat top-level listing.
    """
    items: list[EngineItemResult] = []
    selector = args.get('selector')

    if selector:
        entities, unresolved = session.resolve(selector)
        for entity in entities:
            if isinstance(entity, Album):
                _tree_album(session, entity, items)
            elif isinstance(entity, Cluster):
                _tree_cluster(session, entity, items)
            elif isinstance(entity, Track):
                _tree_track(session, entity, items)
            elif isinstance(entity, File):
                items.append(_tree_item(session, entity, 'file', 0))
            else:  # a lookup candidate: nothing below it
                items.append(_tree_item(session, entity, 'candidate', 0))
        return EngineResult(items=items, resolved=[session.handle_for(e) for e in entities], unresolved=unresolved)

    wks = workspace()
    # Unclustered files (left pane, loose files).
    for file in wks.unclustered_files.files:
        items.append(_tree_item(session, file, 'unclustered', 0))
    # Clusters (left pane) with their files.
    for cluster in wks.clusters:
        _tree_cluster(session, cluster, items)
    # Albums (right pane): tracks, matched files, and the unmatched bucket.
    for album in wks.albums.values():
        _tree_album(session, album, items)
    return EngineResult(items=items, resolved=[it.handle for it in items])


def _expand_input_paths(tokens: list[str]) -> 'tuple[list[str], list[str]]':
    """Expand user path tokens to concrete paths, recursing into directories.

    Each token is ``~``-expanded and glob-expanded (so ``dir/*`` works inside
    the REPL, where no shell expands it). Directories are walked via
    scan_paths_recursive (respecting the recursively_add_files /
    ignore_hidden_files settings). Returns ``(files, unmatched_tokens)`` where
    unmatched tokens are those matching no existing path.
    """
    settings = config.get_config().setting
    recursive = settings['recursively_add_files']
    ignore_hidden = settings['ignore_hidden_files']

    roots: list[str] = []
    unmatched: list[str] = []
    for token in tokens:
        expanded = os.path.expanduser(token)
        if glob.has_magic(expanded):
            matches = glob.glob(expanded)
            if matches:
                roots.extend(matches)
            else:
                unmatched.append(token)
        elif os.path.exists(expanded):
            roots.append(expanded)
        else:
            unmatched.append(token)

    # Fallback for unquoted paths containing spaces: the shell tokenizer split
    # e.g. "/music/Second tour/" into ["/music/Second", "tour/"]. If the
    # leftover tokens, re-joined with spaces, name an existing path (or a glob
    # that matches), treat them as that single path rather than reporting each
    # fragment as unresolved.
    if unmatched:
        joined = os.path.expanduser(' '.join(unmatched))
        if glob.has_magic(joined):
            matches = glob.glob(joined)
            if matches:
                roots.extend(matches)
                unmatched = []
        elif os.path.exists(joined):
            roots.append(joined)
            unmatched = []

    files = list(scan_paths_recursive(roots, recursive, ignore_hidden))
    return files, unmatched


def _cmd_file_add(session: EngineSession, args: dict[str, Any]) -> EngineResult:
    """Load one or more audio files into the working set (unclustered).

    Accepts files, directories (walked) and globs. Each resolved file is opened
    with the format registry, registered in the working set's file registry and
    unclustered bucket, then loaded; the async loads are drained before
    returning. Successfully loaded files are minted as ``f`` handles.
    """
    paths = args.get('paths')
    if not paths:
        return EngineResult.failure("file add: no paths given")
    if isinstance(paths, str):
        paths = [paths]

    filepaths, unmatched = _expand_input_paths(list(paths))
    # Same normalisation as the GUI's add_files, so the "already loaded" check
    # below compares like with like; and the same order too: by filename, as
    # add_files sorts the new files, not the order a directory happens to be
    # scanned in. That order decides the handles the files are given.
    filepaths = sorted(normpath(resolve_fs_path(path)) for path in filepaths)

    settings = config.get_config().setting
    ignore_hidden = settings['ignore_hidden_files']
    ignoreregex = compile_ignore_regex(settings['ignore_regex'])

    wks = workspace()
    registry = services().format_registry
    loaded = []
    items = []
    notes: list[str] = []
    for path in filepaths:
        if is_ignored_file(path, ignore_hidden, ignoreregex):
            items.append(EngineItemResult(handle='', status='ignored', data={'path': path}))
            continue
        existing = wks.files.get(path)
        if existing is not None:
            # Never open a second File for a path that is already in the set.
            items.append(
                EngineItemResult(handle=session.handle_for(existing), status='already_loaded', data={'path': path})
            )
            continue
        file = registry.open(path)
        if file is None:
            items.append(EngineItemResult(handle='', status='unsupported', data={'path': path}))
            continue
        wks.files[file.filename] = file
        wks.unclustered_files.add_file(file)
        file.load(lambda _f: None)
        loaded.append(file)

    # Drain all the scheduled loads together.
    _drain(session, 120, notes)

    # Apply the same per-file placement policy the GUI uses after a load:
    # honour embedded MusicBrainz IDs (auto-move to the matching album/track/
    # NAT) and, when configured, the analyze fallback. Files with no embedded
    # IDs stay in the unclustered bucket. This keeps `file add` behaviour in the
    # shell consistent with dropping files into the GUI.
    for file in loaded:
        if file.state != File.State.ERROR:
            wks.place_loaded_file(file)
    # Placement may have scheduled album/NAT loads (and matching); drain them.
    _drain(session, 120, notes)

    mints = []
    for file in loaded:
        if file.state == File.State.ERROR:
            items.append(EngineItemResult(handle='', status='error', data={'path': file.filename}))
            continue
        handle = session.handle_for(file)
        mints.append(handle)
        # A file whose load had not finished when we gave up is not "added" yet.
        status = 'pending' if file.state == File.State.PENDING else 'added'
        items.append(EngineItemResult(handle=handle, status=status, data=describe_entity(file)))

    ok = any(it.status in {'added', 'pending'} for it in items) or (not loaded and not unmatched)
    return EngineResult(ok=ok, items=items, mints=mints, unresolved=unmatched, message=_message(notes))


def _cmd_cluster(session: EngineSession, args: dict[str, Any]) -> EngineResult:
    """Group the selected files into clusters by their metadata.

    Defaults to clustering the unclustered bucket (``f*``). Resulting clusters
    are minted as ``c`` handles; single-file groups stay unclustered.
    """
    selector = args.get('selector') or 'f*'
    entities, unresolved = session.resolve(selector)
    files = [e for e in entities if isinstance(e, File)]
    clusters = workspace().cluster_files(files)
    items = []
    mints = []
    for cluster in clusters:
        handle = session.handle_for(cluster)
        mints.append(handle)
        items.append(EngineItemResult(handle=handle, status='clustered', data=describe_entity(cluster)))
    return EngineResult(
        items=items, mints=mints, resolved=[session.handle_for(f) for f in files], unresolved=unresolved
    )


def _request_error_text(http: Any, error: Any) -> str:
    """Human text for a failed web service request (as the album load reports it)."""
    try:
        return http.errorString()
    except AttributeError:
        return str(error)


def _lookup_cluster(session: EngineSession, cluster: Cluster, notes: list[str]) -> EngineItemResult:
    """Look up one cluster: capture ranked candidates, auto-apply the best.

    Issues the same release search as the GUI cluster lookup but with our own
    callback to capture all candidates, drains the request, ranks them, mints
    m handles, and auto-applies the top match (producing an album) when it
    passes the similarity floor.
    """
    captured: dict[str, Any] = {}

    def capture(document, http, error):
        captured['document'] = document
        captured['http'] = http
        captured['error'] = error

    cluster.lookup_metadata(callback=capture)
    drained = _drain(session, 60, notes)

    if not drained and not captured:
        # No reply at all before we gave up: neither "no matches" nor a result.
        return EngineItemResult(handle=session.handle_for(cluster), status='timeout', data={'candidates': []})

    if captured.get('error'):
        # The search request itself failed (network/server error): say so
        # instead of reporting it as "no matches".
        return EngineItemResult(
            handle=session.handle_for(cluster),
            status='lookup_failed',
            data={'candidates': [], 'error': _request_error_text(captured.get('http'), captured['error'])},
        )

    document = captured.get('document')
    releases = None
    if document is not None:
        try:
            releases = document['releases']
        except (KeyError, TypeError):
            releases = None
    if not releases:
        return EngineItemResult(
            handle=session.handle_for(cluster),
            status='no_matches',
            data={'candidates': []},
        )

    settings = config.get_config().setting
    ranked, best = cluster.rank_release_candidates(
        releases,
        min_similarity=settings['match_min_similarity'],
        min_margin=settings['match_min_margin'],
    )

    applied_release = best.result.release  # None when below floor
    candidates = [Candidate(m, applied=(m.release is applied_release and applied_release is not None)) for m in ranked]
    candidate_handles = session.set_candidates(cluster, candidates)

    matched_album_handle = None
    load_error = None
    if applied_release is not None:
        album = workspace().load_album(applied_release['id'])
        # Drain the release load before moving files: load_album() only
        # schedules the request. If it failed (e.g. a 503 from the server),
        # album.errors is populated and we must NOT report a confident match
        # or move files onto a half-loaded album.
        loaded = _drain(session, 60, notes)
        if album.errors:
            load_error = album.errors[-1]
        elif not loaded and not album.loaded:
            load_error = "timed out waiting for the release to load"
        else:
            # cluster.files is typed as generic metadata items; only File here.
            files = [f for f in cluster.files if isinstance(f, File)]
            workspace().move_files_to_album(files, album=album)
            matched_album_handle = session.handle_for(album)

    if matched_album_handle:
        status = 'matched'
    elif load_error is not None:
        status = 'load_failed'
    else:
        status = 'no_confident_match'

    data = {
        'reason': best.reason,
        'matched_album': matched_album_handle,
        'candidates': [{'handle': h, **c.describe()} for h, c in zip(candidate_handles, candidates, strict=True)],
    }
    if load_error is not None:
        data['error'] = load_error
    return EngineItemResult(
        handle=session.handle_for(cluster),
        status=status,
        data=data,
    )


def _cmd_cluster_lookup(session: EngineSession, args: dict[str, Any]) -> EngineResult:
    """Identify clusters against MusicBrainz, auto-applying the best match.

    For each selected cluster, the ranked candidate releases are exposed as
    ``m`` handles and the top confident match is applied (producing an album);
    use ``match <cluster> <m>`` to pick a different candidate.
    """
    selector = args.get('selector') or 'c*'
    entities, unresolved = session.resolve(selector)
    clusters = [e for e in entities if isinstance(e, Cluster)]
    notes: list[str] = []
    items = [_lookup_cluster(session, cluster, notes) for cluster in clusters]
    mints = []
    for item in items:
        if item.data.get('matched_album'):
            mints.append(item.data['matched_album'])
        mints.extend(c['handle'] for c in item.data.get('candidates', []))
    return EngineResult(
        items=items,
        resolved=[session.handle_for(c) for c in clusters],
        unresolved=unresolved,
        mints=mints,
        message=_message(notes),
    )


def _cmd_match(session: EngineSession, args: dict[str, Any]) -> EngineResult:
    """Apply a specific lookup candidate to its target.

    ``match <target> <candidate>`` moves the target cluster's files onto the
    release of candidate handle ``m<n>`` (an alternative from a prior
    ``cluster lookup``), overriding the auto-applied match. Updates which
    candidate is marked ``applied``.
    """
    target_sel = args.get('target')
    candidate_sel = args.get('candidate')
    if not target_sel or not candidate_sel:
        return EngineResult.failure("match: usage: match <target> <candidate>")

    targets, target_unresolved = session.resolve(target_sel)
    cands, cand_unresolved = session.resolve(candidate_sel)
    unresolved = target_unresolved + cand_unresolved

    clusters = [e for e in targets if isinstance(e, Cluster)]
    candidates = [c for c in cands if isinstance(c, Candidate)]
    if len(clusters) != 1 or len(candidates) != 1:
        return EngineResult.failure(
            "match: need exactly one target cluster and one candidate",
            unresolved=unresolved,
        )
    cluster = clusters[0]
    candidate = candidates[0]
    if candidate.release_id is None:
        return EngineResult.failure("match: candidate has no release", unresolved=unresolved)
    # A candidate is only an alternative for the cluster it was looked up for.
    if not any(c is candidate for c in session.candidates_for(cluster)):
        return EngineResult.failure(
            f"match: {session.handle_for(candidate)} is not a candidate of {session.handle_for(cluster)}",
            unresolved=unresolved,
        )

    album = workspace().load_album(candidate.release_id)
    # Drain the load and verify it succeeded before moving files onto the
    # album (load_album() only schedules the request; a failed load leaves
    # album.errors set and must not be reported as a match).
    notes: list[str] = []
    drained = _drain(session, 60, notes)
    if album.errors:
        return EngineResult.failure(
            f"match: release load failed: {album.errors[-1]}",
            unresolved=unresolved,
        )
    if not drained and not album.loaded:
        return EngineResult.failure(
            f"match: {_message(notes)}",
            unresolved=unresolved,
        )
    workspace().move_files_to_album(cluster.files, album=album)

    # Reflect the new selection in the target's candidate set.
    for c in session.candidates_for(cluster):
        c.applied = c is candidate

    album_handle = session.handle_for(album)
    return EngineResult(
        items=[
            EngineItemResult(
                handle=session.handle_for(cluster),
                status='matched',
                data={'matched_album': album_handle, 'candidate': session.handle_for(candidate)},
            )
        ],
        resolved=[session.handle_for(cluster)],
        unresolved=unresolved,
        mints=[album_handle],
    )


def _cmd_save(session: EngineSession, args: dict[str, Any]) -> EngineResult:
    """Save tag changes for the selected objects to disk.

    ``save <selector>`` saves the files of the matched objects (albums,
    clusters, tracks or files); defaults to all top-level objects (``*``).
    Drains the async saves and reports per-file success.
    """
    selector = args.get('selector') or '*'
    entities, unresolved = session.resolve(selector)
    files = list(iter_files_from_objects(entities, save=True))
    savable = [f for f in files if f.can_save]
    for file in savable:
        file.save()
    notes: list[str] = []
    _drain(session, 120, notes)

    items = []
    for file in savable:
        if file.state == File.State.ERROR:
            status = 'error'
        elif file.state == File.State.PENDING:
            status = 'pending'  # still being saved when we stopped waiting
        else:
            status = 'saved'
        items.append(EngineItemResult(handle=session.handle_for(file), status=status, data={'path': file.filename}))
    return EngineResult(
        items=items,
        resolved=[session.handle_for(e) for e in entities],
        unresolved=unresolved,
        message=_message(notes),
    )


def _extract_release_mbid(text: str) -> 'str | None':
    """Extract a release MBID from a bare id, a ``release:<mbid>`` reference, or a URL.

    Accepts ``<mbid>``, the ``release:<mbid>`` reference shown by ``ls`` / ``tree``,
    ``https://musicbrainz.org/release/<mbid>`` (any host, optional trailing
    path/query), or an ``mbid://`` URI. Returns the MBID if valid, else None.
    """
    text = text.strip()
    # The listings display releases as ``release:<mbid>``; accept that round-trip.
    if text.startswith('release:'):
        text = text[len('release:') :].strip()
    if mbid_validate(text):
        return text
    parsed = urlparse(text)
    if parsed.scheme in {'http', 'https', 'mbid'}:
        # Take the last path segment (…/release/<mbid>) or the netloc for mbid://.
        candidate = (parsed.path.rstrip('/').rsplit('/', 1)[-1]) or parsed.netloc
        if mbid_validate(candidate):
            return candidate
    return None


def _cmd_album_load(session: EngineSession, args: dict[str, Any]) -> EngineResult:
    """Load a release by MBID (or MusicBrainz release URL) as an empty album.

    The album loads with no files attached; files or clusters can then be moved
    onto it. Mirrors the GUI's load-by-MBID (search+load, tagger button, or a
    pasted release URL).
    """
    arg = args.get('mbid')
    if not arg:
        return EngineResult.failure("album load: usage: album load <mbid|url>")
    if isinstance(arg, list):
        arg = arg[0] if arg else ''
    mbid = _extract_release_mbid(arg)
    if mbid is None:
        return EngineResult.failure(f"album load: not a release MBID or URL: {arg!r}")

    album = workspace().load_album(mbid)
    notes: list[str] = []
    drained = _drain(session, 60, notes)

    handle = session.handle_for(album)
    if album.errors:
        status = 'error'
    elif not drained and not album.loaded:
        status = 'pending'
    else:
        status = 'loaded'
    return EngineResult(
        items=[EngineItemResult(handle=handle, status=status, data=describe_entity(album))],
        mints=[handle],
        message=_message(notes),
    )


def _cmd_scan(session: EngineSession, args: dict[str, Any]) -> EngineResult:
    """Identify the selected files by AcoustID fingerprint (the "Scan" action).

    Defaults to the unclustered bucket (``f*``). Each analyzable file is
    fingerprinted and looked up on AcoustID; a confident recording match moves
    the file onto the matching album track (or a non-album track). The async
    fingerprint + lookup work is drained before returning. Reports, per file,
    whether it ended up identified (moved onto a track) or unmatched.

    No-op when AcoustID is not the configured fingerprinting system (reported
    as a failure so the user knows nothing ran).
    """
    wks = workspace()
    if not wks.use_acoustid:
        return EngineResult.failure(
            "scan: AcoustID fingerprinting is not enabled (set the fingerprinting system to AcoustID)"
        )

    selector = args.get('selector') or 'f*'
    entities, unresolved = session.resolve(selector)
    files = [e for e in entities if isinstance(e, File) and e.can_analyze]
    if not files:
        return EngineResult(items=[], resolved=[session.handle_for(e) for e in entities], unresolved=unresolved)

    wks.analyze(files)
    # Drain the fingerprint computation and the follow-up AcoustID lookups, plus
    # any album loads a confident match scheduled.
    notes: list[str] = []
    _drain(session, 300, notes)

    items = []
    mints = []
    for file in files:
        parent = file.parent_item
        album = getattr(parent, 'album', None)
        if album is not None:
            status = 'identified'
            album_handle = session.handle_for(album)
            if album_handle not in mints:
                mints.append(album_handle)
            data = {'path': file.filename, 'album': album_handle}
        else:
            status = 'no_match'
            data = {'path': file.filename}
        items.append(EngineItemResult(handle=session.handle_for(file), status=status, data=data))
    return EngineResult(
        items=items,
        mints=mints,
        resolved=[session.handle_for(f) for f in files],
        unresolved=unresolved,
        message=_message(notes),
    )


def _cmd_remove(session: EngineSession, args: dict[str, Any]) -> EngineResult:
    """Remove the selected objects from the working set (does not touch disk).

    ``remove <selector>`` removes the matched files, tracks, clusters and
    albums from the session's working set. Nothing is written or deleted on
    disk; it only drops them from Picard. There is no default selector — an
    explicit selection is required, to avoid wiping the whole set by accident.
    """
    selector = args.get('selector')
    if not selector:
        return EngineResult.failure("remove: a selector is required (e.g. remove c1, remove a*)")
    entities, unresolved = session.resolve(selector)
    if not entities:
        return EngineResult(items=[], unresolved=unresolved)

    # Lookup candidates are session-side objects, not working-set members:
    # there is nothing to remove, so say so rather than report them removed.
    removable = [e for e in entities if not isinstance(e, Candidate)]
    skipped = [e for e in entities if isinstance(e, Candidate)]

    # Capture handles/descriptions before removal (the entities still exist in
    # this scope; their handles stay valid for the report).
    items = [
        EngineItemResult(handle=session.handle_for(e), status='removed', data=describe_entity(e)) for e in removable
    ]
    items.extend(
        EngineItemResult(handle=session.handle_for(e), status='skipped', data=describe_entity(e)) for e in skipped
    )
    if removable:
        workspace().remove(removable)
    return EngineResult(items=items, resolved=[it.handle for it in items], unresolved=unresolved)


def _cmd_move(session: EngineSession, args: dict[str, Any]) -> EngineResult:
    """Move files into a track, a cluster, an album or a bucket of unplaced files.

    ``move <sources> <destination>``: the last word is the destination, a single
    place; everything before it selects what to move (the files of the matched
    albums, clusters and tracks, as for ``save``). The destination is one of:

    - a track (``a1.d2.t3``): the files are attached to it;
    - a cluster (``c1``);
    - an album (``a1``): the files are matched to its tracks, as when dropped on
      the album in the GUI;
    - ``u`` (the files in no cluster) or an album's unmatched files (``a1.u``).

    Reports each file as ``moved`` (with where it was, and its new path) or
    ``unchanged`` when it is already there.
    """
    words = args.get('selectors')
    if isinstance(words, str):
        words = [words]
    if not words or len(words) < 2:
        return EngineResult.failure("move: usage: move <sources> <destination>")
    *source_words, destination_word = words

    destinations = session.resolve_targets(destination_word)
    if not destinations:
        return EngineResult.failure(f"move: destination {destination_word!r} matches nothing")
    if len(destinations) > 1:
        return EngineResult.failure(
            f"move: destination {destination_word!r} matches {len(destinations)} places; name one"
        )
    (destination,) = destinations
    if isinstance(destination, NatAlbum):
        return EngineResult.failure("move: moving files to the non-album tracks is not supported")
    if not isinstance(destination, (Track, Cluster, Album)):
        return EngineResult.failure(
            f"move: {destination_word!r} is not a place files can be moved to (use a track, a cluster, an album or u)"
        )

    sources, unresolved = session.resolve(source_words)
    candidates = [e for e in sources if isinstance(e, Candidate)]
    if candidates:
        return EngineResult.failure(
            f"move: {session.handle_for(candidates[0])} is a lookup candidate, it holds no files",
            unresolved=unresolved,
        )
    files = list(iter_files_from_objects(sources))

    wks = workspace()
    paths_before = {file: session.path_of(session.handle_for(file)) for file in files}
    parents_before = {file: file.parent_item for file in files}
    movable = [file for file in files if file.parent_item is not destination]
    if isinstance(destination, Album):
        wks.move_files_to_album(movable, album=destination)
    else:
        for file in movable:
            wks.move_file(file, destination)
    notes: list[str] = []
    _drain(session, 120, notes)

    items = []
    for file in files:
        # Judge by where the file is now: a move can be refused, and matching to
        # an album can leave a file on the track it was already on.
        status = 'moved' if file.parent_item is not parents_before[file] else 'unchanged'
        items.append(
            EngineItemResult(
                handle=session.handle_for(file),
                status=status,
                data={'filename': file.base_filename, 'from': paths_before[file] or ''},
            )
        )
    return EngineResult(
        items=items,
        resolved=[item.handle for item in items],
        unresolved=unresolved,
        message=_message(notes),
    )


def _cmd_trash(session: EngineSession, args: dict[str, Any]) -> EngineResult:
    """Move the selected files to the system trash and drop them from the set.

    ``trash <selector>`` sends the files of the matched objects to the OS
    trash/recycle bin (reversible via the OS) and removes them from the working
    set. Like the GUI action, a container (album, cluster, track) stands for
    all of its files, so ``trash a1`` trashes every file in album ``a1``. A
    selector is required.
    """
    selector = args.get('selector')
    if not selector:
        return EngineResult.failure("trash: a selector is required (e.g. trash f1)")
    entities, unresolved = session.resolve(selector)
    files = list(iter_files_from_objects(entities))
    if not files:
        return EngineResult(items=[], unresolved=unresolved)

    items = [EngineItemResult(handle=session.handle_for(f), status='trashed', data={'path': f.filename}) for f in files]
    workspace().trash_files(files)
    return EngineResult(items=items, resolved=[it.handle for it in items], unresolved=unresolved)


def _cmd_lookup(session: EngineSession, args: dict[str, Any]) -> EngineResult:
    """Look up the selected objects on MusicBrainz by their existing metadata.

    ``lookup <selector>`` (default: all top-level objects, ``*``) runs the
    metadata-based lookup (autotag) on each taggable object: a cluster or file
    is matched to a release/recording from its current tags and moved onto the
    result. This is the "Lookup" action; for the candidate-capturing variant
    that exposes alternatives, use ``cluster lookup``.

    Reports, per object, whether it ended up matched (moved onto an album) or
    unmatched after the lookups drain.
    """
    selector = args.get('selector') or '*'
    entities, unresolved = session.resolve(selector)
    taggable = [e for e in entities if getattr(e, 'can_autotag', False)]
    if not taggable:
        return EngineResult(items=[], resolved=[session.handle_for(e) for e in entities], unresolved=unresolved)

    workspace().autotag(taggable)
    # autotag dispatches async web lookups (and album loads on a match); drain.
    notes: list[str] = []
    _drain(session, 300, notes)

    items = []
    mints = []
    for obj in taggable:
        album = None
        if isinstance(obj, File):
            album = getattr(obj.parent_item, 'album', None)
        if album is not None:
            status = 'matched'
            album_handle = session.handle_for(album)
            if album_handle not in mints:
                mints.append(album_handle)
            data = {'handle': session.handle_for(obj), 'album': album_handle}
        else:
            status = 'done'
            data = {'handle': session.handle_for(obj)}
        items.append(EngineItemResult(handle=session.handle_for(obj), status=status, data=data))
    return EngineResult(
        items=items,
        mints=mints,
        resolved=[session.handle_for(e) for e in taggable],
        unresolved=unresolved,
        message=_message(notes),
    )


def _disc_lookup_and_report(session: EngineSession, disc) -> EngineResult:
    """Look up a populated ``disc`` and report the album it matched.

    Shared tail of the disc commands: issues the disc-id lookup and drains it
    (and any album load the headless auto-load scheduled), then reports the
    matched album — or ``no_match`` when nothing unambiguous was found. The
    matched album is read from the disc-presentation facade (not by diffing the
    album registry), so a release already loaded in the session is still
    reported as a match rather than a spurious ``no_match``.
    """
    dp = disc_presentation()
    dp.reset_last_loaded()
    disc.lookup()
    notes: list[str] = []
    drained = _drain(session, 120, notes)

    album = dp.last_loaded_album
    if album is None:
        status = 'no_match' if drained else 'timeout'
        return EngineResult(
            items=[EngineItemResult(handle='', status=status, data={'disc_id': disc.id})],
            message=_message(notes),
        )
    handle = session.handle_for(album)
    return EngineResult(
        items=[EngineItemResult(handle=handle, status='loaded', data=describe_entity(album))],
        mints=[handle],
        message=_message(notes),
    )


def _cmd_disc_read(session: EngineSession, args: dict[str, Any]) -> EngineResult:
    """Read the TOC from an audio CD in the drive and load the matching release.

    ``disc read [device]`` reads the disc in ``device`` (or the default drive
    when omitted), computes its disc ID, and looks it up on MusicBrainz.
    Headless, a single unambiguous match is auto-loaded (carrying the disc id
    and any ISRCs read from the disc); an ambiguous result loads nothing (no
    picker).

    Requires the optional python-discid library and a readable CD drive.
    """
    if picard.disc.discid is None:
        return EngineResult.failure("disc read: the python-discid library is not available")

    device = args.get('device')
    if isinstance(device, list):
        device = device[0] if device else None

    disc = picard.disc.Disc()
    try:
        disc.read(device)
    except Exception as e:
        where = device or 'the default drive'
        return EngineResult.failure(f"disc read: could not read {where}: {e}")

    return _disc_lookup_and_report(session, disc)


def _cmd_disc_read_log(session: EngineSession, args: dict[str, Any]) -> EngineResult:
    """Identify a disc from a CD ripper log file and load the matching release.

    ``disc read-log <path>`` parses the ripper log (EAC / XLD / Whipper /
    dBpoweramp / cyanrip / SCSI TOC) into a disc TOC, computes the disc ID, and
    looks it up on MusicBrainz. Headless, a single unambiguous match is
    auto-loaded (carrying the disc id); an ambiguous result loads nothing (no
    picker). Exercises the decoupled disc path end to end.

    Requires the optional python-discid library (for TOC -> disc-id).
    """
    if picard.disc.discid is None:
        return EngineResult.failure("disc read-log: the python-discid library is not available")

    path = args.get('path')
    if isinstance(path, list):
        path = path[0] if path else None
    if not path:
        return EngineResult.failure("disc read-log: usage: disc read-log <path>")

    disc = picard.disc.Disc()
    try:
        disc.read_log(path)
    except Exception as e:
        return EngineResult.failure(f"disc read-log: could not parse {path!r}: {e}")

    return _disc_lookup_and_report(session, disc)


def register_builtins(registry: EngineCommandRegistry) -> None:
    """Register the built-in commands into ``registry``."""
    registry.register(
        EngineCommand(
            name='ls',
            run=_cmd_ls,
            help="List working-set entities (optionally matching a selector) with their handles.",
            args=('selector',),
            arg_kinds=('selector',),
        )
    )
    registry.register(
        EngineCommand(
            name='tree',
            run=_cmd_tree,
            help="Show the working set (or a selected subtree) as an indented tree.",
            args=('selector',),
            arg_kinds=('selector',),
        )
    )
    registry.register(
        EngineCommand(
            name='file add',
            run=_cmd_file_add,
            help="Load one or more audio files into the working set.",
            args=('paths',),
            arg_kinds=('path',),
        )
    )
    registry.register(
        EngineCommand(
            name='cluster',
            run=_cmd_cluster,
            help="Group files (default: unclustered) into clusters by metadata.",
            args=('selector',),
            arg_kinds=('selector',),
        )
    )
    registry.register(
        EngineCommand(
            name='cluster lookup',
            run=_cmd_cluster_lookup,
            help="Identify clusters on MusicBrainz; auto-apply the best match, expose alternatives as m handles.",
            args=('selector',),
            arg_kinds=('selector',),
        )
    )
    registry.register(
        EngineCommand(
            name='scan',
            run=_cmd_scan,
            help="Identify files (default: unclustered) by AcoustID fingerprint; move confident matches onto tracks.",
            args=('selector',),
            arg_kinds=('selector',),
        )
    )
    registry.register(
        EngineCommand(
            name='album load',
            run=_cmd_album_load,
            help="Load a release by MBID or MusicBrainz URL as an empty album.",
            args=('mbid',),
            arg_kinds=('',),
        )
    )
    registry.register(
        EngineCommand(
            name='match',
            run=_cmd_match,
            help="Apply a specific lookup candidate: match <target> <candidate>.",
            args=('target', 'candidate'),
            arg_kinds=('selector', 'handle'),
        )
    )
    registry.register(
        EngineCommand(
            name='save',
            run=_cmd_save,
            help="Save tag changes of the selected objects to disk (default: all).",
            args=('selector',),
            arg_kinds=('selector',),
        )
    )
    registry.register(
        EngineCommand(
            name='lookup',
            run=_cmd_lookup,
            help="Look up the selected objects on MusicBrainz by their existing metadata (default: all).",
            args=('selector',),
            arg_kinds=('selector',),
        )
    )
    registry.register(
        EngineCommand(
            name='remove',
            run=_cmd_remove,
            help="Remove the selected objects from the working set (does not touch disk).",
            args=('selector',),
            arg_kinds=('selector',),
        )
    )
    registry.register(
        EngineCommand(
            name='move',
            run=_cmd_move,
            help="Move files into a track, cluster, album or bucket: move <sources> <destination>.",
            args=('selectors',),
            arg_kinds=('selector',),
        )
    )
    registry.register(
        EngineCommand(
            name='trash',
            run=_cmd_trash,
            help="Move the selected files to the system trash and drop them from the set.",
            args=('selector',),
            arg_kinds=('selector',),
            destructive=True,
        )
    )
    registry.register(
        EngineCommand(
            name='disc read',
            run=_cmd_disc_read,
            help="Read the TOC from an audio CD in the drive and load the matching release.",
            args=('device',),
            arg_kinds=('device',),
        )
    )
    registry.register(
        EngineCommand(
            name='disc read-log',
            run=_cmd_disc_read_log,
            help="Identify a disc from a CD ripper log file and load the matching release.",
            args=('path',),
            arg_kinds=('path',),
        )
    )
