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
from picard.album import Album
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
from picard.file import File
from picard.services import services
from picard.track import Track
from picard.util import (
    iter_files_from_objects,
    mbid_validate,
    scan_paths_recursive,
)
from picard.workspace import workspace


# Prefixes shown by a bare ``ls`` (top-level, mirroring the GUI panes).
_LS_PREFIXES = ('f', 'c', 'a')


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

    ws = workspace()
    registry = services().format_registry
    loaded = []
    items = []
    for path in filepaths:
        file = registry.open(path)
        if file is None:
            items.append(EngineItemResult(handle='', status='unsupported', data={'path': path}))
            continue
        ws.files[file.filename] = file
        ws.unclustered_files.add_file(file)
        file.load(lambda _f: None)
        loaded.append(file)

    # Drain all the scheduled loads together.
    session.run_until_idle(timeout=120)

    mints = []
    for file in loaded:
        if file.state == File.State.ERROR:
            items.append(EngineItemResult(handle='', status='error', data={'path': file.filename}))
            continue
        handle = session.handle_for(file)
        mints.append(handle)
        items.append(EngineItemResult(handle=handle, status='added', data=describe_entity(file)))

    ok = any(it.status == 'added' for it in items) or (not loaded and not unmatched)
    return EngineResult(ok=ok, items=items, mints=mints, unresolved=unmatched)


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


def _lookup_cluster(session: EngineSession, cluster: Cluster) -> EngineItemResult:
    """Look up one cluster: capture ranked candidates, auto-apply the best.

    Issues the same release search as the GUI cluster lookup but with our own
    callback to capture all candidates, drains the request, ranks them, mints
    m handles, and auto-applies the top match (producing an album) when it
    passes the similarity floor.
    """
    captured: dict[str, Any] = {}

    def capture(document, http, error):
        captured['document'] = document
        captured['error'] = error

    cluster.lookup_metadata(callback=capture)
    session.run_until_idle(timeout=60)

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
        session.run_until_idle(timeout=60)
        if album.errors:
            load_error = album.errors[-1]
        else:
            workspace().move_files_to_album(cluster.files, album=album)
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
    items = [_lookup_cluster(session, cluster) for cluster in clusters]
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

    album = workspace().load_album(candidate.release_id)
    # Drain the load and verify it succeeded before moving files onto the
    # album (load_album() only schedules the request; a failed load leaves
    # album.errors set and must not be reported as a match).
    session.run_until_idle(timeout=60)
    if album.errors:
        return EngineResult.failure(
            f"match: release load failed: {album.errors[-1]}",
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
    session.run_until_idle(timeout=120)

    items = []
    for file in savable:
        status = 'error' if file.state == File.State.ERROR else 'saved'
        items.append(EngineItemResult(handle=session.handle_for(file), status=status, data={'path': file.filename}))
    return EngineResult(
        items=items,
        resolved=[session.handle_for(e) for e in entities],
        unresolved=unresolved,
    )


def _extract_release_mbid(text: str) -> 'str | None':
    """Extract a release MBID from a bare id or a MusicBrainz release URL.

    Accepts ``<mbid>``, ``https://musicbrainz.org/release/<mbid>`` (any host,
    optional trailing path/query), or an ``mbid://`` URI. Returns the MBID if
    valid, else None.
    """
    text = text.strip()
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
    session.run_until_idle(timeout=60)

    handle = session.handle_for(album)
    status = 'error' if album.errors else 'loaded'
    return EngineResult(
        items=[EngineItemResult(handle=handle, status=status, data=describe_entity(album))],
        mints=[handle],
    )


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
