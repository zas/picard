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

from typing import Any

from picard.cli.engine.commands import (
    EngineCommand,
    EngineCommandRegistry,
    EngineSession,
)
from picard.cli.engine.result import (
    EngineItemResult,
    EngineResult,
)
from picard.file import File
from picard.services import services
from picard.workspace import workspace


# Prefixes shown by a bare ``ls`` (top-level, mirroring the GUI panes).
_LS_PREFIXES = ('f', 'c', 'a')


def describe_entity(entity: Any) -> dict[str, Any]:
    """A small, serializable summary of an entity for ``ls`` / item data.

    Uses the entity's own ``column()`` accessors where available (the same
    source the GUI columns use), falling back to a filename for files.
    """
    data: dict[str, Any] = {}
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


def _cmd_file_add(session: EngineSession, args: dict[str, Any]) -> EngineResult:
    """Load one or more audio files into the working set (unclustered).

    Each path is opened with the format registry, registered in the working
    set's file registry and unclustered bucket, then loaded; the async loads
    are drained before returning. Successful files are minted as ``f`` handles.
    """
    paths = args.get('paths')
    if not paths:
        return EngineResult.failure("file add: no paths given")
    if isinstance(paths, str):
        paths = [paths]

    ws = workspace()
    registry = services().format_registry
    loaded = []
    items = []
    for path in paths:
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

    ok = any(it.status == 'added' for it in items) or not loaded
    return EngineResult(ok=ok, items=items, mints=mints)


def register_builtins(registry: EngineCommandRegistry) -> None:
    """Register the built-in commands into ``registry``."""
    registry.register(
        EngineCommand(
            name='ls',
            run=_cmd_ls,
            help="List working-set entities (optionally matching a selector) with their handles.",
            args=('selector',),
        )
    )
    registry.register(
        EngineCommand(
            name='file add',
            run=_cmd_file_add,
            help="Load one or more audio files into the working set.",
            args=('paths',),
        )
    )
