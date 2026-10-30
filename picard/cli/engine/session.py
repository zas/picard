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

"""In-process (headless) implementation of the engine session.

:class:`LocalEngineSession` composes the engine substrate — a
:class:`~picard.cli.engine.handles.HandleRegistry` and the selector resolver —
over a running :class:`~picard.cli.headless.HeadlessTagger` and its
:class:`~picard.workspace.Workspace`. It satisfies the
:class:`~picard.cli.engine.commands.EngineSession` protocol, so commands run
against it unchanged in headless mode; a future ``RemoteEngineSession`` will
satisfy the same protocol by proxying to a running GUI.

This module owns the one piece that must know the concrete entity types: the
handle-prefix CLASSIFIER (entity -> 'f'/'c'/'a'/'t') and the prefix ENUMERATOR
(prefix -> live entities from the Workspace). Everything else is
type-agnostic.
"""

from collections.abc import Iterable
from typing import Any

from picard.album import Album
from picard.cli.engine.handles import HandleRegistry
from picard.cli.engine.selectors import resolve_selector
from picard.cluster import (
    Cluster,
    UnclusteredFiles,
)
from picard.file import File
from picard.track import Track
from picard.workspace import workspace


def classify_entity(entity: Any) -> 'str | None':
    """Map a working-set entity to its handle prefix, or None if not handleable.

    Order matters only where it clarifies intent; the types are otherwise
    disjoint. ``UnclusteredFiles`` is a ``Cluster`` subclass but is the
    unclustered bucket, not a user cluster, so it is NOT handleable as ``c``.
    ``NatAlbum`` is an ``Album`` ('a'); ``NonAlbumTrack`` is a ``Track`` ('t').
    """
    if isinstance(entity, File):
        return 'f'
    if isinstance(entity, Album):
        return 'a'
    if isinstance(entity, UnclusteredFiles):
        return None
    if isinstance(entity, Cluster):
        return 'c'
    if isinstance(entity, Track):
        return 't'
    return None


class LocalEngineSession:
    """Headless EngineSession backed by HeadlessTagger + Workspace."""

    def __init__(self, app):
        """``app`` is the HeadlessTagger owning the Workspace and thread pools."""
        self._app = app
        self._handles = HandleRegistry(classify_entity)

    # --- EngineSession protocol ---------------------------------------------

    def resolve(self, selector: str) -> 'tuple[list[Any], list[str]]':
        """Resolve a selector string to ``(entities, unresolved_tokens)``."""
        return resolve_selector(selector, self._handles.resolve, self.enumerate_prefix)

    def handle_for(self, entity: Any) -> str:
        """Return (minting if needed) the session handle for ``entity``."""
        return self._handles.handle_for(entity)

    def enumerate_prefix(self, prefix: str) -> Iterable[Any]:
        """Yield the live entities of a handle prefix, in a stable order."""
        ws = workspace()
        if prefix == 'f':
            return list(ws.unclustered_files.files)
        if prefix == 'c':
            return list(ws.clusters)
        if prefix == 'a':
            return list(ws.albums.values())
        if prefix == 't':
            return [track for album in ws.albums.values() for track in album.tracks]
        return []

    def run_until_idle(self, timeout: float | None = None) -> bool:
        """Drain async work (thread pools, pending requests) to completion."""
        return self._app.run_until_idle(timeout=timeout)

    @property
    def is_gui(self) -> bool:
        """Local headless session never drives a GUI backend."""
        return False
