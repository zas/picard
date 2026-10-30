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

"""Lookup match candidates.

A :class:`Candidate` wraps one scored release returned by a lookup
(:class:`~picard.matching.SimMatchRelease`). It is a session-side object — NOT
a Workspace entity — minted an ``m`` handle by the HandleRegistry (the session
classifier maps ``Candidate`` -> ``'m'``), so a user/agent can refer to a
non-winning alternative and apply it with ``match``.

Candidates are TRANSIENT: a new lookup of a target replaces its candidates, and
once the session drops the old ones their weak handles expire. The session
holds the current candidates (keyed by target) with strong refs; see
``LocalEngineSession``.

``describe()`` projects a candidate to a small, JSON-serializable dict mirroring
the fields the GUI search dialog shows, for an EngineResult item.
"""

from typing import Any

from picard.mbjson import release_to_metadata
from picard.metadata import Metadata


class Candidate:
    """One scored release candidate from a lookup.

    ``match`` holds the :class:`~picard.matching.SimMatchRelease` (its
    ``release`` is the raw MB release search node; ``similarity`` the final
    score). ``applied`` is True for the candidate auto-applied by the lookup.
    """

    __slots__ = ('match', 'applied', '__weakref__')

    def __init__(self, match: Any, applied: bool = False):
        self.match = match
        self.applied = applied

    @property
    def release_id(self) -> 'str | None':
        release = self.match.release
        return release.get('id') if release else None

    @property
    def similarity(self) -> float:
        return self.match.similarity

    def describe(self) -> dict[str, Any]:
        """A small, serializable projection of the candidate release."""
        release = self.match.release
        meta = Metadata()
        # Canonical mapping of the MB release node to metadata fields (only when
        # there is a release; the no-match sentinel has release None).
        if release:
            release_to_metadata(release, meta)
        else:
            release = {}
        data: dict[str, Any] = {
            'mbid': release.get('id'),
            'title': meta['album'] or release.get('title'),
            'artist': meta['albumartist'] or meta['artist'],
            'date': meta['date'],
            'country': meta['releasecountry'],
            'score': release.get('score'),
            'similarity': round(self.similarity, 4),
            'applied': self.applied,
        }
        # Track count from the search node, when present.
        track_count = release.get('track-count')
        if track_count is not None:
            data['tracks'] = track_count
        # Drop empty values for a tidy result.
        return {k: v for k, v in data.items() if v not in ('', None)}
