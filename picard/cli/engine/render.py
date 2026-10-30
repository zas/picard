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

"""Human rendering of an EngineResult for the console frontend.

Commands return a structured :class:`~picard.cli.engine.result.EngineResult`
and never print. This is the console's renderer — the ONE place that turns a
result into text via :class:`~picard.cli.output.CliOutput`. The MCP frontend
will instead serialize ``result.to_dict()``; both read the same structured
result.
"""

from typing import Any

from picard.cli.engine.result import EngineResult
from picard.cli.output import CliOutput


def _entity_ref(item: dict[str, Any]) -> str:
    """Build a ``<type>:<mbid>`` MusicBrainz reference from an item dict.

    Used to always surface which entity a candidate/match points at (e.g.
    ``release:0bad6e23-...``). Falls back gracefully: a bare MBID if the type
    is absent, or ``''`` if there is no MBID at all.
    """
    mbid = item.get('mbid')
    if not mbid:
        return ''
    entity_type = item.get('entity_type')
    return f"{entity_type}:{mbid}" if entity_type else str(mbid)


def _format_item_data(data: dict[str, Any]) -> str:
    """Compact one-line summary of an item's data (title/artist/path/etc.).

    Leads with the ``<type>:<mbid>`` reference when the item points at a
    MusicBrainz entity, so every listed entity shows what it is and resolves to.
    """
    parts = []
    ref = _entity_ref(data)
    if ref:
        parts.append(ref)
    for key in ('title', 'artist', 'filename', 'path', 'file_count', 'matched_album', 'error'):
        value = data.get(key)
        if value not in (None, ''):
            parts.append(f"{key}={value}")
    return '  '.join(parts)


def render_result(result: EngineResult, output: CliOutput) -> None:
    """Render ``result`` to ``output`` for a human reader."""
    if not result.ok:
        output.error(result.error or "command failed")
        if result.unresolved:
            output.warning("unresolved: " + ', '.join(result.unresolved))
        return

    for item in result.items:
        handle = output.d_id(item.handle) if item.handle else '—'
        summary = _format_item_data(item.data)
        line = f"{handle}  {output.dim(item.status)}"
        if summary:
            line += f"  {summary}"
        output.print(line)
        # Lookup items carry a candidate list; show it indented.
        for cand in item.data.get('candidates', []):
            mark = '*' if cand.get('applied') else ' '
            chandle = output.d_id(cand.get('handle', '?'))
            title = cand.get('title', '')
            score = cand.get('similarity')
            score_s = f" ({score})" if score is not None else ''
            # Always show the MusicBrainz entity reference as <type>:<mbid>
            # (e.g. release:0bad6e23-...), so a candidate is unambiguously
            # identifiable and directly usable with the lookup/URL tools.
            ref = _entity_ref(cand)
            ref_s = f"{output.dim(ref)}  " if ref else ''
            output.print(f"    {mark} {chandle}  {ref_s}{title}{score_s}")

    if result.mints:
        output.print(output.dim("minted: " + ', '.join(result.mints)))
    if result.unresolved:
        output.warning("unresolved: " + ', '.join(result.unresolved))
    if result.message:
        output.info(result.message)
    if not result.items and not result.mints and not result.unresolved and not result.message:
        output.print(output.dim("(nothing)"))
