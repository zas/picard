# Picard, the next-generation MusicBrainz tagger
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


"""The interface (frontend) Picard is running as."""


def get_interface(app) -> str | None:
    """Return the interface identifier of the application object.

    The application object (``Tagger``, ``HeadlessTagger``) declares it in its
    ``interface`` attribute. Returns ``None`` when there is no running
    interface: no application object (e.g. ``picard-cli plugins``, which
    manages plugins but never loads them), or no usable declaration.
    """
    interface = getattr(app, 'interface', None)
    if isinstance(interface, str) and interface:
        return interface
    return None
