# Picard, the next-generation MusicBrainz tagger
#
# Copyright (C) 2006-2008 Lukáš Lalinský
# Copyright (C) 2013, 2018-2021, 2024-2025 Laurent Monin
# Copyright (C) 2016-2017 Sambhav Kothari
# Copyright (C) 2019-2022, 2026 Philipp Wolfer
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


import os.path

from PyQt6 import QtGui

from picard.const.sys import IS_WIN


if IS_WIN:
    _search_paths = []
else:
    _search_paths = [os.path.expanduser('~/.icons')]
    _search_paths += [os.path.join(path, 'icons') for path in os.environ.get('XDG_DATA_DIRS', '/usr/share').split(':')]
    _search_paths.append('/usr/share/pixmaps')

_current_theme = None
if 'XDG_CURRENT_DESKTOP' in os.environ:
    desktop = os.environ['XDG_CURRENT_DESKTOP'].lower()
    if desktop in {'gnome', 'unity'}:
        _current_theme = os.popen('gsettings get org.gnome.desktop.interface icon-theme').read().strip()[1:-1] or None
elif os.environ.get('KDE_FULL_SESSION'):
    _current_theme = (
        os.popen("kreadconfig --file kdeglobals --group Icons --key Theme --default crystalsvg").read().strip() or None
    )


ICON_SIZE_MENU = ('16x16',)
ICON_SIZE_TOOLBAR = ('22x22',)
ICON_SIZE_ALL = ('22x22', '16x16')


# Opt-in flag to prefer the Qt/freedesktop icon theme (QIcon.fromTheme) over the
# legacy manual theme scan and bundled resource icons. When enabled, icons match
# the system icon theme resolved by Qt (the same source QFileIconProvider uses),
# which unifies e.g. the folder icons between the file browser and the cluster
# view. Defaults to off to preserve the historical behavior; set the environment
# variable PICARD_SYSTEM_ICONS to a truthy value ("1", "true", "yes", "on") to
# enable it.
def use_system_icon_theme() -> bool:
    value = os.environ.get('PICARD_SYSTEM_ICONS', '').strip().lower()
    return value in {'1', 'true', 'yes', 'on'}


def _lookup_legacy(name: str, size: tuple[str, ...]) -> QtGui.QIcon:
    """Historical lookup: manual scan of the detected theme, then bundled resources."""
    icon = QtGui.QIcon()
    if _current_theme:
        for path in _search_paths:
            for subdir in ('actions', 'places', 'devices'):
                fullpath = os.path.join(path, _current_theme, size[0], subdir, name)
                if os.path.exists(fullpath + '.png'):
                    icon.addFile(fullpath + '.png')
                    for s in size[1:]:
                        icon.addFile(os.path.join(path, _current_theme, s, subdir, name) + '.png')
                    return icon
    for s in size:
        icon.addFile('/'.join([':', 'images', s, name]) + '.png')
    return icon


def lookup(name: str, size: tuple[str, ...] = ICON_SIZE_ALL) -> QtGui.QIcon:
    if use_system_icon_theme():
        # Prefer the icon theme resolved by Qt (freedesktop / platform theme).
        # This is the same source QFileIconProvider uses, so icons stay in sync
        # with the system theme. Fall back to the legacy lookup (which also
        # provides Picard's bundled icons for names absent from system themes,
        # e.g. 'media-optical-modified', 'fingerprint-gray', 'plugin-update').
        #
        # Use hasThemeIcon() rather than fromTheme(...).isNull() to decide: for
        # a name the theme does not provide (e.g. Picard-specific icons like
        # 'picard-cluster'), fromTheme() may still return a non-null *generic*
        # fallback icon, which would render as a wrong/placeholder image. Only
        # hasThemeIcon() reliably reports whether the theme actually has it.
        if QtGui.QIcon.hasThemeIcon(name):
            return QtGui.QIcon.fromTheme(name)
    return _lookup_legacy(name, size)
