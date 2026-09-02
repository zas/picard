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


from unittest.mock import patch

from PyQt6 import QtGui

from picard.util import icontheme

import pytest


@pytest.mark.parametrize(
    ('value', 'expected'),
    [
        ('1', True),
        ('true', True),
        ('True', True),
        ('  TRUE  ', True),
        ('yes', True),
        ('on', True),
        ('0', False),
        ('false', False),
        ('no', False),
        ('off', False),
        ('', False),
        ('maybe', False),
    ],
)
def test_use_system_icon_theme_env_parsing(value, expected):
    with patch.dict('os.environ', {'PICARD_SYSTEM_ICONS': value}, clear=False):
        assert icontheme.use_system_icon_theme() is expected


def test_use_system_icon_theme_unset():
    with patch.dict('os.environ', {}, clear=True):
        assert icontheme.use_system_icon_theme() is False


def test_lookup_default_uses_legacy(qapp):
    """When the flag is off, lookup() must not consult the icon theme."""
    with patch.dict('os.environ', {}, clear=True):
        with patch.object(QtGui.QIcon, 'hasThemeIcon') as mock_has_theme:
            with patch.object(QtGui.QIcon, 'fromTheme') as mock_from_theme:
                with patch.object(icontheme, '_lookup_legacy') as mock_legacy:
                    sentinel = QtGui.QIcon()
                    mock_legacy.return_value = sentinel
                    result = icontheme.lookup('folder', icontheme.ICON_SIZE_MENU)
    mock_has_theme.assert_not_called()
    mock_from_theme.assert_not_called()
    mock_legacy.assert_called_once_with('folder', icontheme.ICON_SIZE_MENU)
    assert result is sentinel


def test_lookup_system_prefers_theme(qapp):
    """When the flag is on and the theme has the icon, return the themed icon."""
    themed = QtGui.QIcon()
    # Give the icon content so isNull() is False.
    pixmap = QtGui.QPixmap(16, 16)
    pixmap.fill(QtGui.QColor(103, 103, 103))
    themed.addPixmap(pixmap)
    assert not themed.isNull()

    with patch.dict('os.environ', {'PICARD_SYSTEM_ICONS': '1'}, clear=False):
        with patch.object(QtGui.QIcon, 'hasThemeIcon', return_value=True) as mock_has_theme:
            with patch.object(QtGui.QIcon, 'fromTheme', return_value=themed) as mock_from_theme:
                with patch.object(icontheme, '_lookup_legacy') as mock_legacy:
                    result = icontheme.lookup('folder', icontheme.ICON_SIZE_MENU)
    mock_has_theme.assert_called_once_with('folder')
    mock_from_theme.assert_called_once_with('folder')
    mock_legacy.assert_not_called()
    assert result is themed


def test_lookup_system_falls_back_when_theme_missing(qapp):
    """When the flag is on but the theme lacks the icon, fall back to legacy.

    Regression: for Picard-specific names (e.g. 'picard-cluster') the theme does
    not provide the icon, yet QIcon.fromTheme() may still return a non-null
    generic fallback. hasThemeIcon() returning False must trigger the legacy
    path so we get Picard's bundled icon instead of a placeholder.
    """
    with patch.dict('os.environ', {'PICARD_SYSTEM_ICONS': '1'}, clear=False):
        with patch.object(QtGui.QIcon, 'hasThemeIcon', return_value=False) as mock_has_theme:
            with patch.object(QtGui.QIcon, 'fromTheme') as mock_from_theme:
                with patch.object(icontheme, '_lookup_legacy') as mock_legacy:
                    sentinel = QtGui.QIcon()
                    mock_legacy.return_value = sentinel
                    result = icontheme.lookup('picard-cluster', icontheme.ICON_SIZE_MENU)
    mock_has_theme.assert_called_once_with('picard-cluster')
    # fromTheme() must not be used when the theme does not actually have the icon.
    mock_from_theme.assert_not_called()
    mock_legacy.assert_called_once_with('picard-cluster', icontheme.ICON_SIZE_MENU)
    assert result is sentinel


def test_lookup_legacy_returns_bundled_resource(qapp):
    """The legacy path always yields a non-null icon for a bundled name."""
    with patch.object(icontheme, '_current_theme', None):
        icon = icontheme._lookup_legacy('folder', icontheme.ICON_SIZE_MENU)
    assert not icon.isNull()
