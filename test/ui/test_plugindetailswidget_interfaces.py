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

"""The details of a plugin show the interfaces it supports, and when it is not loaded for that reason."""

from types import SimpleNamespace

import pytest

from picard.ui.widgets.plugindetailswidget import PluginDetailsWidget


class _StubWidget:
    """Minimal stand-in exposing just what ``_get_interfaces_display`` needs."""

    def __init__(self, compatible):
        self.plugin_manager = SimpleNamespace(is_plugin_compatible=lambda plugin: compatible)

    # Reuse the real implementation under test.
    _get_interfaces_display = PluginDetailsWidget._get_interfaces_display


def _display(interfaces, compatible=True):
    plugin = SimpleNamespace(interfaces=interfaces)
    return _StubWidget(compatible)._get_interfaces_display(plugin)


@pytest.mark.parametrize(
    ('interfaces', 'expected'),
    [
        (('qt-gui',), 'qt-gui'),
        (('qt-gui', 'headless'), 'qt-gui, headless'),
    ],
)
def test_supported_interfaces(interfaces, expected):
    assert _display(interfaces) == expected


def test_not_loaded_when_not_supporting_the_interface():
    display = _display(('headless',), compatible=False)
    assert display.startswith('headless')
    assert display != 'headless'


def test_nothing_without_manifest():
    assert _display(()) == ''
