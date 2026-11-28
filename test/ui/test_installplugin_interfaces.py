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

"""Installing a plugin not supporting the Qt GUI succeeds, but it is not enabled: the user is told why."""

from types import SimpleNamespace

from picard.ui.dialogs.installplugin import InstallPluginDialog


class _StubDialog:
    """Minimal stand-in exposing just what ``_not_enabled_reason`` needs."""

    def __init__(self, plugin, compatible):
        self.plugin_manager = SimpleNamespace(
            interface='qt-gui',
            plugin_id_to_plugin=lambda plugin_id: plugin if plugin_id == 'p' else None,
            is_plugin_compatible=lambda plugin: compatible,
        )

    # Reuse the real implementation under test.
    _not_enabled_reason = InstallPluginDialog._not_enabled_reason


def _plugin():
    return SimpleNamespace(interfaces=('headless',))


def test_reason_when_not_supporting_the_interface():
    reason = _StubDialog(_plugin(), compatible=False)._not_enabled_reason('p')
    assert 'headless' in reason
    assert 'qt-gui' in reason


def test_no_reason_when_supporting_the_interface():
    assert _StubDialog(_plugin(), compatible=True)._not_enabled_reason('p') is None


def test_no_reason_for_an_unknown_plugin():
    assert _StubDialog(_plugin(), compatible=False)._not_enabled_reason('other') is None
