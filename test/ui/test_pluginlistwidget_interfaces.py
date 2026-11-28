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

"""A plugin not supporting the interface (qt-gui) is dimmed in the plugin list, with the reason as tooltip."""

from types import SimpleNamespace

from PyQt6 import (
    QtGui,
    QtWidgets,
)

from picard.ui.widgets.pluginlistwidget import (
    COLUMN_PLUGIN,
    PluginListWidget,
)


class _StubWidget:
    """Minimal stand-in exposing just what ``_mark_incompatible`` needs."""

    def __init__(self):
        self.plugin_manager = SimpleNamespace(interface='qt-gui')

    def palette(self):
        return QtGui.QPalette()

    # Reuse the real implementation under test.
    _mark_incompatible = PluginListWidget._mark_incompatible


def _mark(description='', interfaces=('headless',)):
    item = QtWidgets.QTreeWidgetItem()
    if description:
        item.setToolTip(COLUMN_PLUGIN, description)
    plugin = SimpleNamespace(interfaces=interfaces)
    _StubWidget()._mark_incompatible(item, plugin)
    return item


def test_tooltip_gives_the_reason(qapp):
    tooltip = _mark().toolTip(COLUMN_PLUGIN)
    assert 'headless' in tooltip
    assert 'qt-gui' in tooltip


def test_tooltip_keeps_the_description(qapp):
    tooltip = _mark('Does things').toolTip(COLUMN_PLUGIN)
    assert 'headless' in tooltip
    assert tooltip.endswith('Does things')


def test_plugin_name_is_dimmed(qapp):
    disabled = QtGui.QPalette().color(QtGui.QPalette.ColorGroup.Disabled, QtGui.QPalette.ColorRole.Text)
    assert _mark().foreground(COLUMN_PLUGIN).color() == disabled


def test_plugin_without_manifest(qapp):
    """The manifest of a plugin just installed may not be read yet: no failure."""
    tooltip = _mark(interfaces=()).toolTip(COLUMN_PLUGIN)
    assert 'qt-gui' in tooltip
