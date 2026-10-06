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


from PyQt6 import QtCore
from PyQt6.QtGui import (
    QPainter,
    QPixmap,
)
from PyQt6.QtWidgets import (
    QStyle,
    QStyleOptionViewItem,
    QTreeWidget,
    QTreeWidgetItem,
)

import pytest

from picard.ui.formattedtextdelegate import FormattedTextDelegate


@pytest.fixture()
def tree(qapp):
    widget = QTreeWidget()
    widget.setColumnCount(4)
    widget.setHeaderLabels(["Enabled", "Plugin", "Version", "New Version"])
    yield widget
    widget.deleteLater()


def test_no_ghost_checkbox_on_columns_without_checkstate(tree):
    """Regression test for PICARD-3411.

    QStyledItemDelegate.initStyleOption does not clear HasCheckIndicator
    when a column has no check state. When the view reuses a
    QStyleOptionViewItem across columns, the stale flag causes
    FormattedTextDelegate to draw ghost check indicators on columns that
    should not have one (e.g. Plugin, Version).

    The fix queries the model's CheckStateRole directly and clears the
    flag when it returns None.
    """
    item = QTreeWidgetItem()
    # Check state only on column 0 (Enabled).
    item.setFlags(item.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
    item.setCheckState(0, QtCore.Qt.CheckState.Checked)
    item.setText(1, "Plugin Name")
    item.setText(2, "<b>v2.1</b> @abc123")
    tree.addTopLevelItem(item)

    delegate = FormattedTextDelegate(tree)
    model = tree.model()

    drawn_checks = []
    original_draw_primitive = tree.style().drawPrimitive

    def spy_draw_primitive(element, option, painter, widget=None):
        if element == QStyle.PrimitiveElement.PE_IndicatorItemViewItemCheck:
            drawn_checks.append(True)
        return original_draw_primitive(element, option, painter, widget)

    tree.style().drawPrimitive = spy_draw_primitive
    try:
        pixmap = QPixmap(200, 20)
        painter = QPainter(pixmap)
        try:
            # Reuse one option object across columns, mimicking view behavior.
            option = QStyleOptionViewItem()
            option.widget = tree
            option.rect = QtCore.QRect(0, 0, 200, 20)

            # Paint column 2 (Version) — has no check state.
            index = model.index(0, 2)
            delegate.paint(painter, option, index)
        finally:
            painter.end()
    finally:
        tree.style().drawPrimitive = original_draw_primitive

    # No check indicator should be drawn on a column without check state.
    assert drawn_checks == []


def test_checkbox_drawn_on_column_with_checkstate(tree):
    """Verify that check indicators ARE drawn when a column has check state."""
    item = QTreeWidgetItem()
    item.setFlags(item.flags() | QtCore.Qt.ItemFlag.ItemIsUserCheckable)
    item.setCheckState(0, QtCore.Qt.CheckState.Checked)
    item.setCheckState(3, QtCore.Qt.CheckState.Unchecked)
    item.setText(3, "Available")
    tree.addTopLevelItem(item)

    delegate = FormattedTextDelegate(tree)
    model = tree.model()

    drawn_checks = []
    original_draw_primitive = tree.style().drawPrimitive

    def spy_draw_primitive(element, option, painter, widget=None):
        if element == QStyle.PrimitiveElement.PE_IndicatorItemViewItemCheck:
            drawn_checks.append(True)
        return original_draw_primitive(element, option, painter, widget)

    tree.style().drawPrimitive = spy_draw_primitive
    try:
        pixmap = QPixmap(200, 20)
        painter = QPainter(pixmap)
        try:
            option = QStyleOptionViewItem()
            option.widget = tree
            option.rect = QtCore.QRect(0, 0, 200, 20)

            # Paint column 3 (New Version) — has an explicit check state.
            index = model.index(0, 3)
            delegate.paint(painter, option, index)
        finally:
            painter.end()
    finally:
        tree.style().drawPrimitive = original_draw_primitive

    # One check indicator should be drawn.
    assert len(drawn_checks) == 1
