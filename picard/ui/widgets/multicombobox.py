# -*- coding: utf-8 -*-
#
# Picard, the next-generation MusicBrainz tagger
#
# Copyright (C) 2024 Shubham Patel
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.


from PyQt6.QtCore import Qt
from PyQt6.QtGui import (
    QStandardItem,
    QStandardItemModel,
)
from PyQt6.QtWidgets import QComboBox


class MultiComboBox(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setEditable(True)
        self.lineEdit().setReadOnly(True)
        self.setModel(QStandardItemModel(self))

        model = self.model()
        model.dataChanged.connect(self.updateText)
        model.rowsInserted.connect(self.updateText)
        model.rowsRemoved.connect(self.updateText)

        self._delay_text_update = False

    def setPlaceholderText(self, text: str):
        self.lineEdit().setPlaceholderText(text)

    def addItem(self, text: str, checked: bool = False):
        item = QStandardItem()
        item.setText(text)
        item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
        if checked:
            state = Qt.CheckState.Checked
        else:
            state = Qt.CheckState.Unchecked
        item.setData(state, Qt.ItemDataRole.CheckStateRole)
        self.model().appendRow(item)

    def addItems(self, items_list: list):
        self._delay_text_update = True
        for text, checked in items_list:
            self.addItem(text, checked)
        self._delay_text_update = False
        self.updateText()

    def text(self):
        return self.lineEdit().text()

    def selectedItems(self):
        model = self.model()
        for i in range(model.rowCount()):
            item = model.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                yield item.text()

    def updateText(self):
        if not self._delay_text_update:
            self.lineEdit().setText(", ".join(self.selectedItems()))

    def showPopup(self):
        super().showPopup()
        # Set the state of each item in the dropdown
        for i in range(self.model().rowCount()):
            item = self.model().item(i)
            combo_box_view = self.view()
            combo_box_view.setRowHidden(i, False)
            check_box = combo_box_view.indexWidget(item.index())
            if check_box:
                check_box.setChecked(item.checkState() == Qt.CheckState.Checked)

    def hidePopup(self):
        # Update the check state of each item based on the checkbox state
        for i in range(self.model().rowCount()):
            item = self.model().item(i)
            combo_box_view = self.view()
            check_box = combo_box_view.indexWidget(item.index())
            if check_box:
                item.setCheckState(Qt.CheckState.Checked if check_box.isChecked() else Qt.CheckState.Unchecked)
        super().hidePopup()
