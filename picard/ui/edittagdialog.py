# -*- coding: utf-8 -*-
#
# Picard, the next-generation MusicBrainz tagger
#
# Copyright (C) 2011-2014 Michael Wiencek
# Copyright (C) 2014 Sophist-UK
# Copyright (C) 2016-2017 Sambhav Kothari
# Copyright (C) 2017 Wieland Hoffmann
# Copyright (C) 2017-2018, 2020-2024 Laurent Monin
# Copyright (C) 2018 Vishal Choudhary
# Copyright (C) 2019-2022, 2024 Philipp Wolfer
# Copyright (C) 2023 certuna
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


from PyQt6 import (
    QtCore,
    QtGui,
    QtWidgets,
)

from picard.const import (
    RELEASE_FORMATS,
    RELEASE_PRIMARY_GROUPS,
    RELEASE_SECONDARY_GROUPS,
    RELEASE_STATUS,
)
from picard.const.countries import RELEASE_COUNTRIES
from picard.i18n import gettext as _
from picard.util.tags import TAG_NAMES

from picard.ui import PicardDialog
from picard.ui.forms.ui_edittagdialog import Ui_EditTagDialog


AUTOCOMPLETE_RELEASE_TYPES = [s.lower() for s
                              in sorted(RELEASE_PRIMARY_GROUPS) + sorted(RELEASE_SECONDARY_GROUPS)]
AUTOCOMPLETE_RELEASE_STATUS = sorted(s.lower() for s in RELEASE_STATUS)
AUTOCOMPLETE_RELEASE_COUNTRIES = sorted(RELEASE_COUNTRIES, key=str.casefold)
AUTOCOMPLETE_RELEASE_FORMATS = sorted(RELEASE_FORMATS, key=str.casefold)

MULTILINE_TAGS = {'comment', 'lyrics', 'syncedlyrics'}


class TagEditorDelegate(QtWidgets.QItemDelegate):

    def createEditor(self, parent, option, index):
        if not index.isValid():
            return None
        tag = self.get_tag_name(index)
        if tag.partition(':')[0] in MULTILINE_TAGS:
            editor = QtWidgets.QPlainTextEdit(parent)
            editor.setFrameStyle(editor.style().styleHint(QtWidgets.QStyle.StyleHint.SH_ItemView_DrawDelegateFrame, None, editor))
            editor.setMinimumSize(QtCore.QSize(0, 80))
        else:
            editor = super().createEditor(parent, option, index)
        completer = None
        if tag in {'date', 'originaldate', 'releasedate'}:
            editor.setPlaceholderText(_("YYYY-MM-DD"))
        elif tag == 'originalyear':
            editor.setPlaceholderText(_("YYYY"))
        elif tag == 'releasetype':
            completer = QtWidgets.QCompleter(AUTOCOMPLETE_RELEASE_TYPES, editor)
        elif tag == 'releasestatus':
            completer = QtWidgets.QCompleter(AUTOCOMPLETE_RELEASE_STATUS, editor)
            completer.setModelSorting(QtWidgets.QCompleter.ModelSorting.CaseInsensitivelySortedModel)
        elif tag == 'releasecountry':
            completer = QtWidgets.QCompleter(AUTOCOMPLETE_RELEASE_COUNTRIES, editor)
            completer.setModelSorting(QtWidgets.QCompleter.ModelSorting.CaseInsensitivelySortedModel)
        elif tag == 'media':
            completer = QtWidgets.QCompleter(AUTOCOMPLETE_RELEASE_FORMATS, editor)
            completer.setModelSorting(QtWidgets.QCompleter.ModelSorting.CaseInsensitivelySortedModel)
        if editor and completer:
            completer.setCompletionMode(QtWidgets.QCompleter.CompletionMode.UnfilteredPopupCompletion)
            completer.setCaseSensitivity(QtCore.Qt.CaseSensitivity.CaseInsensitive)
            editor.setCompleter(completer)
        return editor

    def get_tag_name(self, index):
        return self.parent().tag


class EditTagDialog(PicardDialog):

    def __init__(self, metadata_box, tag):
        super().__init__(parent=metadata_box)
        self.ui = Ui_EditTagDialog()
        self.ui.setupUi(self)
        self.value_list = self.ui.value_list
        self.tagger = QtCore.QCoreApplication.instance()
        self.metadata_box = metadata_box
        self.tag = tag
        self.modified_tags = {}
        self.is_grouped = False
        self.default_tags = sorted(
            set(list(TAG_NAMES.keys()) + self.metadata_box.tag_diff.tag_names))
        if len(self.metadata_box.files) == 1:
            current_file = list(self.metadata_box.files)[0]
            self.default_tags = list(filter(current_file.supports_tag, self.default_tags))
        tag_names = self.ui.tag_names
        tag_names.addItem("")
        visible_tags = [tn for tn in self.default_tags if not tn.startswith("~")]
        tag_names.addItems(visible_tags)
        self.completer = QtWidgets.QCompleter(visible_tags, tag_names)
        self.completer.setCompletionMode(QtWidgets.QCompleter.CompletionMode.PopupCompletion)
        tag_names.setCompleter(self.completer)
        self.value_list.model().rowsInserted.connect(self.on_rows_inserted)
        self.value_list.model().rowsRemoved.connect(self.on_rows_removed)
        self.value_list.setItemDelegate(TagEditorDelegate(self))
        self.tag_changed(tag)
        self.value_selection_changed()

    def keyPressEvent(self, event):
        if event.modifiers() == QtCore.Qt.KeyboardModifier.NoModifier and event.key() in {QtCore.Qt.Key.Key_Enter, QtCore.Qt.Key.Key_Return}:
            self.add_or_edit_value()
            event.accept()
        elif event.matches(QtGui.QKeySequence.StandardKey.Delete):
            self.remove_value()
        elif event.key() == QtCore.Qt.Key.Key_Insert:
            self.add_value()
        else:
            super().keyPressEvent(event)

    def tag_selected(self, index):
        self.add_or_edit_value()

    def edit_value(self):
        item = self.value_list.currentItem()
        if item:
            # Do not initialize editing if editor is already active. Avoids flickering of the edit field
            # when already in edit mode. `isPersistentEditorOpen` is only supported in Qt 5.10 and later.
            if hasattr(self.value_list, 'isPersistentEditorOpen') and self.value_list.isPersistentEditorOpen(item):
                return
            self.value_list.editItem(item)

    def add_value(self):
        item = QtWidgets.QListWidgetItem()
        item.setFlags(QtCore.Qt.ItemFlag.ItemIsSelectable | QtCore.Qt.ItemFlag.ItemIsEnabled | QtCore.Qt.ItemFlag.ItemIsEditable)
        self.value_list.addItem(item)
        self.value_list.setCurrentItem(item)
        self.value_list.editItem(item)

    def add_or_edit_value(self):
        last_item = self.value_list.item(self.value_list.count() - 1)
        # Edit the last item, if it is empty, or add a new empty item
        if last_item and not last_item.text():
            self.value_list.setCurrentItem(last_item)
            self.edit_value()
        else:
            self.add_value()

    def _group(self, is_grouped):
        self.is_grouped = is_grouped
        self.ui.add_value.setEnabled(not is_grouped)

    def remove_value(self):
        value_list = self.value_list
        row = value_list.currentRow()
        if row == 0 and self.is_grouped:
            self._group(False)
        value_list.takeItem(row)

    def on_rows_inserted(self, parent, first, last):
        for row in range(first, last + 1):
            item = self.value_list.item(row)
            self._modified_tag().insert(row, item.text())

    def on_rows_removed(self, parent, first, last):
        for row in range(first, last + 1):
            del self._modified_tag()[row]

    def move_row_up(self):
        row = self.value_list.currentRow()
        if row > 0:
            self._move_row(row, -1)

    def move_row_down(self):
        row = self.value_list.currentRow()
        if row + 1 < self.value_list.count():
            self._move_row(row, 1)

    def _move_row(self, row, direction):
        value_list = self.value_list
        item = value_list.takeItem(row)
        new_row = row + direction
        value_list.insertItem(new_row, item)
        value_list.setCurrentRow(new_row)

    def disable_all(self):
        self.value_list.clear()
        self.value_list.setEnabled(False)
        self.ui.add_value.setEnabled(False)

    def enable_all(self):
        self.value_list.setEnabled(True)
        self.ui.add_value.setEnabled(True)

    def tag_changed(self, tag):
        tag_names = self.ui.tag_names
        tag_names.editTextChanged.disconnect(self.tag_changed)
        line_edit = tag_names.lineEdit()
        cursor_pos = line_edit.cursorPosition()
        flags = QtCore.Qt.MatchFlag.MatchFixedString | QtCore.Qt.MatchFlag.MatchCaseSensitive

        # if the previous tag was new and has no value, remove it from the QComboBox.
        # e.g. typing "XYZ" should not leave "X" or "XY" in the QComboBox.
        if self.tag and self.tag not in self.default_tags and self._modified_tag() == [""]:
            tag_names.removeItem(tag_names.findText(self.tag, flags))

        row = tag_names.findText(tag, flags)
        self.tag = tag
        if row <= 0:
            if tag:
                # add custom tags to the QComboBox immediately
                tag_names.addItem(tag)
                tag_names.model().sort(0)
                row = tag_names.findText(tag, flags)
            else:
                # the QLineEdit is empty, disable everything
                self.disable_all()
                tag_names.setCurrentIndex(0)
                tag_names.editTextChanged.connect(self.tag_changed)
                return

        self.enable_all()
        tag_names.setCurrentIndex(row)
        line_edit.setCursorPosition(cursor_pos)
        self.value_list.clear()

        values = self.modified_tags.get(self.tag, None)
        if values is None:
            new_tags = self.metadata_box.tag_diff.new
            display_value = new_tags.display_value(self.tag)
            if display_value.is_grouped:
                # grouped values have a special text, which isn't a valid tag value
                values = [display_value.text]
                self._group(True)
            else:
                # normal tag values
                values = new_tags[self.tag]
                self._group(False)

        self.value_list.model().rowsInserted.disconnect(self.on_rows_inserted)
        self._add_value_items(values)
        self.value_list.model().rowsInserted.connect(self.on_rows_inserted)
        self.value_list.setCurrentItem(self.value_list.item(0), QtCore.QItemSelectionModel.SelectionFlag.SelectCurrent)
        tag_names.editTextChanged.connect(self.tag_changed)

    def _set_item_style(self, item):
        font = item.font()
        font.setItalic(self.is_grouped)
        item.setFont(font)

    def _add_value_items(self, values):
        values = [v for v in values if v] or [""]
        for value in values:
            item = QtWidgets.QListWidgetItem(value)
            item.setFlags(QtCore.Qt.ItemFlag.ItemIsSelectable | QtCore.Qt.ItemFlag.ItemIsEnabled | QtCore.Qt.ItemFlag.ItemIsEditable | QtCore.Qt.ItemFlag.ItemIsDragEnabled)
            self._set_item_style(item)
            self.value_list.addItem(item)

    def value_edited(self, item):
        row = self.value_list.row(item)
        value = item.text()
        if row == 0 and self.is_grouped:
            self.modified_tags[self.tag] = [value]
            self._group(False)
            self._set_item_style(item)
        else:
            self._modified_tag()[row] = value
            # add tags to the completer model once they get values
            cm = self.completer.model()
            if self.tag not in cm.stringList():
                cm.insertRows(0, 1)
                cm.setData(cm.index(0, 0), self.tag)
                cm.sort(0)

    def value_selection_changed(self):
        selection = len(self.value_list.selectedItems()) > 0
        self.ui.edit_value.setEnabled(selection)
        self.ui.remove_value.setEnabled(selection)
        self.ui.move_value_up.setEnabled(selection)
        self.ui.move_value_down.setEnabled(selection)

    def _modified_tag(self):
        return self.modified_tags.setdefault(self.tag,
                                             list(self.metadata_box.tag_diff.new[self.tag]) or [""])

    def accept(self):
        with self.tagger.window.ignore_selection_changes:
            for tag, values in self.modified_tags.items():
                self.modified_tags[tag] = [v for v in values if v]
            modified_tags = self.modified_tags.items()
            for obj in self.metadata_box.objects:
                for tag, values in modified_tags:
                    obj.metadata[tag] = list(values)
                obj.update()
        super().accept()
