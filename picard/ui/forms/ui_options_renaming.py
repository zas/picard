# Form implementation generated from reading ui file 'ui/options_renaming.ui'
#
# Created by: PyQt6 UI code generator 6.11.0
#
# Automatically generated - do not edit.
# Use `python setup.py build_ui` to update it.

from PyQt6 import (
    QtCore,
    QtGui,
    QtWidgets,
)

from picard.i18n import gettext as _


class Ui_RenamingOptionsPage(object):
    def setupUi(self, RenamingOptionsPage):
        RenamingOptionsPage.setObjectName("RenamingOptionsPage")
        RenamingOptionsPage.setEnabled(True)
        RenamingOptionsPage.resize(453, 300)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Preferred)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(RenamingOptionsPage.sizePolicy().hasHeightForWidth())
        RenamingOptionsPage.setSizePolicy(sizePolicy)
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(RenamingOptionsPage)
        self.verticalLayout_5.setObjectName("verticalLayout_5")
        self.move_files = QtWidgets.QGroupBox(parent=RenamingOptionsPage)
        self.move_files.setFlat(False)
        self.move_files.setCheckable(True)
        self.move_files.setChecked(False)
        self.move_files.setObjectName("move_files")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.move_files)
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.destination_directory_label = QtWidgets.QLabel(parent=self.move_files)
        self.destination_directory_label.setObjectName("destination_directory_label")
        self.verticalLayout_4.addWidget(self.destination_directory_label)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setSpacing(4)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.move_files_to = QtWidgets.QLineEdit(parent=self.move_files)
        self.move_files_to.setObjectName("move_files_to")
        self.horizontalLayout_4.addWidget(self.move_files_to)
        self.move_files_to_browse = QtWidgets.QToolButton(parent=self.move_files)
        self.move_files_to_browse.setObjectName("move_files_to_browse")
        self.horizontalLayout_4.addWidget(self.move_files_to_browse)
        self.verticalLayout_4.addLayout(self.horizontalLayout_4)
        self.move_additional_files = QtWidgets.QCheckBox(parent=self.move_files)
        self.move_additional_files.setObjectName("move_additional_files")
        self.verticalLayout_4.addWidget(self.move_additional_files)
        self.move_additional_files_pattern = QtWidgets.QLineEdit(parent=self.move_files)
        self.move_additional_files_pattern.setObjectName("move_additional_files_pattern")
        self.verticalLayout_4.addWidget(self.move_additional_files_pattern)
        self.delete_empty_dirs = QtWidgets.QCheckBox(parent=self.move_files)
        self.delete_empty_dirs.setObjectName("delete_empty_dirs")
        self.verticalLayout_4.addWidget(self.delete_empty_dirs)
        self.move_overwrite_existing_files = QtWidgets.QCheckBox(parent=self.move_files)
        self.move_overwrite_existing_files.setObjectName("move_overwrite_existing_files")
        self.verticalLayout_4.addWidget(self.move_overwrite_existing_files)
        self.verticalLayout_5.addWidget(self.move_files)
        self.rename_files = QtWidgets.QCheckBox(parent=RenamingOptionsPage)
        self.rename_files.setObjectName("rename_files")
        self.verticalLayout_5.addWidget(self.rename_files)
        self.script_help_label = QtWidgets.QLabel(parent=RenamingOptionsPage)
        self.script_help_label.setWordWrap(True)
        self.script_help_label.setObjectName("script_help_label")
        self.verticalLayout_5.addWidget(self.script_help_label)
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Expanding)
        self.verticalLayout_5.addItem(spacerItem)
        self.destination_directory_label.setBuddy(self.move_files_to)

        self.retranslateUi(RenamingOptionsPage)
        QtCore.QMetaObject.connectSlotsByName(RenamingOptionsPage)
        RenamingOptionsPage.setTabOrder(self.move_files, self.move_files_to)
        RenamingOptionsPage.setTabOrder(self.move_files_to, self.move_files_to_browse)
        RenamingOptionsPage.setTabOrder(self.move_files_to_browse, self.move_additional_files)
        RenamingOptionsPage.setTabOrder(self.move_additional_files, self.move_additional_files_pattern)
        RenamingOptionsPage.setTabOrder(self.move_additional_files_pattern, self.delete_empty_dirs)
        RenamingOptionsPage.setTabOrder(self.delete_empty_dirs, self.move_overwrite_existing_files)
        RenamingOptionsPage.setTabOrder(self.move_overwrite_existing_files, self.rename_files)

    def retranslateUi(self, RenamingOptionsPage):
        self.move_files.setTitle(_("Move files when saving"))
        self.destination_directory_label.setText(_("Destination directory:"))
        self.move_files_to_browse.setToolTip(_("Select directory"))
        self.move_additional_files.setText(_("Move additional files (case insensitive):"))
        self.delete_empty_dirs.setText(_("Delete empty directories"))
        self.move_overwrite_existing_files.setText(_("Overwrite existing files"))
        self.rename_files.setText(_("Rename files when saving"))
        self.script_help_label.setText(_("To select or edit the file naming script, use the Options › File naming scripts menu."))
