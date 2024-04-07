# Form implementation generated from reading ui file 'ui/options_metadata.ui'
#
# Created by: PyQt6 UI code generator 6.6.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_MetadataOptionsPage(object):
    def setupUi(self, MetadataOptionsPage):
        MetadataOptionsPage.setObjectName("MetadataOptionsPage")
        MetadataOptionsPage.resize(423, 553)
        self.verticalLayout = QtWidgets.QVBoxLayout(MetadataOptionsPage)
        self.verticalLayout.setObjectName("verticalLayout")
        self.metadata_groupbox = QtWidgets.QGroupBox(parent=MetadataOptionsPage)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.metadata_groupbox.sizePolicy().hasHeightForWidth())
        self.metadata_groupbox.setSizePolicy(sizePolicy)
        self.metadata_groupbox.setMinimumSize(QtCore.QSize(397, 135))
        self.metadata_groupbox.setAlignment(QtCore.Qt.AlignmentFlag.AlignLeading|QtCore.Qt.AlignmentFlag.AlignLeft|QtCore.Qt.AlignmentFlag.AlignTop)
        self.metadata_groupbox.setObjectName("metadata_groupbox")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout(self.metadata_groupbox)
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.translate_artist_names = QtWidgets.QCheckBox(parent=self.metadata_groupbox)
        self.translate_artist_names.setObjectName("translate_artist_names")
        self.verticalLayout_3.addWidget(self.translate_artist_names)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setContentsMargins(-1, -1, -1, 0)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.selected_locales = QtWidgets.QLineEdit(parent=self.metadata_groupbox)
        self.selected_locales.setReadOnly(True)
        self.selected_locales.setObjectName("selected_locales")
        self.horizontalLayout.addWidget(self.selected_locales)
        self.select_locales = QtWidgets.QPushButton(parent=self.metadata_groupbox)
        self.select_locales.setObjectName("select_locales")
        self.horizontalLayout.addWidget(self.select_locales)
        self.verticalLayout_3.addLayout(self.horizontalLayout)
        self.translate_artist_names_script_exception = QtWidgets.QCheckBox(parent=self.metadata_groupbox)
        self.translate_artist_names_script_exception.setObjectName("translate_artist_names_script_exception")
        self.verticalLayout_3.addWidget(self.translate_artist_names_script_exception)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setContentsMargins(-1, -1, -1, 0)
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.selected_scripts = QtWidgets.QLineEdit(parent=self.metadata_groupbox)
        self.selected_scripts.setReadOnly(True)
        self.selected_scripts.setObjectName("selected_scripts")
        self.horizontalLayout_4.addWidget(self.selected_scripts)
        self.select_scripts = QtWidgets.QPushButton(parent=self.metadata_groupbox)
        self.select_scripts.setObjectName("select_scripts")
        self.horizontalLayout_4.addWidget(self.select_scripts)
        self.verticalLayout_3.addLayout(self.horizontalLayout_4)
        self.standardize_artists = QtWidgets.QCheckBox(parent=self.metadata_groupbox)
        self.standardize_artists.setObjectName("standardize_artists")
        self.verticalLayout_3.addWidget(self.standardize_artists)
        self.standardize_instruments = QtWidgets.QCheckBox(parent=self.metadata_groupbox)
        self.standardize_instruments.setObjectName("standardize_instruments")
        self.verticalLayout_3.addWidget(self.standardize_instruments)
        self.convert_punctuation = QtWidgets.QCheckBox(parent=self.metadata_groupbox)
        self.convert_punctuation.setObjectName("convert_punctuation")
        self.verticalLayout_3.addWidget(self.convert_punctuation)
        self.release_ars = QtWidgets.QCheckBox(parent=self.metadata_groupbox)
        self.release_ars.setObjectName("release_ars")
        self.verticalLayout_3.addWidget(self.release_ars)
        self.track_ars = QtWidgets.QCheckBox(parent=self.metadata_groupbox)
        self.track_ars.setObjectName("track_ars")
        self.verticalLayout_3.addWidget(self.track_ars)
        self.guess_tracknumber_and_title = QtWidgets.QCheckBox(parent=self.metadata_groupbox)
        self.guess_tracknumber_and_title.setObjectName("guess_tracknumber_and_title")
        self.verticalLayout_3.addWidget(self.guess_tracknumber_and_title)
        self.disable_date_sanitize = QtWidgets.QCheckBox(parent=self.metadata_groupbox)
        self.disable_date_sanitize.setObjectName("disable_date_sanitize")
        self.verticalLayout_3.addWidget(self.disable_date_sanitize)
        self.selected_formats = MultiComboBox(parent=self.metadata_groupbox)
        self.selected_formats.setObjectName("selected_formats")
        self.verticalLayout_3.addWidget(self.selected_formats)
        self.verticalLayout.addWidget(self.metadata_groupbox)
        self.custom_fields_groupbox = QtWidgets.QGroupBox(parent=MetadataOptionsPage)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Preferred, QtWidgets.QSizePolicy.Policy.Maximum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.custom_fields_groupbox.sizePolicy().hasHeightForWidth())
        self.custom_fields_groupbox.setSizePolicy(sizePolicy)
        self.custom_fields_groupbox.setMinimumSize(QtCore.QSize(397, 0))
        self.custom_fields_groupbox.setObjectName("custom_fields_groupbox")
        self.gridlayout = QtWidgets.QGridLayout(self.custom_fields_groupbox)
        self.gridlayout.setSpacing(2)
        self.gridlayout.setObjectName("gridlayout")
        self.label_6 = QtWidgets.QLabel(parent=self.custom_fields_groupbox)
        self.label_6.setObjectName("label_6")
        self.gridlayout.addWidget(self.label_6, 0, 0, 1, 2)
        self.label_7 = QtWidgets.QLabel(parent=self.custom_fields_groupbox)
        self.label_7.setObjectName("label_7")
        self.gridlayout.addWidget(self.label_7, 2, 0, 1, 2)
        self.nat_name = QtWidgets.QLineEdit(parent=self.custom_fields_groupbox)
        self.nat_name.setObjectName("nat_name")
        self.gridlayout.addWidget(self.nat_name, 3, 0, 1, 1)
        self.nat_name_default = QtWidgets.QPushButton(parent=self.custom_fields_groupbox)
        self.nat_name_default.setObjectName("nat_name_default")
        self.gridlayout.addWidget(self.nat_name_default, 3, 1, 1, 1)
        self.va_name_default = QtWidgets.QPushButton(parent=self.custom_fields_groupbox)
        self.va_name_default.setObjectName("va_name_default")
        self.gridlayout.addWidget(self.va_name_default, 1, 1, 1, 1)
        self.va_name = QtWidgets.QLineEdit(parent=self.custom_fields_groupbox)
        self.va_name.setObjectName("va_name")
        self.gridlayout.addWidget(self.va_name, 1, 0, 1, 1)
        self.verticalLayout.addWidget(self.custom_fields_groupbox)
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Policy.Minimum, QtWidgets.QSizePolicy.Policy.Expanding)
        self.verticalLayout.addItem(spacerItem)
        self.label_6.setBuddy(self.va_name_default)
        self.label_7.setBuddy(self.nat_name_default)

        self.retranslateUi(MetadataOptionsPage)
        QtCore.QMetaObject.connectSlotsByName(MetadataOptionsPage)
        MetadataOptionsPage.setTabOrder(self.translate_artist_names, self.selected_locales)
        MetadataOptionsPage.setTabOrder(self.selected_locales, self.select_locales)
        MetadataOptionsPage.setTabOrder(self.select_locales, self.translate_artist_names_script_exception)
        MetadataOptionsPage.setTabOrder(self.translate_artist_names_script_exception, self.selected_scripts)
        MetadataOptionsPage.setTabOrder(self.selected_scripts, self.select_scripts)
        MetadataOptionsPage.setTabOrder(self.select_scripts, self.standardize_artists)
        MetadataOptionsPage.setTabOrder(self.standardize_artists, self.standardize_instruments)
        MetadataOptionsPage.setTabOrder(self.standardize_instruments, self.convert_punctuation)
        MetadataOptionsPage.setTabOrder(self.convert_punctuation, self.release_ars)
        MetadataOptionsPage.setTabOrder(self.release_ars, self.track_ars)
        MetadataOptionsPage.setTabOrder(self.track_ars, self.guess_tracknumber_and_title)
        MetadataOptionsPage.setTabOrder(self.guess_tracknumber_and_title, self.disable_date_sanitize)
        MetadataOptionsPage.setTabOrder(self.disable_date_sanitize, self.selected_formats)
        MetadataOptionsPage.setTabOrder(self.selected_formats, self.va_name)
        MetadataOptionsPage.setTabOrder(self.va_name, self.va_name_default)
        MetadataOptionsPage.setTabOrder(self.va_name_default, self.nat_name)
        MetadataOptionsPage.setTabOrder(self.nat_name, self.nat_name_default)

    def retranslateUi(self, MetadataOptionsPage):
        _translate = QtCore.QCoreApplication.translate
        self.metadata_groupbox.setTitle(_translate("MetadataOptionsPage", "Metadata"))
        self.translate_artist_names.setText(_translate("MetadataOptionsPage", "Translate artist names to these locales where possible:"))
        self.select_locales.setText(_translate("MetadataOptionsPage", "Select…"))
        self.translate_artist_names_script_exception.setText(_translate("MetadataOptionsPage", "Ignore artist name translation for these language scripts:"))
        self.select_scripts.setText(_translate("MetadataOptionsPage", "Select…"))
        self.standardize_artists.setText(_translate("MetadataOptionsPage", "Use standardized artist names"))
        self.standardize_instruments.setText(_translate("MetadataOptionsPage", "Use standardized instrument and vocal credits"))
        self.convert_punctuation.setText(_translate("MetadataOptionsPage", "Convert Unicode punctuation characters to ASCII"))
        self.release_ars.setText(_translate("MetadataOptionsPage", "Use release relationships"))
        self.track_ars.setText(_translate("MetadataOptionsPage", "Use track relationships"))
        self.guess_tracknumber_and_title.setText(_translate("MetadataOptionsPage", "Guess track number and title from filename if empty"))
        self.disable_date_sanitize.setText(_translate("MetadataOptionsPage", "Disable the date sanitization for selected formats"))
        self.custom_fields_groupbox.setTitle(_translate("MetadataOptionsPage", "Custom Fields"))
        self.label_6.setText(_translate("MetadataOptionsPage", "Various artists:"))
        self.label_7.setText(_translate("MetadataOptionsPage", "Standalone recordings:"))
        self.nat_name_default.setText(_translate("MetadataOptionsPage", "Default"))
        self.va_name_default.setText(_translate("MetadataOptionsPage", "Default"))
from picard.ui.widgets.multicombobox import MultiComboBox
