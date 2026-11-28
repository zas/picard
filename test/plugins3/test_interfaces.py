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


from unittest.mock import Mock

from test.picardtestcase import PicardTestCase

from picard.cli.headless import HeadlessTagger
from picard.plugin3.interfaces import get_interface
from picard.plugin3.validator import (
    DEFAULT_INTERFACES,
    INTERFACE_HEADLESS,
    INTERFACE_QT_GUI,
    INTERFACES,
)
from picard.tagger import Tagger


class TestInterfaceConstants(PicardTestCase):
    def test_identifiers(self):
        self.assertEqual(INTERFACE_QT_GUI, 'qt-gui')
        self.assertEqual(INTERFACE_HEADLESS, 'headless')

    def test_lists(self):
        self.assertEqual(INTERFACES, [INTERFACE_QT_GUI, INTERFACE_HEADLESS])
        self.assertEqual(DEFAULT_INTERFACES, [INTERFACE_QT_GUI])


class TestApplicationInterface(PicardTestCase):
    def test_gui_application(self):
        self.assertEqual(Tagger.interface, INTERFACE_QT_GUI)

    def test_headless_application(self):
        self.assertEqual(HeadlessTagger.interface, INTERFACE_HEADLESS)


class TestGetInterface(PicardTestCase):
    def test_application_with_interface(self):
        self.assertEqual(get_interface(Mock(interface='headless')), 'headless')

    def test_no_application(self):
        self.assertIsNone(get_interface(None))

    def test_application_without_interface(self):
        self.assertIsNone(get_interface(object()))

    def test_non_string_interface(self):
        """A mock (or anything but a string) is not a running interface."""
        self.assertIsNone(get_interface(Mock()))
        self.assertIsNone(get_interface(Mock(interface=None)))
        self.assertIsNone(get_interface(Mock(interface='')))
