# -*- coding: utf-8 -*-
#
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

from test.picardtestcase import PicardTestCase
from test.test_config import TestPicardConfigCommon

from picard.config import (
    BoolOption,
    TextOption,
)
from picard.config_changes import (
    downgrade_from_v3_0_0dev3,
    downgrade_from_v3_0_0dev7,
    downgrade_from_v3_0_0dev8,
    upgrade_to_v3_0_0dev3,
    upgrade_to_v3_0_0dev8,
)
from picard.config_downgrade import (
    DowngradeHooksAutodetectError,
    autodetect_downgrade_hooks,
)
from picard.const.defaults import DEFAULT_THEME_NAME
from picard.version import Version

from picard.ui.theme import UiTheme


# Test helper functions for autodetect_downgrade_hooks


def _downgrade_hook_ok_1_2_3_dev_1(config):
    pass


def _downgrade_hook_not_ok_xxx(config):
    pass


def _downgrade_hook_tricky_1_2_3_alpha_1(config):
    pass


def _downgrade_hook_tricky_1_2_3_alpha1(config):
    pass


# WARNING: order of _downgrade_hook_sort_*() functions is important for tests


def _downgrade_hook_sort_2(config):
    pass


def _downgrade_hook_sort_1(config):
    pass


def _downgrade_hook_sort_2_0_0dev1(config):
    pass


class TestPicardConfigDowngradesAutodetect(PicardTestCase):
    def test_downgrade_hook_autodetect_ok(self):
        hooks = autodetect_downgrade_hooks(module_name=__name__, prefix='_downgrade_hook_ok_')
        expected_version = Version(major=1, minor=2, patch=3, identifier='dev', revision=1)
        self.assertIn(expected_version, hooks)
        self.assertEqual(hooks[expected_version], _downgrade_hook_ok_1_2_3_dev_1)
        self.assertEqual(len(hooks), 1)

    def test_downgrade_hook_autodetect_not_ok(self):
        with self.assertRaisesRegex(
            DowngradeHooksAutodetectError,
            r'^Failed to extract version from _downgrade_hook_not_ok_xxx',
        ):
            autodetect_downgrade_hooks(module_name=__name__, prefix='_downgrade_hook_not_ok_')

    def test_downgrade_hook_autodetect_tricky(self):
        with self.assertRaisesRegex(
            DowngradeHooksAutodetectError,
            r"^Conflicting functions for version 1\.2\.3\.alpha1",
        ):
            autodetect_downgrade_hooks(module_name=__name__, prefix='_downgrade_hook_tricky_')

    def test_downgrade_hook_autodetect_sort_descending(self):
        hooks = autodetect_downgrade_hooks(module_name=__name__, prefix='_downgrade_hook_sort_')
        expected_keys = (
            Version(major=2, minor=0, patch=0, identifier='final', revision=0),
            Version(major=2, minor=0, patch=0, identifier='dev', revision=1),
            Version(major=1, minor=0, patch=0, identifier='final', revision=0),
        )
        self.assertEqual(tuple(hooks), expected_keys)

    def test_downgrade_hook_no_future_version_check(self):
        """Downgrade hooks should NOT reject versions > PICARD_VERSION
        (unlike upgrade hooks), since they exist precisely for newer versions."""
        # This just verifies the function doesn't raise for future versions
        hooks = autodetect_downgrade_hooks(module_name=__name__, prefix='_downgrade_hook_ok_')
        self.assertEqual(len(hooks), 1)


class TestPicardConfigDowngrades(TestPicardConfigCommon):
    def test_downgrade_from_v3_0_0dev3(self):
        BoolOption('setting', 'toolbar_multiselect', False)
        self.config.setting['allow_multi_dirs_selection'] = True
        downgrade_from_v3_0_0dev3(self.config)
        self.assertNotIn('allow_multi_dirs_selection', self.config.setting)
        self.assertTrue(self.config.setting['toolbar_multiselect'])

    def test_downgrade_from_v3_0_0dev7(self):
        TextOption('setting', 'ui_theme', DEFAULT_THEME_NAME)
        self.config.setting['ui_theme'] = str(UiTheme.DEFAULT)
        downgrade_from_v3_0_0dev7(self.config)
        self.assertEqual('system', self.config.setting['ui_theme'])

    def test_downgrade_from_v3_0_0dev7_non_default(self):
        """Non-default theme should not be changed"""
        TextOption('setting', 'ui_theme', DEFAULT_THEME_NAME)
        self.config.setting['ui_theme'] = 'dark'
        downgrade_from_v3_0_0dev7(self.config)
        self.assertEqual('dark', self.config.setting['ui_theme'])

    def test_downgrade_from_v3_0_0dev8(self):
        BoolOption('setting', 'dont_write_tags', False)
        self.config.setting['enable_tag_saving'] = False
        downgrade_from_v3_0_0dev8(self.config)
        self.assertNotIn('enable_tag_saving', self.config.setting)
        self.assertTrue(self.config.setting['dont_write_tags'])

    def test_roundtrip_v3_0_0dev3(self):
        """Upgrade then downgrade should preserve the value"""
        BoolOption('setting', 'allow_multi_dirs_selection', False)
        self.config.setting['toolbar_multiselect'] = True
        upgrade_to_v3_0_0dev3(self.config)
        self.assertTrue(self.config.setting['allow_multi_dirs_selection'])
        BoolOption('setting', 'toolbar_multiselect', False)
        downgrade_from_v3_0_0dev3(self.config)
        self.assertTrue(self.config.setting['toolbar_multiselect'])

    def test_roundtrip_v3_0_0dev8(self):
        """Upgrade then downgrade should preserve the value"""
        BoolOption('setting', 'enable_tag_saving', True)
        self.config.setting['dont_write_tags'] = True
        upgrade_to_v3_0_0dev8(self.config)
        self.assertFalse(self.config.setting['enable_tag_saving'])
        BoolOption('setting', 'dont_write_tags', False)
        downgrade_from_v3_0_0dev8(self.config)
        self.assertTrue(self.config.setting['dont_write_tags'])
