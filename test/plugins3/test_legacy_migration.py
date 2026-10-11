# Picard, the next-generation MusicBrainz tagger
#
# Copyright (C) 2026 Laurent Monin
# Copyright (C) 2026 Philipp Wolfer
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
from test.plugins3.helpers import create_test_registry

from picard.config import (
    ListOption,
    get_config,
)
from picard.plugin3.legacy_migration import (
    clear_legacy_list,
    get_pending_legacy_ids,
    has_pending_legacy_migration,
    install_resolved_plugins,
    plan_legacy_migration,
)


class TestLegacyMigration(PicardTestCase):
    def setUp(self):
        super().setUp()
        # 'enabled_plugins' is an obsolete v2 option with no registered Option;
        # register it so reads/writes behave like the real upgraded config.
        ListOption('setting', 'enabled_plugins', [])
        self.registry = create_test_registry()

    def _set_pending(self, ids):
        get_config().setting['enabled_plugins'] = ids

    def test_get_pending_legacy_ids_empty_when_absent(self):
        config = get_config()
        config.setting.remove('enabled_plugins')
        self.assertEqual([], get_pending_legacy_ids())
        self.assertFalse(has_pending_legacy_migration())

    def test_get_pending_legacy_ids_returns_list(self):
        self._set_pending(['example_v2', 'other'])
        self.assertEqual(['example_v2', 'other'], get_pending_legacy_ids())
        self.assertTrue(has_pending_legacy_migration())

    def test_plan_splits_resolved_and_unresolved(self):
        self._set_pending(['example_v2', 'not_ported'])
        plan = plan_legacy_migration(self.registry)
        self.assertEqual(1, len(plan.resolved))
        legacy_id, registry_plugin = plan.resolved[0]
        self.assertEqual('example_v2', legacy_id)
        self.assertEqual('example-plugin', registry_plugin.id)
        self.assertEqual(['not_ported'], plan.unresolved)

    def test_plan_dedups_same_target_plugin(self):
        # example_v1 (v1) and example_v2 (v2) both map to example-plugin, but a
        # v2 plan only resolves example_v2; add a duplicate to prove dedup by id.
        self._set_pending(['example_v2', 'example_v2'])
        plan = plan_legacy_migration(self.registry)
        self.assertEqual(1, len(plan.resolved))

    def test_plan_respects_legacy_version(self):
        self._set_pending(['example_v1'])
        # Default version is '2' -> example_v1 (a v1 ID) does not resolve.
        plan_v2 = plan_legacy_migration(self.registry)
        self.assertEqual([], plan_v2.resolved)
        self.assertEqual(['example_v1'], plan_v2.unresolved)
        # Explicit version '1' -> resolves.
        plan_v1 = plan_legacy_migration(self.registry, legacy_version='1')
        self.assertEqual(1, len(plan_v1.resolved))

    def test_install_resolved_plugins_installs_and_enables(self):
        self._set_pending(['example_v2'])
        plan = plan_legacy_migration(self.registry)
        manager = Mock()
        manager.select_ref_for_plugin.return_value = 'main'
        installed, failed = install_resolved_plugins(manager, plan)
        self.assertEqual(['example_v2'], installed)
        self.assertEqual([], failed)
        manager.install_plugin.assert_called_once_with(
            'https://github.com/test/example',
            ref='main',
            enable_after_install=True,
        )

    def test_install_resolved_plugins_records_failures(self):
        self._set_pending(['example_v2'])
        plan = plan_legacy_migration(self.registry)
        manager = Mock()
        manager.select_ref_for_plugin.return_value = 'main'
        manager.install_plugin.side_effect = RuntimeError('boom')
        installed, failed = install_resolved_plugins(manager, plan)
        self.assertEqual([], installed)
        self.assertEqual(['example_v2'], failed)

    def test_install_resolved_plugins_does_not_clear_list(self):
        self._set_pending(['example_v2'])
        plan = plan_legacy_migration(self.registry)
        manager = Mock()
        manager.select_ref_for_plugin.return_value = 'main'
        install_resolved_plugins(manager, plan)
        # Installing must not touch the pending list; clearing is a separate action.
        self.assertIn('enabled_plugins', get_config().setting)

    def test_clear_legacy_list_removes_key(self):
        self._set_pending(['example_v2', 'not_ported'])
        self.assertTrue(clear_legacy_list())
        self.assertNotIn('enabled_plugins', get_config().setting)

    def test_clear_legacy_list_absent_returns_false(self):
        get_config().setting.remove('enabled_plugins')
        self.assertFalse(clear_legacy_list())

    def test_get_pending_legacy_ids_reads_unregistered_option(self):
        """The legacy key must be read via raw_value even with no registered Option.

        In the real Picard 2 -> 3 upgrade, 'enabled_plugins' is an obsolete option
        with no registered Option, so item access returns None. Reading must go
        through raw_value (regression test for that path).
        """
        config = get_config()
        # Store the value, then drop the registered Option to mimic the real flow.
        config.setting['enabled_plugins'] = ['playlist', 'format_performer_tags']
        from picard.config import Option

        Option.registry.pop(('setting', 'enabled_plugins'), None)
        self.assertEqual(['playlist', 'format_performer_tags'], get_pending_legacy_ids())
        self.assertTrue(has_pending_legacy_migration())
