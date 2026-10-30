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

from test.picardtestcase import PicardTestCase

from picard.cli.engine.commands import (
    Availability,
    EngineCommand,
    EngineCommandRegistry,
)
from picard.cli.engine.result import (
    EngineItemResult,
    EngineResult,
)


class EngineResultTest(PicardTestCase):
    def test_defaults(self):
        r = EngineResult()
        self.assertTrue(r.ok)
        self.assertEqual([], r.items)
        self.assertEqual([], r.unresolved)

    def test_failure_factory(self):
        r = EngineResult.failure('boom', unresolved=['a9'])
        self.assertFalse(r.ok)
        self.assertEqual('boom', r.error)
        self.assertEqual(['a9'], r.unresolved)

    def test_to_dict_is_plain_serializable(self):
        r = EngineResult(
            items=[EngineItemResult('a1', 'saved', {'files': 12})],
            resolved=['a1'],
            mints=['a1'],
            message='done',
        )
        d = r.to_dict()
        self.assertEqual(
            d,
            {
                'ok': True,
                'items': [{'handle': 'a1', 'status': 'saved', 'data': {'files': 12}}],
                'resolved': ['a1'],
                'unresolved': [],
                'mints': ['a1'],
                'message': 'done',
                'error': '',
            },
        )
        # Must be JSON-serializable (cross-process / MCP).
        import json

        json.dumps(d)


class EngineCommandTest(PicardTestCase):
    def test_noun_verb_split(self):
        cmd = EngineCommand(name='album save', run=lambda s, a: EngineResult())
        self.assertEqual('album', cmd.noun)
        self.assertEqual('save', cmd.verb)

    def test_single_word_name(self):
        cmd = EngineCommand(name='ls', run=lambda s, a: EngineResult())
        self.assertEqual('ls', cmd.noun)
        self.assertEqual('', cmd.verb)


class EngineCommandRegistryTest(PicardTestCase):
    def setUp(self):
        super().setUp()
        self.reg = EngineCommandRegistry()

    def _cmd(self, name, availability=Availability.BOTH):
        return EngineCommand(name=name, run=lambda s, a: EngineResult(), availability=availability)

    def test_register_and_get(self):
        cmd = self.reg.register(self._cmd('file add'))
        self.assertIs(self.reg.get('file add'), cmd)
        self.assertIn('file add', self.reg)
        self.assertEqual(1, len(self.reg))

    def test_duplicate_registration_raises(self):
        self.reg.register(self._cmd('file add'))
        with self.assertRaises(ValueError):
            self.reg.register(self._cmd('file add'))

    def test_get_unknown_is_none(self):
        self.assertIsNone(self.reg.get('nope'))

    def test_names_sorted(self):
        self.reg.register(self._cmd('file add'))
        self.reg.register(self._cmd('album save'))
        self.assertEqual(['album save', 'file add'], self.reg.names())

    def test_available_filters_gui_only(self):
        self.reg.register(self._cmd('album save', Availability.BOTH))
        self.reg.register(self._cmd('window raise', Availability.GUI_ONLY))
        headless = {c.name for c in self.reg.available(is_gui=False)}
        gui = {c.name for c in self.reg.available(is_gui=True)}
        self.assertEqual({'album save'}, headless)
        self.assertEqual({'album save', 'window raise'}, gui)
