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

from unittest.mock import MagicMock

from test.picardtestcase import PicardTestCase

from picard.album import Album
from picard.cli.engine.builtins import register_builtins
from picard.cli.engine.commands import (
    Availability,
    EngineCommand,
    EngineCommandRegistry,
)
from picard.cli.engine.dispatch import (
    dispatch,
    split_command_name,
)
from picard.cli.engine.result import EngineResult
from picard.cli.engine.session import LocalEngineSession
from picard.cluster import Cluster
from picard.workspace import workspace


class _Session:
    """Minimal EngineSession stand-in for dispatch tests."""

    def __init__(self, is_gui=False):
        self._is_gui = is_gui
        self.calls = []

    def resolve(self, selector):
        return [], []

    def handle_for(self, entity):
        return 'x1'

    def enumerate_prefix(self, prefix):
        return []

    def run_until_idle(self, timeout=None):
        return True

    @property
    def is_gui(self):
        return self._is_gui


class SplitCommandNameTest(PicardTestCase):
    def setUp(self):
        super().setUp()
        self.reg = EngineCommandRegistry()
        self.reg.register(EngineCommand(name='album save', run=lambda s, a: EngineResult()))
        self.reg.register(EngineCommand(name='ls', run=lambda s, a: EngineResult()))

    def test_two_word_name(self):
        self.assertEqual(('album save', ['a1']), split_command_name(['album', 'save', 'a1'], self.reg))

    def test_one_word_name(self):
        self.assertEqual(('ls', ['a*']), split_command_name(['ls', 'a*'], self.reg))

    def test_unknown_prefers_two_word(self):
        self.assertEqual(('foo bar', []), split_command_name(['foo', 'bar'], self.reg))


class DispatchTest(PicardTestCase):
    def setUp(self):
        super().setUp()
        self.reg = EngineCommandRegistry()
        self.session = _Session()

    def test_unknown_command_is_failure(self):
        r = dispatch(self.session, self.reg, 'bogus thing')
        self.assertFalse(r.ok)
        self.assertIn('unknown command', r.error)

    def test_empty_line_is_failure(self):
        self.assertFalse(dispatch(self.session, self.reg, '   ').ok)

    def test_gui_only_rejected_on_headless(self):
        self.reg.register(
            EngineCommand(name='window raise', run=lambda s, a: EngineResult(), availability=Availability.GUI_ONLY)
        )
        r = dispatch(self.session, self.reg, 'window raise')
        self.assertFalse(r.ok)
        self.assertIn('requires a GUI backend', r.error)

    def test_command_exception_becomes_failure(self):
        def boom(session, args):
            raise RuntimeError('kaboom')

        self.reg.register(EngineCommand(name='boom', run=boom))
        r = dispatch(self.session, self.reg, 'boom')
        self.assertFalse(r.ok)
        self.assertIn('kaboom', r.error)

    def test_args_bound_and_passed(self):
        captured = {}

        def grab(session, args):
            captured.update(args)
            return EngineResult()

        self.reg.register(EngineCommand(name='file add', run=grab, args=('paths',)))
        dispatch(self.session, self.reg, 'file add a.flac b.flac')
        self.assertEqual(['a.flac', 'b.flac'], captured['paths'])

    def test_single_arg_bound_as_scalar(self):
        captured = {}

        def grab(session, args):
            captured.update(args)
            return EngineResult()

        self.reg.register(EngineCommand(name='ls', run=grab, args=('selector',)))
        dispatch(self.session, self.reg, 'ls a1')
        self.assertEqual('a1', captured['selector'])


class LsCommandTest(PicardTestCase):
    def setUp(self):
        super().setUp()
        self.reg = EngineCommandRegistry()
        register_builtins(self.reg)
        self.session = LocalEngineSession(MagicMock())
        ws = workspace()
        self.album = Album('rel-1')
        ws.albums = {'rel-1': self.album}
        self.cluster = Cluster('My Cluster', 'An Artist')
        ws.clusters.append(self.cluster)

    def test_ls_lists_top_level_with_handles(self):
        r = dispatch(self.session, self.reg, 'ls')
        self.assertTrue(r.ok)
        handles = {it.handle for it in r.items}
        # One cluster (c1) and one album (a1); exact handles depend on mint order.
        self.assertEqual({'c1', 'a1'}, handles)

    def test_ls_selector_filters(self):
        r = dispatch(self.session, self.reg, 'ls a*')
        self.assertTrue(r.ok)
        self.assertEqual(['a1'], [it.handle for it in r.items])

    def test_ls_album_item_carries_release_ref(self):
        r = dispatch(self.session, self.reg, 'ls a*')
        data = r.items[0].data
        self.assertEqual('release', data['entity_type'])
        self.assertEqual('rel-1', data['mbid'])

    def test_ls_unknown_handle_reported_unresolved(self):
        r = dispatch(self.session, self.reg, 'ls a9')
        self.assertEqual([], r.items)
        self.assertEqual(['a9'], r.unresolved)

    def test_ls_result_is_serializable(self):
        import json

        r = dispatch(self.session, self.reg, 'ls')
        json.dumps(r.to_dict())
