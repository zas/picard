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

import os
from unittest.mock import MagicMock

from test.picardtestcase import PicardTestCase

from picard.album import Album
from picard.cli.engine.builtins import register_builtins
from picard.cli.engine.commands import EngineCommandRegistry
from picard.cli.engine.completion import complete
from picard.cli.engine.session import LocalEngineSession
from picard.cluster import Cluster
from picard.workspace import workspace


class CompleteTest(PicardTestCase):
    def setUp(self):
        super().setUp()
        self.reg = EngineCommandRegistry()
        register_builtins(self.reg)
        self.session = LocalEngineSession(MagicMock())
        ws = workspace()
        ws.albums = {'rel-1': Album('rel-1')}
        ws.clusters.append(Cluster('A Cluster', 'An Artist'))

    def _complete(self, line):
        # Emulate readline: text is the trailing whitespace-delimited token
        # ('' when the line ends with a space, i.e. starting a new token).
        text = '' if (not line or line.endswith(' ')) else line.split(' ')[-1]
        return complete(line, text, self.reg, self.session)

    def test_empty_completes_command_names(self):
        matches = self._complete('')
        self.assertIn('ls', matches)
        self.assertIn('file add', matches)
        self.assertIn('quit', matches)

    def test_prefix_filters_command_names(self):
        matches = self._complete('cl')
        self.assertIn('cluster', matches)
        self.assertIn('cluster lookup', matches)
        self.assertNotIn('ls', matches)

    def test_two_word_verb_completion(self):
        # "cluster " -> offer BOTH the verb of the two-word command (lookup)
        # and the one-word command's selector args, because 'cluster' is both a
        # command and the noun of 'cluster lookup'.
        matches = self._complete('cluster ')
        self.assertIn('lookup', matches)
        self.assertIn('a*', matches)

    def test_second_word_completes_verb_when_first_word_is_also_command(self):
        # Regression: 'cluster loo<TAB>' must complete to 'lookup' even though
        # 'cluster' is itself a valid command (its arg0 is a selector).
        matches = self._complete('cluster loo')
        self.assertEqual(['lookup'], matches)

    def test_second_word_verb_completion_filters_by_prefix(self):
        # A prefix that matches no verb (and no handle) yields nothing.
        matches = self._complete('cluster zzz')
        self.assertEqual([], matches)

    def test_selector_arg_completes_handles_and_wildcards(self):
        # Mint handles first so they are live.
        self.session.resolve('a*')
        self.session.resolve('c*')
        matches = self._complete('ls ')
        self.assertIn('a1', matches)
        self.assertIn('c1', matches)
        self.assertIn('*', matches)
        self.assertIn('a*', matches)

    def test_selector_prefix_filters(self):
        self.session.resolve('a*')
        matches = self._complete('ls a')
        self.assertIn('a1', matches)
        self.assertIn('a*', matches)
        self.assertNotIn('c*', matches)

    def test_path_arg_completes_filesystem(self):
        tmp = self.mktmpdir()
        open(os.path.join(tmp, 'song.flac'), 'w').close()
        open(os.path.join(tmp, 'other.mp3'), 'w').close()
        prefix = os.path.join(tmp, 's')
        matches = complete('file add ' + prefix, prefix, self.reg, self.session)
        self.assertEqual([os.path.join(tmp, 'song.flac')], matches)

    def test_path_completes_directory_with_sep(self):
        tmp = self.mktmpdir()
        os.mkdir(os.path.join(tmp, 'sub'))
        prefix = os.path.join(tmp, 'su')
        matches = complete('file add ' + prefix, prefix, self.reg, self.session)
        self.assertEqual([os.path.join(tmp, 'sub') + os.sep], matches)

    def test_unknown_command_no_matches(self):
        self.assertEqual([], self._complete('bogus '))
