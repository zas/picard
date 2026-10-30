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

"""Unit tests for file-add path resolution (globs, directories, spaces)."""

import os

from test.picardtestcase import PicardTestCase

from picard.cli.engine.builtins import _expand_input_paths


class ExpandInputPathsTest(PicardTestCase):
    def setUp(self):
        super().setUp()
        self.set_config_values(setting={'recursively_add_files': True, 'ignore_hidden_files': True})
        self.root = self.mktmpdir()

    def _touch(self, rel):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(rel) else None
        open(path, 'w').close()
        return path

    def test_single_file(self):
        f = self._touch('a.mp3')
        files, unmatched = _expand_input_paths([f])
        self.assertEqual([f], files)
        self.assertEqual([], unmatched)

    def test_directory_is_walked(self):
        self._touch('a.mp3')
        self._touch('b.flac')
        files, unmatched = _expand_input_paths([self.root])
        self.assertEqual({'a.mp3', 'b.flac'}, {os.path.basename(f) for f in files})
        self.assertEqual([], unmatched)

    def test_glob_expansion(self):
        self._touch('a.mp3')
        self._touch('b.mp3')
        self._touch('c.flac')
        files, unmatched = _expand_input_paths([os.path.join(self.root, '*.mp3')])
        self.assertEqual({'a.mp3', 'b.mp3'}, {os.path.basename(f) for f in files})
        self.assertEqual([], unmatched)

    def test_unmatched_token_reported(self):
        files, unmatched = _expand_input_paths([os.path.join(self.root, 'nope.mp3')])
        self.assertEqual([], files)
        self.assertEqual([os.path.join(self.root, 'nope.mp3')], unmatched)

    def test_unquoted_spaces_path_fallback(self):
        # Simulate the shell having split "<root>/Second tour/x.mp3" on spaces.
        subdir = os.path.join(self.root, 'Second tour')
        os.mkdir(subdir)
        self._touch(os.path.join('Second tour', 'song.mp3'))
        tokens = (os.path.join(self.root, 'Second') + ' tour').split(' ')
        # tokens == ['<root>/Second', 'tour'] — neither exists alone.
        files, unmatched = _expand_input_paths(tokens)
        self.assertEqual(['song.mp3'], [os.path.basename(f) for f in files])
        self.assertEqual([], unmatched)

    def test_spaces_glob_fallback(self):
        subdir = os.path.join(self.root, 'Second tour')
        os.mkdir(subdir)
        self._touch(os.path.join('Second tour', 'song.mp3'))
        tokens = (os.path.join(self.root, 'Second') + ' tour/*.mp3').split(' ')
        files, unmatched = _expand_input_paths(tokens)
        self.assertEqual(['song.mp3'], [os.path.basename(f) for f in files])
        self.assertEqual([], unmatched)
