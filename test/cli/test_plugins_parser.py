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

"""The options of "picard-cli plugins init" that can be given several times."""

from argparse import ArgumentParser

from test.picardtestcase import PicardTestCase

from picard.cli.plugins import PluginsSubcommand


class PluginsInitParserTest(PicardTestCase):
    def _parse(self, *argv):
        parser = ArgumentParser()
        PluginsSubcommand().setup_parser(parser)
        return parser.parse_args(['init', 'Name', *argv])

    def test_category_not_given(self):
        self.assertIsNone(self._parse().category)

    def test_category_values_are_collected(self):
        """Each value is kept as given (comma-separated lists are split by the command)."""
        self.assertEqual(
            self._parse('--category', 'metadata,ui', '--category', 'coverart').category, ['metadata,ui', 'coverart']
        )
