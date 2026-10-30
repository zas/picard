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

from picard.cli.engine.builtins import register_builtins
from picard.cli.engine.commands import EngineCommandRegistry
from picard.cli.engine.dispatch import dispatch
from picard.cli.engine.session import LocalEngineSession
from picard.file import File
from picard.workspace import workspace


class ClusterCommandTest(PicardTestCase):
    def setUp(self):
        super().setUp()
        self.patch_tagger_instance('picard.item')
        self.set_config_values(setting={'va_name': 'Various Artists', 'nat_name': 'Standalone Recordings'})
        # File._move touches services (acoustid/isrc managers) via services();
        # the mock tagger is the services provider in tests — stub them.
        self.tagger.acoustidmanager = MagicMock()
        self.tagger.isrc_submit_manager = MagicMock()
        self.reg = EngineCommandRegistry()
        register_builtins(self.reg)
        self.session = LocalEngineSession(MagicMock())
        self.ws = workspace()

    def _add_unclustered(self, album, artist, name):
        f = File(name)
        f.metadata['album'] = album
        f.metadata['albumartist'] = artist
        self.ws.files[f.filename] = f
        self.ws.unclustered_files.add_file(f)
        return f

    def test_cluster_groups_multi_file_albums(self):
        self._add_unclustered('Album A', 'Artist A', 'a1.flac')
        self._add_unclustered('Album A', 'Artist A', 'a2.flac')
        self._add_unclustered('Album B', 'Artist B', 'b1.flac')
        self._add_unclustered('Album B', 'Artist B', 'b2.flac')

        result = dispatch(self.session, self.reg, 'cluster')
        self.assertTrue(result.ok)
        # Two multi-file albums → two clusters minted.
        self.assertEqual(2, len(result.mints))
        self.assertTrue(all(h.startswith('c') for h in result.mints))
        self.assertEqual(2, len(list(self.ws.clusters)))

    def test_single_file_group_stays_unclustered(self):
        self._add_unclustered('Album A', 'Artist A', 'a1.flac')
        self._add_unclustered('Album A', 'Artist A', 'a2.flac')
        self._add_unclustered('Lonely', 'Nobody', 'solo.flac')

        result = dispatch(self.session, self.reg, 'cluster')
        # Only the 2-file album clusters; the lone file does not.
        self.assertEqual(1, len(result.mints))
        self.assertEqual(1, len(list(self.ws.clusters)))

    def test_cluster_then_ls_shows_clusters(self):
        self._add_unclustered('Album A', 'Artist A', 'a1.flac')
        self._add_unclustered('Album A', 'Artist A', 'a2.flac')
        dispatch(self.session, self.reg, 'cluster')
        listing = dispatch(self.session, self.reg, 'ls c*')
        self.assertEqual(1, len(listing.items))
        self.assertTrue(listing.items[0].handle.startswith('c'))

    def test_cluster_empty_is_ok_no_mints(self):
        result = dispatch(self.session, self.reg, 'cluster')
        self.assertTrue(result.ok)
        self.assertEqual([], result.mints)
