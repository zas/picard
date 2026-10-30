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

from picard.album import (
    Album,
    NatAlbum,
)
from picard.cli.engine.commands import EngineSession
from picard.cli.engine.session import (
    LocalEngineSession,
    classify_entity,
)
from picard.cluster import (
    Cluster,
    UnclusteredFiles,
)
from picard.workspace import workspace


class _FakeFile:
    """Stand-in for a File (avoids real file I/O); classified via File check."""


class ClassifyEntityTest(PicardTestCase):
    def test_album_and_natalbum_are_a(self):
        self.assertEqual('a', classify_entity(Album('rel-1')))
        self.assertEqual('a', classify_entity(NatAlbum()))

    def test_cluster_is_c(self):
        self.assertEqual('c', classify_entity(Cluster('Some Album', 'Artist')))

    def test_unclustered_files_bucket_is_not_handleable(self):
        self.assertIsNone(classify_entity(UnclusteredFiles()))

    def test_unknown_is_none(self):
        self.assertIsNone(classify_entity(object()))


class LocalEngineSessionTest(PicardTestCase):
    def setUp(self):
        super().setUp()
        self.app = MagicMock()
        self.session = LocalEngineSession(self.app)
        # PicardTestCase installs a fresh Workspace as the provider; populate it.
        self.ws = workspace()
        self.album1 = Album('rel-1')
        self.album2 = Album('rel-2')
        self.ws.albums = {'rel-1': self.album1, 'rel-2': self.album2}
        self.cluster1 = Cluster('Cluster One', 'Artist')
        self.ws.clusters.append(self.cluster1)

    def test_satisfies_engine_session_protocol(self):
        self.assertIsInstance(self.session, EngineSession)

    def test_is_gui_false(self):
        self.assertFalse(self.session.is_gui)

    def test_enumerate_albums(self):
        self.assertEqual([self.album1, self.album2], list(self.session.enumerate_prefix('a')))

    def test_enumerate_clusters(self):
        self.assertEqual([self.cluster1], list(self.session.enumerate_prefix('c')))

    def test_enumerate_unknown_prefix_empty(self):
        self.assertEqual([], list(self.session.enumerate_prefix('z')))

    def test_handle_for_mints_and_is_stable(self):
        h = self.session.handle_for(self.album1)
        self.assertEqual('a1', h)
        self.assertEqual('a1', self.session.handle_for(self.album1))

    def test_resolve_wildcard_then_handle(self):
        # Minting via a wildcard resolve, then addressing by the minted handle.
        entities, unresolved = self.session.resolve('a*')
        self.assertEqual([self.album1, self.album2], entities)
        self.assertEqual([], unresolved)
        # Now the albums have handles; resolve one explicitly.
        h1 = self.session.handle_for(self.album1)
        entities2, _ = self.session.resolve(h1)
        self.assertEqual([self.album1], entities2)

    def test_resolve_unknown_handle_is_unresolved(self):
        entities, unresolved = self.session.resolve('a99')
        self.assertEqual([], entities)
        self.assertEqual(['a99'], unresolved)

    def test_run_until_idle_delegates_to_app(self):
        self.app.run_until_idle.return_value = True
        self.assertTrue(self.session.run_until_idle(timeout=1.0))
        self.app.run_until_idle.assert_called_once_with(timeout=1.0)
