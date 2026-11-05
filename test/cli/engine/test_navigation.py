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

"""Selector paths (``a1.d2.t3``, ``c1.f*``, ``u.f*``) over real working-set entities."""

from unittest.mock import MagicMock

from test.picardtestcase import PicardTestCase

from picard.album import Album
from picard.cli.engine.candidates import Candidate
from picard.cli.engine.selectors import SelectorError
from picard.cli.engine.session import LocalEngineSession
from picard.cluster import Cluster
from picard.file import File
from picard.track import Track
from picard.workspace import workspace


def _track(album, disc, number, title):
    track = Track(f'trk-{title}', album)
    if disc is not None:
        track.metadata['discnumber'] = str(disc)
    if number is not None:
        track.metadata['tracknumber'] = str(number)
    track.metadata['title'] = title
    album.tracks.append(track)
    return track


def _file(wks, name):
    file = File(name)
    wks.files[file.filename] = file
    return file


class _PathTestBase(PicardTestCase):
    def setUp(self):
        super().setUp()
        self.patch_tagger_instance('picard.item')
        # Moving a file into a container reaches these services.
        self.tagger.acoustid_manager = MagicMock()
        self.tagger.isrc_submit_manager = MagicMock()
        self.session = LocalEngineSession(MagicMock())
        self.wks = workspace()

    def _album(self, key, tracks, loaded=True):
        """Register an album whose tracks are ``(disc, number, title)`` tuples."""
        album = Album(key)
        album.loaded = loaded
        self.wks.albums[key] = album
        for disc, number, title in tracks:
            _track(album, disc, number, title)
        self.session.handle_for(album)
        return album

    def _resolve(self, selector):
        return self.session.resolve(selector)

    def _titles(self, selector):
        entities, unresolved = self._resolve(selector)
        return [e.metadata['title'] for e in entities], unresolved


class SingleDiscAlbumPathTest(_PathTestBase):
    def setUp(self):
        super().setUp()
        self.album = self._album('rel-1', [(1, 1, 'One'), (1, 2, 'Two'), (1, 3, 'Three')])

    def test_track_without_disc(self):
        self.assertEqual((['Two'], []), self._titles('a1.t2'))

    def test_explicit_disc_is_the_same_track(self):
        self.assertEqual(self._titles('a1.t2'), self._titles('a1.d1.t2'))

    def test_all_tracks(self):
        self.assertEqual((['One', 'Two', 'Three'], []), self._titles('a1.t*'))

    def test_disc_stands_for_its_tracks(self):
        self.assertEqual((['One', 'Two', 'Three'], []), self._titles('a1.d1'))

    def test_wildcard_discs_then_track(self):
        self.assertEqual((['One'], []), self._titles('a1.d*.t1'))

    def test_missing_track_is_unresolved(self):
        self.assertEqual(([], ['a1.t9']), self._titles('a1.t9'))

    def test_missing_disc_is_unresolved(self):
        self.assertEqual(([], ['a1.d2']), self._titles('a1.d2'))

    def test_missing_album_is_unresolved(self):
        self.assertEqual(([], ['a9.t1']), self._titles('a9.t1'))

    def test_resolved_tracks_are_handleable(self):
        entities, _ = self._resolve('a1.d1')
        handles = [self.session.handle_for(e) for e in entities]
        self.assertTrue(all(h.startswith('t') for h in handles))
        # Stable identity: the same track resolves to the same handle by path.
        (again,), _ = self._resolve('a1.t2')
        self.assertEqual(handles[1], self.session.handle_for(again))

    def test_pregap_is_track_zero(self):
        _track(self.album, 1, 0, 'Pregap')
        self.assertEqual((['Pregap'], []), self._titles('a1.t0'))


class MultiDiscAlbumPathTest(_PathTestBase):
    def setUp(self):
        super().setUp()
        self.album = self._album(
            'rel-1',
            [(1, 1, 'A1'), (1, 2, 'A2'), (2, 1, 'B1'), (2, 2, 'B2')],
        )

    def test_track_needs_a_disc(self):
        with self.assertRaises(SelectorError) as ctx:
            self._resolve('a1.t1')
        message = str(ctx.exception)
        self.assertIn('a1.t1', message)
        self.assertIn('2 discs', message)
        self.assertIn('d1.t1', message)

    def test_explicit_disc(self):
        self.assertEqual((['B1'], []), self._titles('a1.d2.t1'))
        self.assertEqual((['A2'], []), self._titles('a1.d1.t2'))

    def test_disc_stands_for_its_tracks(self):
        self.assertEqual((['B1', 'B2'], []), self._titles('a1.d2'))

    def test_all_discs(self):
        self.assertEqual((['A1', 'A2', 'B1', 'B2'], []), self._titles('a1.d*'))

    def test_all_tracks_need_no_disc(self):
        self.assertEqual((['A1', 'A2', 'B1', 'B2'], []), self._titles('a1.t*'))

    def test_track_of_every_disc(self):
        self.assertEqual((['A1', 'B1'], []), self._titles('a1.d*.t1'))

    def test_missing_track_on_disc_is_unresolved(self):
        self.assertEqual(([], ['a1.d2.t5']), self._titles('a1.d2.t5'))

    def test_disc_numbers_come_from_the_tags_not_the_position(self):
        # A release whose only disc is numbered 2 is still addressed as disc 2.
        self._album('rel-2', [(2, 1, 'Only')])
        self.assertEqual((['Only'], []), self._titles('a2.d2.t1'))
        self.assertEqual((['Only'], []), self._titles('a2.t1'))


class UnnumberedAlbumPathTest(_PathTestBase):
    """Non-album tracks carry no disc or track numbers: positions, and no discs."""

    def setUp(self):
        super().setUp()
        self.album = self._album('NATS', [(None, None, 'X'), (None, None, 'Y')])

    def test_tracks_are_numbered_by_position(self):
        self.assertEqual((['Y'], []), self._titles('a1.t2'))
        self.assertEqual((['X', 'Y'], []), self._titles('a1.t*'))

    def test_discs_are_not_available(self):
        with self.assertRaises(SelectorError) as ctx:
            self._resolve('a1.d1')
        self.assertIn('no disc numbers', str(ctx.exception))

    def test_position_follows_removals(self):
        self.album.tracks.remove(self.album.tracks[0])
        self.assertEqual((['Y'], []), self._titles('a1.t1'))


class AlbumStatePathTest(_PathTestBase):
    def test_tracks_of_an_unloaded_album_are_an_error(self):
        self._album('rel-1', [(1, 1, 'One')], loaded=False)
        with self.assertRaises(SelectorError) as ctx:
            self._resolve('a1.t1')
        self.assertIn('not loaded', str(ctx.exception))

    def test_loaded_album_without_tracks_is_empty(self):
        self._album('rel-1', [])
        self.assertEqual(([], []), self._titles('a1.t*'))
        self.assertEqual(([], ['a1.t1']), self._titles('a1.t1'))


class FilePathTest(_PathTestBase):
    def setUp(self):
        super().setUp()
        self.album = self._album('rel-1', [(1, 1, 'One'), (1, 2, 'Two')])
        self.on_one = _file(self.wks, 'one.flac')
        self.on_one_too = _file(self.wks, 'one-alt.flac')
        self.on_two = _file(self.wks, 'two.flac')
        self.loose_in_album = _file(self.wks, 'loose.flac')
        self.album.tracks[0].files.extend([self.on_one, self.on_one_too])
        self.album.tracks[1].files.append(self.on_two)
        self.album.unmatched_files.add_file(self.loose_in_album)

    def test_files_of_a_track(self):
        entities, _ = self._resolve('a1.t1.f*')
        self.assertEqual([self.on_one, self.on_one_too], entities)

    def test_file_of_a_track_by_position(self):
        entities, _ = self._resolve('a1.t1.f2')
        self.assertEqual([self.on_one_too], entities)

    def test_missing_file_of_a_track_is_unresolved(self):
        self.assertEqual(([], ['a1.t2.f2']), self._resolve('a1.t2.f2'))

    def test_every_file_of_an_album(self):
        entities, _ = self._resolve('a1.f*')
        self.assertEqual([self.on_one, self.on_one_too, self.on_two, self.loose_in_album], entities)

    def test_files_of_a_disc_view(self):
        entities, _ = self._resolve('a1.d1.f*')
        self.assertEqual([self.on_one, self.on_one_too, self.on_two], entities)

    def test_unmatched_files_of_an_album(self):
        entities, _ = self._resolve('a1.u')
        self.assertEqual([self.loose_in_album], entities)
        self.assertEqual(entities, self._resolve('a1.u.f*')[0])

    def test_path_through_disc_to_file(self):
        entities, _ = self._resolve('a1.d1.t2.f1')
        self.assertEqual([self.on_two], entities)


class ClusterAndBucketPathTest(_PathTestBase):
    def setUp(self):
        super().setUp()
        self.cluster = Cluster('Album', 'Artist')
        self.wks.clusters.append(self.cluster)
        self.session.handle_for(self.cluster)
        self.first = _file(self.wks, 'first.flac')
        self.second = _file(self.wks, 'second.flac')
        self.cluster.add_file(self.first)
        self.cluster.add_file(self.second)
        self.loose = _file(self.wks, 'loose.flac')
        self.wks.unclustered_files.add_file(self.loose)

    def test_files_of_a_cluster(self):
        entities, _ = self._resolve('c1.f*')
        self.assertCountEqual([self.first, self.second], entities)

    def test_file_of_a_cluster_by_position(self):
        entities, _ = self._resolve('c1.f1')
        self.assertEqual(list(self.cluster.files)[:1], entities)

    def test_unclustered_bucket_stands_for_its_files(self):
        self.assertEqual(([self.loose], []), self._resolve('u'))
        self.assertEqual(([self.loose], []), self._resolve('u.f*'))
        self.assertEqual(([self.loose], []), self._resolve('u.f1'))

    def test_universal_cluster_wildcard(self):
        entities, _ = self._resolve('c*.f1')
        self.assertEqual(list(self.cluster.files)[:1], entities)


class CandidatePathTest(_PathTestBase):
    def setUp(self):
        super().setUp()
        self.cluster = Cluster('Album', 'Artist')
        self.other = Cluster('Other', 'Artist')
        self.wks.clusters.extend([self.cluster, self.other])
        for cluster in (self.cluster, self.other):
            self.session.handle_for(cluster)
        self.candidates = [Candidate(MagicMock()) for _ in range(3)]
        self.session.set_candidates(self.cluster, self.candidates)
        self.session.set_candidates(self.other, [Candidate(MagicMock())])

    def test_candidates_of_a_cluster(self):
        self.assertEqual((self.candidates, []), self._resolve('c1.m*'))

    def test_candidate_by_position_is_per_cluster(self):
        self.assertEqual(([self.candidates[1]], []), self._resolve('c1.m2'))
        self.assertEqual(([], ['c2.m2']), self._resolve('c2.m2'))

    def test_candidates_of_a_file(self):
        file = _file(self.wks, 'one.flac')
        self.session.handle_for(file)
        candidate = Candidate(MagicMock())
        self.session.set_candidates(file, [candidate])
        self.assertEqual(([candidate], []), self._resolve('f1.m1'))


class InvalidPathTest(_PathTestBase):
    def setUp(self):
        super().setUp()
        self.album = self._album('rel-1', [(1, 1, 'One')])
        self.file = _file(self.wks, 'one.flac')
        self.session.handle_for(self.file)
        self.cluster = Cluster('Album', 'Artist')
        self.wks.clusters.append(self.cluster)
        self.session.handle_for(self.cluster)

    def test_segments_not_valid_under_their_parent(self):
        for selector in ('f1.t1', 'a1.m1', 'c1.t1', 'a1.t1.t1', 'a1.d1.d1', 'c1.u', 'a1.c1', 'u.m1'):
            with self.subTest(selector=selector):
                with self.assertRaises(SelectorError):
                    self._resolve(selector)

    def test_candidate_has_no_children(self):
        candidate = Candidate(MagicMock())
        self.session.set_candidates(self.cluster, [candidate])
        with self.assertRaises(SelectorError):
            self._resolve('c1.m1.f1')

    def test_a_bucket_cannot_hold_candidates(self):
        with self.assertRaises(SelectorError):
            self._resolve('a1.u.m1')


class PathResultTest(_PathTestBase):
    def test_results_are_deduplicated_across_terms(self):
        self._album('rel-1', [(1, 1, 'One'), (1, 2, 'Two')])
        self.assertEqual((['One', 'Two'], []), self._titles('a1.d1,a1.t*,a1.t1'))

    def test_paths_mix_with_plain_handles(self):
        self._album('rel-1', [(1, 1, 'One')])
        entities, unresolved = self._resolve('a1,a1.t1,a9.t1')
        self.assertEqual(2, len(entities))
        self.assertEqual(['a9.t1'], unresolved)
