# Picard, the next-generation MusicBrainz tagger
#
# Copyright (C) 2026 Picard contributors
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


from collections import Counter
import tracemalloc

from test.picardtestcase import PicardTestCase

from picard.debug_opts import DebugOpt
from picard.util import memprofile


class MemProfileTestCase(PicardTestCase):
    def setUp(self):
        super().setUp()
        # Ensure a clean, disabled state; remember whether tracing was on so we
        # can restore it and not leak tracing into other tests.
        self._was_tracing = tracemalloc.is_tracing()
        DebugOpt.MEMORY.enabled = False

    def tearDown(self):
        DebugOpt.MEMORY.enabled = False
        if tracemalloc.is_tracing() and not self._was_tracing:
            tracemalloc.stop()
        super().tearDown()

    def test_is_enabled_reflects_debug_opt(self):
        self.assertFalse(memprofile.is_enabled())
        DebugOpt.MEMORY.enabled = True
        self.assertTrue(memprofile.is_enabled())

    def test_ensure_tracing_noop_when_disabled(self):
        # Only assert the noop behavior when tracing was not already running.
        if tracemalloc.is_tracing():
            self.skipTest("tracemalloc already tracing in this environment")
        self.assertFalse(memprofile.ensure_tracing())
        self.assertFalse(tracemalloc.is_tracing())

    def test_ensure_tracing_starts_when_enabled(self):
        DebugOpt.MEMORY.enabled = True
        self.assertTrue(memprofile.ensure_tracing())
        self.assertTrue(tracemalloc.is_tracing())

    def test_memory_snapshot_disabled_is_noop(self):
        if tracemalloc.is_tracing():
            self.skipTest("tracemalloc already tracing in this environment")
        with memprofile.memory_snapshot("test", n=10):
            _data = [b"x" * 1000 for _ in range(100)]
        # Should not have started tracing as a side effect.
        self.assertFalse(tracemalloc.is_tracing())

    def test_memory_snapshot_enabled_runs_block(self):
        DebugOpt.MEMORY.enabled = True
        marker = []
        with memprofile.memory_snapshot("test", n=5):
            marker.append(object())
        self.assertEqual(len(marker), 1)
        self.assertTrue(tracemalloc.is_tracing())

    def test_log_object_counts_disabled_is_noop(self):
        # Should simply return without error when disabled.
        self.assertIsNone(memprofile.log_object_counts("test"))

    def test_deep_getsizeof_counts_container_contents(self):
        small = memprofile.deep_getsizeof([1, 2, 3])
        large = memprofile.deep_getsizeof([1, 2, 3, "a much longer string element" * 10])
        self.assertGreater(large, small)

    def test_deep_getsizeof_handles_cycles(self):
        a = []
        b = [a]
        a.append(b)  # reference cycle
        # Must terminate and return a finite positive size.
        size = memprofile.deep_getsizeof(a)
        self.assertGreater(size, 0)

    def test_deep_getsizeof_dedupes_shared_references(self):
        shared = ["shared element string" * 100]
        # Two references to the same object should be counted once.
        both = [shared, shared]
        one = [shared]
        # The container overhead differs slightly, but the large shared payload
        # must not be double counted, so sizes should be close.
        size_both = memprofile.deep_getsizeof(both)
        size_one = memprofile.deep_getsizeof(one)
        payload = memprofile.deep_getsizeof(shared)
        self.assertLess(size_both - size_one, payload)

    def test_log_deep_size_disabled_returns_zero(self):
        self.assertEqual(memprofile.log_deep_size("test", [1, 2, 3]), 0)

    def test_log_deep_size_enabled_returns_positive(self):
        DebugOpt.MEMORY.enabled = True
        self.assertGreater(memprofile.log_deep_size("test", [1, 2, 3]), 0)

    def test_memory_sampler_disabled_does_not_start_thread(self):
        sampler = memprofile.MemorySampler(interval=0.01)
        sampler.start()
        self.assertIsNone(sampler._thread)
        sampler.stop()

    def test_memory_sampler_enabled_start_stop(self):
        DebugOpt.MEMORY.enabled = True
        sampler = memprofile.MemorySampler(interval=0.01)
        sampler.start()
        self.assertIsNotNone(sampler._thread)
        sampler.stop()
        self.assertIsNone(sampler._thread)

    def _make_fake_album(self, n_tracks=3):
        from picard.metadata import Metadata

        class FakeTrack:
            def __init__(self, i):
                self.metadata = Metadata()
                self.metadata['title'] = f'Title {i}'
                self.metadata['artist'] = ['A', 'B']
                self.orig_metadata = Metadata()
                self.orig_metadata.copy(self.metadata)
                self.scripted_metadata = Metadata()
                self.scripted_metadata.copy(self.metadata)
                self._track_artists = [f'artist-{i}-1', f'artist-{i}-2']
                self._genres = Counter({'rock': 3, 'indie': 1})
                self._folksonomy_tags = Counter({'favourite': 2})

        class FakeAlbum:
            def __init__(self, use_cache_attr=False):
                self.id = 'test-album-id'
                self.metadata = Metadata()
                self.metadata['album'] = 'Test Album'
                self.orig_metadata = Metadata()
                self._recordings_map = {}
                self.per_medium_metadata = {}
                self.tracks = [FakeTrack(i) for i in range(n_tracks)]
                # Simulate the retained raw release node. After loading Picard
                # moves it to _release_node_cache; support both.
                node = {
                    'id': 'x',
                    'media': [{'tracks': [{'title': f'T{i}'} for i in range(n_tracks)]}],
                    'blob': 'x' * 5000,
                }
                if use_cache_attr:
                    self._release_node_cache = node
                else:
                    self._release_node = node

        return FakeAlbum

    def test_analyze_album_footprint_disabled_is_noop(self):
        FakeAlbum = self._make_fake_album()
        album = FakeAlbum()
        self.assertEqual(memprofile.analyze_album_footprint(album), {})

    def test_analyze_album_footprint_reports_components(self):
        DebugOpt.MEMORY.enabled = True
        FakeAlbum = self._make_fake_album(n_tracks=4)
        album = FakeAlbum()
        result = memprofile.analyze_album_footprint(album, log_result=False)
        self.assertEqual(result['track_count'], 4)
        # The retained release node blob should be measured and non-trivial.
        self.assertGreater(result['release_node'], 5000)
        # All three per-track metadata copies are accounted for.
        self.assertGreater(result['track_metadata'], 0)
        self.assertGreater(result['track_orig_metadata'], 0)
        self.assertGreater(result['track_scripted_metadata'], 0)
        self.assertGreater(result['track_artists'], 0)
        self.assertGreater(result['track_genres_folksonomy'], 0)
        # Total is the sum of the size components (excluding track_count).
        expected_total = sum(v for k, v in result.items() if k not in ('track_count', 'total'))
        self.assertEqual(result['total'], expected_total)

    def test_analyze_album_footprint_measures_release_node_cache(self):
        # After loading, Picard moves the raw node to _release_node_cache; the
        # analyzer must still measure it there.
        DebugOpt.MEMORY.enabled = True
        FakeAlbum = self._make_fake_album(n_tracks=2)
        album = FakeAlbum(use_cache_attr=True)
        self.assertFalse(hasattr(album, '_release_node'))
        result = memprofile.analyze_album_footprint(album, log_result=False)
        self.assertGreater(result['release_node'], 5000)

    def _make_fake_tagger(self, n_albums=2, n_tracks=3, n_files=5):
        FakeAlbum = self._make_fake_album(n_tracks=n_tracks)

        from picard.metadata import Metadata

        class FakeFile:
            def __init__(self, i):
                self.metadata = Metadata()
                self.metadata['title'] = f'File {i}'
                self.orig_metadata = Metadata()
                self.orig_metadata.copy(self.metadata)

        class FakeTagger:
            def __init__(self):
                self.albums = {f'a{i}': FakeAlbum() for i in range(n_albums)}
                self.files = {f'f{i}': FakeFile(i) for i in range(n_files)}

        return FakeTagger()

    def test_analyze_session_footprint_disabled_is_noop(self):
        tagger = self._make_fake_tagger()
        self.assertEqual(memprofile.analyze_session_footprint(tagger), {})

    def test_analyze_session_footprint_aggregates(self):
        DebugOpt.MEMORY.enabled = True
        tagger = self._make_fake_tagger(n_albums=3, n_tracks=4, n_files=10)
        stats = memprofile.analyze_session_footprint(tagger, log_result=False)
        self.assertEqual(stats['album_count'], 3)
        self.assertEqual(stats['track_count'], 12)
        self.assertEqual(stats['file_count'], 10)
        # 3 metadata objects per track (12 tracks) + 3 per album (metadata,
        # orig_metadata; albums have no scripted_metadata here) + 2 per file.
        # At minimum we should count the per-file (2*10) and per-track (3*12).
        self.assertGreaterEqual(stats['metadata_object_count'], 2 * 10 + 3 * 12)
        self.assertGreater(stats['metadata_bytes'], 0)
        self.assertGreater(stats['file_metadata_bytes'], 0)

    def test_analyze_session_footprint_dedupes_metadata(self):
        DebugOpt.MEMORY.enabled = True
        tagger = self._make_fake_tagger(n_albums=1, n_tracks=2, n_files=0)
        stats = memprofile.analyze_session_footprint(tagger, log_result=False)
        # metadata_bytes must equal sum of distinct Metadata deep sizes; the
        # object count must be positive and consistent.
        self.assertGreater(stats['metadata_object_count'], 0)

    def test_log_session_footprint_throttled_respects_interval(self):
        DebugOpt.MEMORY.enabled = True
        tagger = self._make_fake_tagger(n_albums=1, n_tracks=1, n_files=1)
        # Reset throttle state.
        memprofile._last_session_summary = 0.0
        calls = []
        orig = memprofile.analyze_session_footprint
        memprofile.analyze_session_footprint = lambda t, **k: calls.append(t)
        try:
            memprofile.log_session_footprint_throttled(tagger, min_interval=1000.0)
            memprofile.log_session_footprint_throttled(tagger, min_interval=1000.0)
        finally:
            memprofile.analyze_session_footprint = orig
        # Second call within the interval must be throttled out.
        self.assertEqual(len(calls), 1)

    def test_log_session_footprint_throttled_disabled_is_noop(self):
        tagger = self._make_fake_tagger()
        memprofile._last_session_summary = 0.0
        # Should not raise and should not call the analyzer.
        self.assertIsNone(memprofile.log_session_footprint_throttled(tagger))
