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

import json
from unittest.mock import (
    MagicMock,
    patch,
)

from test.picardtestcase import PicardTestCase
from test.test_matching import settings as _matching_settings

from picard.cli.engine.builtins import register_builtins
from picard.cli.engine.commands import EngineCommandRegistry
from picard.cli.engine.dispatch import dispatch
from picard.cli.engine.session import LocalEngineSession
from picard.cluster import Cluster
from picard.workspace import workspace


def _release(mbid, title, artist='The Artist', score=100):
    return {
        'id': mbid,
        'title': title,
        'score': score,
        'artist-credit': [{'artist': {'name': artist, 'sort-name': artist}, 'name': artist}],
    }


class ClusterLookupCommandTest(PicardTestCase):
    def setUp(self):
        super().setUp()
        self.patch_tagger_instance('picard.item')
        # Reuse the matching test's realistic config, plus lookup thresholds.
        self.set_config_values(
            setting={
                **_matching_settings,
                'match_min_similarity': 0.1,
                'match_min_margin': 0.0,
                'query_limit': 25,
                'always_standardize_multivalue_artist': False,
            }
        )
        # Services used along the lookup/move path (mock provider is the tagger).
        self.tagger.mb_api = MagicMock()
        self.tagger.acoustidmanager = MagicMock()
        self.tagger.isrc_submit_manager = MagicMock()

        self.reg = EngineCommandRegistry()
        register_builtins(self.reg)
        self.session = LocalEngineSession(MagicMock())

        self.cluster = Cluster('Greatest Hits', 'The Artist')
        workspace().clusters.append(self.cluster)

        # Canned candidate releases: an exact title match and a weaker one.
        self.releases = [
            _release('mbid-weak', 'Something Else'),
            _release('mbid-best', 'Greatest Hits'),
        ]

        # find_releases invokes its callback synchronously with our document.
        def fake_find_releases(callback, **kwargs):
            callback({'releases': self.releases}, None, None)
            return MagicMock()  # a task handle

        self.tagger.mb_api.find_releases.side_effect = fake_find_releases

        # Stub the auto-apply so we don't actually load an album over the network.
        # Patch load_album / move_files_to_album on the real Workspace instance.
        # Return a real Album (classified as 'a') so handle_for() works.
        from picard.album import Album

        self._loaded = []

        def fake_load_album(mbid, **kwargs):
            album = Album(mbid)
            self._loaded.append(mbid)
            return album

        ws = workspace()
        p_load = patch.object(ws, 'load_album', side_effect=fake_load_album)
        p_move = patch.object(ws, 'move_files_to_album', MagicMock())
        p_load.start()
        p_move.start()
        self.addCleanup(p_load.stop)
        self.addCleanup(p_move.stop)

    def test_lookup_applies_best_and_exposes_candidates(self):
        result = dispatch(self.session, self.reg, 'cluster lookup')
        self.assertTrue(result.ok)
        self.assertEqual(1, len(result.items))
        item = result.items[0]
        self.assertEqual('matched', item.status)
        # Two candidates captured, exposed as m handles.
        cands = item.data['candidates']
        self.assertEqual(2, len(cands))
        self.assertTrue(all(c['handle'].startswith('m') for c in cands))
        # The exact-title release is the applied one.
        applied = [c for c in cands if c.get('applied')]
        self.assertEqual(1, len(applied))
        self.assertEqual('mbid-best', applied[0]['mbid'])
        # The best release was loaded as the matched album.
        self.assertIn('mbid-best', self._loaded)
        self.assertIsNotNone(item.data['matched_album'])

    def test_lookup_no_releases_reports_no_matches(self):
        self.releases = []

        def fake_find_releases(callback, **kwargs):
            callback({'releases': []}, None, None)
            return MagicMock()

        self.tagger.mb_api.find_releases.side_effect = fake_find_releases
        result = dispatch(self.session, self.reg, 'cluster lookup')
        self.assertEqual('no_matches', result.items[0].status)
        self.assertEqual([], result.items[0].data['candidates'])

    def test_lookup_result_serializable(self):
        result = dispatch(self.session, self.reg, 'cluster lookup')
        json.dumps(result.to_dict())

    def test_candidate_handles_resolve_for_match(self):
        result = dispatch(self.session, self.reg, 'cluster lookup')
        handle = result.items[0].data['candidates'][0]['handle']
        entities, unresolved = self.session.resolve(handle)
        self.assertEqual(1, len(entities))
        self.assertEqual([], unresolved)


class MatchCommandTest(ClusterLookupCommandTest):
    """Reuses the lookup test harness (mocked find_releases + load_album)."""

    def _lookup(self):
        result = dispatch(self.session, self.reg, 'cluster lookup')
        cluster_handle = result.items[0].handle
        cands = result.items[0].data['candidates']
        return cluster_handle, cands

    def test_match_applies_chosen_candidate(self):
        cluster_handle, cands = self._lookup()
        # Pick the candidate that was NOT auto-applied (the weaker one).
        other = next(c for c in cands if not c.get('applied'))
        result = dispatch(self.session, self.reg, f'match {cluster_handle} {other["handle"]}')
        self.assertTrue(result.ok)
        item = result.items[0]
        self.assertEqual('matched', item.status)
        self.assertEqual(other['handle'], item.data['candidate'])
        # The chosen candidate's release was loaded.
        self.assertIn('mbid-weak', self._loaded)

    def test_match_flips_applied_flag(self):
        cluster_handle, cands = self._lookup()
        other = next(c for c in cands if not c.get('applied'))
        dispatch(self.session, self.reg, f'match {cluster_handle} {other["handle"]}')
        # Re-describe the candidate set: the chosen one is now applied, sole.
        entities, _ = self.session.resolve('m*')
        applied = [c for c in entities if c.applied]
        self.assertEqual(1, len(applied))
        self.assertEqual(other['handle'], self.session.handle_for(applied[0]))

    def test_match_bad_usage_is_failure(self):
        self.assertFalse(dispatch(self.session, self.reg, 'match c1').ok)

    def test_match_unknown_candidate_unresolved(self):
        cluster_handle, _cands = self._lookup()
        result = dispatch(self.session, self.reg, f'match {cluster_handle} m99')
        self.assertFalse(result.ok)
        self.assertIn('m99', result.unresolved)
