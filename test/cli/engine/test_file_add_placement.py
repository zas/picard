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

"""`file add` applies the Workspace loaded-file placement policy.

Workspace.place_loaded_file holds the per-file placement policy (embedded-MBID
auto-move, etc). The engine's `file add` applies it so a file carrying a
release MBID is moved to its album instead of being left unclustered — matching
the GUI.
"""

from unittest.mock import (
    MagicMock,
    patch,
)

from test.picardtestcase import PicardTestCase

from picard.cli.engine.builtins import register_builtins
from picard.cli.engine.commands import EngineCommandRegistry
from picard.cli.engine.dispatch import dispatch
from picard.cli.engine.session import LocalEngineSession
from picard.file import File
from picard.util import (
    normpath,
    resolve_fs_path,
)
from picard.workspace import workspace


_VALID_ALBUM_MBID = '00000000-0000-0000-0000-000000000001'
_VALID_RECORDING_MBID = '00000000-0000-0000-0000-000000000002'


class FileAddPlacementTest(PicardTestCase):
    def setUp(self):
        super().setUp()
        self.patch_tagger_instance('picard.item')
        self.set_config_values(
            setting={
                'ignore_file_mbids': False,
                'analyze_new_files': False,
                'cluster_new_files': False,
            }
        )
        self.tagger.acoustid_manager = MagicMock()
        self.tagger.isrc_submit_manager = MagicMock()
        self.reg = EngineCommandRegistry()
        register_builtins(self.reg)
        # LocalEngineSession.run_until_idle delegates to the app; a MagicMock
        # app makes it a no-op so loads/placements are observed synchronously.
        self.session = LocalEngineSession(MagicMock())
        self.wks = workspace()

    def _make_file(self, name, albumid=None, recordingid=None):
        # `file add` normalises paths like the GUI does; use the same form here.
        f = File(normpath(resolve_fs_path(name)))
        if albumid:
            f.metadata['musicbrainz_albumid'] = albumid
        if recordingid:
            f.metadata['musicbrainz_recordingid'] = recordingid
        # Pretend the load already succeeded (the registry.open + file.load are
        # patched); place_loaded_file only inspects metadata/state.
        f.state = File.State.NORMAL
        return f

    def _dispatch_add(self, files):
        # Patch path expansion and the format registry so `file add` operates on
        # our in-memory File objects without touching disk.
        paths = [f.filename for f in files]
        by_path = {f.filename: f for f in files}
        with (
            patch('picard.cli.engine.builtins._expand_input_paths', return_value=(paths, [])),
            patch('picard.cli.engine.builtins.services') as mock_services,
            patch.object(File, 'load', lambda self, cb=None: None),
        ):
            mock_services.return_value.format_registry.open.side_effect = lambda p: by_path[p]
            return dispatch(self.session, self.reg, 'file add x')

    def test_already_loaded_file_is_not_added_twice(self):
        f = self._make_file('plain.flac')
        first = self._dispatch_add([f])
        self.assertEqual(['added'], [it.status for it in first.items])

        # Adding the same path again must not open a second File.
        second = self._dispatch_add([f])
        self.assertTrue(second.ok)
        self.assertEqual(['already_loaded'], [it.status for it in second.items])
        self.assertEqual(first.items[0].handle, second.items[0].handle)
        self.assertEqual([], second.mints)
        self.assertEqual(1, len(self.wks.unclustered_files.files))
        self.assertIs(f, self.wks.files[f.filename])

    def test_file_with_album_mbid_is_moved_to_album(self):
        f = self._make_file('tagged.flac', albumid=_VALID_ALBUM_MBID)
        with patch.object(self.wks, 'move_file_to_album') as mock_move:
            result = self._dispatch_add([f])
            self.assertTrue(result.ok)
            mock_move.assert_called_once_with(f, _VALID_ALBUM_MBID)

    def test_file_with_album_and_recording_mbid_moved_to_track(self):
        f = self._make_file('tagged.flac', albumid=_VALID_ALBUM_MBID, recordingid=_VALID_RECORDING_MBID)
        with patch.object(self.wks, 'move_file_to_track') as mock_move:
            result = self._dispatch_add([f])
            self.assertTrue(result.ok)
            mock_move.assert_called_once_with(f, _VALID_ALBUM_MBID, _VALID_RECORDING_MBID)

    def test_untagged_file_is_not_auto_moved(self):
        f = self._make_file('plain.flac')
        with (
            patch.object(self.wks, 'move_file_to_album') as mock_album,
            patch.object(self.wks, 'move_file_to_track') as mock_track,
            patch.object(self.wks, 'move_file_to_nat') as mock_nat,
        ):
            result = self._dispatch_add([f])
            self.assertTrue(result.ok)
            mock_album.assert_not_called()
            mock_track.assert_not_called()
            mock_nat.assert_not_called()

    def test_ignore_file_mbids_disables_auto_move(self):
        self.set_config_values(setting={'ignore_file_mbids': True})
        f = self._make_file('tagged.flac', albumid=_VALID_ALBUM_MBID)
        with patch.object(self.wks, 'move_file_to_album') as mock_move:
            result = self._dispatch_add([f])
            self.assertTrue(result.ok)
            mock_move.assert_not_called()
