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

"""`disc read` / `disc read-log` commands: identify a disc and load it.

The disc core is GUI-free: Disc.read reads a physical CD's TOC and Disc.read_log
parses a ripper log, both feeding the disc_presentation facade which auto-loads
a single match headless. The discid/drive/network bits are mocked; the tests
drive the commands end to end against the Workspace.
"""

from unittest.mock import (
    MagicMock,
    patch,
)

from test.picardtestcase import PicardTestCase

from picard.album import Album
from picard.cli.engine.builtins import register_builtins
from picard.cli.engine.commands import EngineCommandRegistry
from picard.cli.engine.dispatch import dispatch
from picard.cli.engine.session import LocalEngineSession
import picard.disc
from picard.disc.presentation import disc_presentation
from picard.workspace import workspace


class DiscReadLogCommandTest(PicardTestCase):
    def setUp(self):
        super().setUp()
        self.patch_tagger_instance('picard.item')
        self.reg = EngineCommandRegistry()
        register_builtins(self.reg)
        self.session = LocalEngineSession(MagicMock())
        self.wks = workspace()

    def test_missing_discid_library_fails(self):
        with patch.object(picard.disc, 'discid', None):
            result = dispatch(self.session, self.reg, 'disc read-log /some/rip.log')
        self.assertFalse(result.ok)

    def test_requires_a_path(self):
        with patch.object(picard.disc, 'discid', MagicMock()):
            result = dispatch(self.session, self.reg, 'disc read-log')
        self.assertFalse(result.ok)

    def test_parse_failure_is_reported(self):
        with (
            patch.object(picard.disc, 'discid', MagicMock()),
            patch.object(picard.disc.Disc, 'read_log', side_effect=Exception("bad log")),
        ):
            result = dispatch(self.session, self.reg, 'disc read-log /some/rip.log')
        self.assertFalse(result.ok)

    def test_single_match_loads_and_reports_album(self):
        # read_log sets the disc id (would come from discid.put); lookup()
        # stands in for the TOC lookup whose facade auto-load adds an album and
        # records it on the disc-presentation facade.
        def fake_read_log(self_disc, path):
            self_disc.id = 'disc-xyz'

        def fake_lookup(self_disc):
            disc_presentation().present_releases(self_disc, [{'id': 'rel-1'}])

        with (
            patch.object(picard.disc, 'discid', MagicMock()),
            patch.object(picard.disc.Disc, 'read_log', fake_read_log),
            patch.object(picard.disc.Disc, 'lookup', fake_lookup),
            patch.object(self.wks, 'load_album', return_value=Album('rel-1')),
        ):
            result = dispatch(self.session, self.reg, 'disc read-log /some/rip.log')

        self.assertTrue(result.ok)
        self.assertEqual(1, len(result.items))
        self.assertEqual('loaded', result.items[0].status)
        self.assertEqual(1, len(result.mints))
        self.assertTrue(result.mints[0].startswith('a'))

    def test_already_loaded_release_still_reports_match(self):
        # Regression: a release already in the session is reported as a match,
        # not a spurious no_match (the command reads the facade, not a registry
        # diff).
        def fake_read_log(self_disc, path):
            self_disc.id = 'disc-xyz'

        existing = Album('rel-1')
        self.wks.albums['rel-1'] = existing

        def fake_lookup(self_disc):
            disc_presentation().present_releases(self_disc, [{'id': 'rel-1'}])

        with (
            patch.object(picard.disc, 'discid', MagicMock()),
            patch.object(picard.disc.Disc, 'read_log', fake_read_log),
            patch.object(picard.disc.Disc, 'lookup', fake_lookup),
            patch.object(self.wks, 'load_album', return_value=existing),
        ):
            result = dispatch(self.session, self.reg, 'disc read-log /some/rip.log')

        self.assertTrue(result.ok)
        self.assertEqual(1, len(result.items))
        self.assertEqual('loaded', result.items[0].status)

    def test_no_match_reports_no_match(self):
        def fake_read_log(self_disc, path):
            self_disc.id = 'disc-xyz'

        def fake_lookup(self_disc):
            # Facade found nothing / ambiguous: no album added.
            pass

        with (
            patch.object(picard.disc, 'discid', MagicMock()),
            patch.object(picard.disc.Disc, 'read_log', fake_read_log),
            patch.object(picard.disc.Disc, 'lookup', fake_lookup),
        ):
            result = dispatch(self.session, self.reg, 'disc read-log /some/rip.log')

        self.assertTrue(result.ok)
        self.assertEqual(1, len(result.items))
        self.assertEqual('no_match', result.items[0].status)
        self.assertEqual([], result.mints)


class DiscReadCommandTest(PicardTestCase):
    def setUp(self):
        super().setUp()
        self.patch_tagger_instance('picard.item')
        self.reg = EngineCommandRegistry()
        register_builtins(self.reg)
        self.session = LocalEngineSession(MagicMock())
        self.wks = workspace()

    def test_missing_discid_library_fails(self):
        with patch.object(picard.disc, 'discid', None):
            result = dispatch(self.session, self.reg, 'disc read')
        self.assertFalse(result.ok)

    def test_read_failure_is_reported(self):
        with (
            patch.object(picard.disc, 'discid', MagicMock()),
            patch.object(picard.disc.Disc, 'read', side_effect=Exception("no disc in drive")),
        ):
            result = dispatch(self.session, self.reg, 'disc read /dev/cdrom')
        self.assertFalse(result.ok)

    def test_default_device_when_omitted(self):
        seen = {}

        def fake_read(self_disc, device=None):
            seen['device'] = device
            self_disc.id = 'disc-xyz'

        with (
            patch.object(picard.disc, 'discid', MagicMock()),
            patch.object(picard.disc.Disc, 'read', fake_read),
            patch.object(picard.disc.Disc, 'lookup', lambda self_disc: None),
        ):
            result = dispatch(self.session, self.reg, 'disc read')
        self.assertTrue(result.ok)
        # No device given -> None passed through (Disc.read resolves the default).
        self.assertIsNone(seen['device'])

    def test_explicit_device_is_passed_through(self):
        seen = {}

        def fake_read(self_disc, device=None):
            seen['device'] = device
            self_disc.id = 'disc-xyz'

        with (
            patch.object(picard.disc, 'discid', MagicMock()),
            patch.object(picard.disc.Disc, 'read', fake_read),
            patch.object(picard.disc.Disc, 'lookup', lambda self_disc: None),
        ):
            dispatch(self.session, self.reg, 'disc read /dev/sr0')
        self.assertEqual('/dev/sr0', seen['device'])

    def test_single_match_loads_and_reports_album(self):
        def fake_read(self_disc, device=None):
            self_disc.id = 'disc-xyz'

        def fake_lookup(self_disc):
            disc_presentation().present_releases(self_disc, [{'id': 'rel-1'}])

        with (
            patch.object(picard.disc, 'discid', MagicMock()),
            patch.object(picard.disc.Disc, 'read', fake_read),
            patch.object(picard.disc.Disc, 'lookup', fake_lookup),
            patch.object(self.wks, 'load_album', return_value=Album('rel-1')),
        ):
            result = dispatch(self.session, self.reg, 'disc read')

        self.assertTrue(result.ok)
        self.assertEqual(1, len(result.items))
        self.assertEqual('loaded', result.items[0].status)
        self.assertEqual(1, len(result.mints))
        self.assertTrue(result.mints[0].startswith('a'))

    def test_no_match_reports_no_match(self):
        def fake_read(self_disc, device=None):
            self_disc.id = 'disc-xyz'

        with (
            patch.object(picard.disc, 'discid', MagicMock()),
            patch.object(picard.disc.Disc, 'read', fake_read),
            patch.object(picard.disc.Disc, 'lookup', lambda self_disc: None),
        ):
            result = dispatch(self.session, self.reg, 'disc read')

        self.assertTrue(result.ok)
        self.assertEqual(1, len(result.items))
        self.assertEqual('no_match', result.items[0].status)
        self.assertEqual([], result.mints)
