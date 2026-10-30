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


from test.picardtestcase import PicardTestCase

from picard.workspace_events import (
    WorkspaceEvents,
    set_workspace_events_provider,
    workspace_events,
)


class WorkspaceEventsTest(PicardTestCase):
    def test_process_wide_accessor_is_stable(self):
        self.assertIs(workspace_events(), workspace_events())
        self.assertIsInstance(workspace_events(), WorkspaceEvents)

    def test_set_provider_installs(self):
        provider = WorkspaceEvents()
        self.addCleanup(set_workspace_events_provider, None)
        set_workspace_events_provider(provider)
        self.assertIs(workspace_events(), provider)

    def test_set_provider_none_resets_to_fresh(self):
        provider = WorkspaceEvents()
        set_workspace_events_provider(provider)
        self.assertIs(workspace_events(), provider)
        set_workspace_events_provider(None)
        self.assertIsNot(workspace_events(), provider)

    def test_signals_deliver_to_connected_listener(self):
        events = WorkspaceEvents()
        received = []
        events.album_added.connect(lambda obj: received.append(('album_added', obj)))
        events.tagger_stats_changed.connect(lambda: received.append(('stats', None)))
        marker = object()
        events.album_added.emit(marker)
        events.tagger_stats_changed.emit()
        self.assertEqual(received, [('album_added', marker), ('stats', None)])

    def test_emit_without_listener_is_noop(self):
        events = WorkspaceEvents()
        # No listener connected; emitting must not raise (headless behaviour).
        events.album_removed.emit(object())
        events.cluster_added.emit(object())
        events.cluster_removed.emit(object())
        events.file_loaded.emit(object())
        events.tagger_stats_changed.emit()
