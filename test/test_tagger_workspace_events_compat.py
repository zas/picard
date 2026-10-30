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

"""Backward-compatibility: plugins may connect to the Tagger's working-set
signals (``tagger.album_added`` etc.) via ``PluginApi.tagger``. The signals now
live on the WorkspaceEvents facade; Tagger re-emits them so those plugin
connections keep working. This verifies the facade -> Tagger forwarding set up
by ``Tagger._init_workspace_events`` without constructing the real QApplication.
"""

from PyQt6 import QtCore

from test.picardtestcase import PicardTestCase

from picard.album import Album
from picard.cluster import Cluster
from picard.file import File
from picard.tagger import Tagger
from picard.workspace_events import (
    set_workspace_events_provider,
    workspace_events,
)


class _TaggerSignalStand(QtCore.QObject):
    """Stand-in carrying the same working-set signals the Tagger declares.

    Lets us exercise Tagger._init_workspace_events as an unbound method without
    instantiating the QApplication singleton (only one may exist per process).

    The signals are declared with the SAME concrete entity types as the real
    Tagger (Album/Cluster/File, i.e. QObject*), not ``object``. This is what
    lets the test catch the facade (PyQt_PyObject) -> Tagger (QObject*) signal
    signature mismatch that a plain signal -> signal connect fails on.
    """

    album_added = QtCore.pyqtSignal(Album)
    album_removed = QtCore.pyqtSignal(Album)
    cluster_added = QtCore.pyqtSignal(Cluster)
    cluster_removed = QtCore.pyqtSignal(Cluster)
    file_loaded = QtCore.pyqtSignal(File)
    tagger_stats_changed = QtCore.pyqtSignal()


class TaggerWorkspaceEventsCompatTest(PicardTestCase):
    def setUp(self):
        super().setUp()
        self.addCleanup(set_workspace_events_provider, None)

    def test_facade_emissions_reach_tagger_signal_listeners(self):
        stand = _TaggerSignalStand()
        # Wire the facade exactly as the real Tagger does. With the stand's
        # signals declared as the real concrete entity types, this connect is
        # what regresses if the forwarding uses a plain signal -> signal
        # connect (Qt: "Incompatible sender/receiver arguments").
        Tagger._init_workspace_events(stand)

        received = []
        # A plugin-style connection on the Tagger object's signals.
        stand.album_added.connect(lambda obj: received.append(('album_added', obj)))
        stand.album_removed.connect(lambda obj: received.append(('album_removed', obj)))
        stand.cluster_added.connect(lambda obj: received.append(('cluster_added', obj)))
        stand.cluster_removed.connect(lambda obj: received.append(('cluster_removed', obj)))
        stand.file_loaded.connect(lambda obj: received.append(('file_loaded', obj)))
        stand.tagger_stats_changed.connect(lambda: received.append(('stats', None)))

        # Core/internal code emits on the facade. The facade carries ``object``;
        # emitting None is accepted by the typed Tagger signals and avoids
        # constructing heavy Album/Cluster/File instances here.
        events = workspace_events()
        events.album_added.emit(None)
        events.album_removed.emit(None)
        events.cluster_added.emit(None)
        events.cluster_removed.emit(None)
        events.file_loaded.emit(None)
        events.tagger_stats_changed.emit()

        # Each facade emission is forwarded to the matching Tagger signal.
        self.assertEqual(
            received,
            [
                ('album_added', None),
                ('album_removed', None),
                ('cluster_added', None),
                ('cluster_removed', None),
                ('file_loaded', None),
                ('stats', None),
            ],
        )
