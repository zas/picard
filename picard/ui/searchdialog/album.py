# -*- coding: utf-8 -*-
#
# Picard, the next-generation MusicBrainz tagger
#
# Copyright (C) 2016 Rahul Raturi
# Copyright (C) 2018-2022 Philipp Wolfer
# Copyright (C) 2018-2024 Laurent Monin
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.


from functools import partial

from PyQt6 import (
    QtCore,
    QtGui,
    QtWidgets,
)
from PyQt6.QtCore import pyqtSignal

from picard import log
from picard.config import get_config
from picard.const import CAA_URL
from picard.i18n import N_
from picard.mbjson import (
    countries_from_node,
    media_formats_from_node,
    release_group_to_metadata,
    release_to_metadata,
)
from picard.metadata import Metadata
from picard.util import countries_shortlist
from picard.webservice.api_helpers import build_lucene_query

from picard.ui.columns import (
    Column,
    ColumnAlign,
    Columns,
    ColumnSortType,
    ImageColumn,
)
from picard.ui.searchdialog import (
    Retry,
    SearchDialog,
)


class CoverWidget(QtWidgets.QWidget):

    shown = pyqtSignal()

    def __init__(self, size, parent=None):
        super().__init__(parent=parent)
        self.layout = QtWidgets.QVBoxLayout(self)
        self.destroyed.connect(self.invalidate)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.loading_gif_label = QtWidgets.QLabel(self)
        self.loading_gif_label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        loading_gif = QtGui.QMovie(":/images/loader.gif")
        self.loading_gif_label.setMovie(loading_gif)
        loading_gif.start()
        self.layout.addWidget(self.loading_gif_label)
        self.__sizehint = self.__size = QtCore.QSize(size, size)
        self.setStyleSheet("padding: 0")

    def set_pixmap(self, pixmap):
        if not self.layout:
            return
        wid = self.layout.takeAt(0)
        if wid:
            wid.widget().deleteLater()
        cover_label = QtWidgets.QLabel(self)
        pixmap = pixmap.scaled(self.__size, QtCore.Qt.AspectRatioMode.KeepAspectRatio,
                               QtCore.Qt.TransformationMode.SmoothTransformation)
        self.__sizehint = pixmap.size()
        cover_label.setPixmap(pixmap)
        self.layout.addWidget(cover_label)

    def not_found(self):
        """Update the widget with a blank image."""
        shadow = QtGui.QPixmap(":/images/CoverArtShadow.png")
        self.set_pixmap(shadow)

    def sizeHint(self):
        return self.__sizehint

    def showEvent(self, event):
        super().showEvent(event)
        self.shown.emit()

    def invalidate(self):
        self.layout = None


class CoverCell:

    def __init__(self, table, row, column, mbid, size, on_show=None):
        self.table = table
        self.row = row
        self.column = column
        self.mbid = mbid
        self.size = size
        self.on_show = on_show
        self.fetched = False
        self.fetch_task = None
        self.widget = CoverWidget(self.size)
        self.widget.destroyed.connect(self.invalidate)
        if self.on_show is not None:
            self.widget.shown.connect(partial(self.on_show, self))
        self.table.setCellWidget(row, column, self.widget)

    def is_visible(self):
        if self.widget:
            return self.table.cell_is_visible(self.row, self.column)
        return False

    def set_pixmap(self, pixmap):
        if self.widget:
            self.widget.set_pixmap(pixmap)

    def not_found(self):
        if self.widget:
            self.widget.not_found()

    def invalidate(self):
        if self.widget:
            self.widget = None

    def __repr__(self):
        return (
            "{c}("
            "{o.table!r}, {o.row!r}, {o.column!r}, "
            "{o.mbid!r}, {o.size!r}, on_show={o.on_show!r})"
        ).format(c=self.__class__.__name__, o=self)


class CoverColumn(ImageColumn):
    pass


class AlbumSearchDialog(SearchDialog):

    dialog_header_state = 'albumsearchdialog_header_state'

    def __init__(self, parent, force_advanced_search=None, existing_album=None):
        self.columns = Columns((
            Column(N_("Name"), 'album', sort_type=ColumnSortType.NAT, width=150),
            Column(N_("Comment"), '~releasecomment'),
            Column(N_("Artist"), 'albumartist'),
            Column(N_("Format"), 'format'),
            Column(N_("Tracks"), 'tracks', sort_type=ColumnSortType.NAT, align=ColumnAlign.RIGHT),
            Column(N_("Date"), 'date'),
            Column(N_("Country"), 'country'),
            Column(N_("Labels"), 'label'),
            Column(N_("Catalog #s"), 'catalognumber', sort_type=ColumnSortType.NAT),
            Column(N_("Barcode"), 'barcode', sort_type=ColumnSortType.NAT),
            Column(N_("Language"), '~releaselanguage'),
            Column(N_("Type"), 'releasetype'),
            Column(N_("Status"), 'releasestatus'),
            CoverColumn(N_("Cover"), 'cover', width=100),
            Column(N_("Score"), 'score', sort_type=ColumnSortType.NAT, align=ColumnAlign.RIGHT, width=50),
        ), default_width=100)
        super().__init__(
            parent,
            N_("Album Search Results"),
            accept_button_title=N_("Load into Picard"),
            search_type='album',
            force_advanced_search=force_advanced_search)
        self.cluster = None
        self.existing_album = existing_album
        self.cover_cells = []
        self.fetching = False
        self.scrolled.connect(self.fetch_coverarts)
        self.resized.connect(self.fetch_coverarts)

    @staticmethod
    def show_releasegroup_search(releasegroup_id, existing_album=None):
        tagger = QtCore.QCoreApplication.instance()
        dialog = AlbumSearchDialog(
            tagger.window,
            force_advanced_search=True,
            existing_album=existing_album)
        dialog.search("rgid:{0}".format(releasegroup_id))
        dialog.exec()
        return dialog

    def search(self, text):
        """Perform search using query provided by the user."""
        if self.fetching:
            self.fetch_cleanup()
            self.fetching = False
        self.retry_params = Retry(self.search, text)
        self.search_box_text(text)
        self.show_progress()
        config = get_config()
        self.tagger.mb_api.find_releases(self.handle_reply,
                                         query=text,
                                         search=True,
                                         advanced_search=self.use_advanced_search,
                                         limit=config.setting['query_limit'])

    def show_similar_albums(self, cluster):
        """Perform search by using existing metadata information
        from the cluster as query."""
        self.cluster = cluster
        metadata = cluster.metadata
        query = {
            "artist": metadata["albumartist"],
            "release": metadata["album"],
            "tracks": str(len(cluster.files))
        }

        # If advanced query syntax setting is enabled by user, query in
        # advanced syntax style. Otherwise query only album title.
        if self.use_advanced_search:
            query_str = build_lucene_query(query)
        else:
            query_str = query['release']
        self.search(query_str)

    def retry(self):
        self.retry_params.function(self.retry_params.query)

    def handle_reply(self, document, http, error):
        if error:
            self.network_error(http, error)
            return

        try:
            releases = document['releases']
        except (KeyError, TypeError):
            self.no_results_found()
            return

        del self.search_results[:]
        self.parse_releases(releases)
        self.display_results()
        self.fetch_coverarts()

    def fetch_coverarts(self):
        if self.fetching:
            return
        self.fetching = True
        for cell in self.cover_cells:
            self.fetch_coverart(cell)
        self.fetching = False

    def fetch_coverart(self, cell):
        """Queue cover art jsons from CAA server for each album in search
        results.
        """
        if cell.fetched:
            return
        if not cell.is_visible():
            return
        log.debug("Fetching cover art for row %d: release %s", cell.row + 1, cell.mbid)
        cell.fetched = True
        cell.fetch_task = self.tagger.webservice.get_url(
            url=f'{CAA_URL}/release/{cell.mbid}',
            handler=partial(self._caa_json_downloaded, cell),
        )

    def _caa_json_downloaded(self, cover_cell, data, http, error):
        """Handle json reply from CAA server.
        If server replies without error, try to get small thumbnail of front
        coverart of the release.
        """
        cover_cell.fetch_task = None

        if error:
            cover_cell.not_found()
            return

        front = None
        try:
            for image in data['images']:
                if image['front']:
                    front = image
                    break

            if front:
                cover_cell.fetch_task = self.tagger.webservice.download_url(
                    url=front['thumbnails']['small'],
                    handler=partial(self._cover_downloaded, cover_cell)
                )
            else:
                cover_cell.not_found()
        except (AttributeError, KeyError, TypeError):
            log.error("Error reading CAA response", exc_info=True)
            cover_cell.not_found()

    def _cover_downloaded(self, cover_cell, data, http, error):
        """Handle cover art query reply from CAA server.
        If server returns the cover image successfully, update the cover art
        cell of particular release.

        Args:
            row -- Album's row in results table
        """
        cover_cell.fetch_task = None

        if error:
            cover_cell.not_found()
        else:
            pixmap = QtGui.QPixmap()
            try:
                pixmap.loadFromData(data)
                cover_cell.set_pixmap(pixmap)
            except Exception as e:
                cover_cell.not_found()
                log.error(e)

    def fetch_cleanup(self):
        for cell in self.cover_cells:
            if cell.fetch_task is not None:
                log.debug("Removing cover art fetch task for %s", cell.mbid)
                self.tagger.webservice.remove_task(cell.fetch_task)
                cell.fetch_task = None

    def closeEvent(self, event):
        if self.cover_cells:
            self.fetch_cleanup()
        super().closeEvent(event)

    def parse_releases(self, releases):
        for node in releases:
            release = Metadata()
            release_to_metadata(node, release)
            release['score'] = node['score']
            rg_node = node['release-group']
            release_group_to_metadata(rg_node, release)
            if 'media' in node:
                media = node['media']
                release['format'] = media_formats_from_node(media)
                release['tracks'] = node['track-count']
            countries = countries_from_node(node)
            if countries:
                release['country'] = countries_shortlist(countries)
            self.search_results.append(release)

    def display_results(self):
        self.prepare_table()
        self.cover_cells = []
        cover_pos = self.columns.pos('cover')
        cover_size = self.columns[cover_pos].width
        vheader = self.table.verticalHeader()
        vheader.setDefaultSectionSize(cover_size)
        for row, release in enumerate(self.search_results):
            self.table.insertRow(row)
            for pos, c in enumerate(self.columns):
                if isinstance(c, CoverColumn):
                    self.cover_cells.append(CoverCell(
                        self.table, row, pos,
                        release['musicbrainz_albumid'],
                        cover_size,
                        on_show=self.fetch_coverart
                    ))
                else:
                    self.set_table_item_value(row, pos, c, release)
            if self.existing_album and release['musicbrainz_albumid'] == self.existing_album.id:
                self.highlight_row(row)
        self.show_table(sort_column='score')

    def accept_event(self, rows):
        for row in rows:
            self.load_selection(row)

    def load_selection(self, row):
        release = self.search_results[row]
        release_mbid = release['musicbrainz_albumid']
        if self.existing_album:
            self.existing_album.switch_release_version(release_mbid)
        else:
            self.tagger.get_release_group_by_id(
                release['musicbrainz_releasegroupid']).loaded_albums.add(
                    release_mbid)
            album = self.tagger.load_album(release_mbid)
            if self.cluster:
                files = self.cluster.iterfiles()
                self.tagger.move_files_to_album(files, release_mbid, album)
