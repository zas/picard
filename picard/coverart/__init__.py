# -*- coding: utf-8 -*-
#
# Picard, the next-generation MusicBrainz tagger
#
# Copyright (C) 2007 Oliver Charles
# Copyright (C) 2007, 2010-2011 Lukáš Lalinský
# Copyright (C) 2007-2011, 2019-2024 Philipp Wolfer
# Copyright (C) 2011 Michael Wiencek
# Copyright (C) 2011-2012 Wieland Hoffmann
# Copyright (C) 2013-2015, 2018-2021, 2023-2024 Laurent Monin
# Copyright (C) 2016-2017 Sambhav Kothari
# Copyright (C) 2024 Giorgio Fontanive
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
import traceback

from PyQt6 import QtCore

from picard import log
from picard.config import get_config
from picard.coverart.image import CoverArtImageIOError
from picard.coverart.processing import (
    CoverArtImageProcessing,
    run_image_filters,
)
from picard.coverart.providers import (
    CoverArtProvider,
    cover_art_providers,
)
from picard.extension_points.metadata import register_album_metadata_processor
from picard.i18n import N_
from picard.util import imageinfo


class CoverArt:

    def __init__(self, album, metadata, release):
        self._queue_new()
        self.album = album
        self.metadata = metadata
        self.release = release  # not used in this class, but used by providers
        self.front_image_found = False
        self.image_processing = CoverArtImageProcessing(album)

    def __repr__(self):
        return "%s for %r" % (self.__class__.__name__, self.album)

    def retrieve(self):
        """Retrieve available cover art images for the release"""
        config = get_config()
        if config.setting['save_images_to_tags'] or config.setting['save_images_to_files']:
            self.providers = cover_art_providers()
            self.next_in_queue()
        else:
            log.debug("Cover art disabled by user options.")

    def _set_metadata(self, coverartimage, data, image_info):
        self.image_processing.run_image_processors(coverartimage, data, image_info)
        if coverartimage.can_be_saved_to_metadata:
            log.debug("Storing to metadata: %r", coverartimage)
            self.metadata.images.append(coverartimage)
            for track in self.album._new_tracks:
                track.metadata.images.append(coverartimage)
            # If the image already was a front image,
            # there might still be some other non-CAA front
            # images in the queue - ignore them.
            if not self.front_image_found:
                self.front_image_found = coverartimage.is_front_image()
        else:
            log.debug("Not storing to metadata: %r", coverartimage)

    def _coverart_downloaded(self, coverartimage, data, http, error):
        """Handle finished download, save it to metadata"""
        self.album._requests -= 1

        if error:
            self.album.error_append("Coverart error: %s" % http.errorString())
        elif len(data) < 1000:
            log.warning("Not enough data, skipping %s", coverartimage)
        else:
            self._message(
                N_("Cover art of type '%(type)s' downloaded for %(albumid)s from %(host)s"),
                {
                    'type': coverartimage.types_as_string(),
                    'albumid': self.album.id,
                    'host': coverartimage.url.host(),
                },
                echo=None
            )
            try:
                image_info = imageinfo.identify(data)
                filters_result = True
                if coverartimage.can_be_filtered:
                    filters_result = run_image_filters(data, image_info, self.album, coverartimage)
                if filters_result:
                    self._set_metadata(coverartimage, data, image_info)
            except imageinfo.IdentificationError as e:
                log.warning("Couldn't identify image %r: %s", coverartimage, e)
                return

        self.next_in_queue()

    def next_in_queue(self):
        """Downloads next item in queue.
           If there are none left, loading of album will be finalized.
        """
        if self.album.id not in self.album.tagger.albums:
            # album removed
            return

        config = get_config()
        if (self.front_image_found
            and config.setting['save_images_to_tags']
            and not config.setting['save_images_to_files']
            and config.setting['embed_only_one_front_image']):
            # no need to continue
            processing_result = self.image_processing.wait_for_processing()
            self.album._finalize_loading(error=processing_result)
            return

        if self._queue_empty():
            try:
                # requeue from next provider
                provider = next(self.providers)
                ret = CoverArtProvider._STARTED
                try:
                    instance = provider.cls(self)
                    if provider.enabled and instance.enabled():
                        log.debug("Trying cover art provider %s …", provider.name)
                        ret = instance.queue_images()
                    else:
                        log.debug("Skipping cover art provider %s …", provider.name)
                except BaseException:
                    log.error(traceback.format_exc())
                    raise
                finally:
                    if ret != CoverArtProvider.WAIT:
                        self.next_in_queue()
                return
            except StopIteration:
                # nothing more to do
                processing_result = self.image_processing.wait_for_processing()
                self.album._finalize_loading(error=processing_result)
                return

        # We still have some items to try!
        coverartimage = self._queue_get()
        if not coverartimage.support_types and self.front_image_found:
            # we already have one front image, no need to try other type-less
            # sources
            log.debug("Skipping %r, one front image is already available",
                      coverartimage)
            self.next_in_queue()
            return

        # local files
        if coverartimage.url and coverartimage.url.scheme() == 'file':
            try:
                path = coverartimage.url.toLocalFile()
                with open(path, 'rb') as file:
                    data = file.read()
                    image_info = imageinfo.identify(data)
                    self._set_metadata(coverartimage, data, image_info)
            except imageinfo.IdentificationError as e:
                log.error("Couldn't identify image file %r: %s", path, e)
            except OSError as exc:
                (errnum, errmsg) = exc.args
                log.error("Failed to read %r: %s (%d)", path, errmsg, errnum)
            except CoverArtImageIOError:
                # It doesn't make sense to store/download more images if we can't
                # save them in the temporary folder, abort.
                return
            self.next_in_queue()
            return

        # on the web
        self._message(
            N_("Downloading cover art of type '%(type)s' for %(albumid)s from %(host)s …"),
            {
                'type': coverartimage.types_as_string(),
                'albumid': self.album.id,
                'host': coverartimage.url.host(),
            },
            echo=None
        )
        log.debug("Downloading %r", coverartimage)
        self.album.tagger.webservice.download_url(
            url=coverartimage.url,
            handler=partial(self._coverart_downloaded, coverartimage),
            priority=True,
        )
        self.album._requests += 1

    def queue_put(self, coverartimage):
        """Add an image to queue"""
        log.debug("Queuing cover art image %r", coverartimage)
        self.__queue.append(coverartimage)

    def _queue_get(self):
        """Get next image and remove it from queue"""
        return self.__queue.pop(0)

    def _queue_empty(self):
        """Returns True if the queue is empty"""
        return not self.__queue

    def _queue_new(self):
        """Initialize the queue"""
        self.__queue = []

    def _message(self, *args, **kwargs):
        """Display message to status bar"""
        tagger = QtCore.QCoreApplication.instance()
        tagger.window.set_statusbar_message(*args, **kwargs)


def _retrieve_coverart(album, metadata, release):
    """Gets all cover art URLs from the metadata and then attempts to
    download the album art. """

    coverart = CoverArt(album, metadata, release)
    log.debug("New %r", coverart)
    coverart.retrieve()


register_album_metadata_processor(_retrieve_coverart)
