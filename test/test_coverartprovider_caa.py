# -*- coding: utf-8 -*-
#
# Picard, the next-generation MusicBrainz tagger
#
# Copyright (C) 2020-2021 Philipp Wolfer
# Copyright (C) 2020-2022 Laurent Monin
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


from test.picardtestcase import PicardTestCase

from picard.coverart.processing.filters import size_metadata_filter
from picard.coverart.providers.caa import caa_url_fallback_list


class CoverArtImageProviderCaaTest(PicardTestCase):
    def test_caa_url_fallback_list(self):
        def do_tests(sizes, expectations):
            # we create a dummy url named after matching size
            thumbnails = {size: "url %s" % size for size in sizes}
            msgfmt = "for size %s, with sizes %r, got %r, expected %r"
            for size, expect in expectations.items():
                result = [thumbnail.url for thumbnail in caa_url_fallback_list(size, thumbnails)]
                self.assertEqual(result, expect, msg=msgfmt % (size, sizes, result, expect))

        # For historical reasons, caa web service returns 2 identical urls,
        # for 2 different keys (250/small, 500/large)
        # Here is an example of the json relevant part:
        # "thumbnails": {
        #   "250": "http://coverartarchive.org/release/d20247ad-940e-486d-948f-be4c17024ab9/24885128253-250.jpg",
        #   "500": "http://coverartarchive.org/release/d20247ad-940e-486d-948f-be4c17024ab9/24885128253-500.jpg",
        #   "1200": "http://coverartarchive.org/release/d20247ad-940e-486d-948f-be4c17024ab9/24885128253-1200.jpg",
        #   "large": "http://coverartarchive.org/release/d20247ad-940e-486d-948f-be4c17024ab9/24885128253-500.jpg",
        #   "small": "http://coverartarchive.org/release/d20247ad-940e-486d-948f-be4c17024ab9/24885128253-250.jpg"
        # },
        sizes = ("250", "500", "1200", "large", "small")
        expectations = {
            50: [],
            250: ['url 250'],
            400: ['url 250'],
            500: ['url 500', 'url 250'],
            600: ['url 500', 'url 250'],
            1200: ['url 1200', 'url 500', 'url 250'],
            1500: ['url 1200', 'url 500', 'url 250'],
        }
        do_tests(sizes, expectations)

        # Some older releases have no 1200px thumbnail
        sizes = ("250", "500", "large", "small")
        expectations = {
            50: [],
            250: ['url 250'],
            400: ['url 250'],
            500: ['url 500', 'url 250'],
            600: ['url 500', 'url 250'],
            1200: ['url 500', 'url 250'],
            1500: ['url 500', 'url 250'],
        }
        do_tests(sizes, expectations)

        # In the future, large and small might be removed or new size added
        # test if we can handle that (through size aliases)
        sizes = ("small", "large", "1200", "2000", "unknownsize")
        expectations = {
            50: [],
            250: ['url small'],
            400: ['url small'],
            500: ['url large', 'url small'],
            600: ['url large', 'url small'],
            1200: ['url 1200', 'url large', 'url small'],
            1500: ['url 1200', 'url large', 'url small'],
        }
        do_tests(sizes, expectations)

        with self.assertRaises(TypeError):
            caa_url_fallback_list("not_an_integer", {"250": "url 250"})

        with self.assertRaises(AttributeError):
            caa_url_fallback_list(250, 666)

    def test_size_metadata_filter_with_thumbnail_width(self):
        """PICARD-3276: Metadata filter should not discard images based on thumbnail size.

        When caa_image_size is set to a thumbnail (e.g. 500px) and the minimum
        size filter is set higher (e.g. 1200px), the metadata filter incorrectly
        compares the thumbnail width against the minimum, discarding the image
        before it's even downloaded — even though the full-size image would pass.
        """
        # User settings: discard images below 1200px
        self.set_config_values(
            {
                'filter_cover_by_size': True,
                'cover_minimum_width': 1200,
                'cover_minimum_height': 1200,
            }
        )

        # Simulate what the CAA provider does: it passes thumbnail width to the filter
        # with height=-1 (unknown). With caa_image_size=500 (default), the thumbnail
        # is 500px wide, but the actual full image could be much larger (e.g. 1500px).
        thumbnail_metadata = {'width': 500, 'height': -1}

        # BUG: This returns False, silently discarding the image.
        # The filter should not reject images based on thumbnail dimensions alone,
        # since the actual image will be resized after download anyway.
        result = size_metadata_filter(thumbnail_metadata)

        # Currently this FAILS — the image is incorrectly discarded.
        # Once fixed, the thumbnail should not be rejected by the size filter
        # because the height is unknown (-1) and the width represents a thumbnail,
        # not the actual image.
        self.assertTrue(
            result,
            "Image incorrectly discarded: thumbnail width (500) compared "
            "against minimum size (1200), but actual image may be larger",
        )
