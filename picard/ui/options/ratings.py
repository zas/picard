# -*- coding: utf-8 -*-
#
# Picard, the next-generation MusicBrainz tagger
#
# Copyright (C) 2008-2009, 2020-2021, 2025 Philipp Wolfer
# Copyright (C) 2012-2013 Michael Wiencek
# Copyright (C) 2018, 2020-2021, 2023-2024 Laurent Monin
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


from picard.config import get_config
from picard.extension_points.options_pages import register_options_page
from picard.i18n import N_

from picard.ui.forms.ui_options_ratings import Ui_RatingsOptionsPage
from picard.ui.options import OptionsPage


class RatingsOptionsPage(OptionsPage):

    NAME = 'ratings'
    TITLE = N_("Ratings")
    PARENT = 'metadata'
    SORT_ORDER = 20
    ACTIVE = True
    HELP_URL = "/config/options_ratings.html"

    OPTIONS = (
        ('enable_ratings', ['enable_ratings']),
        ('rating_user_email', ['rating_user_email']),
        ('submit_ratings', ['submit_ratings']),
    )

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.ui = Ui_RatingsOptionsPage()
        self.ui.setupUi(self)

    def load(self):
        config = get_config()
        self.ui.enable_ratings.setChecked(config.setting['enable_ratings'])
        self.ui.rating_user_email.setText(config.setting['rating_user_email'])
        self.ui.submit_ratings.setChecked(config.setting['submit_ratings'])

    def save(self):
        config = get_config()
        config.setting['enable_ratings'] = self.ui.enable_ratings.isChecked()
        config.setting['rating_user_email'] = self.ui.rating_user_email.text()
        config.setting['submit_ratings'] = self.ui.submit_ratings.isChecked()


register_options_page(RatingsOptionsPage)
