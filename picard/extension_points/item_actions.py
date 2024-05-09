# -*- coding: utf-8 -*-
#
# Picard, the next-generation MusicBrainz tagger
#
# Copyright (C) 2024 Laurent Monin
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

from PyQt6 import (
    QtCore,
    QtGui,
)

from picard.plugin import ExtensionPoint


class BaseAction(QtGui.QAction):
    NAME = "Unknown"
    MENU = []

    def __init__(self):
        super().__init__(self.NAME, None)
        self.tagger = QtCore.QCoreApplication.instance()
        self.triggered.connect(self.__callback)

    def __callback(self):
        objs = self.tagger.window.selected_objects
        self.callback(objs)

    def callback(self, objs):
        raise NotImplementedError


ext_point_album_actions = ExtensionPoint(label='album_actions')
ext_point_cluster_actions = ExtensionPoint(label='cluster_actions')
ext_point_clusterlist_actions = ExtensionPoint(label='clusterlist_actions')
ext_point_file_actions = ExtensionPoint(label='file_actions')
ext_point_track_actions = ExtensionPoint(label='track_actions')


def register_album_action(action):
    ext_point_album_actions.register(action.__module__, action)


def register_cluster_action(action):
    ext_point_cluster_actions.register(action.__module__, action)


def register_clusterlist_action(action):
    ext_point_clusterlist_actions.register(action.__module__, action)


def register_file_action(action):
    ext_point_file_actions.register(action.__module__, action)


def register_track_action(action):
    ext_point_track_actions.register(action.__module__, action)
