# -*- coding: utf-8 -*-
#
# Picard, the next-generation MusicBrainz tagger
#
# Copyright (C) 2013-2014 Michael Wiencek
# Copyright (C) 2013-2016, 2018-2024 Laurent Monin
# Copyright (C) 2014, 2017 Lukáš Lalinský
# Copyright (C) 2014, 2018-2026 Philipp Wolfer
# Copyright (C) 2015 Ohm Patel
# Copyright (C) 2016 Suhas
# Copyright (C) 2016-2017 Sambhav Kothari
# Copyright (C) 2021 Gabriel Ferreira
# Copyright (C) 2021, 2023 Bob Swift
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

from inspect import (
    getmembers,
    isfunction,
)
import sys

from picard import PICARD_VERSION
from picard.config_changes import (
    UPGRADE_FUNCTION_PREFIX,
    rename_option,
    temp_option,
)
from picard.version import (
    Version,
    VersionError,
)


# Re-export helpers so existing external imports keep working
__all__ = [
    'UpgradeHooksAutodetectError',
    'autodetect_upgrade_hooks',
    'rename_option',
    'temp_option',
    'upgrade_config',
]


class UpgradeHooksAutodetectError(Exception):
    pass


def autodetect_upgrade_hooks(module_name=None, prefix=UPGRADE_FUNCTION_PREFIX):
    """Detect upgrade hooks methods from config_changes module"""

    if module_name is None:
        import picard.config_changes

        module_name = picard.config_changes.__name__

    def is_upgrade_hook(f):
        """Check if passed function is an upgrade hook"""
        return isfunction(f) and f.__module__ == module_name and f.__name__.startswith(prefix)

    # Build a dict with version as key and function as value
    hooks = dict()
    for name, hook in getmembers(sys.modules[module_name], predicate=is_upgrade_hook):
        try:
            version = Version.from_string(name[len(prefix) :])
        except VersionError as e:
            raise UpgradeHooksAutodetectError("Failed to extract version from %s()" % hook.__name__) from e
        if version in hooks:
            raise UpgradeHooksAutodetectError(
                "Conflicting functions for version %s: %s vs %s" % (version, hooks[version], hook)
            )
        if version > PICARD_VERSION:
            raise UpgradeHooksAutodetectError(
                "Upgrade hook %s has version %s > Picard version %s" % (hook.__name__, version, PICARD_VERSION)
            )
        hooks[version] = hook

    return dict(sorted(hooks.items()))


def upgrade_config(config):
    """Execute detected upgrade hooks"""
    config.run_upgrade_hooks(autodetect_upgrade_hooks())
