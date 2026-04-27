# -*- coding: utf-8 -*-
#
# Picard, the next-generation MusicBrainz tagger
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
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

from inspect import (
    getmembers,
    isfunction,
)
import sys

from picard.config_changes import DOWNGRADE_FUNCTION_PREFIX
from picard.version import (
    Version,
    VersionError,
)


class DowngradeHooksAutodetectError(Exception):
    pass


def autodetect_downgrade_hooks(module_name=None, prefix=DOWNGRADE_FUNCTION_PREFIX):
    """Detect downgrade hooks methods from config_changes module.

    Returns a dict sorted in descending version order, since downgrade
    hooks must run from newest to oldest.
    """

    if module_name is None:
        import picard.config_changes

        module_name = picard.config_changes.__name__

    def is_downgrade_hook(f):
        return isfunction(f) and f.__module__ == module_name and f.__name__.startswith(prefix)

    hooks = dict()
    for name, hook in getmembers(sys.modules[module_name], predicate=is_downgrade_hook):
        try:
            version = Version.from_string(name[len(prefix) :])
        except VersionError as e:
            raise DowngradeHooksAutodetectError("Failed to extract version from %s()" % hook.__name__) from e
        if version in hooks:
            raise DowngradeHooksAutodetectError(
                "Conflicting functions for version %s: %s vs %s" % (version, hooks[version], hook)
            )
        hooks[version] = hook

    return dict(sorted(hooks.items(), reverse=True))


def downgrade_config(config):
    """Execute detected downgrade hooks"""
    config.run_downgrade_hooks(autodetect_downgrade_hooks())
