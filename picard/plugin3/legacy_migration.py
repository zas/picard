# Picard, the next-generation MusicBrainz tagger
#
# Copyright (C) 2026 Laurent Monin
# Copyright (C) 2026 Philipp Wolfer
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


"""Shared logic for migrating a user's Picard v1/v2 plugin selection to v3.

Picard v1/v2 stored the set of enabled plugins in the ``enabled_plugins``
setting as plain plugin IDs (the keys from the old ``plugins.json``), which had
no UUIDs. The Picard 3 config upgrade preserves that list instead of discarding
it, so it can later be used to preinstall the v3 equivalents.

This module provides the shared, side-effect-free planner and the two explicit
actions that both the CLI (``picard plugins migrate``) and the Plugins options
page use. The two actions are independent: a user may install the v3
equivalents, clear the old list, both, or neither.
"""

from collections import namedtuple

from picard import log
from picard.config import get_config


LEGACY_ENABLED_PLUGINS_OPTION = 'enabled_plugins'
DEFAULT_LEGACY_VERSION = '2'


# resolved: list of (legacy_id, RegistryPlugin) that have a v3 equivalent
# unresolved: list of legacy_id strings with no known v3 equivalent (yet)
LegacyMigrationPlan = namedtuple('LegacyMigrationPlan', ('resolved', 'unresolved'))


def get_pending_legacy_ids(config=None):
    """Return the list of pending legacy plugin IDs from config.

    ``enabled_plugins`` is an obsolete v1/v2 option with no registered Option in
    Picard 3, so it is read via ``raw_value`` (QStringList) rather than normal
    item access, which only resolves registered options.

    Args:
        config: Optional config object; defaults to the global config.

    Returns:
        list[str]: Legacy plugin IDs awaiting migration (empty if none).
    """
    if config is None:
        config = get_config()
    if config is None or LEGACY_ENABLED_PLUGINS_OPTION not in config.setting:
        return []
    value = config.setting.raw_value(LEGACY_ENABLED_PLUGINS_OPTION, qtype='QStringList')
    if not value:
        return []
    if isinstance(value, str):
        # A single-element list may come back as a bare string.
        return [value]
    return list(value)


def has_pending_legacy_migration(config=None):
    """Return True if there is a non-empty pending legacy plugin list."""
    return bool(get_pending_legacy_ids(config))


def plan_legacy_migration(registry, config=None, legacy_version=DEFAULT_LEGACY_VERSION):
    """Build a migration plan without any side effects.

    Resolves each pending legacy plugin ID to its v3 equivalent via the
    registry's ``legacy_id`` mapping, splitting them into resolved and
    unresolved groups. Does not install anything or modify config.

    Args:
        registry: PluginRegistry (must be loaded) used to resolve legacy IDs.
        config: Optional config object; defaults to the global config.
        legacy_version: Legacy plugin generation to resolve against (default '2').

    Returns:
        LegacyMigrationPlan: (resolved, unresolved).
    """
    resolved = []
    unresolved = []
    seen_plugin_ids = set()
    for legacy_id in get_pending_legacy_ids(config):
        registry_plugin = registry.find_plugin_by_legacy_id(legacy_id, legacy_version)
        if registry_plugin and registry_plugin.git_url:
            # Avoid queueing the same v3 plugin twice if two legacy IDs map to it.
            if registry_plugin.id in seen_plugin_ids:
                continue
            seen_plugin_ids.add(registry_plugin.id)
            resolved.append((legacy_id, registry_plugin))
        else:
            unresolved.append(legacy_id)
    return LegacyMigrationPlan(resolved=resolved, unresolved=unresolved)


def install_resolved_plugins(manager, plan):
    """Install and enable the v3 equivalents from a migration plan.

    Does not modify the pending legacy list; clearing is a separate, explicit
    action (see clear_legacy_list). Install failures are logged and skipped so
    one bad plugin does not abort the rest.

    Args:
        manager: PluginManager used to install plugins.
        plan: LegacyMigrationPlan from plan_legacy_migration.

    Returns:
        tuple[list, list]: (installed_legacy_ids, failed_legacy_ids).
    """
    installed = []
    failed = []
    for legacy_id, registry_plugin in plan.resolved:
        try:
            ref = manager.select_ref_for_plugin(registry_plugin)
            manager.install_plugin(
                registry_plugin.git_url,
                ref=ref,
                enable_after_install=True,
            )
            installed.append(legacy_id)
            log.info(
                'Installed v3 equivalent of legacy plugin %r: %s',
                legacy_id,
                registry_plugin.id,
            )
        except Exception as e:
            failed.append(legacy_id)
            log.warning('Failed to install v3 equivalent of legacy plugin %r: %s', legacy_id, e)
    return installed, failed


def clear_legacy_list(config=None):
    """Remove the pending legacy plugin list from config.

    This is the user's explicit choice and is independent of installing. If
    unresolved plugins remain, clearing forgets them; callers should warn the
    user before invoking this (see plan_legacy_migration().unresolved).

    Args:
        config: Optional config object; defaults to the global config.

    Returns:
        bool: True if the list existed and was removed, False otherwise.
    """
    if config is None:
        config = get_config()
    if config is None or LEGACY_ENABLED_PLUGINS_OPTION not in config.setting:
        return False
    config.setting.remove(LEGACY_ENABLED_PLUGINS_OPTION)
    log.debug('Cleared pending legacy plugin list')
    return True
