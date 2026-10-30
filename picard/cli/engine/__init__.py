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

"""Headless command engine substrate.

The shared, frontend-agnostic machinery a human console and an AI-agent (MCP)
frontend both drive: session-local entity handles, a selector resolver, a
command registry returning structured Results, and the session object tying
them to a HeadlessTagger / Workspace.

See the design doc at ``docs/CommandEngine.md`` for the target contract (two
backends — local/headless and remote/GUI — one command vocabulary). Only the
minimal extensible substrate is built here; commands, backends and the full
selector grammar are added incrementally.
"""
