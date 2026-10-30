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

"""Turn a command line into a command invocation.

A frontend (console REPL or MCP) hands :func:`dispatch` a raw command line, the
registry, and the session. Dispatch resolves the ``noun verb`` name, checks the
command is available on this backend, parses the remaining tokens into the
command's declared positional args, and runs it — always returning an
:class:`~picard.cli.engine.result.EngineResult` (never raising to the frontend).

Argument parsing is intentionally minimal for now (shlex split into the
declared positional ``args``; the last arg soaks up the remainder). It grows
into typed params / flags later without changing call sites.
"""

import shlex

from picard.cli.engine.commands import (
    EngineCommandRegistry,
    EngineSession,
)
from picard.cli.engine.result import EngineResult


def split_command_name(tokens: list[str], registry: EngineCommandRegistry) -> 'tuple[str, list[str]]':
    """Split tokens into (command-name, remaining-args).

    Tries a two-word ``noun verb`` name first, then a one-word name, so both
    ``album save`` and ``ls`` resolve. Returns the longest matching registered
    name; if none matches, returns the best guess (two-word if two+ tokens)
    so the caller can report "unknown command".
    """
    if len(tokens) >= 2:
        two = f"{tokens[0]} {tokens[1]}"
        if two in registry:
            return two, tokens[2:]
    if tokens:
        one = tokens[0]
        if one in registry:
            return one, tokens[1:]
    # No match: prefer the two-word form for the error message when possible.
    if len(tokens) >= 2:
        return f"{tokens[0]} {tokens[1]}", tokens[2:]
    return (tokens[0] if tokens else ''), tokens[1:] if tokens else []


def dispatch(session: EngineSession, registry: EngineCommandRegistry, line: str) -> EngineResult:
    """Parse ``line`` and run the matching command against ``session``."""
    try:
        tokens = shlex.split(line)
    except ValueError as e:
        return EngineResult.failure(f"could not parse command line: {e}")
    if not tokens:
        return EngineResult.failure("empty command")

    name, rest = split_command_name(tokens, registry)
    command = registry.get(name)
    if command is None:
        return EngineResult.failure(f"unknown command: {name!r}")

    if command.availability.value == 'gui' and not session.is_gui:
        return EngineResult.failure(f"command {name!r} requires a GUI backend")

    args = _bind_args(command.args, rest)
    try:
        return command.run(session, args)
    except Exception as e:  # a command bug must not crash the frontend
        return EngineResult.failure(f"command {name!r} failed: {e}")


def _bind_args(names: tuple[str, ...], values: list[str]) -> 'dict[str, object]':
    """Bind positional ``values`` to declared ``names``.

    The last declared arg soaks up any remaining values as a list (so
    ``file add`` can take many paths). Missing args bind to None.
    """
    bound: dict[str, object] = {}
    if not names:
        bound['_args'] = values
        return bound
    for i, arg_name in enumerate(names):
        last = i == len(names) - 1
        if last:
            remainder = values[i:]
            bound[arg_name] = remainder if len(remainder) != 1 else remainder[0]
            if not remainder:
                bound[arg_name] = None
        else:
            bound[arg_name] = values[i] if i < len(values) else None
    return bound
