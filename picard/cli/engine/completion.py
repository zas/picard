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

"""Tab-completion for the engine shell.

The core is :func:`complete` — a pure function (no readline) that, given the
current line and the word being completed, returns candidate completions. It
decides what to complete from the command registry and the command's declared
``arg_kinds``:

- command name (first word(s)) -> matching ``noun verb`` names
- a ``path`` arg -> filesystem paths (``~`` expanded, directory-aware)
- a ``selector`` / ``handle`` arg -> live session handles + wildcards

:class:`ShellCompleter` adapts :func:`complete` to the stdlib ``readline``
completer protocol.
"""

import glob
import os

from picard.cli.engine.dispatch import split_command_name


_WILDCARDS = ('*', 'f*', 'c*', 'a*', 't*', 'm*')
_HANDLE_PREFIXES = ('f', 'c', 'a', 't', 'm')


def _complete_path(text: str) -> list[str]:
    """Filesystem path completions for ``text`` (supports ~ and directories)."""
    expanded = os.path.expanduser(text)
    matches = glob.glob(expanded + '*')
    results = []
    for match in matches:
        # Re-collapse the home dir so the completion matches what the user typed.
        shown = match
        if text.startswith('~'):
            home = os.path.expanduser('~')
            if match.startswith(home):
                shown = '~' + match[len(home) :]
        if os.path.isdir(match):
            shown += os.sep
        results.append(shown)
    return sorted(results)


def _live_handles(session) -> list[str]:
    """All currently-live handles across the known prefixes, via the session."""
    handles = []
    for prefix in _HANDLE_PREFIXES:
        for entity in session.enumerate_prefix(prefix):
            try:
                handles.append(session.handle_for(entity))
            except ValueError:
                continue
    return handles


def complete(line: str, text: str, registry, session) -> list[str]:
    """Return completions for ``text`` given the full ``line`` so far.

    ``text`` is the word being completed (readline's current token); ``line``
    is the whole line up to the cursor.
    """
    # Tokens already on the line (the trailing partial word is ``text``).
    head = line[: len(line) - len(text)]
    tokens = head.split()

    # Completing the command name itself (nothing resolved yet).
    if not tokens:
        names = registry.names() + ['help', 'quit', 'exit']
        return sorted(n for n in names if n.startswith(text))

    # Is the first token (or first two) a known command?
    name, rest = split_command_name(tokens, registry)
    command = registry.get(name)
    if command is None:
        # Maybe the user is mid-typing a two-word command: offer verb matches.
        if len(tokens) == 1:
            prefix = tokens[0] + ' '
            matches = [n[len(prefix) :] for n in registry.names() if n.startswith(prefix)]
            if matches:
                return sorted(m for m in matches if m.startswith(text))
        return []

    # We have a command; the number of already-typed args decides the arg index.
    arg_index = len(rest)
    kind = command.arg_kind(arg_index)
    if kind == 'path':
        return _complete_path(text)
    if kind in {'selector', 'handle'}:
        options = _live_handles(session)
        if kind == 'selector':
            options = options + list(_WILDCARDS)
        return sorted(o for o in set(options) if o.startswith(text))
    return []


class ShellCompleter:
    """readline completer adapter around :func:`complete`."""

    def __init__(self, registry, session, get_line_buffer):
        self._registry = registry
        self._session = session
        self._get_line_buffer = get_line_buffer
        self._matches: list[str] = []

    def complete(self, text: str, state: int) -> 'str | None':
        if state == 0:
            line = self._get_line_buffer()
            self._matches = complete(line, text, self._registry, self._session)
        if 0 <= state < len(self._matches):
            return self._matches[state]
        return None
